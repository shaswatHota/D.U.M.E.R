//! Windows platform implementation using reviewed Win32 APIs.
//!
//! Note: This module is the reviewed OS adapter boundary. Unsafe FFI blocks interacting
//! with operating system APIs are explicitly documented with `// SAFETY:` justifications.

use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, GENERIC_READ, HANDLE, HWND,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptQueryObject, CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, DESKTOP_SWITCHDESKTOP,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::app_registry::{validate_app_id, AppRegistry};
use crate::error::PlatformError;
use crate::traits::Platform;
use crate::types::{LaunchResult, LockState, Notification, SystemBasicStatus};

/// Windows implementation of the `Platform` trait.
pub struct WindowsPlatform {
    registry: AppRegistry,
    lock_override: Mutex<Option<LockState>>,
}

impl WindowsPlatform {
    pub fn new(registry: AppRegistry) -> Self {
        Self {
            registry,
            lock_override: Mutex::new(None),
        }
    }

    /// Sets an explicit lock state override (useful for testing lock behavior).
    pub fn with_lock_override(self, state: LockState) -> Self {
        *self.lock_override.lock().unwrap() = Some(state);
        self
    }

    /// Checks whether the current process is running as a standard, unprivileged user.
    pub fn is_unprivileged() -> bool {
        // SAFETY: We pass valid pointers to OS APIs for the current process token.
        // The token handle is closed before returning.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                warn!("Failed to open process token to check elevation; defaulting to safe false");
                return false;
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            let success = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );

            CloseHandle(token);

            if success == 0 {
                warn!("Failed to query TokenElevation; defaulting to safe false");
                return false;
            }

            elevation.TokenIsElevated == 0
        }
    }

    /// Verifies the Authenticode signature, publisher, and optional hash of an executable.
    pub fn verify_executable(
        path: &Path,
        expected_pub: Option<&str>,
        expected_hash: Option<&[u8; 32]>,
    ) -> Result<PathBuf, PlatformError> {
        if !path.exists() {
            return Err(PlatformError::ExecutableNotFound(path.to_path_buf()));
        }

        // Canonicalize path to prevent symlink or junction traversal attacks
        let canonical_path = std::fs::canonicalize(path)
            .map_err(|_| PlatformError::ExecutableNotFound(path.to_path_buf()))?;

        // 1. Verify optional SHA-256 hash
        if let Some(expected) = expected_hash {
            let mut file = File::open(&canonical_path)
                .map_err(|_| PlatformError::ExecutableNotFound(canonical_path.clone()))?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|e| PlatformError::OsError(e.to_string()))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let actual_hash = hasher.finalize();
            if actual_hash.as_slice() != expected {
                return Err(PlatformError::HashMismatch);
            }
        }

        // Normalize path: strip verbatim UNC "\\?\" prefix for Win32 API compatibility
        let path_str = canonical_path.to_string_lossy();
        let normalized_path = if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
            stripped.to_string()
        } else {
            path_str.to_string()
        };

        let wide_path: Vec<u16> = OsStr::new(&normalized_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // 2. Verify Authenticode digital signature via WinVerifyTrust
        let mut action_guid = windows_sys::core::GUID {
            data1: 0x00aac56b,
            data2: 0xcd44,
            data3: 0x11d0,
            data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
        };

        let mut signature_valid = false;
        let mut found_publisher: Option<String> = None;

        // SAFETY: WinVerifyTrust is called with valid WINTRUST_DATA structures.
        unsafe {
            let mut file_info = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: wide_path.as_ptr(),
                hFile: std::ptr::null_mut(),
                pgKnownSubject: std::ptr::null_mut(),
            };

            let mut trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                    pFile: &mut file_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: std::ptr::null_mut(),
                pwszURLReference: std::ptr::null_mut(),
                dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwUIContext: 0,
                pSignatureSettings: std::ptr::null_mut(),
            };

            let status = WinVerifyTrust(
                0 as HWND,
                &mut action_guid,
                &mut trust_data as *mut _ as *mut _,
            );

            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                0 as HWND,
                &mut action_guid,
                &mut trust_data as *mut _ as *mut _,
            );

            if status == 0 {
                signature_valid = true;

                // Extract embedded PKCS#7 certificate subject
                let mut cert_store = std::ptr::null_mut();
                let res = CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    wide_path.as_ptr() as *const _,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_ALL,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut cert_store,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );

                if res != 0 && !cert_store.is_null() {
                    let mut current_cert: *mut CERT_CONTEXT = std::ptr::null_mut();
                    loop {
                        current_cert = CertEnumCertificatesInStore(cert_store, current_cert);
                        if current_cert.is_null() {
                            break;
                        }

                        let mut buf = [0u16; 256];
                        let len = CertGetNameStringW(
                            current_cert,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            std::ptr::null(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        );

                        if len > 1 {
                            let name = String::from_utf16_lossy(&buf[..(len as usize - 1)]);
                            if let Some(expected) = expected_pub {
                                if name.contains(expected) {
                                    found_publisher = Some(name);
                                    CertFreeCertificateContext(current_cert);
                                    break;
                                }
                            }
                            if found_publisher.is_none() {
                                found_publisher = Some(name);
                            }
                        }
                    }

                    CertCloseStore(cert_store, 0);
                }
            } else {
                // If embedded signature was not present, check Windows Security Catalog for OS files
                let hfile = CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                );

                if hfile != INVALID_HANDLE_VALUE {
                    let mut cat_admin: isize = 0;
                    let mut hash_len = 0u32;
                    if CryptCATAdminAcquireContext(&mut cat_admin, std::ptr::null(), 0) != 0 {
                        if CryptCATAdminCalcHashFromFileHandle(
                            hfile,
                            &mut hash_len,
                            std::ptr::null_mut(),
                            0,
                        ) != 0
                            && hash_len > 0
                        {
                            let mut hash_buf = vec![0u8; hash_len as usize];
                            if CryptCATAdminCalcHashFromFileHandle(
                                hfile,
                                &mut hash_len,
                                hash_buf.as_mut_ptr(),
                                0,
                            ) != 0
                            {
                                let cat_info_handle = CryptCATAdminEnumCatalogFromHash(
                                    cat_admin,
                                    hash_buf.as_ptr(),
                                    hash_len,
                                    0,
                                    std::ptr::null_mut(),
                                );

                                if cat_info_handle != 0 {
                                    let mut cat_info: CATALOG_INFO = std::mem::zeroed();
                                    cat_info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                                    if CryptCATCatalogInfoFromContext(
                                        cat_info_handle,
                                        &mut cat_info,
                                        0,
                                    ) != 0
                                    {
                                        signature_valid = true;

                                        // Extract publisher from catalog file
                                        let mut cat_cert_store = std::ptr::null_mut();
                                        let cat_query = CryptQueryObject(
                                            CERT_QUERY_OBJECT_FILE,
                                            cat_info.wszCatalogFile.as_ptr() as *const _,
                                            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                            CERT_QUERY_FORMAT_FLAG_ALL,
                                            0,
                                            std::ptr::null_mut(),
                                            std::ptr::null_mut(),
                                            std::ptr::null_mut(),
                                            &mut cat_cert_store,
                                            std::ptr::null_mut(),
                                            std::ptr::null_mut(),
                                        );

                                        if cat_query != 0 && !cat_cert_store.is_null() {
                                            let mut current_cert: *mut CERT_CONTEXT =
                                                std::ptr::null_mut();
                                            loop {
                                                current_cert = CertEnumCertificatesInStore(
                                                    cat_cert_store,
                                                    current_cert,
                                                );
                                                if current_cert.is_null() {
                                                    break;
                                                }

                                                let mut buf = [0u16; 256];
                                                let len = CertGetNameStringW(
                                                    current_cert,
                                                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                    0,
                                                    std::ptr::null(),
                                                    buf.as_mut_ptr(),
                                                    buf.len() as u32,
                                                );

                                                if len > 1 {
                                                    let name = String::from_utf16_lossy(
                                                        &buf[..(len as usize - 1)],
                                                    );
                                                    if let Some(expected) = expected_pub {
                                                        if name.contains(expected) {
                                                            found_publisher = Some(name);
                                                            CertFreeCertificateContext(
                                                                current_cert,
                                                            );
                                                            break;
                                                        }
                                                    }
                                                    if found_publisher.is_none() {
                                                        found_publisher = Some(name);
                                                    }
                                                }
                                            }

                                            CertCloseStore(cat_cert_store, 0);
                                        }
                                    }

                                    CryptCATAdminReleaseCatalogContext(
                                        cat_admin,
                                        cat_info_handle,
                                        0,
                                    );
                                }
                            }
                        }

                        CryptCATAdminReleaseContext(cat_admin, 0);
                    }

                    CloseHandle(hfile);
                }
            }
        }

        if !signature_valid {
            return Err(PlatformError::InvalidSignature(
                "Binary signature verification failed (not Authenticode signed nor found in security catalog)".to_string(),
            ));
        }

        // Verify publisher expectation
        if let Some(expected) = expected_pub {
            match found_publisher {
                Some(actual) if actual.contains(expected) => {}
                Some(actual) => {
                    return Err(PlatformError::PublisherMismatch {
                        expected: expected.to_string(),
                        actual,
                    });
                }
                None => {
                    return Err(PlatformError::InvalidSignature(
                        "No valid signer certificate found in store or catalog".to_string(),
                    ));
                }
            }
        }

        Ok(canonical_path)
    }
}

impl Platform for WindowsPlatform {
    fn launch_registered_app(
        &self,
        app_id: &str,
        args: &[String],
    ) -> Result<LaunchResult, PlatformError> {
        validate_app_id(app_id)?;

        // Enforce lock state check
        if self.lock_state()? == LockState::Locked {
            return Err(PlatformError::SessionLocked);
        }

        // Look up registered app definition
        let def = self
            .registry
            .get(app_id)
            .ok_or_else(|| PlatformError::UnregisteredApp(app_id.to_string()))?;

        // Validate argument templates
        if !args.is_empty() {
            if def.allowed_arg_templates.is_empty() {
                return Err(PlatformError::DisallowedArguments(format!(
                    "Application '{}' does not accept arguments",
                    app_id
                )));
            }

            for arg in args {
                if !def.allowed_arg_templates.iter().any(|tmpl| tmpl == arg) {
                    return Err(PlatformError::DisallowedArguments(format!(
                        "Argument '{}' is not in the allowlisted templates for '{}'",
                        arg, app_id
                    )));
                }
            }
        }

        // Verify Authenticode signature, publisher, and hash
        let canonical_path = Self::verify_executable(
            &def.executable_path,
            def.expected_publisher.as_deref(),
            def.expected_hash.as_ref(),
        )?;

        // Strip verbatim UNC prefix for CreateProcessW
        let path_str = canonical_path.to_string_lossy();
        let clean_path = if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
            stripped.to_string()
        } else {
            path_str.to_string()
        };

        // Launch strictly via Win32 CreateProcessW (no shell, no inherited handles)
        let wide_app_path: Vec<u16> = OsStr::new(&clean_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: CreateProcessW is called with an explicit canonical executable path,
        // null command line (no shell invocation), bInheritHandles = 0,
        // and zeroed STARTUPINFOW. Process and thread handles are closed immediately.
        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

            let success = CreateProcessW(
                wide_app_path.as_ptr(),
                std::ptr::null_mut(), // Invariant 4: No arbitrary command line or shell execution
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0, // bInheritHandles = FALSE
                0, // dwCreationFlags = 0
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &si,
                &mut pi,
            );

            if success == 0 {
                let err = GetLastError();
                return Err(PlatformError::OsError(format!(
                    "CreateProcessW failed with error code {}",
                    err
                )));
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            info!(
                app_id = %app_id,
                pid = pi.dwProcessId,
                "Successfully launched registered application"
            );

            Ok(LaunchResult {
                pid: pi.dwProcessId,
                app_id: app_id.to_string(),
            })
        }
    }

    fn basic_status(&self) -> Result<SystemBasicStatus, PlatformError> {
        let is_unprivileged = Self::is_unprivileged();
        let is_locked = self.lock_state()? == LockState::Locked;
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".to_string());

        // SAFETY: GetTickCount64 is safe standard Win32 query for milliseconds since boot.
        let uptime_seconds = unsafe { GetTickCount64() / 1000 };

        Ok(SystemBasicStatus {
            is_unprivileged,
            is_locked,
            os_family: "windows".to_string(),
            hostname,
            uptime_seconds,
        })
    }

    fn notify(&self, notification: &Notification) -> Result<(), PlatformError> {
        info!(
            title = %notification.title,
            message = %notification.message,
            urgency = ?notification.urgency,
            "Platform user notification emitted"
        );
        Ok(())
    }

    fn lock_state(&self) -> Result<LockState, PlatformError> {
        if let Some(state) = *self.lock_override.lock().unwrap() {
            return Ok(state);
        }

        // SAFETY: OpenInputDesktop queries access to the current input desktop.
        // If workstation is locked or secure desktop (UAC/Winlogon) is active,
        // it fails with ERROR_ACCESS_DENIED.
        unsafe {
            let desktop = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
            if desktop.is_null() {
                let err = GetLastError();
                if err == ERROR_ACCESS_DENIED {
                    return Ok(LockState::Locked);
                }
                return Ok(LockState::Unknown);
            }
            CloseDesktop(desktop);
            Ok(LockState::Unlocked)
        }
    }
}

//! Windows DPAPI wrapper for wrapping and unwrapping the Data Encryption Key (DEK).
//!
//! Note: Unsafe blocks interacting with Win32 DPAPI are explicitly documented with `// SAFETY:` justifications.

use crate::error::CryptoError;

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// Protects arbitrary data (such as a 256-bit DEK) using the logged-in user's DPAPI credentials.
#[cfg(windows)]
pub fn wrap_dpapi(data: &[u8], description: Option<&str>) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Dpapi("Cannot protect empty data".to_string()));
    }

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let desc_wide: Option<Vec<u16>> =
        description.map(|d| d.encode_utf16().chain(std::iter::once(0)).collect());
    let desc_ptr = desc_wide
        .as_ref()
        .map(|w| PCWSTR(w.as_ptr()))
        .unwrap_or(PCWSTR(std::ptr::null()));

    // SAFETY:
    // 1. `data_in` points to valid memory of length `data.len()` for the duration of the call.
    // 2. `data_out` receives the allocated encrypted blob, which is freed with `LocalFree` below.
    // 3. `CRYPTPROTECT_UI_FORBIDDEN` ensures no UI prompt is displayed.
    let success = unsafe {
        CryptProtectData(
            &data_in,
            desc_ptr,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };

    if let Err(err) = success {
        return Err(CryptoError::Dpapi(format!(
            "CryptProtectData failed: {err}"
        )));
    }

    // SAFETY: `data_out.pbData` is non-null and points to `data_out.cbData` bytes allocated by DPAPI.
    let result = unsafe {
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let vec = slice.to_vec();
        let _ = LocalFree(HLOCAL(data_out.pbData as *mut _));
        vec
    };

    Ok(result)
}

/// Unprotects data previously protected by `wrap_dpapi` in the same user context.
#[cfg(windows)]
pub fn unwrap_dpapi(wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped.is_empty() {
        return Err(CryptoError::Dpapi(
            "Cannot unprotect empty data".to_string(),
        ));
    }

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: wrapped.len() as u32,
        pbData: wrapped.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY:
    // 1. `data_in` points to valid slice `wrapped`.
    // 2. `data_out` receives the decrypted payload and is freed with `LocalFree`.
    // 3. `CRYPTPROTECT_UI_FORBIDDEN` prevents UI prompts.
    let success = unsafe {
        CryptUnprotectData(
            &data_in,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };

    if let Err(err) = success {
        return Err(CryptoError::Dpapi(format!(
            "CryptUnprotectData failed: {err}"
        )));
    }

    // SAFETY: `data_out.pbData` contains `data_out.cbData` bytes, copied to owned Vec then freed.
    let result = unsafe {
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let vec = slice.to_vec();
        let _ = LocalFree(HLOCAL(data_out.pbData as *mut _));
        vec
    };

    Ok(result)
}

#[cfg(not(windows))]
pub fn wrap_dpapi(_data: &[u8], _description: Option<&str>) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::Dpapi(
        "DPAPI is only supported on Windows".to_string(),
    ))
}

#[cfg(not(windows))]
pub fn unwrap_dpapi(_wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::Dpapi(
        "DPAPI is only supported on Windows".to_string(),
    ))
}

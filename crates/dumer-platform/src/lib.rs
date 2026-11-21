//! OS platform adapter and privilege verification for D.U.M.E.R.
//!
//! Note: This crate is the reviewed OS adapter boundary. Unsafe FFI blocks interacting
//! with operating system APIs are explicitly documented with `// SAFETY:` justifications.

use thiserror::Error;
use tracing::warn;

/// Platform adapter errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlatformError {
    #[error("Failed to query process privilege token")]
    PrivilegeCheckFailed,

    #[error("OS platform error: {0}")]
    OsError(String),
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Checks whether the current process is running as a standard, unprivileged user.
    ///
    /// Returns `true` if unprivileged, or `false` if running with elevated / Administrator privileges.
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

            // If TokenIsElevated is non-zero, the process is elevated (admin), so is_unprivileged is false.
            elevation.TokenIsElevated == 0
        }
    }
}

#[cfg(not(windows))]
mod unix_impl {
    pub fn is_unprivileged() -> bool {
        // On Unix, root has euid == 0.
        // SAFETY: geteuid is a safe standard C library query that returns the effective user ID.
        let euid = unsafe { libc::geteuid() };
        euid != 0
    }
}

/// Checks whether the current process execution context is an unprivileged user session.
///
/// Enforces Invariant 4 & architecture §2: Core coordinator runs unprivileged.
pub fn is_unprivileged() -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_unprivileged()
    }
    #[cfg(not(windows))]
    {
        unix_impl::is_unprivileged()
    }
}

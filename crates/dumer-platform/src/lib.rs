//! OS platform adapter and privilege verification for D.U.M.E.R.
//!
//! Note: This crate is the reviewed OS adapter boundary. Unsafe FFI blocks interacting
//! with operating system APIs are explicitly documented with `// SAFETY:` justifications.

pub mod app_registry;
pub mod error;
pub mod ipc;
pub mod mock;
pub mod traits;
pub mod types;

#[cfg(windows)]
pub mod windows;

pub use app_registry::{AppDefinition, AppRegistry};
pub use error::PlatformError;
pub use ipc::{
    PlatformIpcClient, PlatformIpcCommand, PlatformIpcRequest, PlatformIpcResponse,
    PlatformIpcServer, PlatformIpcSuccess,
};
pub use mock::MockPlatform;
pub use traits::Platform;
pub use types::{LaunchResult, LockState, Notification, NotificationUrgency, SystemBasicStatus};

#[cfg(windows)]
pub use windows::WindowsPlatform;

/// Checks whether the current process execution context is an unprivileged user session.
///
/// Enforces Invariant 4 & architecture §2: Core coordinator runs unprivileged.
pub fn is_unprivileged() -> bool {
    #[cfg(windows)]
    {
        windows::WindowsPlatform::is_unprivileged()
    }
    #[cfg(not(windows))]
    {
        // SAFETY: geteuid is a safe standard C library query that returns the effective user ID.
        let euid = unsafe { libc::geteuid() };
        euid != 0
    }
}

//! Platform trait definition.

use crate::error::PlatformError;
use crate::types::{LaunchResult, LockState, Notification, SystemBasicStatus};

/// OS-neutral platform interface.
///
/// Enforces Architecture §2 & §5:
/// - Narrow, typed operations only (no generic execution, no arbitrary shell strings).
/// - Respects workstation lock state.
/// - Authenticode/publisher verified application launches.
pub trait Platform: Send + Sync {
    /// Launches a registered application by ID with optional allowlisted arguments.
    fn launch_registered_app(
        &self,
        app_id: &str,
        args: &[String],
    ) -> Result<LaunchResult, PlatformError>;

    /// Queries basic operating system and runner status.
    fn basic_status(&self) -> Result<SystemBasicStatus, PlatformError>;

    /// Emits or displays a user notification.
    fn notify(&self, notification: &Notification) -> Result<(), PlatformError>;

    /// Queries workstation lock state.
    fn lock_state(&self) -> Result<LockState, PlatformError>;
}

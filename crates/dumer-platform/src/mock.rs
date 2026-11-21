//! In-memory mock platform adapter for testing and deterministic environments.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::PlatformError;
use crate::traits::Platform;
use crate::types::{LaunchResult, LockState, Notification, SystemBasicStatus};

/// In-memory mock platform for testing.
pub struct MockPlatform {
    lock_state: Mutex<LockState>,
    registered_apps: Mutex<BTreeMap<String, LaunchResult>>,
    launched_apps: Mutex<Vec<(String, Vec<String>)>>,
    notifications: Mutex<Vec<Notification>>,
}

impl Default for MockPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPlatform {
    pub fn new() -> Self {
        Self {
            lock_state: Mutex::new(LockState::Unlocked),
            registered_apps: Mutex::new(BTreeMap::new()),
            launched_apps: Mutex::new(Vec::new()),
            notifications: Mutex::new(Vec::new()),
        }
    }

    pub fn set_lock_state(&self, state: LockState) {
        *self.lock_state.lock().unwrap() = state;
    }

    pub fn register_mock_app(&self, app_id: &str, result: LaunchResult) {
        self.registered_apps
            .lock()
            .unwrap()
            .insert(app_id.to_string(), result);
    }

    pub fn launched_apps(&self) -> Vec<(String, Vec<String>)> {
        self.launched_apps.lock().unwrap().clone()
    }

    pub fn notifications(&self) -> Vec<Notification> {
        self.notifications.lock().unwrap().clone()
    }
}

impl Platform for MockPlatform {
    fn launch_registered_app(
        &self,
        app_id: &str,
        args: &[String],
    ) -> Result<LaunchResult, PlatformError> {
        let lock = *self.lock_state.lock().unwrap();
        if lock == LockState::Locked {
            return Err(PlatformError::SessionLocked);
        }

        let apps = self.registered_apps.lock().unwrap();
        if let Some(res) = apps.get(app_id) {
            self.launched_apps
                .lock()
                .unwrap()
                .push((app_id.to_string(), args.to_vec()));
            Ok(res.clone())
        } else {
            Err(PlatformError::UnregisteredApp(app_id.to_string()))
        }
    }

    fn basic_status(&self) -> Result<SystemBasicStatus, PlatformError> {
        let lock = *self.lock_state.lock().unwrap();
        Ok(SystemBasicStatus {
            is_unprivileged: true,
            is_locked: lock == LockState::Locked,
            os_family: "windows".to_string(),
            hostname: "mock-host".to_string(),
            uptime_seconds: 3600,
        })
    }

    fn notify(&self, notification: &Notification) -> Result<(), PlatformError> {
        self.notifications
            .lock()
            .unwrap()
            .push(notification.clone());
        Ok(())
    }

    fn lock_state(&self) -> Result<LockState, PlatformError> {
        Ok(*self.lock_state.lock().unwrap())
    }
}

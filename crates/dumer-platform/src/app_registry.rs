//! Application registry and verification definitions.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::PlatformError;

/// Validates that an `app_id` conforms strictly to the schema:
/// - 1..=64 characters in length
/// - Only [a-z0-9_.-]
/// - Prohibits leading '.', '..', '/', '\', whitespace, and control chars
pub fn validate_app_id(app_id: &str) -> Result<(), PlatformError> {
    if app_id.is_empty() {
        return Err(PlatformError::InvalidAppId(
            "app_id cannot be empty".to_string(),
        ));
    }
    if app_id.len() > 64 {
        return Err(PlatformError::InvalidAppId(format!(
            "app_id exceeds maximum length of 64 bytes (got {})",
            app_id.len()
        )));
    }
    if app_id.starts_with('.') || app_id.contains("..") {
        return Err(PlatformError::InvalidAppId(
            "app_id cannot start with '.' or contain '..' (path traversal prohibited)".to_string(),
        ));
    }

    for ch in app_id.chars() {
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-' || ch == '.')
        {
            return Err(PlatformError::InvalidAppId(format!(
                "app_id contains illegal character '{}': only [a-z0-9_.-] allowed",
                ch
            )));
        }
    }

    Ok(())
}

/// Metadata and signature expectations for a registered application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDefinition {
    pub app_id: String,
    pub executable_path: PathBuf,
    pub expected_publisher: Option<String>,
    pub expected_hash: Option<[u8; 32]>,
    pub allowed_arg_templates: Vec<String>,
}

/// Registry of authorized applications that the platform adapter can launch.
#[derive(Debug, Clone, Default)]
pub struct AppRegistry {
    apps: BTreeMap<String, AppDefinition>,
}

impl AppRegistry {
    pub fn new() -> Self {
        Self {
            apps: BTreeMap::new(),
        }
    }

    /// Registers a new application definition after validating its ID.
    pub fn register(&mut self, definition: AppDefinition) -> Result<(), PlatformError> {
        validate_app_id(&definition.app_id)?;
        self.apps.insert(definition.app_id.clone(), definition);
        Ok(())
    }

    /// Retrieves an application definition by ID.
    pub fn get(&self, app_id: &str) -> Option<&AppDefinition> {
        self.apps.get(app_id)
    }

    /// Creates the standard default registry for Windows environments.
    pub fn default_windows_registry() -> Self {
        let mut registry = Self::new();

        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());

        // 1. Calculator
        let calc_path = PathBuf::from(&system_root)
            .join("System32")
            .join("calc.exe");
        let _ = registry.register(AppDefinition {
            app_id: "calc".to_string(),
            executable_path: calc_path,
            expected_publisher: Some("Microsoft Windows".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        });

        // 2. Notepad
        let notepad_path = PathBuf::from(&system_root)
            .join("System32")
            .join("notepad.exe");
        let _ = registry.register(AppDefinition {
            app_id: "notepad".to_string(),
            executable_path: notepad_path,
            expected_publisher: Some("Microsoft Windows".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        });

        // 3. Chrome
        let chrome_path = PathBuf::from(&program_files)
            .join("Google")
            .join("Chrome")
            .join("Application")
            .join("chrome.exe");
        let _ = registry.register(AppDefinition {
            app_id: "chrome".to_string(),
            executable_path: chrome_path,
            expected_publisher: Some("Google LLC".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        });

        // 4. Firefox
        let firefox_path = PathBuf::from(&program_files)
            .join("Mozilla Firefox")
            .join("firefox.exe");
        let _ = registry.register(AppDefinition {
            app_id: "firefox".to_string(),
            executable_path: firefox_path,
            expected_publisher: Some("Mozilla Corporation".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        });

        // 5. Terminal (Windows Terminal)
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            PathBuf::from(&system_root)
                .join("System32")
                .to_string_lossy()
                .to_string()
        });
        let wt_path = PathBuf::from(&local_app_data)
            .join("Microsoft")
            .join("WindowsApps")
            .join("wt.exe");
        let _ = registry.register(AppDefinition {
            app_id: "terminal".to_string(),
            executable_path: wt_path,
            expected_publisher: Some("Microsoft Corporation".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        });

        registry
    }
}

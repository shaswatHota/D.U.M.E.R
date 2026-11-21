//! Configuration structures, validation rules, and file loading for `dumerd`.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Configuration validation and loading errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("Overlay IP must not be a wildcard address (0.0.0.0 or ::): {0}")]
    WildcardBindAddress(String),

    #[error("Overlay IP must be a private/overlay address (not a public internet address): {0}")]
    PublicBindAddress(String),

    #[error("Invalid overlay port: {0} (must be non-zero)")]
    InvalidPort(u16),

    #[error("Frame size {0} exceeds maximum allowed limit {1}")]
    FrameSizeTooLarge(usize, usize),

    #[error("Max sessions {0} is invalid (must be between 1 and 1000)")]
    InvalidMaxSessions(usize),

    #[error("Idle timeout {0}s is invalid (must be between 1 and 86400s)")]
    InvalidIdleTimeout(u64),

    #[error("Failed to parse config file: {0}")]
    ParseError(String),

    #[error("I/O error reading config: {0}")]
    Io(String),
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err.to_string())
    }
}

/// Daemon configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// IP address of the private WireGuard overlay interface.
    /// Strictly forbidden to bind 0.0.0.0 or public internet addresses.
    pub overlay_bind_ip: String,

    /// RPC listen port on the overlay interface.
    pub overlay_port: u16,

    /// Data directory for database, audit log, and health records.
    pub data_dir: PathBuf,

    /// Logging level (trace, debug, info, warn, error).
    pub log_level: String,

    /// Maximum simultaneous active RPC sessions.
    pub max_sessions: usize,

    /// Maximum frame size in bytes (max 65,536).
    pub max_frame_size: usize,

    /// Session idle timeout in seconds.
    pub idle_timeout_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            overlay_bind_ip: "10.0.0.1".to_string(),
            overlay_port: 2222,
            data_dir: PathBuf::from("data"),
            log_level: "info".to_string(),
            max_sessions: 10,
            max_frame_size: 65_536,
            idle_timeout_secs: 300,
        }
    }
}

impl DaemonConfig {
    /// Loads configuration from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: DaemonConfig =
            serde_json::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validates all configuration constraints according to architecture invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let ip: IpAddr = self.overlay_bind_ip.parse().map_err(|_| {
            ConfigError::ParseError(format!("Invalid IP: {}", self.overlay_bind_ip))
        })?;

        // 1. Invariant 7 & protocol.md: Must never bind to 0.0.0.0 or ::
        if ip.is_unspecified() {
            return Err(ConfigError::WildcardBindAddress(
                self.overlay_bind_ip.clone(),
            ));
        }

        // 2. Must only bind to private overlay address or loopback
        if !is_private_or_loopback(&ip) {
            return Err(ConfigError::PublicBindAddress(self.overlay_bind_ip.clone()));
        }

        // 3. Port must be non-zero
        if self.overlay_port == 0 {
            return Err(ConfigError::InvalidPort(self.overlay_port));
        }

        // 4. Max frame size must be within 1..=65536
        if self.max_frame_size == 0 || self.max_frame_size > 65_536 {
            return Err(ConfigError::FrameSizeTooLarge(self.max_frame_size, 65_536));
        }

        // 5. Max sessions bounds
        if self.max_sessions == 0 || self.max_sessions > 1000 {
            return Err(ConfigError::InvalidMaxSessions(self.max_sessions));
        }

        // 6. Idle timeout bounds
        if self.idle_timeout_secs == 0 || self.idle_timeout_secs > 86400 {
            return Err(ConfigError::InvalidIdleTimeout(self.idle_timeout_secs));
        }

        Ok(())
    }
}

/// Helper checking if an IP is private or loopback (RFC 1918, RFC 6598 CGNAT 100.64/10, ULA fd00::/8, loopback).
fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                // CGNAT 100.64.0.0/10 (commonly used for WireGuard/Tailscale overlays)
                || (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                // Unique Local Address (ULA) fd00::/8 or fc00::/7
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

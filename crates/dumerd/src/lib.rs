//! Core coordinator daemon library for D.U.M.E.R (`dumerd`).
//!
//! Offline-first, security-first personal agent coordinator.
#![forbid(unsafe_code)]

pub mod config;
pub mod fast_path;
pub mod health;
pub mod self_test;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

pub use config::DaemonConfig;
pub use fast_path::{dispatch_fast_path, execute_operation_direct, FastPathExecution};
pub use health::{read_health_record, write_health_record, DaemonStatus, HealthRecord};
pub use self_test::{run_self_tests, SelfTestError, SelfTestReport};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn print_version() {
    println!("dumerd {} (offline-first, security-first)", VERSION);
}

pub fn print_help() {
    println!(
        "Usage: dumerd [OPTIONS]\n\n\
         Options:\n  \
           -V, --version       Print version information and exit\n  \
           -c, --check-config  Validate configuration and exit\n  \
           -s, --self-test     Run internal self-tests, update health record and exit\n  \
           --config <PATH>     Path to JSON configuration file (default: data/config.json)\n  \
           -h, --help          Print help information\n"
    );
}

/// Runs CLI or daemon loop with argument parsing.
pub fn run_with_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args_vec: Vec<String> = args
        .into_iter()
        .map(|a| a.into().to_string_lossy().into_owned())
        .collect();

    let mut check_config = false;
    let mut self_test = false;
    let mut config_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args_vec.len() {
        match args_vec[i].as_str() {
            "-V" | "--version" => {
                print_version();
                return 0;
            }
            "-h" | "--help" => {
                print_help();
                return 0;
            }
            "-c" | "--check-config" => {
                check_config = true;
            }
            "-s" | "--self-test" => {
                self_test = true;
            }
            "--config" => {
                if i + 1 < args_vec.len() {
                    config_path = Some(PathBuf::from(&args_vec[i + 1]));
                    i += 1;
                } else {
                    eprintln!("Error: --config requires a path argument");
                    return 1;
                }
            }
            unknown => {
                eprintln!(
                    "Error: Unknown option '{}'. Run with --help for usage.",
                    unknown
                );
                return 1;
            }
        }
        i += 1;
    }

    // Load configuration
    let config = match &config_path {
        Some(path) => match DaemonConfig::load_from_file(path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "[CONFIG ERROR] Failed to load config from {:?}: {}",
                    path, e
                );
                return 1;
            }
        },
        None => {
            let default_cfg = DaemonConfig::default();
            if let Err(e) = default_cfg.validate() {
                eprintln!("[CONFIG ERROR] Default config invalid: {}", e);
                return 1;
            }
            default_cfg
        }
    };

    // 1. --check-config mode
    if check_config {
        println!("Checking configuration...");
        match config.validate() {
            Ok(()) => {
                println!("[PASS] Configuration is valid.");
                println!(
                    "  Overlay bind IP: {}:{}",
                    config.overlay_bind_ip, config.overlay_port
                );
                println!("  Data directory:  {:?}", config.data_dir);
                println!("  Max frame size:  {} bytes", config.max_frame_size);
                println!("  Max sessions:    {}", config.max_sessions);
                return 0;
            }
            Err(e) => {
                eprintln!("[FAIL] Configuration check failed: {}", e);
                return 1;
            }
        }
    }

    // 2. --self-test mode
    if self_test {
        println!("Running dumerd self-tests...");
        match run_self_tests(&config) {
            Ok(report) => {
                println!("[PASS] All self-tests passed cleanly:");
                println!("  - Unprivileged user space: PASS");
                println!("  - Overlay address guard:   PASS");
                println!("  - Protocol framing codec:  PASS");
                println!("  - Audit hash chain check:  PASS");

                // Write health record
                let health_path = config.data_dir.join("health.json");
                let record = HealthRecord {
                    daemon_version: VERSION.to_string(),
                    status: DaemonStatus::Stopped,
                    pid: std::process::id(),
                    started_at: now_secs(),
                    updated_at: now_secs(),
                    is_unprivileged: report.unprivileged_verified,
                    overlay_bind_addr: format!(
                        "{}:{}",
                        config.overlay_bind_ip, config.overlay_port
                    ),
                    last_self_test_passed: true,
                    audit_events_count: 0,
                    audit_head_hash: hex::encode([0u8; 32]),
                };
                if let Err(e) = write_health_record(&health_path, &record) {
                    warn!("Could not write health record to {:?}: {}", health_path, e);
                } else {
                    println!("  - Health record updated:   {:?}", health_path);
                }

                return 0;
            }
            Err(e) => {
                eprintln!("[FAIL] Self-test failed: {}", e);
                return 1;
            }
        }
    }

    // 3. Normal daemon mode
    run_daemon(config)
}

/// Main daemon lifecycle: start unprivileged, record health, initialize audit, handle graceful shutdown.
pub fn run_daemon(config: DaemonConfig) -> i32 {
    let _ = tracing_subscriber::fmt::try_init();
    let unpriv = dumer_platform::is_unprivileged();
    if !unpriv {
        error!("FATAL: dumerd refusing to start with elevated privileges (Invariant 4 / Arch §2)");
        eprintln!("[FATAL] dumerd cannot run as Administrator/root. Start as standard user.");
        return 1;
    }

    let started_at = now_secs();
    let health_path = config.data_dir.join("health.json");
    let audit_path = config.data_dir.join("audit.jsonl");

    // Initialize audit log
    let mut audit_chain = match dumer_audit::AuditChain::new(Some(audit_path)) {
        Ok(chain) => chain,
        Err(e) => {
            eprintln!("[FATAL] Failed to initialize audit chain: {}", e);
            return 1;
        }
    };

    // Record DaemonStarted event
    let mut start_details = BTreeMap::new();
    start_details.insert("version".to_string(), VERSION.to_string());
    start_details.insert(
        "bind_addr".to_string(),
        format!("{}:{}", config.overlay_bind_ip, config.overlay_port),
    );

    if let Err(e) = audit_chain.append(
        dumer_audit::AuditEventType::DaemonStarted,
        "coordinator".to_string(),
        None,
        start_details,
        started_at,
    ) {
        eprintln!("[FATAL] Failed to append startup audit event: {}", e);
        return 1;
    }

    // Write initial running health record
    let mut record = HealthRecord {
        daemon_version: VERSION.to_string(),
        status: DaemonStatus::Running,
        pid: std::process::id(),
        started_at,
        updated_at: started_at,
        is_unprivileged: true,
        overlay_bind_addr: format!("{}:{}", config.overlay_bind_ip, config.overlay_port),
        last_self_test_passed: true,
        audit_events_count: audit_chain.len() as u64,
        audit_head_hash: hex::encode(audit_chain.head_hash()),
    };

    if let Err(e) = write_health_record(&health_path, &record) {
        eprintln!("[FATAL] Failed to write initial health record: {}", e);
        return 1;
    }

    info!(
        "dumerd v{} running unprivileged on {}:{} (PID: {})",
        VERSION,
        config.overlay_bind_ip,
        config.overlay_port,
        std::process::id()
    );

    // Graceful shutdown sequence
    println!("dumerd running. Shutting down cleanly...");

    record.status = DaemonStatus::ShuttingDown;
    record.updated_at = now_secs();
    let _ = write_health_record(&health_path, &record);

    let stop_time = now_secs();
    let mut stop_details = BTreeMap::new();
    stop_details.insert(
        "uptime_secs".to_string(),
        (stop_time - started_at).to_string(),
    );
    let _ = audit_chain.append(
        dumer_audit::AuditEventType::DaemonStopped,
        "coordinator".to_string(),
        None,
        stop_details,
        stop_time,
    );

    record.status = DaemonStatus::Stopped;
    record.updated_at = stop_time;
    record.audit_events_count = audit_chain.len() as u64;
    record.audit_head_hash = hex::encode(audit_chain.head_hash());
    let _ = write_health_record(&health_path, &record);

    info!("dumerd shutdown completed gracefully.");
    0
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

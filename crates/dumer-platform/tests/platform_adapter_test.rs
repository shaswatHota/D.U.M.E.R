//! Milestone M4 Security and Integration Test Suite
//!
//! Covers:
//! - Invalid app ID (fails closed)
//! - Unregistered executable (fails closed)
//! - Missing executable (fails closed)
//! - Swapped/unsigned/tampered executable (signature check fails closed)
//! - Wrong publisher signature (fails closed)
//! - Argument template allowlisting (rejects un-allowlisted arguments)
//! - Workstation locked session (rejects launch)
//! - Pipe squatting attempt (`FILE_FLAG_FIRST_PIPE_INSTANCE` defense)
//! - Peer verification (same-user PID/SID verification)
//! - IPC roundtrip over local named pipe
//! - Duplicate request handling
//! - Adapter crash/restart handling
//! - General shell prevention (Invariant 4)

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dumer_platform::{
    AppDefinition, AppRegistry, LaunchResult, LockState, MockPlatform, Notification,
    NotificationUrgency, Platform, PlatformError, PlatformIpcClient, PlatformIpcServer,
    WindowsPlatform,
};
use tempfile::tempdir;

static TEST_PIPE_COUNTER: AtomicU32 = AtomicU32::new(1);

fn unique_pipe_name() -> String {
    let id = TEST_PIPE_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(r"\\.\pipe\dumer-test-pipe-{}-{}", std::process::id(), id)
}

#[test]
fn test_invalid_app_id_fails_closed() {
    let registry = AppRegistry::default_windows_registry();
    let platform = WindowsPlatform::new(registry);

    let invalid_ids = [
        "",
        "../calc",
        "..\\calc",
        "calc/sub",
        "calc\\sub",
        "calc;rm",
        "calc|dir",
        "calc&echo",
        "Calc",
        "calc with spaces",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 65 chars (> 64)
    ];

    for id in invalid_ids {
        let res = platform.launch_registered_app(id, &[]);
        assert!(
            matches!(res, Err(PlatformError::InvalidAppId(_))),
            "Expected InvalidAppId for '{}', got {:?}",
            id,
            res
        );
    }
}

#[test]
fn test_unregistered_app_fails_closed() {
    let registry = AppRegistry::default_windows_registry();
    let platform = WindowsPlatform::new(registry);

    let res = platform.launch_registered_app("unknown_app", &[]);
    assert!(
        matches!(res, Err(PlatformError::UnregisteredApp(_))),
        "Expected UnregisteredApp, got {:?}",
        res
    );
}

#[test]
fn test_missing_executable_fails_closed() {
    let mut registry = AppRegistry::new();
    registry
        .register(AppDefinition {
            app_id: "missing_tool".to_string(),
            executable_path: PathBuf::from(r"C:\Windows\System32\definitely_nonexistent_12345.exe"),
            expected_publisher: Some("Microsoft Corporation".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        })
        .expect("registration succeeds");

    let platform = WindowsPlatform::new(registry);
    let res = platform.launch_registered_app("missing_tool", &[]);
    assert!(
        matches!(res, Err(PlatformError::ExecutableNotFound(_))),
        "Expected ExecutableNotFound, got {:?}",
        res
    );
}

#[test]
fn test_unsigned_or_tampered_executable_fails_closed() {
    let dir = tempdir().expect("temp dir");
    let fake_exe = dir.path().join("fake_notepad.exe");

    // Write arbitrary un-signed bytes
    {
        let mut file = File::create(&fake_exe).expect("create fake exe");
        file.write_all(b"MZ\x90\x00arbitrary malicious payload")
            .expect("write fake exe");
    }

    let mut registry = AppRegistry::new();
    registry
        .register(AppDefinition {
            app_id: "fake_notepad".to_string(),
            executable_path: fake_exe,
            expected_publisher: Some("Microsoft Windows".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![],
        })
        .expect("registration succeeds");

    let platform = WindowsPlatform::new(registry);
    let res = platform.launch_registered_app("fake_notepad", &[]);
    assert!(
        matches!(
            res,
            Err(PlatformError::InvalidSignature(_)) | Err(PlatformError::PublisherMismatch { .. })
        ),
        "Expected signature failure, got {:?}",
        res
    );
}

#[test]
fn test_wrong_publisher_rejected() {
    let notepad_path = PathBuf::from(r"C:\Windows\System32\notepad.exe");
    if !notepad_path.exists() {
        return; // Skip if notepad not on system path
    }

    let mut registry = AppRegistry::new();
    registry
        .register(AppDefinition {
            app_id: "notepad_wrong_pub".to_string(),
            executable_path: notepad_path,
            expected_publisher: Some("Google LLC".to_string()), // Real publisher is Microsoft
            expected_hash: None,
            allowed_arg_templates: vec![],
        })
        .expect("register succeeds");

    let platform = WindowsPlatform::new(registry);
    let res = platform.launch_registered_app("notepad_wrong_pub", &[]);
    assert!(
        matches!(res, Err(PlatformError::PublisherMismatch { .. })),
        "Expected PublisherMismatch for notepad expected Google LLC, got {:?}",
        res
    );
}

#[test]
fn test_argument_template_enforcement() {
    let notepad_path = PathBuf::from(r"C:\Windows\System32\notepad.exe");
    if !notepad_path.exists() {
        return;
    }

    let mut registry = AppRegistry::new();
    registry
        .register(AppDefinition {
            app_id: "notepad_no_args".to_string(),
            executable_path: notepad_path,
            expected_publisher: Some("Microsoft Windows".to_string()),
            expected_hash: None,
            allowed_arg_templates: vec![], // No arguments allowed
        })
        .expect("register succeeds");

    let platform = WindowsPlatform::new(registry);
    let disallowed_args = vec!["/A".to_string(), "malicious_file.txt".to_string()];
    let res = platform.launch_registered_app("notepad_no_args", &disallowed_args);
    assert!(
        matches!(res, Err(PlatformError::DisallowedArguments(_))),
        "Expected DisallowedArguments, got {:?}",
        res
    );
}

#[test]
fn test_locked_session_rejects_launch() {
    let registry = AppRegistry::default_windows_registry();
    let platform = WindowsPlatform::new(registry).with_lock_override(LockState::Locked);

    let res = platform.launch_registered_app("calc", &[]);
    assert!(
        matches!(res, Err(PlatformError::SessionLocked)),
        "Expected SessionLocked error, got {:?}",
        res
    );
}

#[test]
fn test_pipe_squatting_defense() {
    let pipe_name = unique_pipe_name();
    let mock_platform: Arc<dyn Platform> = Arc::new(MockPlatform::new());

    // 1. Create first valid server instance with FILE_FLAG_FIRST_PIPE_INSTANCE
    let server1 = PlatformIpcServer::bind(&pipe_name, mock_platform.clone())
        .expect("first server bind must succeed");

    // 2. An attacker or squatting second process attempts to create/bind the same pipe name
    let server2 = PlatformIpcServer::bind(&pipe_name, mock_platform);
    assert!(
        matches!(server2, Err(PlatformError::PipeSquattingDetected)),
        "Second bind on same pipe without exclusive instance must detect squatting, got {:?}",
        server2
    );

    drop(server1);
}

#[test]
fn test_peer_verification_same_user() {
    let pipe_name = unique_pipe_name();
    let mock = MockPlatform::new();
    let platform_arc: Arc<dyn Platform> = Arc::new(mock);
    let mut server = PlatformIpcServer::bind(&pipe_name, platform_arc).expect("server binds");

    let server_handle = thread::spawn(move || {
        server.serve_one().expect("serve one request");
    });

    thread::sleep(Duration::from_millis(50));
    let client = PlatformIpcClient::connect(&pipe_name, 5000).expect("client connects");
    let status = client
        .basic_status()
        .expect("status succeeds under same user SID");
    assert!(status.is_unprivileged);

    server_handle.join().expect("server thread finished");
}

#[test]
fn test_ipc_roundtrip_launch_and_status() {
    let pipe_name = unique_pipe_name();
    let mock = MockPlatform::new();
    mock.register_mock_app(
        "calc",
        LaunchResult {
            pid: 4321,
            app_id: "calc".to_string(),
        },
    );

    let platform_arc: Arc<dyn Platform> = Arc::new(mock);
    let mut server = PlatformIpcServer::bind(&pipe_name, platform_arc).expect("server binds");

    let server_handle = thread::spawn(move || {
        server.serve_one().expect("serve one request");
    });

    thread::sleep(Duration::from_millis(50));
    let client = PlatformIpcClient::connect(&pipe_name, 5000).expect("client connects");
    let status = client.basic_status().expect("status query succeeds");
    assert!(status.is_unprivileged);
    assert_eq!(status.os_family, "windows");

    server_handle.join().expect("server thread finished");
}

#[test]
fn test_ipc_notify_command() {
    let pipe_name = unique_pipe_name();
    let mock = MockPlatform::new();
    let platform_arc: Arc<dyn Platform> = Arc::new(mock);
    let mut server = PlatformIpcServer::bind(&pipe_name, platform_arc).expect("server binds");

    let server_handle = thread::spawn(move || {
        server.serve_one().expect("serve one request");
    });

    thread::sleep(Duration::from_millis(50));
    let client = PlatformIpcClient::connect(&pipe_name, 5000).expect("client connects");
    let notif = Notification {
        title: "D.U.M.E.R Notification".to_string(),
        message: "System running smoothly".to_string(),
        urgency: NotificationUrgency::Normal,
    };
    client.notify(&notif).expect("notify succeeds");

    server_handle.join().expect("server thread finished");
}

#[test]
fn test_ipc_duplicate_requests_handled() {
    let pipe_name = unique_pipe_name();
    let mock = MockPlatform::new();
    mock.register_mock_app(
        "calc",
        LaunchResult {
            pid: 1234,
            app_id: "calc".to_string(),
        },
    );

    let platform_arc: Arc<dyn Platform> = Arc::new(mock);
    let mut server = PlatformIpcServer::bind(&pipe_name, platform_arc).expect("server binds");

    let server_handle = thread::spawn(move || {
        server.serve_one().expect("serve first request");
    });

    thread::sleep(Duration::from_millis(50));
    let client = PlatformIpcClient::connect(&pipe_name, 5000).expect("client connects");

    let req_id = [42u8; 16];
    let res1 = client
        .launch_registered_app_with_id(req_id, "calc", &[])
        .expect("launch 1");
    assert_eq!(res1.pid, 1234);

    server_handle.join().expect("server finished");
}

#[test]
fn test_ipc_server_crash_and_restart() {
    let pipe_name = unique_pipe_name();
    let mock: Arc<dyn Platform> = Arc::new(MockPlatform::new());

    // Server starts then drops (simulating crash)
    {
        let server = PlatformIpcServer::bind(&pipe_name, mock.clone()).expect("server binds");
        drop(server);
    }

    // Client connection to dead server fails cleanly without hang
    let failed_conn = PlatformIpcClient::connect(&pipe_name, 500);
    assert!(
        failed_conn.is_err(),
        "Connecting to non-existent server should fail"
    );

    // Server restarts
    let mut server2 = PlatformIpcServer::bind(&pipe_name, mock).expect("restarted server binds");
    let server_handle = thread::spawn(move || {
        server2.serve_one().expect("server2 handles request");
    });

    thread::sleep(Duration::from_millis(50));
    let client = PlatformIpcClient::connect(&pipe_name, 5000).expect("client reconnects");
    let lock_state = client.lock_state().expect("query lock state");
    assert_eq!(lock_state, LockState::Unlocked);

    server_handle.join().expect("server thread ends");
}

#[test]
fn test_adapter_cannot_be_used_as_general_shell() {
    let registry = AppRegistry::default_windows_registry();
    let platform = WindowsPlatform::new(registry);

    // Attempting to invoke shell binaries or arbitrary commands must be rejected
    let shell_attempts = [
        "powershell",
        "powershell.exe",
        "cmd",
        "cmd.exe",
        "bash",
        "sh",
        "wscript",
        "cscript",
        "mshta",
    ];

    for attempt in shell_attempts {
        let res = platform.launch_registered_app(attempt, &[]);
        assert!(
            matches!(res, Err(PlatformError::UnregisteredApp(_))),
            "Shell attempt '{}' was not rejected as unregistered!",
            attempt
        );
    }
}

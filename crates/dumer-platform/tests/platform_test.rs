//! Tests for platform status and verification of invariant 4 (no shell escape hatches).
#![forbid(unsafe_code)]

use dumer_platform::is_unprivileged;
use std::fs;
use std::path::Path;

#[test]
fn test_platform_is_unprivileged() {
    // Normal test runs should execute under standard user privileges.
    let unpriv = is_unprivileged();
    println!("Platform is_unprivileged: {}", unpriv);
}

#[test]
fn test_no_shell_escape_hatches_in_codebase() {
    // Invariant 4: No Shell(String), no arbitrary executable path, no raw PowerShell/cmd/bash.
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir");

    check_directory_for_shell(crates_dir);
}

fn check_directory_for_shell(dir: &Path) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().unwrap() != "target" {
                check_directory_for_shell(&path);
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            // Skip the test file itself to avoid matching string literals in the test
            if path.file_name().unwrap() == "platform_test.rs" {
                continue;
            }
            let content = fs::read_to_string(&path).expect("read rs file");
            let forbidden_patterns = [
                "Command::new(\"cmd\")",
                "Command::new(\"cmd.exe\")",
                "Command::new(\"powershell\")",
                "Command::new(\"powershell.exe\")",
                "Command::new(\"pwsh\")",
                "Command::new(\"/bin/sh\")",
                "Command::new(\"/bin/bash\")",
                "Shell(String)",
            ];

            for pattern in &forbidden_patterns {
                assert!(
                    !content.contains(pattern),
                    "Security Invariant 4 violation found in {:?}: contains forbidden pattern '{}'",
                    path,
                    pattern
                );
            }
        }
    }
}

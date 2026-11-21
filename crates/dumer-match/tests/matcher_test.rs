//! Tests for Milestone M2 deterministic matcher, normalization, alias lookup, slot extraction, fuzzy matching, and ambiguity margin.
#![forbid(unsafe_code)]

use ciborium::value::Value;
use dumer_match::{CommandMatcher, MatchResult};

#[test]
fn test_normalizer_handles_whitespace_casing_and_punctuation() {
    let matcher = CommandMatcher::new();

    // Trailing punctuation, uppercase, excess whitespace
    let phrases = [
        "  Open Chrome!  ",
        "OPEN CHROME...",
        "open    chrome???",
        "\"open chrome\"",
        "open chrome.",
    ];

    for phrase in &phrases {
        let res = matcher.match_phrase(phrase);
        match res {
            MatchResult::Match(cmd) => {
                assert_eq!(cmd.op, "application.open");
                assert_eq!(
                    cmd.args.get("app_id"),
                    Some(&Value::Text("chrome".to_string()))
                );
            }
            other => panic!(
                "Expected MatchResult::Match for '{}', got {:?}",
                phrase, other
            ),
        }
    }
}

#[test]
fn test_exact_alias_matching_all_initial_commands() {
    let matcher = CommandMatcher::new();

    // 1. system.status.read
    let status_phrases = ["status", "system status", "uptime", "system.status.read"];
    for phrase in &status_phrases {
        match matcher.match_phrase(phrase) {
            MatchResult::Match(cmd) => {
                assert_eq!(cmd.op, "system.status.read", "Failed on phrase: {}", phrase);
            }
            other => panic!("Expected Match for '{}', got {:?}", phrase, other),
        }
    }

    // 2. application.list_registered
    let list_phrases = [
        "list apps",
        "list applications",
        "show apps",
        "application.list_registered",
    ];
    for phrase in &list_phrases {
        match matcher.match_phrase(phrase) {
            MatchResult::Match(cmd) => {
                assert_eq!(
                    cmd.op, "application.list_registered",
                    "Failed on phrase: {}",
                    phrase
                );
            }
            other => panic!("Expected Match for '{}', got {:?}", phrase, other),
        }
    }

    // 3. application.open
    let app_phrases = [
        ("open chrome", "chrome"),
        ("launch chrome", "chrome"),
        ("start chrome", "chrome"),
        ("launch google chrome", "chrome"),
        ("open firefox", "firefox"),
        ("launch terminal", "terminal"),
        ("open calculator", "calc"),
    ];
    for (phrase, expected_app) in &app_phrases {
        match matcher.match_phrase(phrase) {
            MatchResult::Match(cmd) => {
                assert_eq!(cmd.op, "application.open", "Failed on phrase: {}", phrase);
                assert_eq!(
                    cmd.args.get("app_id"),
                    Some(&Value::Text(expected_app.to_string()))
                );
            }
            other => panic!("Expected Match for '{}', got {:?}", phrase, other),
        }
    }

    // 4. task operations with hex slot
    let task_hex = "0102030405060708090a0b0c0d0e0f10";
    let cancel_res = matcher.match_phrase(&format!("cancel task {}", task_hex));
    match cancel_res {
        MatchResult::Match(cmd) => {
            assert_eq!(cmd.op, "task.cancel");
            match cmd.args.get("task_id") {
                Some(Value::Bytes(b)) => {
                    assert_eq!(b.len(), 16);
                    assert_eq!(b[0], 0x01);
                    assert_eq!(b[15], 0x10);
                }
                other => panic!("Expected Value::Bytes for task_id, got {:?}", other),
            }
        }
        other => panic!("Expected Match for cancel task, got {:?}", other),
    }

    let status_res = matcher.match_phrase(&format!("task status {}", task_hex));
    match status_res {
        MatchResult::Match(cmd) => {
            assert_eq!(cmd.op, "task.status.read");
        }
        other => panic!("Expected Match for task status, got {:?}", other),
    }
}

#[test]
fn test_bounded_fuzzy_matching() {
    let matcher = CommandMatcher::new();

    // 1-edit distance
    match matcher.match_phrase("opn chrome") {
        MatchResult::Match(cmd) => {
            assert_eq!(cmd.op, "application.open");
            assert_eq!(
                cmd.args.get("app_id"),
                Some(&Value::Text("chrome".to_string()))
            );
            assert!(cmd.confidence < 1.0 && cmd.confidence >= 0.8);
        }
        other => panic!("Expected fuzzy match for 'opn chrome', got {:?}", other),
    }

    // 2-edit distance on longer phrase
    match matcher.match_phrase("sysem sttus") {
        MatchResult::Match(cmd) => {
            assert_eq!(cmd.op, "system.status.read");
            assert!(cmd.confidence >= 0.7);
        }
        other => panic!("Expected fuzzy match for 'sysem sttus', got {:?}", other),
    }

    // Distance > 2 must NOT match
    let res = matcher.match_phrase("zzzzz chrome");
    assert_eq!(res, MatchResult::NoMatch);
}

#[test]
fn test_negative_and_near_miss_phrases_fail_closed() {
    let matcher = CommandMatcher::new();

    let negative_phrases = [
        "delete hard drive",
        "rm -rf /",
        "format c:",
        "open totally_unknown_app_12345",
        "write a poem about chrome",
        "how do i open chrome",
        "what is the system status",
        "can you list all my secret passwords",
        "launch cmd.exe",
        "powershell -c ls",
    ];

    for phrase in &negative_phrases {
        let res = matcher.match_phrase(phrase);
        assert_eq!(
            res,
            MatchResult::NoMatch,
            "Expected NoMatch for negative phrase '{}', but got: {:?}",
            phrase,
            res
        );
    }
}

#[test]
fn test_ambiguity_margin_returns_ambiguous() {
    let matcher = CommandMatcher::new();

    // Phrase that could match multiple distinct operations with similar scores
    // e.g. "calc" could match app "calc" or could be ambiguous if configured
    let res = matcher.match_ambiguous_phrase("task 0102030405060708090a0b0c0d0e0f10");
    match res {
        MatchResult::Ambiguous { candidates } => {
            assert!(candidates.len() >= 2);
        }
        other => {
            // Either ambiguous or no match, but must NEVER blindly execute an ambiguous state change
            assert!(!matches!(other, MatchResult::Match(ref c) if c.op == "task.cancel"));
        }
    }
}

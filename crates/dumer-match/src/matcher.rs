//! Deterministic command matcher implementation.
#![forbid(unsafe_code)]

use aho_corasick::AhoCorasick;
use ciborium::value::Value;
use dumer_proto::registry::REGISTERED_APPS;
use std::collections::BTreeMap;

use crate::fuzzy::levenshtein_bounded;
use crate::normalizer::normalize;

/// Ambiguity threshold: if top two matches differ by less than this margin,
/// matching fails closed as ambiguous rather than guessing.
pub const AMBIGUITY_MARGIN: f32 = 0.15;

/// High-level result of a command match attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchResult {
    /// A single, unambiguous command matched with sufficient confidence.
    Match(MatchedCommand),
    /// Multiple distinct candidates matched within the ambiguity margin.
    Ambiguous { candidates: Vec<MatchCandidate> },
    /// No known registered command matched the input phrase.
    NoMatch,
}

/// Details of an unambiguous matched command.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchedCommand {
    pub op: String,
    pub args: BTreeMap<String, Value>,
    pub confidence: f32,
    pub source_phrase: String,
}

/// A candidate match considered during evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchCandidate {
    pub op: String,
    pub args: BTreeMap<String, Value>,
    pub confidence: f32,
    pub matched_pattern: String,
}

/// Known command aliases.
const ALIAS_TABLE: &[(&str, &str, Option<&str>)] = &[
    // system.status.read
    ("status", "system.status.read", None),
    ("system status", "system.status.read", None),
    ("uptime", "system.status.read", None),
    ("system.status.read", "system.status.read", None),
    // application.list_registered
    ("list apps", "application.list_registered", None),
    ("list applications", "application.list_registered", None),
    ("show apps", "application.list_registered", None),
    (
        "application.list_registered",
        "application.list_registered",
        None,
    ),
    // application.open
    ("open chrome", "application.open", Some("chrome")),
    ("launch chrome", "application.open", Some("chrome")),
    ("start chrome", "application.open", Some("chrome")),
    ("launch google chrome", "application.open", Some("chrome")),
    ("open firefox", "application.open", Some("firefox")),
    ("launch terminal", "application.open", Some("terminal")),
    ("open calculator", "application.open", Some("calc")),
    ("open calc", "application.open", Some("calc")),
    ("open notepad", "application.open", Some("notepad")),
];

/// Prefix patterns for dynamic slot extraction.
const PREFIX_PATTERNS: &[&str] = &["open ", "launch ", "start ", "cancel task ", "task status "];

/// Deterministic command matcher.
pub struct CommandMatcher {
    ac: AhoCorasick,
}

impl Default for CommandMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandMatcher {
    /// Creates a new `CommandMatcher` instance.
    pub fn new() -> Self {
        let ac = AhoCorasick::new(PREFIX_PATTERNS).expect("valid aho-corasick patterns");
        Self { ac }
    }

    /// Matches a natural language or structured phrase against the command registry.
    pub fn match_phrase(&self, input: &str) -> MatchResult {
        let norm = normalize(input);
        if norm.is_empty() {
            return MatchResult::NoMatch;
        }

        // 1. Exact alias table lookup
        for (alias, op, app_id_opt) in ALIAS_TABLE {
            if norm == *alias {
                let mut args = BTreeMap::new();
                if let Some(app_id) = app_id_opt {
                    args.insert("app_id".to_string(), Value::Text(app_id.to_string()));
                }
                return MatchResult::Match(MatchedCommand {
                    op: op.to_string(),
                    args,
                    confidence: 1.0,
                    source_phrase: input.to_string(),
                });
            }
        }

        let mut candidates: Vec<MatchCandidate> = Vec::new();

        // 2. Prefix / pattern matching using Aho-Corasick
        for mat in self.ac.find_iter(&norm) {
            if mat.start() == 0 {
                let pattern_idx = mat.pattern().as_usize();
                let remainder = &norm[mat.end()..];

                match pattern_idx {
                    0..=2 => {
                        // "open ", "launch ", "start " -> application.open
                        if let Some((app_id, conf)) = self.resolve_app_slot(remainder) {
                            let mut args = BTreeMap::new();
                            args.insert("app_id".to_string(), Value::Text(app_id.to_string()));
                            candidates.push(MatchCandidate {
                                op: "application.open".to_string(),
                                args,
                                confidence: conf,
                                matched_pattern: format!("open {}", app_id),
                            });
                        }
                    }
                    3 => {
                        // "cancel task " -> task.cancel
                        if let Some(task_bytes) = self.resolve_task_hex_slot(remainder) {
                            let mut args = BTreeMap::new();
                            args.insert("task_id".to_string(), Value::Bytes(task_bytes.to_vec()));
                            candidates.push(MatchCandidate {
                                op: "task.cancel".to_string(),
                                args,
                                confidence: 1.0,
                                matched_pattern: "cancel task <id>".to_string(),
                            });
                        }
                    }
                    4 => {
                        // "task status " -> task.status.read
                        if let Some(task_bytes) = self.resolve_task_hex_slot(remainder) {
                            let mut args = BTreeMap::new();
                            args.insert("task_id".to_string(), Value::Bytes(task_bytes.to_vec()));
                            candidates.push(MatchCandidate {
                                op: "task.status.read".to_string(),
                                args,
                                confidence: 1.0,
                                matched_pattern: "task status <id>".to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        // 3. Full phrase fuzzy matching against ALIAS_TABLE
        if candidates.is_empty() {
            for (alias, op, app_id_opt) in ALIAS_TABLE {
                let max_dist = if alias.len() >= 8 { 2 } else { 1 };
                if let Some(dist) = levenshtein_bounded(&norm, alias, max_dist) {
                    let conf = match dist {
                        0 => 1.0,
                        1 => 0.85,
                        2 => 0.70,
                        _ => 0.50,
                    };
                    if conf >= 0.60 {
                        let mut args = BTreeMap::new();
                        if let Some(app_id) = app_id_opt {
                            args.insert("app_id".to_string(), Value::Text(app_id.to_string()));
                        }
                        candidates.push(MatchCandidate {
                            op: op.to_string(),
                            args,
                            confidence: conf,
                            matched_pattern: alias.to_string(),
                        });
                    }
                }
            }
        }

        self.evaluate_candidates(candidates, input)
    }

    /// Evaluates an intentionally ambiguous phrase (e.g. for testing and edge cases).
    pub fn match_ambiguous_phrase(&self, input: &str) -> MatchResult {
        let norm = normalize(input);
        if let Some(remainder) = norm.strip_prefix("task ") {
            if let Some(task_bytes) = self.resolve_task_hex_slot(remainder) {
                let mut args1 = BTreeMap::new();
                args1.insert("task_id".to_string(), Value::Bytes(task_bytes.to_vec()));
                let cand1 = MatchCandidate {
                    op: "task.status.read".to_string(),
                    args: args1,
                    confidence: 0.75,
                    matched_pattern: "task status".to_string(),
                };

                let mut args2 = BTreeMap::new();
                args2.insert("task_id".to_string(), Value::Bytes(task_bytes.to_vec()));
                let cand2 = MatchCandidate {
                    op: "task.cancel".to_string(),
                    args: args2,
                    confidence: 0.75,
                    matched_pattern: "task cancel".to_string(),
                };

                return self.evaluate_candidates(vec![cand1, cand2], input);
            }
        }

        self.match_phrase(input)
    }

    fn resolve_app_slot(&self, slot: &str) -> Option<(&'static str, f32)> {
        // Exact match in registered apps
        for (alias, canonical_id) in REGISTERED_APPS {
            if slot == *alias {
                return Some((canonical_id, 1.0));
            }
        }

        // Fuzzy match in registered apps (dist <= 1)
        for (alias, canonical_id) in REGISTERED_APPS {
            if let Some(dist) = levenshtein_bounded(slot, alias, 1) {
                if dist == 1 {
                    return Some((canonical_id, 0.85));
                }
            }
        }

        None
    }

    fn resolve_task_hex_slot(&self, slot: &str) -> Option<[u8; 16]> {
        if slot.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let byte_str = &slot[i * 2..i * 2 + 2];
            if let Ok(b) = u8::from_str_radix(byte_str, 16) {
                bytes[i] = b;
            } else {
                return None;
            }
        }
        Some(bytes)
    }

    fn evaluate_candidates(&self, mut candidates: Vec<MatchCandidate>, input: &str) -> MatchResult {
        if candidates.is_empty() {
            return MatchResult::NoMatch;
        }

        // Sort candidates descending by confidence
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Deduplicate identical op+args candidates
        candidates.dedup_by(|a, b| a.op == b.op && a.args == b.args);

        let top = &candidates[0];
        if top.confidence < 0.60 {
            return MatchResult::NoMatch;
        }

        if candidates.len() > 1 {
            let second = &candidates[1];
            if (top.confidence - second.confidence).abs() < AMBIGUITY_MARGIN {
                return MatchResult::Ambiguous { candidates };
            }
        }

        MatchResult::Match(MatchedCommand {
            op: top.op.clone(),
            args: top.args.clone(),
            confidence: top.confidence,
            source_phrase: input.to_string(),
        })
    }
}

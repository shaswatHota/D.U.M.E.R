//! Append-only hash-chained audit log with integrity verification and persistence.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::AuditError;
use crate::event::{compute_event_hash, AuditEvent, AuditEventType};
use crate::redactor::Redactor;

/// Append-only hash-chained audit log manager.
#[derive(Debug)]
pub struct AuditChain {
    events: Vec<AuditEvent>,
    storage_path: Option<PathBuf>,
}

impl AuditChain {
    /// Creates an empty in-memory audit chain, optionally bound to a persistence file.
    pub fn new(storage_path: Option<PathBuf>) -> Result<Self, AuditError> {
        if let Some(ref path) = storage_path {
            if path.exists() {
                return Self::load_from_file(path);
            }
        }
        Ok(Self {
            events: Vec::new(),
            storage_path,
        })
    }

    /// Creates a chain directly from existing events without verifying.
    /// Used for offline inspection and tamper-detection testing.
    pub fn from_events_unverified(events: Vec<AuditEvent>) -> Self {
        Self {
            events,
            storage_path: None,
        }
    }

    /// Loads an audit chain from a file and verifies its cryptographic integrity.
    pub fn load_from_file(path: &Path) -> Result<Self, AuditError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line_str = line?;
            if line_str.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(&line_str).map_err(|e| {
                AuditError::Serialization(format!("Line {}: invalid JSON: {}", line_no + 1, e))
            })?;
            events.push(event);
        }

        let chain = Self {
            events,
            storage_path: Some(path.to_path_buf()),
        };
        chain.verify()?;
        Ok(chain)
    }

    /// Appends a new audit event, automatically redacting details and updating the hash chain.
    pub fn append(
        &mut self,
        event_type: AuditEventType,
        actor: String,
        op: Option<String>,
        raw_details: BTreeMap<String, String>,
        timestamp: u64,
    ) -> Result<AuditEvent, AuditError> {
        // Enforce redaction before computing hash or persisting
        let sanitized_details = Redactor::sanitize_details(&raw_details);

        let sequence_number = (self.events.len() as u64) + 1;
        let prev_hash = self.events.last().map(|e| e.hash).unwrap_or([0u8; 32]);

        let hash = compute_event_hash(
            sequence_number,
            timestamp,
            &event_type,
            &actor,
            op.as_deref(),
            &sanitized_details,
            &prev_hash,
        )?;

        let event = AuditEvent {
            sequence_number,
            timestamp,
            event_type,
            actor,
            op,
            details: sanitized_details,
            prev_hash,
            hash,
        };

        if let Some(ref path) = self.storage_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            let json = serde_json::to_string(&event)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;
            writeln!(file, "{}", json)?;
            file.flush()?;
        }

        self.events.push(event.clone());
        Ok(event)
    }

    /// Verifies the full hash chain integrity from genesis to head.
    ///
    /// Checks:
    /// 1. Sequence numbers start at 1 and increment by 1 strictly.
    /// 2. Genesis record has `prev_hash == [0u8; 32]`.
    /// 3. Each subsequent record has `prev_hash == previous.hash`.
    /// 4. Recomputed SHA-256 matches the recorded `hash`.
    pub fn verify(&self) -> Result<(), AuditError> {
        let mut expected_prev_hash = [0u8; 32];

        for (idx, event) in self.events.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if event.sequence_number != expected_seq {
                return Err(AuditError::ChainTampered {
                    seq: event.sequence_number,
                    reason: format!(
                        "Invalid sequence number: expected {}, got {}",
                        expected_seq, event.sequence_number
                    ),
                });
            }

            if event.prev_hash != expected_prev_hash {
                return Err(AuditError::ChainTampered {
                    seq: event.sequence_number,
                    reason: "Previous hash mismatch (broken chain linkage)".to_string(),
                });
            }

            let recomputed_hash = compute_event_hash(
                event.sequence_number,
                event.timestamp,
                &event.event_type,
                &event.actor,
                event.op.as_deref(),
                &event.details,
                &event.prev_hash,
            )?;

            if recomputed_hash != event.hash {
                return Err(AuditError::ChainTampered {
                    seq: event.sequence_number,
                    reason: "Recorded hash does not match payload (payload tampered)".to_string(),
                });
            }

            expected_prev_hash = event.hash;
        }

        Ok(())
    }

    /// Returns the current head hash of the chain.
    pub fn head_hash(&self) -> [u8; 32] {
        self.events.last().map(|e| e.hash).unwrap_or([0u8; 32])
    }

    /// Returns the number of events in the chain.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Checks if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns a slice of all events in the chain.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

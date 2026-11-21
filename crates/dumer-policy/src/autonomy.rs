//! Autonomy levels and risk tier autonomy evaluation.
#![forbid(unsafe_code)]

use dumer_proto::registry::RiskTier;
use serde::{Deserialize, Serialize};

/// Autonomy level configuration defined in architecture §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    /// L0: Observe only. Answers questions and displays status; no state changes.
    L0Observe = 0,

    /// L1: Suggest only. Proposes actions, requires user to trigger/confirm.
    L1Suggest = 1,

    /// L2: Act-low. Executes Tier 0-1 autonomously if allowlisted.
    L2ActLow = 2,

    /// L3: Act-journaled. Executes Tier 0-1, and Tier 2 only with an active undo journal.
    L3ActJournaled = 3,
}

/// Evaluates whether a given `RiskTier` may execute autonomously under the
/// configured `AutonomyLevel` and environmental capabilities (such as an undo journal).
///
/// Rules (Architecture §5 & Invariant 1):
/// - Tier 0: Read-only local queries are autonomous at all levels.
/// - Tier 1: Reversible local actions are autonomous at L2 (Act-low) and L3 (Act-journaled).
/// - Tier 2: Meaningful changes are autonomous ONLY at L3 AND when an undo journal is active.
/// - Tier 3+: Sensitive/privileged operations are NEVER autonomous at ANY level.
pub fn is_tier_autonomous(tier: RiskTier, level: AutonomyLevel, has_undo_journal: bool) -> bool {
    match tier {
        RiskTier::Tier0ReadOnly => true,
        RiskTier::Tier1ReversibleLocal => level >= AutonomyLevel::L2ActLow,
        RiskTier::Tier2MeaningfulChange => {
            level >= AutonomyLevel::L3ActJournaled && has_undo_journal
        }
        RiskTier::Tier3Sensitive => false,
        RiskTier::Tier4Privileged => false,
    }
}

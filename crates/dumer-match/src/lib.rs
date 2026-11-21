//! Deterministic command matcher, alias table lookup, and slot extraction.
#![forbid(unsafe_code)]

pub mod fuzzy;
pub mod matcher;
pub mod normalizer;

pub use fuzzy::levenshtein_bounded;
pub use matcher::{CommandMatcher, MatchCandidate, MatchResult, MatchedCommand, AMBIGUITY_MARGIN};
pub use normalizer::normalize;

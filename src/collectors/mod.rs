//! Upstream event collectors.
//!
//! Phase 2 implements the T3 Code collector. GitHub collectors remain a later
//! phase.

pub mod t3_sqlite;
pub mod t3_state;

pub use t3_sqlite::{T3Collector, T3CollectorSettings, T3CollectorSummary, T3Source};
pub use t3_state::T3SourceEvent;

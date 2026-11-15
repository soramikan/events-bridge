//! SQLite-backed state store.

pub mod migrations;
pub mod repository;

pub use repository::{
    AttemptOutcome, DueDelivery, Event, EventQuery, IngestOutcome, NewEvent, NewSubscription,
    Repository, Subscription,
};

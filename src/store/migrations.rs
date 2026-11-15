//! Database migrations.
//!
//! The migration files are embedded at compile time so the daemon ships as a
//! single binary. `PRAGMA user_version` records the last applied migration.

use rusqlite::Connection;

/// One embedded migration.
pub struct Migration {
    /// Monotonically increasing version.
    pub version: i64,
    /// SQL executed as a single batch inside a transaction.
    pub sql: &'static str,
}

/// All migrations in application order.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("../../migrations/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../../migrations/002_t3_collector.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../../migrations/003_github_collector.sql"),
    },
];

/// Apply every migration newer than the connection's `user_version`.
pub fn run(conn: &mut Connection) -> rusqlite::Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        // `PRAGMA user_version` does not accept bound parameters.
        tx.pragma_update(None, "user_version", migration.version)?;
        tx.commit()?;
        tracing::info!(version = migration.version, "applied database migration");
    }

    Ok(())
}

/// Current schema version recorded in the database.
pub fn current_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
}

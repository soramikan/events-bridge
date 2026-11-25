use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::edge_protocol::OrcaEdgeEvent;

use super::Repository;

impl Repository {
    /// Record the first successful snapshot's start time, using the existing
    /// cutoff on restart or when another Edge shares this database.
    pub(crate) fn orca_edge_baseline(
        &self,
        environment_id: &str,
        first_poll_ms: i64,
    ) -> Result<i64> {
        let conn = self.lock_connection();
        conn.execute(
            "INSERT INTO orca_edge_baselines VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![environment_id, first_poll_ms],
        )?;
        Ok(conn.query_row(
            "SELECT first_poll_ms FROM orca_edge_baselines WHERE environment_id = ?1",
            [environment_id],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn orca_edge_has_event(&self, id: &str) -> Result<bool> {
        Ok(self.lock_connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM orca_edge_outbox WHERE event_id = ?1)",
            [id],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn queue_orca_edge_event(&self, event: &OrcaEdgeEvent) -> Result<bool> {
        let body = serde_json::to_vec(event)?;
        let changed = self.lock_connection().execute(
            "INSERT INTO orca_edge_outbox (event_id, environment_id, occurred_at_ms, body)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![
                event.event_id(),
                event.environment_id,
                event.occurred_at_ms,
                body
            ],
        )?;
        Ok(changed != 0)
    }

    pub(crate) fn next_orca_edge_event(
        &self,
        environment_id: &str,
    ) -> Result<Option<(String, Vec<u8>)>> {
        Ok(self
            .lock_connection()
            .query_row(
                "SELECT event_id, body FROM orca_edge_outbox
             WHERE environment_id = ?1 AND body IS NOT NULL
             ORDER BY occurred_at_ms, event_id LIMIT 1",
                [environment_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub(crate) fn acknowledge_orca_edge_event(&self, id: &str) -> Result<()> {
        self.lock_connection().execute(
            "UPDATE orca_edge_outbox SET body = NULL WHERE event_id = ?1",
            [id],
        )?;
        Ok(())
    }
}

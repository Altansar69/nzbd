//! Restore detection on Postgres (the shared types and file format are in `crate::anchor`).

use sqlx::Row as _;

use crate::StoreError;
use crate::anchor::{AnchorVerdict, DbAnchor, classes_of, compare, heads_to_probe, hex};
use crate::pg::PgDb;

impl PgDb {
    /// Reads the current anchor values (one snapshot).
    ///
    /// # Errors
    /// Database errors.
    pub async fn capture_anchor(&self) -> Result<DbAnchor, StoreError> {
        let mut tx = self.background().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let r = sqlx::query(
            "SELECT (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS sysid, \
             (SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM nzbd.audit_log_id_seq) AS a, \
             (SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM nzbd.release_id_seq) AS r, \
             (SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM nzbd.search_outbox_seq_seq) AS o, \
             (SELECT backend FROM nzbd.db_state WHERE id = 1) AS backend, \
             (SELECT instance_id FROM nzbd.db_state WHERE id = 1) AS instance_id",
        )
        .fetch_one(&mut *tx)
        .await?;
        let rows = sqlx::query(
            "SELECT class::bigint AS class, head_hash, floor_hash, rows FROM audit_chain_state ORDER BY class",
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DbAnchor {
            backend: r.try_get("backend")?,
            instance_id: hex(&r.try_get::<Vec<u8>, _>("instance_id")?),
            system_identifier: r.try_get("sysid")?,
            seq_audit: r.try_get("a")?,
            seq_release: r.try_get("r")?,
            seq_outbox: r.try_get("o")?,
            classes: classes_of(&rows)?,
        })
    }

    /// Compares the database with an anchor taken earlier (see the module docs).
    ///
    /// # Errors
    /// Database errors.
    pub async fn check_anchor(&self, anchored: &DbAnchor) -> Result<AnchorVerdict, StoreError> {
        let now = self.capture_anchor().await?;
        if let Some(v) = compare(anchored, &now) {
            return Ok(v);
        }
        for (class, (head, _, _)) in heads_to_probe(anchored, &now) {
            let class = i16::try_from(class).map_err(|_| StoreError::OutOfRange("audit class"))?;
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM audit_log WHERE chain_class = $1 AND chain_hash = decode($2, 'hex'))",
            )
            .bind(class)
            .bind(head)
            .fetch_one(self.background())
            .await?;
            if !present {
                return Ok(AnchorVerdict::RestoreDetected("audit head missing"));
            }
        }
        Ok(AnchorVerdict::Consistent)
    }

    /// True when the library holds no account and no release (a new, never used database).
    ///
    /// # Errors
    /// Database errors.
    pub async fn library_is_empty(&self) -> Result<bool, StoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM account) + (SELECT count(*) FROM release) \
             + (SELECT count(*) FROM release_trash)",
        )
        .fetch_one(self.background())
        .await?;
        Ok(n == 0)
    }
}

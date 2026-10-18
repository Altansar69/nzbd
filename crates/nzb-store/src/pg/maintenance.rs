//! Retention on Postgres (T112; 2.x `SqliteDb::purge_logs`, `DATA_MODEL` v3 sections 1, 3.3, 3.4; review M3, SEC-081,
//! SEC-093).
//!
//! The app role cannot choose what is old: it only calls the owner's definer functions `nzbd.audit_purge(class)` and
//! `nzbd.log_retention_apply()`, which take the cutoff from the DATABASE clock and the owner-only `retention_policy`
//! (CHECK floors 90 / 365 / 1 days). Each call removes at most 10,000 rows in its own transaction, so a purge never
//! holds an audit class lock long enough to stall logins; [`PgDb::purge_logs`] calls them until they report 0.
//! The policy itself is written only by [`set_retention_policy`], with the owner role (the `setup` service).

use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions as _, Connection as _, Row as _};

use crate::StoreError;
use crate::backup::PurgeReport;
use crate::pg::PgDb;

/// Upper bound of purge rounds per class in one maintenance run (10,000 rows each: 100M rows), so a run always ends.
const MAX_ROUNDS: u32 = 10_000;

pub use crate::retention::{RETENTION_FLOORS, RetentionPolicy};

/// Writes the retention policy with the OWNER role (the one-shot `setup` service, never `serve`). Values below the
/// floors are refused before any statement runs (and by the table's CHECKs).
///
/// # Errors
/// [`StoreError::OutOfRange`] below a floor; connection or database errors.
pub async fn set_retention_policy(
    owner: PgConnectOptions,
    p: RetentionPolicy,
) -> Result<(), StoreError> {
    p.validate()?;
    let mut conn = owner.connect().await?;
    sqlx::query(
        "UPDATE retention_policy SET log_days = $1, account_days = $2, ingest_days = $3, keep_all = $4, \
         account_keep_all = $5 WHERE id = 1",
    )
    .bind(i32::try_from(p.log_days).map_err(|_| StoreError::OutOfRange("log_days"))?)
    .bind(i32::try_from(p.account_days).map_err(|_| StoreError::OutOfRange("account_days"))?)
    .bind(i32::try_from(p.ingest_days).map_err(|_| StoreError::OutOfRange("ingest_days"))?)
    .bind(p.keep_all)
    .bind(p.account_keep_all)
    .execute(&mut conn)
    .await?;
    conn.close().await?;
    Ok(())
}

impl PgDb {
    /// The retention policy in force (readable by the app role).
    ///
    /// # Errors
    /// Database errors.
    pub async fn retention_policy(&self) -> Result<RetentionPolicy, StoreError> {
        let r = sqlx::query(
            "SELECT log_days, account_days, ingest_days, keep_all, account_keep_all FROM retention_policy \
             WHERE id = 1",
        )
        .fetch_one(self.background())
        .await?;
        let days = |name: &'static str| -> Result<u32, StoreError> {
            u32::try_from(r.try_get::<i32, _>(name)?).map_err(|_| StoreError::OutOfRange(name))
        };
        Ok(RetentionPolicy {
            log_days: days("log_days")?,
            account_days: days("account_days")?,
            ingest_days: days("ingest_days")?,
            keep_all: r.try_get("keep_all")?,
            account_keep_all: r.try_get("account_keep_all")?,
        })
    }

    /// Applies the retention policy (the daily maintenance job and `nzbd cleanup`): audit classes 0 and 1 and the
    /// ingest log, in bounded batches, cutoffs from the database clock. `future_rows` counts audit rows stamped more
    /// than a day ahead of the database clock (they never pin the purge; the caller warns about the clock).
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_logs(&self) -> Result<PurgeReport, StoreError> {
        let pool = self.background();
        let future_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE chain_class IS NOT NULL AND ts > nzbd.db_clock() + 86400",
        )
        .fetch_one(pool)
        .await?;
        let mut audit = 0_u64;
        for class in [0_i16, 1] {
            for _ in 0..MAX_ROUNDS {
                let n: i64 = sqlx::query_scalar("SELECT nzbd.audit_purge($1)")
                    .bind(class)
                    .fetch_one(pool)
                    .await?;
                audit = audit.saturating_add(u64::try_from(n).unwrap_or(0));
                if n == 0 {
                    break;
                }
            }
        }
        let mut ingest = 0_u64;
        for _ in 0..MAX_ROUNDS {
            let n: i64 = sqlx::query_scalar("SELECT nzbd.log_retention_apply()")
                .fetch_one(pool)
                .await?;
            ingest = ingest.saturating_add(u64::try_from(n).unwrap_or(0));
            if n == 0 {
                break;
            }
        }
        Ok(PurgeReport {
            audit,
            ingest,
            future_rows: u64::try_from(future_rows).unwrap_or(0),
        })
    }

    /// Deletes sessions whose `expires_at` is at or before `now` (daily maintenance). Returns rows removed.
    ///
    /// # Errors
    /// Database errors.
    pub async fn purge_expired_sessions(&self, now: i64) -> Result<u64, StoreError> {
        let r = sqlx::query("DELETE FROM session WHERE expires_at <= $1")
            .bind(now)
            .execute(self.background())
            .await?;
        Ok(r.rows_affected())
    }

    /// Daily partition upkeep: the ingest-log months and the `nzb_file` span ahead of the release sequence, each in its
    /// own short transaction (`SECURITY_REVIEW` 31 M1). Returns `(log partitions, file partitions)` created.
    ///
    /// # Errors
    /// Database errors.
    pub async fn partition_upkeep(&self) -> Result<(u32, u32), StoreError> {
        let log = self.ensure_log_partitions().await?;
        let files = self.ensure_file_partitions_ahead().await?;
        Ok((log, files))
    }

    /// Keeps the ingest-log partitions of the current and the next two months (database clock). Startup and daily.
    ///
    /// # Errors
    /// Database errors.
    pub async fn ensure_log_partitions(&self) -> Result<u32, StoreError> {
        let n: i32 = sqlx::query_scalar("SELECT nzbd.ensure_log_partitions()")
            .fetch_one(self.background())
            .await?;
        Ok(u32::try_from(n).unwrap_or(0))
    }
}

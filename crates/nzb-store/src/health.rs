//! Read-only probes for the admin health dashboard (`GET /admin/health`, `nzbd health`).
//!
//! Every method here is a bounded, parameterized `SELECT` (or read-only `PRAGMA`) and never
//! modifies data. The only potentially expensive ones ([`SqliteDb::deep_db_check`],
//! [`SqliteDb::release_shas_limited`]) are meant for the on-demand deep check, never for a per-request
//! path. Nothing returned contains secret material: counts, flags and unix timestamps only.

use std::collections::HashSet;

use nzb_core::Sha256;
use sqlx::Row;
use sqlx::migrate::Migrator;

use crate::{SqliteDb, StoreError};

/// Migrations compiled into this binary (same source as [`SqliteDb::open`]).
static MIGRATOR: Migrator = sqlx::migrate!("../../migrations/v3-sqlite");

/// Applied versus embedded migrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaInfo {
    /// Highest successfully applied version (0 if none).
    pub latest_applied: i64,
    /// Number of successfully applied migrations.
    pub applied: u64,
    /// Highest embedded version.
    pub embedded_latest: i64,
    /// Number of embedded migrations.
    pub embedded: u64,
}

/// Cheap aggregates of the log tables (index-only for the timestamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogCounts {
    /// Rows in `ingest_log`.
    pub ingest_rows: u64,
    /// Rows in `audit_log`.
    pub audit_rows: u64,
    /// Oldest `ingest_log.ts`.
    pub ingest_oldest: Option<i64>,
    /// Newest `ingest_log.ts`.
    pub ingest_newest: Option<i64>,
}

/// Connection pool state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolInfo {
    /// Open writer connections (always 1 when healthy).
    pub writer_open: u32,
    /// Open reader connections.
    pub readers_open: u32,
    /// Idle reader connections.
    pub readers_idle: usize,
    /// Reader pool capacity.
    pub readers_max: u32,
    /// True if either pool has been closed.
    pub closed: bool,
}

/// Account and session facts for the security group. No hashes, ids or addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityFacts {
    /// A user row exists.
    pub user_exists: bool,
    /// The user completed TOTP enrollment.
    pub totp_enabled: bool,
    /// Consecutive failed logins currently counted.
    pub failed_logins: i64,
    /// The account is locked at `now`.
    pub locked: bool,
    /// Sessions with `expires_at > now`.
    pub active_sessions: u64,
    /// API keys that are not revoked.
    pub active_api_keys: u64,
    /// `login.fail` + `mfa.fail` audit events since the cut-off.
    pub failed_logins_recent: u64,
    /// Live (non-tombstoned) accounts.
    pub live_accounts: u64,
    /// Live accounts whose login name is a reserved audit-actor name or the `user-<n>` handle form.
    pub reserved_names: u64,
    /// Accounts whose aggregate or daily second-factor throttle is in force.
    pub throttled_accounts: u64,
}

/// Result of the on-demand database integrity pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeepDbReport {
    /// `PRAGMA quick_check` returned exactly `ok`.
    pub quick_check_ok: bool,
    /// Number of lines other than `ok` it returned (capped).
    pub quick_check_issues: usize,
    /// Foreign-key violations found (capped at 100).
    pub fk_violations: usize,
}

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl SqliteDb {
    /// `SELECT 1` on the writer connection.
    ///
    /// # Errors
    /// Database errors.
    pub async fn ping_writer(&self) -> Result<(), StoreError> {
        let _: i64 = sqlx::query_scalar("SELECT 1")
            .fetch_one(self.writer())
            .await?;
        Ok(())
    }

    /// Applied versus embedded migrations.
    ///
    /// # Errors
    /// Database errors.
    pub async fn schema_info(&self) -> Result<SchemaInfo, StoreError> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(version), 0) AS v, COUNT(*) AS n FROM _sqlx_migrations \
             WHERE success = 1",
        )
        .fetch_one(self.readers())
        .await?;
        Ok(SchemaInfo {
            latest_applied: row.try_get("v")?,
            applied: to_u64(row.try_get("n")?),
            embedded_latest: MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0),
            embedded: u64::try_from(MIGRATOR.iter().count()).unwrap_or(u64::MAX),
        })
    }

    /// Row counts of the two log tables and the ingest time span. Both logs are bounded by
    /// the backup command's retention purge, and the callers cache the result.
    ///
    /// # Errors
    /// Database errors.
    pub async fn log_counts(&self) -> Result<LogCounts, StoreError> {
        let ing = sqlx::query("SELECT COUNT(*) AS n, MIN(ts) AS lo, MAX(ts) AS hi FROM ingest_log")
            .fetch_one(self.readers())
            .await?;
        let audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(self.readers())
            .await?;
        Ok(LogCounts {
            ingest_rows: to_u64(ing.try_get("n")?),
            audit_rows: to_u64(audit),
            ingest_oldest: ing.try_get("lo")?,
            ingest_newest: ing.try_get("hi")?,
        })
    }

    /// Pool state (no I/O).
    #[must_use]
    pub fn pool_info(&self) -> PoolInfo {
        PoolInfo {
            writer_open: self.writer().size(),
            readers_open: self.readers().size(),
            readers_idle: self.readers().num_idle(),
            readers_max: crate::READER_CONNECTIONS,
            closed: self.writer().is_closed() || self.readers().is_closed(),
        }
    }

    /// Account, session and key facts at `now`; failed logins are counted from `since`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn security_facts(&self, now: i64, since: i64) -> Result<SecurityFacts, StoreError> {
        // v2: the hard lock lives in `login_lock` (per account and address); the 1.x columns of
        // `user` are no longer maintained.
        let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account WHERE deleted_at IS NULL")
            .fetch_one(self.readers())
            .await?;
        let unenrolled: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM account WHERE deleted_at IS NULL AND totp_enabled = 0",
        )
        .fetch_one(self.readers())
        .await?;
        let lock = sqlx::query(
            "SELECT COALESCE(MAX(failures), 0) AS f, COALESCE(MAX(locked_until), 0) AS l \
             FROM login_lock",
        )
        .fetch_one(self.readers())
        .await?;
        let user_exists = live > 0;
        let totp_enabled = user_exists && unenrolled == 0;
        let failed_logins: i64 = lock.try_get("f")?;
        let locked = lock.try_get::<i64, _>("l")? > now;
        let reserved_names = self.reserved_login_accounts().await?.len();
        let throttled = self.count_throttled_accounts(now).await?;
        let sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM session WHERE expires_at > ?1")
                .bind(now)
                .fetch_one(self.readers())
                .await?;
        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE revoked_at IS NULL")
            .fetch_one(self.readers())
            .await?;
        // `audit_ts` is a DESC index on `ts`: a range scan over the last 24 h only.
        let failures: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE ts >= ?1 AND event IN ('login.fail', 'mfa.fail')",
        )
        .bind(since)
        .fetch_one(self.readers())
        .await?;
        Ok(SecurityFacts {
            user_exists,
            totp_enabled,
            failed_logins,
            locked,
            active_sessions: to_u64(sessions),
            active_api_keys: to_u64(keys),
            failed_logins_recent: to_u64(failures),
            live_accounts: to_u64(live),
            reserved_names: u64::try_from(reserved_names).unwrap_or(u64::MAX),
            throttled_accounts: throttled,
        })
    }

    /// At most `limit` release digests (lowest ids first) and whether more exist.
    ///
    /// # Errors
    /// Database errors or a stored digest with the wrong length.
    pub async fn release_shas_limited(
        &self,
        limit: u32,
    ) -> Result<(HashSet<Sha256>, bool), StoreError> {
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT sha256 FROM release ORDER BY id LIMIT ?1")
                .bind(i64::from(limit).saturating_add(1))
                .fetch_all(self.readers())
                .await?;
        let partial = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        let set = rows
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|v| {
                <[u8; 32]>::try_from(v)
                    .map(Sha256)
                    .map_err(|_| StoreError::OutOfRange("sha256 length"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok((set, partial))
    }

    /// `PRAGMA quick_check` and `foreign_key_check` on a **reader** connection (read-only
    /// file handle): the file cannot be modified through it. Not cheap on a large database,
    /// so only the deep check calls it, under a deadline.
    ///
    /// # Errors
    /// Database errors.
    pub async fn deep_db_check(&self) -> Result<DeepDbReport, StoreError> {
        let mut conn = self.readers().acquire().await?;
        let lines: Vec<String> = sqlx::query_scalar("PRAGMA quick_check(20)")
            .fetch_all(&mut *conn)
            .await?;
        let quick_check_ok = lines.len() == 1 && lines.first().map(String::as_str) == Some("ok");
        let quick_check_issues = if quick_check_ok { 0 } else { lines.len() };
        let fks: Vec<String> =
            sqlx::query_scalar("SELECT \"table\" FROM pragma_foreign_key_check LIMIT 100")
                .fetch_all(&mut *conn)
                .await?;
        Ok(DeepDbReport {
            quick_check_ok,
            quick_check_issues,
            fk_violations: fks.len(),
        })
    }
}

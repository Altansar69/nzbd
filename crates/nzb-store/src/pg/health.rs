//! Read-only probes for the health dashboard on Postgres (T112; 2.x `health.rs`). Counts, flags and timestamps
//! only; nothing secret.

use std::collections::HashSet;

use nzb_core::Sha256;
use sqlx::Row;

use crate::StoreError;
use crate::health::{DeepDbReport, LogCounts, PoolInfo, SchemaInfo, SecurityFacts};
use crate::pg::{MIGRATOR, PgDb};

fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl PgDb {
    /// `SELECT 1` on the `ingest` pool (2.x: the writer connection).
    ///
    /// # Errors
    /// Database errors.
    pub async fn ping_writer(&self) -> Result<(), StoreError> {
        let _: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(self.ingest())
            .await?;
        Ok(())
    }

    /// Applied versus embedded v3 migrations.
    ///
    /// # Errors
    /// Database errors.
    pub async fn schema_info(&self) -> Result<SchemaInfo, StoreError> {
        let row = sqlx::query(
            "SELECT coalesce(max(version), 0) AS v, count(*) AS n FROM nzbd._sqlx_migrations WHERE success",
        )
        .fetch_one(self.background())
        .await?;
        Ok(SchemaInfo {
            latest_applied: row.try_get("v")?,
            applied: to_u64(row.try_get("n")?),
            embedded_latest: MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0),
            embedded: u64::try_from(MIGRATOR.iter().count()).unwrap_or(u64::MAX),
        })
    }

    /// Row counts of the two log tables and the ingest time span.
    ///
    /// # Errors
    /// Database errors.
    pub async fn log_counts(&self) -> Result<LogCounts, StoreError> {
        let ing = sqlx::query("SELECT count(*) AS n, min(ts) AS lo, max(ts) AS hi FROM ingest_log")
            .fetch_one(self.background())
            .await?;
        let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(self.background())
            .await?;
        Ok(LogCounts {
            ingest_rows: to_u64(ing.try_get("n")?),
            audit_rows: to_u64(audit),
            ingest_oldest: ing.try_get("lo")?,
            ingest_newest: ing.try_get("hi")?,
        })
    }

    /// Pool state (no I/O). The 2.x "writer" is the `ingest` pool, the "readers" the `web` pool.
    #[must_use]
    pub fn pool_info(&self) -> PoolInfo {
        PoolInfo {
            writer_open: self.ingest().size(),
            readers_open: self.web().size(),
            readers_idle: self.web().num_idle(),
            readers_max: self.web().options().get_max_connections(),
            closed: self.ingest().is_closed()
                || self.web().is_closed()
                || self.background().is_closed(),
        }
    }

    /// Account, session and key facts at `now`; failed logins counted from `since`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn security_facts(&self, now: i64, since: i64) -> Result<SecurityFacts, StoreError> {
        let pool = self.background();
        let live: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE deleted_at IS NULL")
            .fetch_one(pool)
            .await?;
        let unenrolled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account WHERE deleted_at IS NULL AND NOT totp_enabled",
        )
        .fetch_one(pool)
        .await?;
        let lock = sqlx::query(
            "SELECT coalesce(max(failures), 0) AS f, coalesce(max(locked_until), 0) AS l FROM login_lock",
        )
        .fetch_one(pool)
        .await?;
        let user_exists = live > 0;
        let totp_enabled = user_exists && unenrolled == 0;
        let failed_logins: i64 = lock.try_get("f")?;
        let locked = lock.try_get::<i64, _>("l")? > now;
        let reserved_names = self.reserved_login_accounts().await?.len();
        let throttled = self.count_throttled_accounts(now).await?;
        let sessions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM session WHERE expires_at > $1")
                .bind(now)
                .fetch_one(pool)
                .await?;
        let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM api_key WHERE revoked_at IS NULL")
            .fetch_one(pool)
            .await?;
        let failures: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE ts >= $1 AND event IN ('login.fail', 'mfa.fail')",
        )
        .bind(since)
        .fetch_one(pool)
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
    /// Database errors.
    pub async fn release_shas_limited(
        &self,
        limit: u32,
    ) -> Result<(HashSet<Sha256>, bool), StoreError> {
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT sha256 FROM release ORDER BY id LIMIT $1")
                .bind(i64::from(limit).saturating_add(1))
                .fetch_all(self.background())
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

    /// The on-demand structural check: every release id is covered by an `nzb_file` partition (an insert beyond the
    /// last partition fails the ingest), and the role privileges are what the design says (SEC-087). Foreign keys
    /// are enforced by Postgres, so `fk_violations` is the count of privilege excesses found. `amcheck` belongs to
    /// `nzbd db check --full` (owner-installed extension, optional).
    ///
    /// # Errors
    /// Database errors.
    pub async fn deep_db_check(&self) -> Result<DeepDbReport, StoreError> {
        let mut conn = self.background().acquire().await?;
        let uncovered: bool = sqlx::query_scalar(
            "SELECT coalesce(max(id), -1) >= (SELECT count(*) FROM pg_catalog.pg_inherits \
             WHERE inhparent = 'nzbd.nzb_file'::regclass) * 10000000::bigint FROM release",
        )
        .fetch_one(&mut *conn)
        .await?;
        let excess = self.privilege_excess(&mut conn).await?;
        Ok(DeepDbReport {
            quick_check_ok: !uncovered && excess.is_empty(),
            quick_check_issues: usize::from(uncovered).saturating_add(excess.len()),
            fk_violations: excess.len(),
        })
    }

    /// Privileges the connected (app) role must NOT have (SEC-087 self-test of `nzbd db check`): returns the names
    /// of the excesses found, empty when the role is as least-privileged as designed.
    ///
    /// # Errors
    /// Database errors.
    pub async fn privilege_self_test(&self) -> Result<Vec<String>, StoreError> {
        let mut conn = self.background().acquire().await?;
        self.privilege_excess(&mut conn).await
    }

    async fn privilege_excess(
        &self,
        conn: &mut sqlx::PgConnection,
    ) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT 'update audit_log' AS what, has_table_privilege('nzbd.audit_log', 'UPDATE') AS bad \
             UNION ALL SELECT 'delete audit_log', has_table_privilege('nzbd.audit_log', 'DELETE') \
             UNION ALL SELECT 'insert audit_log', has_table_privilege('nzbd.audit_log', 'INSERT') \
             UNION ALL SELECT 'update audit_chain_state', has_table_privilege('nzbd.audit_chain_state', 'UPDATE') \
             UNION ALL SELECT 'delete account', has_table_privilege('nzbd.account', 'DELETE') \
             UNION ALL SELECT 'truncate release', has_table_privilege('nzbd.release', 'TRUNCATE') \
             UNION ALL SELECT 'update retention_policy', has_table_privilege('nzbd.retention_policy', 'UPDATE') \
             UNION ALL SELECT 'update db_state', has_table_privilege('nzbd.db_state', 'UPDATE') \
             UNION ALL SELECT 'create in schema nzbd', has_schema_privilege('nzbd', 'CREATE') \
             UNION ALL SELECT 'create in schema public', has_schema_privilege('public', 'CREATE') \
             UNION ALL SELECT 'temp on database', has_database_privilege(current_database(), 'TEMP') \
             UNION ALL SELECT 'create on database', has_database_privilege(current_database(), 'CREATE') \
             UNION ALL SELECT 'update ingest_log', has_table_privilege('nzbd.ingest_log', 'UPDATE') \
             UNION ALL SELECT 'delete ingest_log', has_table_privilege('nzbd.ingest_log', 'DELETE') \
             UNION ALL SELECT 'update nzb_file', has_table_privilege('nzbd.nzb_file', 'UPDATE') \
             UNION ALL SELECT 'delete nzb_file', has_table_privilege('nzbd.nzb_file', 'DELETE') \
             UNION ALL SELECT 'member of a role', \
               EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) \
             UNION ALL SELECT 'owns objects in schema nzbd', \
               EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                       WHERE n.nspname = 'nzbd' AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) \
               OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
                       WHERE n.nspname = 'nzbd' AND p.proowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) \
               OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'nzbd' \
                       AND nspowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) \
             UNION ALL SELECT 'superuser-like attribute', \
               (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls \
                FROM pg_catalog.pg_roles WHERE rolname = current_user)",
        )
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::new();
        for r in &rows {
            if r.try_get::<bool, _>("bad")? {
                out.push(r.try_get::<String, _>("what")?);
            }
        }
        Ok(out)
    }
}

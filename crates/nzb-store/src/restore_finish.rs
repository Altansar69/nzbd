//! Post-restore hygiene (`nzbd db restore-finish`, T107, SEC-036/065/068/069).
//!
//! Restoring an older backup silently undoes every revocation made since the snapshot: API keys
//! (no idle expiry), re-enabled accounts, reverted password hashes and roles, spent TOTP steps,
//! invitations and recovery codes. Nothing in the file says "this was revoked", so the operator
//! runs this once after a restore, BEFORE starting the server: every short-lived or externally
//! held credential is destroyed and every API key is revoked in ONE writer transaction, together
//! with exactly one `cli` audit row (counts only, no secrets, through the chain `append`).
//!
//! Accounts, roles, disabled state, password hashes and the TOTP key stay as the snapshot has
//! them: those cannot be repaired by code, so [`SqliteDb::restore_finish_accounts`] lists them for the
//! operator to compare with what they expect.

use crate::db::SqliteDb;
use crate::error::StoreError;
use sqlx::Row as _;

/// Audit event written by a real (non dry-run) run. Member of the long-retention account class.
pub const RESTORE_FINISH_EVENT: &str = "db.restore_finish";

/// Row counts of one run (what was, or in a dry run would be, removed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreFinishReport {
    /// Sessions deleted (every stage).
    pub sessions: u64,
    /// Credential staging rows deleted.
    pub credential_staging: u64,
    /// Invitation and admin-recovery codes not yet redeemed, deleted.
    pub open_invites: u64,
    /// MFA recovery code rows deleted (accounts regenerate their own).
    pub recovery_codes: u64,
    /// `login_lock` rows deleted.
    pub login_locks: u64,
    /// `account_throttle` rows deleted.
    pub account_throttles: u64,
    /// `user_known_ip` rows deleted.
    pub known_ips: u64,
    /// Pending MFA enrollment tokens (`user.enroll_token_hash`, 24 h TTL) cleared.
    pub enroll_tokens: u64,
    /// API keys revoked (`revoked_by` NULL).
    pub api_keys_revoked: u64,
}

/// One account as the restored file has it, for the operator to review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredAccount {
    /// Account id.
    pub id: i64,
    /// Login name (`~deleted~<id>` for a tombstone).
    pub username: String,
    /// `admin`, `uploader` or `viewer`.
    pub role: String,
    /// Disabled (`disabled_at` set).
    pub disabled: bool,
    /// Tombstoned (`deleted_at` set).
    pub deleted: bool,
    /// Second factor enrolled.
    pub totp_enabled: bool,
}

impl SqliteDb {
    /// Destroys sessions, open invitations, MFA recovery codes, credential staging and throttle
    /// state, and revokes every still-active API key, in one transaction with one audit row.
    /// With `dry_run` only the counts are computed and nothing is written. Idempotent: a second
    /// run finds nothing to remove (and still records its own audit row).
    ///
    /// # Errors
    /// Database errors; the transaction then rolls back as a whole.
    #[allow(clippy::too_many_lines)] // one linear list of statements, one per table
    pub async fn restore_finish(
        &self,
        now: i64,
        dry_run: bool,
    ) -> Result<RestoreFinishReport, StoreError> {
        if dry_run {
            // Write-free: one read on the reader pool.
            let r = sqlx::query(
                "SELECT (SELECT count(*) FROM session) AS sessions, \
                 (SELECT count(*) FROM credential_staging) AS staging, \
                 (SELECT count(*) FROM invite WHERE used_at IS NULL) AS invites, \
                 (SELECT count(*) FROM recovery_code) AS codes, \
                 (SELECT count(*) FROM login_lock) AS locks, \
                 (SELECT count(*) FROM account_throttle) AS throttles, \
                 (SELECT count(*) FROM user_known_ip) AS ips, \
                 (SELECT count(*) FROM account WHERE enroll_token_hash IS NOT NULL \
                    OR enroll_token_expires IS NOT NULL) AS tokens, \
                 (SELECT count(*) FROM api_key WHERE revoked_at IS NULL) AS keys",
            )
            .fetch_one(self.readers())
            .await?;
            let n = |c: &str| -> Result<u64, StoreError> {
                Ok(u64::try_from(r.try_get::<i64, _>(c)?).unwrap_or(0))
            };
            return Ok(RestoreFinishReport {
                sessions: n("sessions")?,
                credential_staging: n("staging")?,
                open_invites: n("invites")?,
                recovery_codes: n("codes")?,
                login_locks: n("locks")?,
                account_throttles: n("throttles")?,
                known_ips: n("ips")?,
                enroll_tokens: n("tokens")?,
                api_keys_revoked: n("keys")?,
            });
        }
        // BEGIN IMMEDIATE: take the write lock first, like every other store writer.
        let mut tx = self.begin_immediate().await?;
        let rep = {
            // Staging first (it references the invite and the session), then its owners.
            let credential_staging = sqlx::query("DELETE FROM credential_staging")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let sessions = sqlx::query("DELETE FROM session")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let open_invites = sqlx::query("DELETE FROM invite WHERE used_at IS NULL")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let recovery_codes = sqlx::query("DELETE FROM recovery_code")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let login_locks = sqlx::query("DELETE FROM login_lock")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let account_throttles = sqlx::query("DELETE FROM account_throttle")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let known_ips = sqlx::query("DELETE FROM user_known_ip")
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let enroll_tokens = sqlx::query(
                "UPDATE account SET enroll_token_hash = NULL, enroll_token_expires = NULL \
                 WHERE enroll_token_hash IS NOT NULL OR enroll_token_expires IS NOT NULL",
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            let api_keys_revoked = sqlx::query(
                "UPDATE api_key SET revoked_at = ?1, revoked_by = NULL WHERE revoked_at IS NULL",
            )
            .bind(now)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            // The restore mark is cleared together with its effects (review 31 L2), and a new index epoch makes sure
            // no index built before the restore is ever served (SEC-091).
            sqlx::query(
                "UPDATE db_state SET restore_pending = 0, restore_finished_at = ?1 WHERE id = 1",
            )
            .bind(now)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE search_state SET epoch = randomblob(16) WHERE id = 1")
                .execute(&mut *tx)
                .await?;
            let rep = RestoreFinishReport {
                sessions,
                credential_staging,
                open_invites,
                recovery_codes,
                login_locks,
                account_throttles,
                known_ips,
                enroll_tokens,
                api_keys_revoked,
            };
            let detail = format!(
                "sessions={} staging={} invites={} recovery_codes={} login_locks={} \
                 throttles={} known_ips={} enroll_tokens={} api_keys_revoked={}",
                rep.sessions,
                rep.credential_staging,
                rep.open_invites,
                rep.recovery_codes,
                rep.login_locks,
                rep.account_throttles,
                rep.known_ips,
                rep.enroll_tokens,
                rep.api_keys_revoked
            );
            crate::account::write_audit_legacy(
                &mut tx,
                now,
                Some("cli"),
                RESTORE_FINISH_EVENT,
                Some(&detail),
                None,
            )
            .await?;
            rep
        };
        tx.commit().await?;
        Ok(rep)
    }

    /// Every account (tombstones included) with role and state, oldest first.
    ///
    /// # Errors
    /// Database errors.
    pub async fn restore_finish_accounts(&self) -> Result<Vec<RestoredAccount>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, username, role, disabled_at, deleted_at, totp_enabled FROM account ORDER BY id",
        )
        .fetch_all(self.readers())
        .await?;
        rows.iter()
            .map(|r| {
                let disabled: Option<i64> = r.try_get("disabled_at")?;
                let deleted: Option<i64> = r.try_get("deleted_at")?;
                let totp: i64 = r.try_get("totp_enabled")?;
                Ok(RestoredAccount {
                    id: r.try_get("id")?,
                    username: r.try_get("username")?,
                    role: r.try_get("role")?,
                    disabled: disabled.is_some(),
                    deleted: deleted.is_some(),
                    totp_enabled: totp != 0,
                })
            })
            .collect()
    }
}

impl SqliteDb {
    /// `db_state.restore_pending`: a restored database `serve` must refuse until `nzbd db restore-finish` (SEC-094).
    ///
    /// # Errors
    /// Database errors.
    pub async fn restore_pending(&self) -> Result<bool, StoreError> {
        let v: i64 = sqlx::query_scalar("SELECT restore_pending FROM db_state WHERE id = 1")
            .fetch_one(self.readers())
            .await?;
        Ok(v != 0)
    }
}

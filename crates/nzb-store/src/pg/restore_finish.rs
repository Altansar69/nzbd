//! `nzbd db restore-finish` on Postgres (T112; 2.x `restore_finish.rs`, SEC-068, SEC-094, review L7).
//!
//! Same SEC-068 effects as 2.x (sessions, staging, open codes, MFA recovery codes, throttle state and enrollment
//! tokens removed, every active API key revoked, one audit row), plus the v3 additions: the search index epoch is
//! rotated (the index of the restored data is never served, SEC-091) and `db_state.restore_pending` is cleared
//! by the owner's definer function `nzbd.restore_finish()`, which also does the cleanup (one atomic step). The anchor file
//! (`paths.state/db-anchor.json`) is rewritten by the caller after the commit.

use sqlx::Row as _;

use crate::StoreError;
use crate::pg::PgDb;
use crate::restore_finish::{RESTORE_FINISH_EVENT, RestoreFinishReport, RestoredAccount};

fn n(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

impl PgDb {
    /// Destroys sessions, open invitations, MFA recovery codes, credential staging and throttle state, revokes every
    /// still-active API key, rotates the search epoch and clears `restore_pending`, in one transaction with one audit
    /// row. With `dry_run` only the counts are computed and nothing is written. Idempotent.
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
            let c: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
                "SELECT (SELECT count(*) FROM session), (SELECT count(*) FROM credential_staging), \
                 (SELECT count(*) FROM invite WHERE used_at IS NULL), (SELECT count(*) FROM recovery_code), \
                 (SELECT count(*) FROM login_lock), (SELECT count(*) FROM account_throttle), \
                 (SELECT count(*) FROM user_known_ip), \
                 (SELECT count(*) FROM account WHERE enroll_token_hash IS NOT NULL OR enroll_token_expires IS NOT NULL), \
                 (SELECT count(*) FROM api_key WHERE revoked_at IS NULL)",
            )
            .fetch_one(self.background())
            .await?;
            return Ok(RestoreFinishReport {
                sessions: n(c.0),
                credential_staging: n(c.1),
                open_invites: n(c.2),
                recovery_codes: n(c.3),
                login_locks: n(c.4),
                account_throttles: n(c.5),
                known_ips: n(c.6),
                enroll_tokens: n(c.7),
                api_keys_revoked: n(c.8),
            });
        }
        let mut tx = self.begin_account().await?;
        // One owner definer function does the cleanup, the epoch rotation and the mark together (SECURITY_REVIEW
        // 31 L2): `restore_pending` can never be cleared without the SEC-068 effects.
        let c: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT n_sessions, n_staging, n_invites, n_recovery_codes, n_login_locks, n_throttles, n_known_ips, \
             n_enroll_tokens, n_keys FROM nzbd.restore_finish()",
        )
        .fetch_one(&mut *tx)
        .await?;
        let (
            sessions,
            credential_staging,
            open_invites,
            recovery_codes,
            login_locks,
            account_throttles,
            known_ips,
        ) = (n(c.0), n(c.1), n(c.2), n(c.3), n(c.4), n(c.5), n(c.6));
        let (enroll_tokens, api_keys_revoked) = (n(c.7), n(c.8));
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
             throttles={} known_ips={} enroll_tokens={} api_keys_revoked={} epoch_rotated=1",
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
        crate::pg::account::write_audit_legacy(
            &mut tx,
            now,
            Some("cli"),
            RESTORE_FINISH_EVENT,
            Some(&detail),
            None,
        )
        .await?;
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
        .fetch_all(self.background())
        .await?;
        rows.iter()
            .map(|r| {
                let disabled: Option<i64> = r.try_get("disabled_at")?;
                let deleted: Option<i64> = r.try_get("deleted_at")?;
                Ok(RestoredAccount {
                    id: r.try_get("id")?,
                    username: r.try_get("username")?,
                    role: r.try_get("role")?,
                    disabled: disabled.is_some(),
                    deleted: deleted.is_some(),
                    totp_enabled: r.try_get("totp_enabled")?,
                })
            })
            .collect()
    }

    /// The current search index epoch (16 random bytes; rotated by `restore-finish`, SEC-091).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_epoch(&self) -> Result<Vec<u8>, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT epoch FROM search_state WHERE id = 1")
                .fetch_one(self.background())
                .await?,
        )
    }
}

impl PgDb {
    /// `db_state.restore_pending` (also part of [`PgDb::readiness`]).
    ///
    /// # Errors
    /// Database errors.
    pub async fn restore_pending(&self) -> Result<bool, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT restore_pending FROM db_state WHERE id = 1")
                .fetch_one(self.background())
                .await?,
        )
    }
}

//! TOTP key rotation on Postgres (T112; 2.x `totp_rotate.rs`, SEC-053): every sealed secret (accounts and staged
//! recoveries) re-sealed in one transaction with compare-and-set per row.

use sqlx::Row;

use crate::StoreError;
use crate::pg::PgDb;
use crate::totp_rotate::{Reseal, ResealReport};

impl PgDb {
    /// Re-seals every user's `totp_secret_enc` through `f(user_id, blob)` in one transaction and
    /// records an audit row `totp_key_rotated` (counts only). With `dry_run` nothing is written.
    ///
    /// # Errors
    /// Any `Undecryptable` verdict aborts the whole run (nothing changes) with an
    /// [`StoreError::Integrity`] naming the affected user ids; database errors likewise.
    #[allow(clippy::too_many_lines)] // one linear transaction: read, decide, write, audit
    pub async fn reseal_totp_secrets<F>(
        &self,
        now: i64,
        dry_run: bool,
        mut f: F,
    ) -> Result<ResealReport, StoreError>
    where
        F: FnMut(i64, &[u8]) -> Reseal,
    {
        // One transaction under the account-domain lock: no concurrent enrollment can change a secret mid-rotation.
        let mut tx = self.begin_account().await?;
        let rows = sqlx::query("SELECT id, totp_secret_enc FROM account ORDER BY id")
            .fetch_all(&mut *tx)
            .await?;
        let mut rep = ResealReport {
            resealed: 0,
            already_current: 0,
            without_secret: 0,
            staging_resealed: 0,
        };
        let mut bad: Vec<i64> = Vec::new();
        let mut updates: Vec<(i64, Vec<u8>, Vec<u8>)> = Vec::new();
        for r in &rows {
            let id: i64 = r.try_get("id")?;
            let blob: Option<Vec<u8>> = r.try_get("totp_secret_enc")?;
            let Some(blob) = blob else {
                rep.without_secret = rep.without_secret.saturating_add(1);
                continue;
            };
            match f(id, &blob) {
                Reseal::Sealed(new) => {
                    rep.resealed = rep.resealed.saturating_add(1);
                    updates.push((id, blob, new));
                }
                Reseal::AlreadyCurrent => {
                    rep.already_current = rep.already_current.saturating_add(1);
                }
                Reseal::Undecryptable => bad.push(id),
            }
        }
        // A staged recovery parks a sealed secret (AAD = user id) until the enrollment confirms:
        // it must move with the user rows or its enrollment page could not open it (SEC-053).
        let staged = sqlx::query(
            "SELECT account_id, totp_secret_enc FROM credential_staging \
             WHERE totp_secret_enc IS NOT NULL ORDER BY account_id",
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut staging_updates: Vec<(i64, Vec<u8>, Vec<u8>)> = Vec::new();
        for r in &staged {
            let id: i64 = r.try_get("account_id")?;
            let blob: Vec<u8> = r.try_get("totp_secret_enc")?;
            match f(id, &blob) {
                Reseal::Sealed(new) => {
                    rep.staging_resealed = rep.staging_resealed.saturating_add(1);
                    staging_updates.push((id, blob, new));
                }
                Reseal::AlreadyCurrent => {}
                Reseal::Undecryptable => bad.push(id),
            }
        }
        if !bad.is_empty() {
            let ids: Vec<String> = bad.iter().map(i64::to_string).collect();
            return Err(StoreError::Integrity(format!(
                "TOTP secret of user id(s) {} opens under neither key; nothing was changed \
                 (check the keys, or run `nzbd user reset-mfa` for them)",
                ids.join(", ")
            )));
        }
        if dry_run {
            return Ok(rep);
        }
        for (id, old, new) in &updates {
            let done = sqlx::query(
                "UPDATE account SET totp_secret_enc = $2 WHERE id = $1 AND totp_secret_enc = $3",
            )
            .bind(id)
            .bind(new)
            .bind(old)
            .execute(&mut *tx)
            .await?;
            if done.rows_affected() != 1 {
                // Changed under us (a running server): abort, the transaction rolls back.
                return Err(StoreError::Integrity(
                    "a TOTP secret changed during rotation; stop the server and retry".into(),
                ));
            }
        }
        for (id, old, new) in &staging_updates {
            let done = sqlx::query(
                "UPDATE credential_staging SET totp_secret_enc = $2 \
                 WHERE account_id = $1 AND totp_secret_enc = $3",
            )
            .bind(id)
            .bind(new)
            .bind(old)
            .execute(&mut *tx)
            .await?;
            if done.rows_affected() != 1 {
                return Err(StoreError::Integrity(
                    "a staged TOTP secret changed during rotation; stop the server and retry"
                        .into(),
                ));
            }
        }
        let detail = format!(
            "resealed={} already_current={} staging={}",
            rep.resealed, rep.already_current, rep.staging_resealed
        );
        crate::pg::account::write_audit_legacy(
            &mut tx,
            now,
            Some("cli"),
            "totp_key_rotated",
            Some(&detail),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(rep)
    }
}

//! 1.x single-account provisioning and the per-account operator resets on Postgres (T112; 2.x `user.rs`).

use sqlx::{PgConnection, Row};

use crate::StoreError;
use crate::account::{AccountError, AuditActor, Role, TOMBSTONE_PASSWORD_HASH};
use crate::pg::PgDb;
use crate::pg::account::{clear_throttle_state, insert_account, write_audit};
use crate::user::UserRow;

fn row_to_user(r: &sqlx::postgres::PgRow) -> Result<UserRow, StoreError> {
    Ok(UserRow {
        id: r.try_get("id")?,
        username: r.try_get("username")?,
        password_hash: r.try_get("password_hash")?,
        totp_enabled: r.try_get("totp_enabled")?,
    })
}

/// The id of the only LIVE account; refuses when there are several (the 1.x commands are ambiguous then:
/// the multi-user commands name the account).
pub(crate) async fn only_live_user(conn: &mut PgConnection) -> Result<i64, StoreError> {
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM account WHERE deleted_at IS NULL ORDER BY id LIMIT 2")
            .fetch_all(&mut *conn)
            .await?;
    match ids.as_slice() {
        [] => Err(StoreError::NotFound),
        [one] => Ok(*one),
        _ => Err(AccountError::AmbiguousAccount.into()),
    }
}

impl PgDb {
    /// Creates the first and only account (1.x provisioning, kept for the single-user CLI path): it is
    /// the **admin**. The "no user exists yet" check and the insert are one `BEGIN IMMEDIATE`
    /// transaction, so two concurrent calls cannot both succeed. Further accounts are created with
    /// [`PgDb::create_account_operator`] (`security.multi_user`).
    ///
    /// # Errors
    /// [`StoreError::UserExists`] if any user exists; [`StoreError::InvalidUsername`];
    /// [`AccountError::ReservedName`].
    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        now: i64,
    ) -> Result<i64, StoreError> {
        crate::account::check_login_name(username)?;
        let mut tx = self.begin_account().await?;
        let any: i64 = sqlx::query_scalar("SELECT count(*) FROM account")
            .fetch_one(&mut *tx)
            .await?;
        if any > 0 {
            return Err(StoreError::UserExists);
        }
        let id = insert_account(&mut tx, username, password_hash, Role::Admin, None, now).await?;
        write_audit(
            &mut tx,
            &AuditActor::cli(),
            now,
            "user.create",
            Some(username),
            None,
            Some(id),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// The oldest live user, if one exists.
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_only_user(&self) -> Result<Option<UserRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, totp_enabled FROM account \
             WHERE deleted_at IS NULL ORDER BY id LIMIT 1",
        )
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(row_to_user).transpose()
    }

    /// Looks a live user up by name (case-insensitive).
    ///
    /// # Errors
    /// Database failure.
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, totp_enabled FROM account \
             WHERE lower(username) = lower($1) AND deleted_at IS NULL",
        )
        .bind(username)
        .fetch_optional(self.web())
        .await?;
        row.as_ref().map(row_to_user).transpose()
    }

    /// Replaces the password hash of the only live account (1.x `user reset-password`); see
    /// [`PgDb::reset_password_for`]. With several accounts it refuses
    /// ([`AccountError::AmbiguousAccount`]).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if there is no user.
    pub async fn reset_password(&self, password_hash: &str, now: i64) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        let id = only_live_user(&mut tx).await?;
        reset_password_in(&mut tx, id, password_hash, true, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Operator `user reset-password <name>`: replaces the account's password hash, clears its lock and
    /// throttle state, revokes its sessions, its API keys, its open recovery codes and its staged swap.
    /// Audit `user.reset_password` (actor `cli`, `target_id`).
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`].
    pub async fn reset_password_for(
        &self,
        user_id: i64,
        password_hash: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        reset_password_in(&mut tx, user_id, password_hash, false, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Clears TOTP of the only live account (1.x `user reset-mfa`); see [`PgDb::reset_mfa_for`].
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if there is no user.
    pub async fn reset_mfa(&self, now: i64) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        let id = only_live_user(&mut tx).await?;
        reset_mfa_in(&mut tx, id, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Operator `user reset-mfa <name>`: clears the TOTP secret, enrollment and replay step, deletes the
    /// recovery codes and every session, revokes open recovery codes and the staged swap, so the next
    /// login must re-enroll. Audit `user.reset_mfa`.
    ///
    /// # Errors
    /// [`AccountError::TargetNotFound`].
    pub async fn reset_mfa_for(&self, user_id: i64, now: i64) -> Result<(), StoreError> {
        let mut tx = self.begin_account().await?;
        reset_mfa_in(&mut tx, user_id, now).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn reset_password_in(
    conn: &mut PgConnection,
    id: i64,
    password_hash: &str,
    revoke_unowned_keys: bool,
    now: i64,
) -> Result<(), StoreError> {
    let res = sqlx::query(
        "UPDATE account SET password_hash = $2, password_changed_at = $3, \
         failed_logins = 0, locked_until = NULL, last_failed_at = NULL \
         WHERE id = $1 AND deleted_at IS NULL AND password_hash <> $4",
    )
    .bind(id)
    .bind(password_hash)
    .bind(now)
    .bind(TOMBSTONE_PASSWORD_HASH)
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AccountError::TargetNotFound.into());
    }
    let sessions = sqlx::query("DELETE FROM session WHERE account_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    // A reset usually follows suspected compromise: upload keys must not survive it. A key without an
    // owner (a database that never had users when it was created) cannot be attributed: it goes too.
    let keys = sqlx::query(
        "UPDATE api_key SET revoked_at = $2 WHERE revoked_at IS NULL \
         AND (owner_id = $1 OR ($3 AND owner_id IS NULL))",
    )
    .bind(id)
    .bind(now)
    .bind(revoke_unowned_keys)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let codes = revoke_recovery_state(conn, id, now).await?;
    clear_throttle_state(conn, id).await?;
    let detail = if codes > 0 {
        format!("sessions_revoked={sessions} api_keys_revoked={keys} codes_revoked={codes}")
    } else {
        format!("sessions_revoked={sessions} api_keys_revoked={keys}")
    };
    write_audit(
        conn,
        &AuditActor::cli(),
        now,
        "user.reset_password",
        Some(&detail),
        None,
        Some(id),
    )
    .await
}

async fn reset_mfa_in(conn: &mut PgConnection, id: i64, now: i64) -> Result<(), StoreError> {
    let res = sqlx::query(
        "UPDATE account SET totp_secret_enc = NULL, totp_enabled = false, totp_last_step = NULL, \
         enroll_token_hash = NULL, enroll_token_expires = NULL WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AccountError::TargetNotFound.into());
    }
    sqlx::query("DELETE FROM recovery_code WHERE account_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let sessions = sqlx::query("DELETE FROM session WHERE account_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    let codes = revoke_recovery_state(conn, id, now).await?;
    let detail = if codes > 0 {
        format!("sessions_revoked={sessions} codes_revoked={codes}")
    } else {
        format!("sessions_revoked={sessions}")
    };
    write_audit(
        conn,
        &AuditActor::cli(),
        now,
        "user.reset_mfa",
        Some(&detail),
        None,
        Some(id),
    )
    .await
}

/// Revokes the open recovery codes issued for `id` and drops its staged swap (every CLI credential
/// command does this, N4).
pub(crate) async fn revoke_recovery_state(
    conn: &mut PgConnection,
    id: i64,
    now: i64,
) -> Result<u64, StoreError> {
    let n = sqlx::query(
        "UPDATE invite SET revoked_at = $2 WHERE purpose = 'recover' AND account_id = $1 \
         AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    crate::pg::invite::drop_staged_swap(conn, id).await?;
    Ok(n)
}

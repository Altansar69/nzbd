//! `nzbd user ...` (`AUTH_SPEC` §Provisioning and "Permission matrix: `nzbd` CLI", SEC-022,
//! SEC-027, SEC-070).
//!
//! Passwords are read only from a no-echo TTY prompt or, when stdin is not a terminal, from
//! stdin lines. They are never accepted via argv or environment, and never printed or logged.

use nzb_store::prelude::*;
use std::fmt::Write as _;
use std::io::{BufRead, IsTerminal};
use std::time::{SystemTime, UNIX_EPOCH};

use nzb_store::{
    AccountError, AccountPolicy, AccountRow, GrantableRole, InviteCode, NewAccount, NewInvite,
    Role, StoreError, username_is_valid,
};
use nzb_web::password::{self, PasswordError};
use nzb_web::totp;

/// Longest accepted piped line (256 chars is at most 1 KiB of UTF-8).
const MAX_PIPED_LINE_BYTES: u64 = 1024;

/// Source of password entries (TTY prompt in production, scripted in tests).
pub trait PasswordSource {
    /// Reads one password entry. `prompt` is shown only for interactive sources.
    ///
    /// # Errors
    /// I/O failure or end of input.
    fn read(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// Interactive no-echo prompt on a TTY, or plain lines from stdin when piped.
pub struct StdinSource;

impl PasswordSource for StdinSource {
    fn read(&mut self, prompt: &str) -> std::io::Result<String> {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            rpassword::prompt_password(prompt)
        } else {
            read_line_from(&mut stdin.lock())
        }
    }
}

/// Reads one line, stripping only the trailing `\n` / `\r\n`. EOF is an error.
fn read_line_from(r: &mut dyn BufRead) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut line = String::new();
    // Bounded read: an endless or huge line must not grow memory without limit.
    let mut limited = r.take(MAX_PIPED_LINE_BYTES);
    if limited.read_line(&mut line)? == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    if !line.ends_with('\n')
        && u64::try_from(line.len()).unwrap_or(u64::MAX) >= MAX_PIPED_LINE_BYTES
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "input line too long",
        ));
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// A user-facing CLI failure (message is safe to print: no secrets).
#[derive(Debug, thiserror::Error)]
pub enum UserCmdError {
    /// Username fails validation.
    #[error("invalid username: use 1-64 characters from A-Z a-z 0-9 . _ -")]
    InvalidUsername,
    /// A user already exists (single-account commands only).
    #[error("a user already exists")]
    UserExists,
    /// No user to modify.
    #[error("no user exists yet; run `nzbd user create <username>` first")]
    NoUser,
    /// No live account with that name.
    #[error("no such account: {0}")]
    UnknownAccount(String),
    /// The two password entries differ.
    #[error("passwords do not match")]
    Mismatch,
    /// Policy violation.
    #[error("{0}")]
    Policy(#[from] PasswordError),
    /// The user already has MFA enabled; there is nothing to enroll.
    #[error(
        "two-factor authentication is already enabled; run `nzbd user reset-mfa` to start over"
    )]
    AlreadyEnrolled,
    /// No secure random bytes available.
    #[error("operating system random source unavailable")]
    Random,
    /// Reading the password failed.
    #[error("could not read password: {0}")]
    Input(std::io::ErrorKind),
    /// A rule of the account model refused the operation (stable code first).
    #[error("{}: {}", .0.code(), explain(*.0))]
    Account(AccountError),
    /// A role argument is not one of `admin`, `uploader`, `viewer`.
    #[error("unknown role: use admin, uploader or viewer")]
    BadRole,
    /// The pre-3.5 role name `member` (D40): refused with the new name instead of a generic error.
    #[error(
        "ROLE_RENAMED: use uploader (the role member was renamed and no longer edits metadata)"
    )]
    RoleRenamed,
    /// The invite role must be uploader or viewer.
    #[error(
        "INVITE_ROLE: an invitation can carry uploader or viewer only; create an administrator with `nzbd user create --role admin`"
    )]
    InviteRole,
    /// Storage failure.
    #[error("{0}")]
    Store(StoreError),
    /// A configuration value the command needs is invalid (stable code first).
    #[error("{0}")]
    Config(String),
}

/// Operator-facing sentence of an account rule (names the setting where one decides).
fn explain(e: AccountError) -> &'static str {
    match e {
        AccountError::MultiUserDisabled => {
            "security.multi_user is false; set it to true in the configuration to create more accounts or invitations"
        }
        AccountError::InvitesDisabled => {
            "security.registration_enabled is false; invitations are switched off (accounts come from `nzbd user create`)"
        }
        AccountError::RoleRequired => "give --role admin, uploader or viewer",
        AccountError::AccountLimit => "security.max_accounts is reached",
        AccountError::TargetNotFound => "no such live account",
        AccountError::LastAdmin => "this would leave no enabled administrator",
        AccountError::LastUsableAdmin => {
            "no other enabled administrator with two-factor set up exists; enroll a second administrator first"
        }
        AccountError::NotDisabled => "disable the account first",
        AccountError::InvalidState => "the account is not in a state this applies to",
        AccountError::ReservedName => "that login name is reserved",
        AccountError::UsernameUnavailable => "that name is already in use",
        AccountError::InvalidDisplayName => "1-32 characters from A-Z a-z 0-9 space . _ -",
        AccountError::DisplayNameTaken => "that display name is not available",
        AccountError::TooManyOpenInvites => "20 invitations are open already; revoke one first",
        AccountError::AmbiguousAccount => "several accounts exist; name the account",
        _ => "refused",
    }
}

impl From<StoreError> for UserCmdError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::UserExists => Self::UserExists,
            StoreError::InvalidUsername => Self::InvalidUsername,
            StoreError::NotFound => Self::NoUser,
            StoreError::Account(a) => Self::Account(a),
            other => Self::Store(other),
        }
    }
}

/// Unix seconds now (0 if the clock is before the epoch; only used for timestamps).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn read_new_password(src: &mut dyn PasswordSource, username: &str) -> Result<String, UserCmdError> {
    let first = src
        .read("New password: ")
        .map_err(|e| UserCmdError::Input(e.kind()))?;
    let second = src
        .read("Repeat password: ")
        .map_err(|e| UserCmdError::Input(e.kind()))?;
    // Plain comparison is fine: both values are the operator's own input, not a verifier.
    if first != second {
        return Err(UserCmdError::Mismatch);
    }
    password::validate_policy(username, &first)?;
    Ok(first)
}

/// Arms MFA enrollment for `user_id`: creates a one-time token (160 bits, 24 h), stores only its
/// domain-separated SHA-256 and returns the display form. The caller prints it once; it is never
/// logged. Also revokes the account's open recovery codes and staged swap (N4).
async fn issue_enroll_token_for(
    db: &nzb_store::Store,
    user_id: i64,
    now: i64,
) -> Result<String, UserCmdError> {
    let token = totp::generate_enroll_token().map_err(|_| UserCmdError::Random)?;
    let expires = now.saturating_add(totp::ENROLL_TOKEN_TTL_SECS);
    if !db
        .set_enrollment_token_for(user_id, &totp::enroll_token_hash(&token), expires, now)
        .await?
    {
        return Err(UserCmdError::AlreadyEnrolled);
    }
    Ok(totp::format_recovery(&token))
}

/// Resolves a live account by login name (or the only account when `name` is `None` and exactly
/// one exists: the 1.x invocations keep working on a single-account database).
async fn resolve(db: &nzb_store::Store, name: Option<&str>) -> Result<AccountRow, UserCmdError> {
    if let Some(n) = name {
        return db
            .get_account_by_username(n)
            .await?
            .ok_or_else(|| UserCmdError::UnknownAccount(n.to_owned()));
    }
    let live: Vec<AccountRow> = db
        .list_accounts(false)
        .await?
        .into_iter()
        .filter(AccountRow::is_live)
        .collect();
    match live.as_slice() {
        [] => Err(UserCmdError::NoUser),
        [one] => Ok(one.clone()),
        _ => Err(UserCmdError::Account(AccountError::AmbiguousAccount)),
    }
}

/// `user create <username> [--role R]`: policy, Argon2id. Creates no session. Returns the one-time
/// MFA enrollment token to hand to the owner. `role = None` is accepted only for the very first
/// account (it becomes the admin); a further account needs `policy.multi_user` (live rows only).
///
/// # Errors
/// See [`UserCmdError`].
pub async fn create(
    db: &nzb_store::Store,
    username: &str,
    role: Option<Role>,
    policy: AccountPolicy,
    src: &mut dyn PasswordSource,
    now: i64,
) -> Result<String, UserCmdError> {
    if !username_is_valid(username) {
        return Err(UserCmdError::InvalidUsername);
    }
    // Fail before prompting for what the store would refuse anyway (it re-checks atomically).
    let live = db.count_live_accounts().await?;
    if live > 0 && !policy.multi_user {
        return Err(UserCmdError::Account(AccountError::MultiUserDisabled));
    }
    if live > 0 && role.is_none() {
        return Err(UserCmdError::Account(AccountError::RoleRequired));
    }
    let pw = read_new_password(src, username)?;
    let phc = password::hash_password(&pw)?;
    let id = db
        .create_account_operator(
            &NewAccount {
                username,
                password_hash: &phc,
                role,
            },
            policy,
            now,
        )
        .await?;
    issue_enroll_token_for(db, id, now).await
}

/// `user reset-password [name]`: new password; revokes sessions, keys, recovery codes and staging.
///
/// # Errors
/// See [`UserCmdError`].
pub async fn reset_password(
    db: &nzb_store::Store,
    name: Option<&str>,
    src: &mut dyn PasswordSource,
    now: i64,
) -> Result<(), UserCmdError> {
    let user = resolve(db, name).await?;
    let pw = read_new_password(src, &user.username)?;
    let phc = password::hash_password(&pw)?;
    db.reset_password_for(user.id, &phc, now).await?;
    Ok(())
}

/// `user reset-mfa [name]`: clears TOTP + recovery codes + sessions and arms a fresh one-time
/// enrollment token (returned for the operator to hand over). Enrollment is impossible without it.
///
/// # Errors
/// [`UserCmdError::NoUser`] when no user exists.
pub async fn reset_mfa(
    db: &nzb_store::Store,
    name: Option<&str>,
    now: i64,
) -> Result<String, UserCmdError> {
    let user = resolve(db, name).await?;
    db.reset_mfa_for(user.id, now).await?;
    issue_enroll_token_for(db, user.id, now).await
}

/// `user enroll-token [name]`: issues a new token (e.g. the first one expired) while MFA is not
/// enabled; also the way to recover an invited account that never finished enrolling.
///
/// # Errors
/// [`UserCmdError::NoUser`], [`UserCmdError::AlreadyEnrolled`].
pub async fn enroll_token(
    db: &nzb_store::Store,
    name: Option<&str>,
    now: i64,
) -> Result<String, UserCmdError> {
    let user = resolve(db, name).await?;
    issue_enroll_token_for(db, user.id, now).await
}

/// `user list`: one line per live account; no secret of any kind. The EMAIL column (D32) is PII
/// shown to the operator only (`-` when none is set).
///
/// # Errors
/// Storage failure.
pub async fn list(db: &nzb_store::Store, now: i64) -> Result<String, UserCmdError> {
    let locked: std::collections::HashSet<i64> =
        db.locked_account_ids(now).await?.into_iter().collect();
    let mut out = format!(
        "{:<5}{:<24}{:<20}{:<8}{:<18}{:<5}{:<22}EMAIL\n",
        "ID", "USERNAME", "DISPLAY NAME", "ROLE", "STATUS", "MFA", "LAST LOGIN"
    );
    for a in db.list_accounts(false).await? {
        let mut status = if a.disabled_at.is_some() {
            "disabled".to_owned()
        } else {
            "active".to_owned()
        };
        if locked.contains(&a.id) {
            status.push_str(",locked");
        }
        if a.recovery_staged_at.is_some() {
            status.push_str(",recovery");
        }
        let _ = writeln!(
            out,
            "{:<5}{:<24}{:<20}{:<8}{:<18}{:<5}{:<22}{}",
            a.id,
            a.username,
            a.handle(),
            a.role.as_str(),
            status,
            if a.totp_enabled { "yes" } else { "no" },
            a.last_login_at
                .map_or_else(|| "never".to_owned(), nzb_web::fmt_utc),
            a.email.as_deref().unwrap_or("-"),
        );
    }
    Ok(out)
}

/// The simple lifecycle commands that take only an account name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    /// `user disable`.
    Disable,
    /// `user enable`.
    Enable,
    /// `user delete` (tombstone, the account must be disabled).
    Delete,
    /// `user unlock` (every lock row and the persisted aggregate).
    Unlock,
    /// `user revoke-sessions`.
    RevokeSessions,
}

/// Applies a [`Lifecycle`] command; returns the number of revoked sessions for
/// `RevokeSessions`, else 0.
///
/// # Errors
/// See [`UserCmdError`]; the last-usable-admin rule applies to disable and delete.
pub async fn lifecycle(
    db: &nzb_store::Store,
    name: &str,
    what: Lifecycle,
    now: i64,
) -> Result<u64, UserCmdError> {
    let target = resolve(db, Some(name)).await?;
    let id = target.id;
    Ok(match what {
        Lifecycle::Disable => db.disable_account_operator(id, now).await.map(|()| 0)?,
        Lifecycle::Enable => db.enable_account_operator(id, now).await.map(|()| 0)?,
        Lifecycle::Delete => db.delete_account_operator(id, now).await.map(|()| 0)?,
        Lifecycle::Unlock => db.unlock_account_operator(id, now).await.map(|()| 0)?,
        Lifecycle::RevokeSessions => db.revoke_account_sessions_operator(id, now).await?,
    })
}

/// `user set-role <name> <role>`: the only way to grant or take away `admin` (D26 b).
///
/// # Errors
/// See [`UserCmdError`].
pub async fn set_role(
    db: &nzb_store::Store,
    name: &str,
    role: Role,
    now: i64,
) -> Result<(), UserCmdError> {
    let target = resolve(db, Some(name)).await?;
    db.set_role_operator(target.id, role, now).await?;
    Ok(())
}

/// `user set-display-name <name> <text>`; an empty text restores the default handle.
///
/// # Errors
/// See [`UserCmdError`].
pub async fn set_display_name(
    db: &nzb_store::Store,
    name: &str,
    text: &str,
    now: i64,
) -> Result<(), UserCmdError> {
    let target = resolve(db, Some(name)).await?;
    let t = text.trim();
    db.set_display_name_operator(target.id, (!t.is_empty()).then_some(t), now)
        .await?;
    Ok(())
}

/// What `user invite` printed (for the caller's output).
#[derive(Debug)]
pub struct Invited {
    /// The grouped one-time code.
    pub code: String,
    /// Expiry (unix seconds).
    pub expires_at: i64,
}

/// `user invite <name> --role uploader|viewer`: issues an invitation code with the operator as the
/// issuer (printed once by the caller; only its hash is stored). Needs `security.multi_user` and
/// `security.registration_enabled`; there is no admin invitation (D27).
///
/// # Errors
/// [`UserCmdError::InviteRole`] for `admin`; the store's refusals (`MULTI_USER_OFF`,
/// `INVITES_DISABLED`, name rules, 20 open invitations).
pub async fn invite(
    db: &nzb_store::Store,
    name: &str,
    role: Role,
    policy: AccountPolicy,
    ttl_secs: i64,
    now: i64,
) -> Result<Invited, UserCmdError> {
    let grant = match role {
        Role::Admin => return Err(UserCmdError::InviteRole),
        Role::Uploader => GrantableRole::Uploader,
        Role::Viewer => GrantableRole::Viewer,
    };
    let entropy = nzb_web::crypto::random_bytes::<{ nzb_store::CODE_ENTROPY_BYTES }>()
        .map_err(|_| UserCmdError::Random)?;
    let code = InviteCode::from_entropy(&entropy);
    db.create_invite_operator(
        &NewInvite {
            username: name,
            role: grant,
            code_hash: &code.hash(),
            ttl_secs,
        },
        policy,
        now,
    )
    .await?;
    Ok(Invited {
        code: code.grouped(),
        expires_at: now.saturating_add(ttl_secs),
    })
}

/// Parses `admin|uploader|viewer` (case-insensitive).
///
/// # Errors
/// [`UserCmdError::RoleRenamed`] for the pre-3.5 name `member` (D40), [`UserCmdError::BadRole`]
/// for anything else that is not a role.
pub fn parse_role(s: &str) -> Result<Role, UserCmdError> {
    let lower = s.to_ascii_lowercase();
    if lower == "member" {
        return Err(UserCmdError::RoleRenamed);
    }
    Role::parse(&lower).ok_or(UserCmdError::BadRole)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn role_parsing_knows_the_three_roles_and_refuses_member_by_name() {
        for (s, r) in [
            ("admin", Role::Admin),
            ("Uploader", Role::Uploader),
            ("VIEWER", Role::Viewer),
        ] {
            assert_eq!(parse_role(s).unwrap(), r);
        }
        for s in ["member", "Member", "MEMBER"] {
            let e = parse_role(s).unwrap_err();
            assert!(matches!(e, UserCmdError::RoleRenamed), "{s}");
            assert!(e.to_string().starts_with("ROLE_RENAMED: use uploader"));
        }
        for s in ["", "owner", "members", " uploader"] {
            assert!(matches!(parse_role(s), Err(UserCmdError::BadRole)), "{s:?}");
        }
    }

    struct Scripted(Vec<&'static str>);
    impl PasswordSource for Scripted {
        fn read(&mut self, _p: &str) -> std::io::Result<String> {
            if self.0.is_empty() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            Ok(self.0.remove(0).to_owned())
        }
    }

    /// The leg's library (`NZBD_TEST_BACKEND`) and what keeps it alive (bind it to a named `_d`).
    async fn open() -> (
        (tempfile::TempDir, nzb_store::test_backend::TestStore),
        nzb_store::Store,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let db = ts.store.clone();
        ((dir, ts), db)
    }

    const PW: &str = "correct horse battery";

    #[tokio::test]
    async fn sec_022_create_stores_argon2id_and_verifies() {
        let (_d, db) = open().await;
        create(
            &db,
            "alice",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec![PW, PW]),
            1,
        )
        .await
        .unwrap();
        let u = db.get_only_user().await.unwrap().unwrap();
        assert!(
            u.password_hash
                .starts_with("$argon2id$v=19$m=65536,t=3,p=1$")
        );
        assert!(!u.password_hash.contains(PW));
        assert!(password::verify_password(PW, &u.password_hash));
        assert!(!u.totp_enabled);
    }

    #[tokio::test]
    async fn sec_022_policy_enforced_by_cli() {
        let (_d, db) = open().await;
        let e = create(
            &db,
            "alice",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec!["short", "short"]),
            1,
        )
        .await
        .unwrap_err();
        assert!(matches!(e, UserCmdError::Policy(PasswordError::TooShort)));
        for (weak, want) in [
            ("aaaaaaaaaaaa", PasswordError::TooFewDistinct),
            ("qwertyuiopas", PasswordError::Pattern),
            ("iloveyou123456", PasswordError::Common),
        ] {
            let e = create(
                &db,
                "alice",
                None,
                AccountPolicy::default(),
                &mut Scripted(vec![weak, weak]),
                1,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&e, UserCmdError::Policy(p) if *p == want),
                "{weak}"
            );
            assert!(!e.to_string().contains(weak));
        }
        let e = create(
            &db,
            "alice",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec![PW, "different password!"]),
            1,
        )
        .await
        .unwrap_err();
        assert!(matches!(e, UserCmdError::Mismatch));
        let e = create(
            &db,
            "administrator",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec!["administrator", "administrator"]),
            1,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            e,
            UserCmdError::Policy(PasswordError::SameAsUsername)
        ));
        assert!(db.get_only_user().await.unwrap().is_none());
        // Error text never echoes the password.
        assert!(!format!("{e}").contains("administrator password"));
    }

    #[tokio::test]
    async fn sec_027_second_user_create_fails_clearly() {
        let (_d, db) = open().await;
        create(
            &db,
            "alice",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec![PW, PW]),
            1,
        )
        .await
        .unwrap();
        // Fails before any prompt is read (empty script would otherwise be an Input error).
        let e = create(
            &db,
            "bob",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec![]),
            2,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            e,
            UserCmdError::Account(AccountError::MultiUserDisabled)
        ));
        assert!(e.to_string().contains("security.multi_user"));
    }

    #[tokio::test]
    async fn sec_027_reset_password_and_mfa_via_cli() {
        let (_d, db) = open().await;
        assert!(matches!(
            reset_password(&db, None, &mut Scripted(vec![]), 1).await,
            Err(UserCmdError::NoUser)
        ));
        assert!(matches!(
            reset_mfa(&db, None, 1).await,
            Err(UserCmdError::NoUser)
        ));
        assert!(matches!(
            enroll_token(&db, None, 1).await,
            Err(UserCmdError::NoUser)
        ));
        create(
            &db,
            "alice",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec![PW, PW]),
            1,
        )
        .await
        .unwrap();
        let newpw = "another long passphrase";
        reset_password(&db, None, &mut Scripted(vec![newpw, newpw]), 2)
            .await
            .unwrap();
        let u = db.get_only_user().await.unwrap().unwrap();
        assert!(password::verify_password(newpw, &u.password_hash));
        assert!(!password::verify_password(PW, &u.password_hash));
        reset_mfa(&db, None, 3).await.unwrap();
    }

    #[tokio::test]
    async fn sec_023_create_and_reset_mfa_print_a_single_use_token_stored_only_hashed() {
        let (_d, db) = open().await;
        let t1 = create(
            &db,
            "alice",
            None,
            AccountPolicy::default(),
            &mut Scripted(vec![PW, PW]),
            100,
        )
        .await
        .unwrap();
        // 160 bits in XXXX-XXXX-... form; the database holds only the domain-separated hash.
        let canon = totp::normalize_enroll_token(&t1).unwrap();
        assert_eq!(t1.replace('-', ""), canon);
        let uid = db.get_only_user().await.unwrap().unwrap().id;
        let hash = totp::enroll_token_hash(&canon);
        // The hash of the printed token verifies; the raw token or a near miss does not; it expires.
        let other = totp::enroll_token_hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(
            !db.check_enrollment_token(uid, Some(other), None, 101)
                .await
                .unwrap()
        );
        assert!(
            !db.check_enrollment_token(
                uid,
                Some(nzb_web::crypto::sha256(canon.as_bytes())),
                None,
                101
            )
            .await
            .unwrap()
        );
        assert!(
            db.check_enrollment_token(uid, Some(hash), None, 101)
                .await
                .unwrap()
        );
        let late = 100 + totp::ENROLL_TOKEN_TTL_SECS;
        assert!(
            !db.check_enrollment_token(uid, Some(hash), None, late)
                .await
                .unwrap()
        );
        // `enroll-token` re-issues (old token stops working); reset-mfa issues a fresh one.
        let t2 = enroll_token(&db, None, 200).await.unwrap();
        assert_ne!(t1, t2);
        let t3 = reset_mfa(&db, None, 300).await.unwrap();
        assert_ne!(t2, t3);
        let audit = db.recent_audit(20).await.unwrap();
        let dump = format!("{audit:?}");
        assert!(audit.iter().any(|a| a.event == "user.enroll_token_issued"));
        for t in [&t1, &t2, &t3] {
            assert!(!dump.contains(t.as_str()) && !dump.contains(&t.replace('-', "")));
        }
        // Once MFA is enabled there is nothing to enroll and no token is issued.
        db.store_pending_totp(uid, b"blob", false).await.unwrap();
        let h3 = totp::enroll_token_hash(&totp::normalize_enroll_token(&t3).unwrap());
        assert!(
            db.confirm_totp_enrollment(uid, b"blob", Some(h3), Some(1), &[], None, 350)
                .await
                .unwrap()
        );
        assert!(matches!(
            enroll_token(&db, None, 400).await,
            Err(UserCmdError::AlreadyEnrolled)
        ));
    }

    #[test]
    fn piped_line_length_is_capped() {
        let mut c = std::io::Cursor::new(vec![b'a'; 1_000_000]);
        let e = read_line_from(&mut c).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        // Exactly at the limit with a newline is fine.
        let mut ok = vec![b'a'; 1023];
        ok.push(b'\n');
        assert_eq!(
            read_line_from(&mut std::io::Cursor::new(ok)).unwrap().len(),
            1023
        );
    }

    #[test]
    fn piped_lines_strip_only_newline() {
        let mut c = std::io::Cursor::new(b"pa ss \r\nsecond\n".to_vec());
        assert_eq!(read_line_from(&mut c).unwrap(), "pa ss ");
        assert_eq!(read_line_from(&mut c).unwrap(), "second");
        assert!(read_line_from(&mut c).is_err());
    }
}

//! The two MFA steps of the login flow: `/login/mfa` (verify) and `/mfa/enroll` (first-time
//! setup) (`AUTH_SPEC` §Login flow, §TOTP, §Recovery codes; SEC-023/026/033).
//!
//! Both steps are reachable only with a `pending_mfa` session (`pending_gate`). Completing either
//! one: counts wrong codes into the per-(account, address) lock, the persisted aggregate and the
//! pending session's own 5-failure cap (one writer transaction each, `*_v2` verdicts), records the
//! completed login (`record_login_success_v2`, the only writer of the known-address set) and
//! mints a NEW `active` session id that replaces the pending one (fixation). Every failure
//! renders the same page with the same text.
//!
//! The enrollment page serves three kinds of pending session (T101):
//! * *token*: the 1.x flow, a host-printed enrollment token proves the holder first;
//! * *proven*: the session was created by an invitation redemption (`enroll_proven`), the code
//!   already played the part of the token;
//! * *recovery*: an admin-issued recovery code was redeemed; the new password and the new TOTP
//!   secret are only STAGED and replace the account's credentials at the final confirmation
//!   (`Store::commit_staged_recovery`), so abandoning the page changes nothing.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use nzb_store::prelude::*;
use nzb_store::{
    AccountError, CommitRecovery, EnrollConfirm, FactorAttempt, FailureKind, MfaState,
    SecondFactor, SessionStage, StoreError,
};
use zeroize::Zeroizing;

use crate::assets::Layout;
use crate::auth::{AuthError, AuthState, ClientMeta, SessionCtx};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::login::{html, internal};
use crate::session::see_other;
use crate::totp;

/// The one failure text for every wrong or malformed second-factor input.
pub const INVALID_CODE: &str = "Invalid code";
/// Failure text for a wrong, expired or missing enrollment token.
pub const INVALID_TOKEN: &str = "Invalid or expired enrollment token";

#[derive(Template)]
#[template(path = "mfa_verify.html")]
struct VerifyPage {
    layout: Layout,
    csrf_token: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "mfa_enroll_token.html")]
struct TokenPage {
    layout: Layout,
    csrf_token: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "mfa_enroll.html")]
struct EnrollPage {
    layout: Layout,
    csrf_token: String,
    error: Option<&'static str>,
    qr: String,
    secret_text: Zeroizing<String>,
    uri: Zeroizing<String>,
    /// The token that proved the holder (token mode only); empty otherwise.
    token: String,
    /// Shown once after a valid invitation redemption.
    welcome: Option<String>,
    /// Recovery flow: the new password applies only after this confirmation.
    recovery: bool,
}

/// Page that shows freshly generated recovery codes exactly once.
#[derive(Template)]
#[template(path = "recovery_codes.html")]
pub(crate) struct RecoveryCodesPage {
    pub(crate) layout: Layout,
    pub(crate) heading: &'static str,
    pub(crate) codes: Vec<String>,
    pub(crate) continue_href: &'static str,
    pub(crate) continue_label: &'static str,
}

/// Decrypts the user's stored secret. `None` when no key is configured or the blob is unreadable.
pub(crate) fn secret_of_state(
    auth: &AuthState,
    user_id: i64,
    st: &MfaState,
) -> Option<Zeroizing<Vec<u8>>> {
    let key = auth.totp_key()?;
    totp::open(key, user_id, st.totp_secret_enc.as_deref()?)
}

/// Classifies the single `code` field: six digits are a TOTP code, 16 base32 characters a
/// recovery code, anything else is counted as a wrong TOTP code. Length/charset come first.
pub(crate) fn factor_from_input(secret: &[u8], now: i64, input: &str) -> SecondFactor {
    if let Some(code) = totp::parse_totp_code(input) {
        SecondFactor::Totp(totp::matching_step(secret, now, &code))
    } else if let Some(canon) = totp::normalize_recovery(input) {
        SecondFactor::Recovery(Some(totp::recovery_hash(&canon)))
    } else {
        SecondFactor::Totp(None)
    }
}

/// Renders a freshly generated batch of recovery codes (shown once), optionally setting a cookie.
pub(crate) fn recovery_response(
    layout: Layout,
    heading: &'static str,
    codes: &[String],
    continue_href: &'static str,
    continue_label: &'static str,
    cookie: Option<axum::http::HeaderValue>,
) -> Response {
    let page = RecoveryCodesPage {
        layout,
        heading,
        codes: codes.iter().map(|c| totp::format_recovery(c)).collect(),
        continue_href,
        continue_label,
    };
    let mut resp = page
        .render()
        .map_or_else(|_| internal(), |b| html(StatusCode::OK, b));
    if let Some(c) = cookie {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, c);
    }
    resp
}

/// Where a pending session belongs: `Ok(state)` for the step it asked for, `Err(redirect)`
/// otherwise.
#[allow(clippy::result_large_err)]
async fn state_for(
    auth: &AuthState,
    sess: &SessionCtx,
    want_enrolled: bool,
) -> Result<MfaState, Response> {
    match auth.db().get_mfa_state(sess.user_id).await {
        Ok(Some(st)) if st.totp_enabled == want_enrolled => Ok(st),
        Ok(Some(_)) => Err(see_other(
            if want_enrolled {
                "/mfa/enroll"
            } else {
                "/login/mfa"
            },
            None,
        )),
        Ok(None) => Err(see_other("/login", None)),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            Err(internal())
        }
    }
}

/// A staged credential swap belongs to the enrollment page, never to the code prompt.
#[allow(clippy::result_large_err)]
async fn redirect_if_recovery(auth: &AuthState, sess: &SessionCtx) -> Result<(), Response> {
    match auth
        .db()
        .staged_swap(sess.user_id, &sess.id_hash, auth.now())
        .await
    {
        Ok(Some(_)) => Err(see_other("/mfa/enroll", None)),
        Ok(None) => Ok(()),
        Err(e) => {
            tracing::error!(error = %e, "staged swap lookup failed");
            Err(internal())
        }
    }
}

fn render_verify(sess: &SessionCtx, error: Option<&'static str>) -> Response {
    VerifyPage {
        layout: Layout::new("Two-factor authentication"),
        csrf_token: sess.csrf_token.clone(),
        error,
    }
    .render()
    .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

pub(crate) async fn get_verify(
    State(auth): State<AuthState>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    if let Err(r) = redirect_if_recovery(&auth, &sess).await {
        return r;
    }
    match state_for(&auth, &sess, true).await {
        Ok(_) => render_verify(&sess, None),
        Err(r) => r,
    }
}

pub(crate) async fn post_verify(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = redirect_if_recovery(&auth, &sess).await {
        return r;
    }
    let st = match state_for(&auth, &sess, true).await {
        Ok(st) => st,
        Err(r) => return r,
    };
    let Some(secret) = secret_of_state(&auth, sess.user_id, &st) else {
        // No key configured or the stored blob is unreadable: fail closed, never skip MFA.
        tracing::error!("TOTP secret unavailable; refusing second-factor login");
        return internal();
    };
    let form = csrf::parse_form(&body);
    let input = csrf::form_get(&form, "code").unwrap_or_default();
    let now = auth.now();
    let factor = factor_from_input(&secret, now, input);
    let recovery = matches!(factor, SecondFactor::Recovery(_));
    let ip_text = ip.to_string();
    let attempt = match auth
        .attempt(Some(sess.user_id), ip, Some(sess.id_hash))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "throttle state failed");
            return internal();
        }
    };
    // The verification above is done whatever the throttle says; a refused (locked, throttled,
    // capped) attempt is answered exactly like a wrong code, after the same work (SEC-064).
    let accepted = match auth
        .db()
        .second_factor_step_v2(
            FactorAttempt {
                user_id: sess.user_id,
                precondition_ok: true,
                factor,
                purpose: "login",
                ip: Some(&ip_text),
                now,
            },
            &attempt.ctx(),
        )
        .await
    {
        Ok(v) => v.accepted,
        Err(e) => {
            tracing::error!(error = %e, "second factor verdict failed");
            return internal();
        }
    };
    if !accepted {
        return render_verify(&sess, Some(INVALID_CODE));
    }
    // The login is complete: only now are the lock state and the known-address set updated, and
    // the session id is replaced (never promoted) so the pending id cannot be reused.
    if let Err(e) = auth
        .db()
        .record_login_success_v2(sess.user_id, Some(attempt.ip_key()), now)
        .await
    {
        tracing::error!(error = %e, "could not record the completed login");
        return internal();
    }
    let meta = ClientMeta::from_request(&headers, Some(ip));
    match auth
        .promote_session(sess.user_id, &meta, &sess.id_hash)
        .await
    {
        // A recovery code was spent: the account page explains how to get a new set.
        Ok((cookie, _)) => see_other(if recovery { "/account" } else { "/" }, Some(cookie)),
        // The pending session vanished (logout, CLI reset, a concurrent request used it first).
        Err(AuthError::Store(StoreError::NotFound)) => {
            see_other("/login", Some(auth.clear_cookie()))
        }
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            internal()
        }
    }
}

/// Pending secret: the stored one, or a freshly generated, sealed and stored one (first visit
/// after the token check, or when the stored blob no longer decrypts, e.g. after a key change).
/// Returns the sealed blob too, so the confirmation can be bound to exactly this secret.
#[allow(clippy::result_large_err)]
async fn pending_secret(
    auth: &AuthState,
    key: &totp::TotpKey,
    uid: i64,
    st: &MfaState,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Response> {
    if let (Some(s), Some(blob)) = (secret_of_state(auth, uid, st), st.totp_secret_enc.clone()) {
        return Ok((s, blob));
    }
    let replace = st.totp_secret_enc.is_some();
    let fresh = totp::generate_secret().map_err(|_| internal())?;
    let sealed = totp::seal(key, uid, &*fresh).map_err(|_| internal())?;
    let stored = match auth.db().store_pending_totp(uid, &sealed, replace).await {
        Ok(Some(b)) => b,
        Ok(None) => return Err(see_other("/login/mfa", None)),
        Err(e) => {
            tracing::error!(error = %e, "could not store pending TOTP secret");
            return Err(internal());
        }
    };
    let secret = totp::open(key, uid, &stored).ok_or_else(internal)?;
    Ok((secret, stored))
}

fn render_token_prompt(sess: &SessionCtx, error: Option<&'static str>) -> Response {
    TokenPage {
        layout: Layout::new("Set up two-factor authentication"),
        csrf_token: sess.csrf_token.clone(),
        error,
    }
    .render()
    .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

/// What the enrollment page is for (see the module docs).
enum Mode {
    /// 1.x: the holder must prove the host-printed enrollment token first.
    Token(MfaState),
    /// Created by an invitation redemption: the code already proved the holder.
    Proven(MfaState),
    /// An admin-issued recovery code was redeemed: credentials are staged, not yet replaced.
    Recovery(MfaState, nzb_store::StagedSwap),
}

impl Mode {
    fn state(&self) -> &MfaState {
        match self {
            Self::Token(st) | Self::Proven(st) | Self::Recovery(st, _) => st,
        }
    }
}

/// Decides which kind of enrollment this pending session is, or where it belongs instead.
#[allow(clippy::result_large_err)]
async fn enroll_mode(auth: &AuthState, sess: &SessionCtx) -> Result<Mode, Response> {
    let st = match auth.db().get_mfa_state(sess.user_id).await {
        Ok(Some(st)) => st,
        Ok(None) => return Err(see_other("/login", None)),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            return Err(internal());
        }
    };
    match auth
        .db()
        .staged_swap(sess.user_id, &sess.id_hash, auth.now())
        .await
    {
        Ok(Some(staged)) => return Ok(Mode::Recovery(st, staged)),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "staged swap lookup failed");
            return Err(internal());
        }
    }
    if st.totp_enabled {
        return Err(see_other("/login/mfa", None));
    }
    if sess.enroll_proven {
        Ok(Mode::Proven(st))
    } else {
        Ok(Mode::Token(st))
    }
}

/// Renders the secret page. `token` is the canonical enrollment token the user already proved
/// (token mode; empty otherwise): it rides along in a hidden field and is verified again,
/// atomically, at confirmation.
fn render_enroll(
    sess: &SessionCtx,
    mode: &Mode,
    secret: &[u8],
    token: &str,
    error: Option<&'static str>,
) -> Response {
    let username = &mode.state().username;
    let uri = Zeroizing::new(totp::otpauth_uri(username, secret));
    let Some(qr) = totp::qr_svg_data_uri(&uri) else {
        return internal();
    };
    EnrollPage {
        layout: Layout::new("Set up two-factor authentication"),
        csrf_token: sess.csrf_token.clone(),
        error,
        qr,
        secret_text: Zeroizing::new(totp::base32_encode(secret)),
        uri,
        token: token.to_owned(),
        // The invitee's login name is shown after a valid redemption only (SEC-064).
        welcome: matches!(mode, Mode::Proven(_)).then(|| username.clone()),
        recovery: matches!(mode, Mode::Recovery(..)),
    }
    .render()
    .map_or_else(|_| internal(), |b| html(StatusCode::OK, b))
}

/// `GET /mfa/enroll`: a plain enrollment asks for the one-time enrollment token printed on the
/// host (`nzbd user create|reset-mfa|enroll-token`); the secret is not generated or shown before
/// it is proven, so knowing the password alone never yields the authenticator secret. A session
/// that came from an invitation or a recovery code shows its (staged) secret directly.
pub(crate) async fn get_enroll(
    State(auth): State<AuthState>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    match enroll_mode(&auth, &sess).await {
        Ok(Mode::Token(_)) => render_token_prompt(&sess, None),
        Ok(mode) => show_secret(&auth, &sess, &mode, "").await,
        Err(r) => r,
    }
}

/// Shows the pending secret of a proven or recovery session (creating and storing it first).
async fn show_secret(auth: &AuthState, sess: &SessionCtx, mode: &Mode, token: &str) -> Response {
    let Some(key) = auth.totp_key() else {
        tracing::error!("no TOTP key configured; enrollment unavailable");
        return internal();
    };
    match pending_for(auth, key, sess, mode).await {
        Ok((secret, _)) => render_enroll(sess, mode, &secret, token, None),
        Err(r) => r,
    }
}

/// The pending secret and its sealed blob for any mode (the blob binds the confirmation to
/// exactly the secret that was displayed).
#[allow(clippy::result_large_err)]
async fn pending_for(
    auth: &AuthState,
    key: &totp::TotpKey,
    sess: &SessionCtx,
    mode: &Mode,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Response> {
    match mode {
        Mode::Token(st) | Mode::Proven(st) => pending_secret(auth, key, sess.user_id, st).await,
        Mode::Recovery(_, staged) => {
            if let Some(blob) = staged.totp_secret_enc.clone()
                && let Some(secret) = totp::open(key, sess.user_id, &blob)
            {
                return Ok((secret, blob));
            }
            let fresh = totp::generate_secret().map_err(|_| internal())?;
            let sealed = totp::seal(key, sess.user_id, &*fresh).map_err(|_| internal())?;
            let stored = match auth
                .db()
                .stage_totp_secret(sess.user_id, &sess.id_hash, &sealed, auth.now())
                .await
            {
                Ok(Some(b)) => b,
                Ok(None) => return Err(see_other("/login", Some(auth.clear_cookie()))),
                Err(e) => {
                    tracing::error!(error = %e, "could not stage the TOTP secret");
                    return Err(internal());
                }
            };
            let secret = totp::open(key, sess.user_id, &stored).ok_or_else(internal)?;
            Ok((secret, stored))
        }
    }
}

/// Step 1 of token enrollment: prove the token, then show (creating on first use) the secret.
async fn enroll_reveal(
    auth: &AuthState,
    sess: &SessionCtx,
    mode: &Mode,
    canon: Option<String>,
    token_hash: Option<[u8; 32]>,
    attempt: &crate::auth::Attempt,
    ip: &str,
) -> Response {
    let ok = match auth
        .db()
        .check_enrollment_token_v2(
            sess.user_id,
            token_hash,
            &attempt.ctx(),
            Some(ip),
            auth.now(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "enrollment token check failed");
            return internal();
        }
    };
    let (true, Some(canon)) = (ok, canon) else {
        return render_token_prompt(sess, Some(INVALID_TOKEN));
    };
    let Some(key) = auth.totp_key() else {
        tracing::error!("no TOTP key configured; enrollment unavailable");
        return internal();
    };
    match pending_for(auth, key, sess, mode).await {
        Ok((secret, _)) => render_enroll(sess, mode, &secret, &canon, None),
        Err(r) => r,
    }
}

// One handler for the three modes of the enrollment POST; splitting it would only scatter the
// shared steps (code parsing, recovery codes, session promotion).
#[allow(clippy::too_many_lines)]
pub(crate) async fn post_enroll(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Extension(sess): Extension<SessionCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mode = match enroll_mode(&auth, &sess).await {
        Ok(m) => m,
        Err(r) => return r,
    };
    let Some(key) = auth.totp_key() else {
        tracing::error!("no TOTP key configured; enrollment unavailable");
        return internal();
    };
    let form = csrf::parse_form(&body);
    let now = auth.now();
    let ip_text = ip.to_string();
    let attempt = match auth
        .attempt(Some(sess.user_id), ip, Some(sess.id_hash))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "throttle state failed");
            return internal();
        }
    };
    let token_mode = matches!(mode, Mode::Token(_));
    let canon = if token_mode {
        csrf::form_get(&form, "token").and_then(totp::normalize_enroll_token)
    } else {
        None
    };
    let token_hash = canon.as_deref().map(totp::enroll_token_hash);
    let has_code = csrf::form_get(&form, "code").is_some();
    if !has_code {
        if token_mode {
            return enroll_reveal(&auth, &sess, &mode, canon, token_hash, &attempt, &ip_text).await;
        }
        return show_secret(&auth, &sess, &mode, "").await;
    }
    // Step 2: confirm with a code. In token mode the token is re-verified inside the confirming
    // transaction.
    if token_mode && canon.is_none() {
        // No usable token: count it like any wrong attempt and ask again.
        let _ = auth
            .db()
            .check_enrollment_token_v2(sess.user_id, None, &attempt.ctx(), Some(&ip_text), now)
            .await;
        return render_token_prompt(&sess, Some(INVALID_TOKEN));
    }
    let (secret, blob) = match pending_for(&auth, key, &sess, &mode).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let input = csrf::form_get(&form, "code").unwrap_or_default();
    let step = totp::parse_totp_code(input).and_then(|c| totp::matching_step(&secret, now, &c));
    let Ok(codes) = totp::generate_recovery_codes() else {
        return internal();
    };
    let hashes: Vec<[u8; 32]> = codes.iter().map(|c| totp::recovery_hash(c)).collect();
    let meta = ClientMeta::from_request(&headers, Some(ip));
    let token_text = canon.clone().unwrap_or_default();
    if let Mode::Recovery(..) = &mode {
        // The commit point of a staged recovery: password, TOTP secret and recovery codes are
        // replaced, every other session and key of the account dies, in one transaction.
        let Some(step) = step else {
            let _ = auth
                .db()
                .record_failure(
                    sess.user_id,
                    attempt.ip_key(),
                    FailureKind::Enrollment,
                    Some(&sess.id_hash),
                    now,
                )
                .await;
            return render_enroll(&sess, &mode, &secret, "", Some(INVALID_CODE));
        };
        let (new_session, cookie, csrf_token) =
            match auth.prepare_session(sess.user_id, SessionStage::Active, &meta) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "session preparation failed");
                    return internal();
                }
            };
        let commit = CommitRecovery {
            user_id: sess.user_id,
            session_hash: &sess.id_hash,
            sealed: &blob,
            step,
            recovery_hashes: &hashes,
            new_session: &new_session,
            ip_key: Some(attempt.ip_key()),
        };
        return match auth
            .db()
            .commit_staged_recovery(&commit, Some(&ip_text), now)
            .await
        {
            Ok(()) => recovery_response(
                Layout::authed("Recovery codes", csrf_token)
                    .hiding(&sess.hidden_categories)
                    .themed(sess.prefs.theme),
                "Your new password and authenticator are active",
                &codes,
                "/",
                "Continue to nzbd",
                Some(cookie),
            ),
            Err(StoreError::Account(AccountError::StagingInvalid)) => {
                // Expired, cancelled or no longer valid: nothing was replaced.
                see_other("/login", Some(auth.clear_cookie()))
            }
            Err(e) => {
                tracing::error!(error = %e, "recovery commit failed");
                internal()
            }
        };
    }
    let confirm = EnrollConfirm {
        user_id: sess.user_id,
        sealed: &blob,
        token_hash: if token_mode { token_hash } else { None },
        step,
        recovery_hashes: &hashes,
    };
    let enrolled = match auth
        .db()
        .confirm_totp_enrollment_v2(&confirm, &attempt.ctx(), Some(&ip_text), now)
        .await
    {
        Ok(v) => v,
        Err(StoreError::NotFound) => return see_other("/mfa/enroll", None),
        Err(e) => {
            tracing::error!(error = %e, "enrollment verdict failed");
            return internal();
        }
    };
    if !enrolled {
        // Wrong code (or the token expired meanwhile): the secret page again, same text.
        return render_enroll(&sess, &mode, &secret, &token_text, Some(INVALID_CODE));
    }
    if let Err(e) = auth
        .db()
        .record_login_success_v2(sess.user_id, Some(attempt.ip_key()), now)
        .await
    {
        tracing::error!(error = %e, "could not record the completed login");
    }
    match auth
        .promote_session(sess.user_id, &meta, &sess.id_hash)
        .await
    {
        Ok((cookie, csrf_token)) => recovery_response(
            Layout::authed("Recovery codes", csrf_token)
                .hiding(&sess.hidden_categories)
                .themed(sess.prefs.theme),
            "Two-factor authentication is on",
            &codes,
            "/",
            "Continue to nzbd",
            Some(cookie),
        ),
        Err(e) => {
            // MFA is already enabled and the hashes are committed: never lose the codes. Show
            // them without a cookie; the user signs in again with TOTP.
            tracing::error!(error = %e, "session creation failed after enrollment");
            recovery_response(
                Layout::new("Recovery codes"),
                "Two-factor authentication is on",
                &codes,
                "/login",
                "Sign in again",
                Some(auth.clear_cookie()),
            )
        }
    }
}

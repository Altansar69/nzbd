//! Login and logout (the MFA steps live in `mfa.rs`) (`AUTH_SPEC` §Login flow; SEC-024/025/026/027).
//!
//! Every credential failure takes the same path: one full Argon2id verification (against the
//! dummy hash when the user is unknown, the input is over-length, or the stored hash is
//! unusable), the same `200` login page and the same text, so the response reveals neither
//! whether the account exists nor whether it is locked.
//!
//! The password step only ever yields a `pending_mfa` session. Failure state is cleared by the
//! *second factor* completing (`mfa.rs` calls `Store::record_login_success_v2`), never by the
//! password step, otherwise an attacker holding the password could reset the counter between
//! TOTP guesses.
//!
//! Throttling is the per-(account, address) lock, the persisted aggregate and the unknown-address
//! bucket of the store's `_v2` verdicts. A throttled attempt has already paid for the same
//! Argon2 verification (or the dummy one) and gets the response of a wrong password.

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use nzb_store::prelude::*;
use nzb_store::{SessionStage, username_is_valid};

use crate::assets::Layout;
use crate::auth::{AuthError, AuthState, ClientMeta, MAX_VERIFY_WAITERS};
use crate::crypto::sha256;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::mfa;
use crate::password::{self, MAX_PASSWORD_CHARS};
use crate::session::{csrf_rejected, enforce_csrf, host_layer, pending_gate, see_other};

/// The one failure text shown for every credential problem.
pub const INVALID_CREDENTIALS: &str = "Invalid credentials";
const EXPIRED_FORM: &str = "This form expired. Please try again.";

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    layout: Layout,
    notice: Option<&'static str>,
    login_token: String,
    username: String,
    // T135 (review 49 L1): no invitation link and no other trace of the instance switches. The
    // page is identical whatever `multi_user`, `registration_enabled` and `invite_path` say, so
    // it tells an anonymous caller neither that invitations exist nor where they are redeemed.
}

pub(crate) fn html(status: StatusCode, body: String) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

pub(crate) fn internal() -> Response {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
}

/// Renders the login form with a fresh single-use token. The token is bound to the `HttpOnly`
/// nonce cookie set on this response: `reuse` keeps the browser's existing nonce (a plain GET,
/// so two open tabs both keep working); `None` mints a new one (after any POST).
fn render_login(
    auth: &AuthState,
    notice: Option<&'static str>,
    username: &str,
    reuse: Option<String>,
) -> Response {
    let nonce = match reuse {
        Some(n) => n,
        None => match csrf::new_login_nonce() {
            Ok(n) => n,
            Err(_) => return internal(),
        },
    };
    let Ok(login_token) = csrf::issue_login_token(&auth.0.token_key, auth.now(), &nonce) else {
        return internal();
    };
    let Some(cookie) = auth.login_nonce_cookie(&nonce) else {
        return internal();
    };
    // Echo the name only when it is a valid username: nothing hostile is reflected, and the
    // output is auto-escaped regardless.
    let username = if username_is_valid(username) {
        username.to_owned()
    } else {
        String::new()
    };
    let page = LoginPage {
        layout: Layout::new("Sign in"),
        notice,
        login_token,
        username,
    };
    match page.render() {
        Ok(body) => {
            let mut resp = html(StatusCode::OK, body);
            resp.headers_mut().append(header::SET_COOKIE, cookie);
            resp
        }
        Err(_) => internal(),
    }
}

async fn get_login(State(auth): State<AuthState>, headers: HeaderMap) -> Response {
    // Already signed in: go to the app. A pending or unknown cookie is simply ignored here.
    if let Ok(Some(s)) = auth.load_session(&headers).await
        && s.stage == SessionStage::Active
    {
        return see_other("/", None);
    }
    render_login(&auth, None, "", auth.presented_login_nonce(&headers))
}

fn is_urlencoded_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        })
}

/// One Argon2id verification on the blocking pool, bounded by `verify_concurrency` (each run
/// needs 64 MiB). The wait queue is bounded too (L3): when it is full the request is refused
/// with `AuthError::Busy` instead of piling up until the request timeout.
pub(crate) async fn verify_blocking(
    auth: &AuthState,
    pw: String,
    hash: String,
) -> Result<bool, AuthError> {
    use std::sync::atomic::Ordering;
    let waiting = &auth.0.verify_waiting;
    if waiting.fetch_add(1, Ordering::AcqRel) >= MAX_VERIFY_WAITERS {
        waiting.fetch_sub(1, Ordering::AcqRel);
        return Err(AuthError::Busy);
    }
    let permit = auth.0.verify_slots.acquire().await;
    waiting.fetch_sub(1, Ordering::AcqRel);
    let _permit = permit.map_err(|_| AuthError::Task)?;
    let r = tokio::task::spawn_blocking(move || password::verify_password(&pw, &hash))
        .await
        .map_err(|_| AuthError::Task);
    auth.0.verify_runs.fetch_add(1, Ordering::Relaxed);
    r
}

/// Hashes a new password on the blocking pool under the same bounded slots as verification
/// (each Argon2id run needs 64 MiB).
pub(crate) async fn hash_blocking(auth: &AuthState, pw: String) -> Result<String, AuthError> {
    use std::sync::atomic::Ordering;
    let waiting = &auth.0.verify_waiting;
    if waiting.fetch_add(1, Ordering::AcqRel) >= MAX_VERIFY_WAITERS {
        waiting.fetch_sub(1, Ordering::AcqRel);
        return Err(AuthError::Busy);
    }
    let permit = auth.0.verify_slots.acquire().await;
    waiting.fetch_sub(1, Ordering::AcqRel);
    let _permit = permit.map_err(|_| AuthError::Task)?;
    tokio::task::spawn_blocking(move || password::hash_password(&pw))
        .await
        .map_err(|_| AuthError::Task)?
        .map_err(AuthError::from)
}

enum Outcome {
    /// Password accepted; carries the user's id and whether TOTP is enrolled.
    PasswordOk {
        user_id: i64,
        enrolled: bool,
    },
    Failed,
}

async fn check_credentials(
    auth: &AuthState,
    username: &str,
    password: &str,
    ip: std::net::IpAddr,
) -> Result<Outcome, AuthError> {
    // Cap input BEFORE any hashing or lookup (review M2): name <= 64 bytes, password <= 256 chars.
    let name_ok = username.len() <= nzb_store::MAX_USERNAME_LEN && username_is_valid(username);
    let pw_ok = password.chars().take(MAX_PASSWORD_CHARS + 1).count() <= MAX_PASSWORD_CHARS;
    let user = if name_ok {
        auth.db().get_login_user(username).await?
    } else {
        None
    };
    // One throttle-state read for every attempt, known name or not, before the verification.
    let attempt = auth.attempt(user.as_ref().map(|u| u.id), ip, None).await?;
    let ip_text = ip.to_string();
    // Unknown user, tombstone (`!` sentinel), unusable stored hash: burn the same work against
    // the dummy hash. A disabled account verifies its real hash (same work) and is refused by
    // the verdict below with the answer of a wrong password.
    let (hash, known) = match &user {
        Some(u) if password::hash_is_usable(&u.password_hash) => (u.password_hash.clone(), true),
        _ => (auth.0.dummy_hash.clone(), false),
    };
    // Over-length input is never hashed; a fixed empty probe keeps the cost identical.
    let probe = if pw_ok {
        password.to_owned()
    } else {
        String::new()
    };
    let verified = verify_blocking(auth, probe, hash).await? && known && pw_ok;
    // The verdict (lock re-read, counter, audit row) is ONE writer transaction taken after the
    // verification, identical in shape for every branch (M1, L1). `user` above is only a hint
    // for which hash to verify; its lock fields are never trusted.
    let reason = if pw_ok { "bad_password" } else { "oversize" };
    let accepted = auth
        .db()
        .login_password_step_v2(
            user.as_ref(),
            verified,
            reason,
            &attempt.ctx(),
            Some(&ip_text),
            auth.now(),
        )
        .await?;
    match (accepted, user) {
        (true, Some(u)) => Ok(Outcome::PasswordOk {
            user_id: u.id,
            enrolled: u.totp_enabled,
        }),
        _ => Ok(Outcome::Failed),
    }
}

async fn post_login(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !csrf::same_origin(&headers, !auth.config().insecure_cookies) {
        return csrf_rejected();
    }
    if !is_urlencoded_form(&headers) {
        return ApiError::new(StatusCode::BAD_REQUEST, "BAD_REQUEST").into_response();
    }
    let form = csrf::parse_form(&body);
    // Token AND the cookie nonce it was issued with, then one-time consumption. Whatever the
    // outcome below, the nonce is rotated: the next form comes with a fresh pair.
    let now = auth.now();
    let token_ok = match (
        auth.presented_login_nonce(&headers),
        csrf::form_get(&form, "login_token"),
    ) {
        (Some(nonce), Some(t)) => csrf::verify_login_token(&auth.0.token_key, now, &nonce, t)
            .is_some_and(|id| auth.0.login_tokens.consume(&id, now)),
        _ => false,
    };
    let username = csrf::form_get(&form, "username").unwrap_or_default();
    if !token_ok {
        // Stale or forged form: no credential check happens, nothing is counted.
        return render_login(&auth, Some(EXPIRED_FORM), username, None);
    }
    let password = csrf::form_get(&form, "password").unwrap_or_default();
    let outcome = match check_credentials(&auth, username, password, ip).await {
        Ok(o) => o,
        Err(AuthError::Busy) => {
            return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "login failed internally");
            return internal();
        }
    };
    let Outcome::PasswordOk { user_id, enrolled } = outcome else {
        return render_login(&auth, Some(INVALID_CREDENTIALS), username, None);
    };
    // Fixation: the presented cookie (if any) is revoked and never reused; the new id is fresh.
    let old = auth.presented_id(&headers).map(|id| sha256(id.as_bytes()));
    let meta = ClientMeta::from_request(&headers, Some(ip));
    match auth
        .start_session(user_id, SessionStage::PendingMfa, &meta, old.as_ref())
        .await
    {
        Ok(cookie) => {
            let mut resp = see_other(
                if enrolled {
                    "/login/mfa"
                } else {
                    "/mfa/enroll"
                },
                Some(cookie),
            );
            // The nonce did its job; drop it (the session cookie stays the first Set-Cookie).
            resp.headers_mut()
                .append(header::SET_COOKIE, auth.clear_login_nonce_cookie());
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "session creation failed");
            internal()
        }
    }
}

async fn post_logout(
    State(auth): State<AuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    req: axum::extract::Request,
) -> Response {
    let sess = match auth.load_session(req.headers()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "session lookup failed");
            return internal();
        }
    };
    let Some(sess) = sess else {
        // Nothing to revoke: just drop whatever cookie the browser holds.
        return see_other("/login", Some(auth.clear_cookie()));
    };
    if let Err(resp) = enforce_csrf(&sess, req, !auth.config().insecure_cookies).await {
        return resp;
    }
    if let Err(e) = auth.end_session(&sess).await {
        tracing::error!(error = %e, "session revoke failed");
        return internal();
    }
    // Attributed to the signing-out account (SEC-067); a pending session (nothing completed yet)
    // is anonymous.
    let who = if sess.stage == SessionStage::Active {
        sess.audit_actor()
    } else {
        nzb_store::AuditActor::anonymous()
    };
    let ip_text = ip.to_string();
    let entry = nzb_store::AuditEntry {
        who,
        event: "logout",
        detail: None,
        ip: Some(&ip_text),
        target_id: None,
    };
    if let Err(e) = auth.db().audit_entry(&entry, auth.now()).await {
        tracing::error!(error = %e, "audit write failed");
    }
    see_other("/login", Some(auth.clear_cookie()))
}

/// The login-flow routes (`RouteClass::LoginFlow`), behind the Host allowlist. The MFA steps
/// additionally require a `pending_mfa` session and CSRF.
pub(crate) fn routes(auth: &AuthState) -> Router {
    // The invitation page (at `security.invite_path`) exists only while `security.multi_user` is
    // on (404 for everybody otherwise).
    let invite = if auth.config().multi_user {
        crate::invite::routes(auth)
    } else {
        Router::new()
    };
    let mfa = Router::new()
        .route("/login/mfa", get(mfa::get_verify).post(mfa::post_verify))
        .route("/mfa/enroll", get(mfa::get_enroll).post(mfa::post_enroll))
        .layer(from_fn_with_state(auth.clone(), pending_gate));
    Router::new()
        .route("/login", get(get_login).post(post_login))
        .route("/logout", post(post_logout))
        .with_state(auth.clone())
        .merge(invite)
        .merge(mfa.with_state(auth.clone()))
        .layer(from_fn_with_state(auth.clone(), host_layer))
}

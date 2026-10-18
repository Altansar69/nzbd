//! Bulk actions on a selection of releases (T119, `docs/UI_SPEC.md`; the 2.x port of the 1.x bulk
//! branch, fulfils T073 "bulk category edit").
//!
//! The index and search result list is a plain HTML form: for every role (T130 bulk download) every row has a
//! checkbox named `id`, and the bar below the table has one submit button per action the caller's
//! role may use. It works without JavaScript; htmx is not involved.
//!
//! Routes (behind the active-session gate, which applies the minimum role of
//! [`crate::routes::INVENTORY`] — a refused role is the uniform 404 — and enforces Origin and the
//! CSRF token on POSTs):
//!
//! * `POST /releases/bulk` (**admin**, D40) with `action=category|source`: applies at once (session +
//!   CSRF only, like the single edits; D26 c: any release).
//! * `POST /releases/bulk/delete/confirm` (**admin**): renders the confirmation page (no state
//!   change). The bar's delete button posts here with `formaction`.
//! * `POST /releases/bulk/delete` (**admin**, strict "login" rate class charged after the role
//!   check): the confirmed delete. It needs the typed word `DELETE` plus the current password and
//!   a fresh TOTP code, verified by the same shared second-factor transaction as the single delete
//!   (wrong attempts feed the lockout, one uniform failure text).
//!
//! # Rules
//! * At most [`MAX_BULK_IDS`] `id` fields; ids are strict positive decimals, de-duplicated.
//!   Violations are plain `400`s with stable codes (`NO_SELECTION`, `TOO_MANY_IDS`,
//!   `INVALID_ID`, `BAD_ACTION`, `INVALID_CATEGORY`, `BAD_REQUEST`).
//! * **Uniform visibility:** if any id is unknown or belongs to a hidden category the whole
//!   request answers the same `404 NOT_FOUND` as an unknown release, before any credential is
//!   examined and with no partial effect. A caller cannot probe which ids exist.
//! * Edits are one database transaction that re-validates the actor and writes the audit rows.
//!   Each account may send at most [`BULK_EDITS_PER_MIN`] edit requests per minute (review L1: one
//!   request rewrites up to 100 releases); more is the uniform `429 RATE_LIMITED`.
//! * Single-value fields (`action`, `category`, `source`, `confirm`, `current_password`, `code`,
//!   `sel`) are refused with `400 BAD_REQUEST` when repeated (review I1).
//! * Deletes are bound to what the admin saw (review M1): the confirmation page carries `sel`, the
//!   SHA-256 over the sorted `"<id>:<sha256 hex>\n"` lines of the releases it listed, and the final
//!   POST recomputes it from the releases it reloads, before the typed word and re-authentication;
//!   a mismatch (an id deleted and reused by a different NZB, or a release replaced) shows the
//!   confirmation page again for the current selection, consuming nothing. Each move then runs
//!   the per-release trash protocol of the single delete ([`crate::cleanup::trash_one`]), which
//!   re-checks that digest inside the move transaction, in an owned task, so the work and its
//!   summary audit row finish even when the client disconnects. Nothing is ever erased: each NZB is moved to the trash. If the acting account
//!   loses its admin role mid-run the remaining releases are left alone and the answer is the
//!   uniform 404.
//!
//! The 15 s request timeout still applies to the response: a very slow delete can answer `504`
//! while the owned task completes (see RUNBOOK); repeating the request is the uniform 404.
//!
//! Only validated numbers from the request reach the pages; titles come from the database and go
//! through `sanitize_text` and askama escaping.
//!
//! The session gate looks for `csrf_token` among the first 32 form fields only, so the forms put
//! the token first (before any `id`).

use nzb_store::prelude::*;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::post;
use nzb_core::sanitize_text;
use nzb_ingest::cleanup::CleanupEnv;
use nzb_store::{AccountActor, AuditEntry, BulkItem, MAX_BULK_IDS, StoreError};

use crate::account::reauth;
use crate::assets::Layout;
use crate::auth::{AuthState, SessionCtx, WallClock};
use crate::cleanup::{
    CleanupDeps, DELETE_SINGLETONS, DELETE_WORD, REAUTH_FAILED, TrashError, trash_one,
};
use crate::crypto;
use crate::csrf;
use crate::ctx::ClientIp;
use crate::error::ApiError;
use crate::index::human_bytes;
use crate::ratelimit::{Clock, Decision, KeyedLimiter};
use crate::release::{fail, internal, not_found, parse_id};

/// `id` fields plus the handful of other fields (csrf token, action, category, source, confirm,
/// password, code) a bulk form carries; a body with more is refused, never truncated.
pub(crate) const MAX_FORM_FIELDS: usize = MAX_BULK_IDS + 16;
/// Longest raw `source` value accepted (same as the single edit).
const MAX_SOURCE_FORM_BYTES: usize = 512;
/// Longest title shown on the pages.
const MAX_TITLE_BYTES: usize = 255;
/// Bulk edit requests (`POST /releases/bulk`) per account and minute (review L1). A constant on
/// purpose: there is no per-account limits section in the configuration to put it in.
pub const BULK_EDITS_PER_MIN: u32 = 10;
/// Upper bound of tracked accounts (the account cap is far below it).
const MAX_TRACKED_ACCOUNTS: usize = 4096;
/// Single-value fields of the edit form.
const EDIT_SINGLETONS: &[&str] = &["action", "category", "source"];
/// Shown when the selection is no longer what the confirmation page listed.
const SELECTION_CHANGED: &str =
    "The selection changed since you opened this page; review it again.";

#[derive(Clone)]
struct St {
    deps: CleanupDeps,
    auth: AuthState,
    /// Per-account budget of bulk edit requests.
    edits: Arc<KeyedLimiter<i64>>,
}

/// The injectable wall clock as the limiter's millisecond clock (tests move the wall clock).
pub(crate) struct WallMs(pub(crate) Arc<dyn WallClock>);

impl Clock for WallMs {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.now_secs().max(0))
            .unwrap_or(0)
            .saturating_mul(1000)
    }
}

/// Routes of the bulk actions; merge them into the `session_routes` of
/// [`crate::router_with_auth`]. The deps are the same as the delete flow's.
pub fn routes(auth: &AuthState, deps: CleanupDeps) -> Router {
    Router::new()
        .route("/releases/bulk", post(post_bulk))
        .route("/releases/bulk/delete/confirm", post(post_confirm))
        .route("/releases/bulk/delete", post(post_delete))
        .with_state(St {
            edits: Arc::new(KeyedLimiter::new(
                BULK_EDITS_PER_MIN,
                MAX_TRACKED_ACCOUNTS,
                Arc::new(WallMs(Arc::clone(&deps.clock))),
            )),
            deps,
            auth: auth.clone(),
        })
}

fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bulk render failed");
            internal()
        }
    }
}

fn bad(code: &'static str) -> Response {
    fail(StatusCode::BAD_REQUEST, code)
}

/// Strictly parsed, sorted and de-duplicated selection.
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
pub(crate) fn selection(form: &[(String, String)]) -> Result<Vec<i64>, Response> {
    let raw: Vec<&str> = csrf::form_all(form, "id").collect();
    if raw.is_empty() {
        return Err(bad("NO_SELECTION"));
    }
    if raw.len() > MAX_BULK_IDS {
        return Err(bad("TOO_MANY_IDS"));
    }
    let mut ids = Vec::with_capacity(raw.len());
    for r in raw {
        ids.push(parse_id(r).ok_or_else(|| bad("INVALID_ID"))?);
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// A parsed urlencoded form.
type Form = Vec<(String, String)>;

/// The parsed form and its selection.
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
fn parse(body: &[u8]) -> Result<(Form, Vec<i64>), Response> {
    let Some(form) = csrf::parse_form_strict(body, MAX_FORM_FIELDS) else {
        return Err(bad("BAD_REQUEST"));
    };
    if !csrf::singletons_ok(&form, DELETE_SINGLETONS) {
        return Err(bad("BAD_REQUEST"));
    }
    let ids = selection(&form)?;
    Ok((form, ids))
}

/// The whole selection, visible to the caller, or the uniform 404.
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
async fn load(st: &St, sess: &SessionCtx, ids: &[i64]) -> Result<Vec<BulkItem>, Response> {
    match st
        .deps
        .env
        .db
        .bulk_items(ids, &sess.hidden_categories)
        .await
    {
        Ok(v) => Ok(v),
        Err(StoreError::NotFound) => Err(not_found()),
        Err(e) => {
            tracing::error!(error = %e, "bulk lookup failed");
            Err(internal())
        }
    }
}

/// Lowercase hex SHA-256 over the sorted `"<id>:<sha256 hex>\n"` lines of `items`: what the
/// confirmation page showed, in one field (the 116-field cap is unaffected).
fn selection_digest(items: &[BulkItem]) -> String {
    let mut lines: Vec<String> = items
        .iter()
        .map(|i| format!("{}:{}\n", i.id, i.sha256.to_hex()))
        .collect();
    lines.sort_unstable();
    crypto::hex(&crypto::sha256(lines.concat().as_bytes()))
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "release" } else { "releases" }
}

// ---------------------------------------------------------------------------------------------
// Pages

#[derive(Template)]
#[template(path = "bulk_delete.html")]
struct ConfirmPage {
    layout: Layout,
    count: usize,
    items: Vec<ConfirmItem>,
    total_size: String,
    /// Digest of the listed selection, posted back and compared (review M1).
    sel: String,
    word: &'static str,
    error: Option<&'static str>,
}

struct ConfirmItem {
    id: i64,
    title: String,
    category: String,
}

#[derive(Template)]
#[template(path = "bulk_result.html")]
struct ResultPage {
    layout: Layout,
    heading: &'static str,
    summary: String,
    items: Vec<ResultItem>,
    /// Link to the Cleanup panel (admin pages only).
    cleanup_link: bool,
}

struct ResultItem {
    title: String,
    status: String,
}

fn confirm_page(
    st: &St,
    sess: &SessionCtx,
    items: &[BulkItem],
    error: Option<&'static str>,
) -> ConfirmPage {
    let tax = st.deps.taxonomy.as_ref();
    let total: u64 = items.iter().fold(0, |a, i| a.saturating_add(i.total_bytes));
    ConfirmPage {
        layout: Layout::for_session("Delete releases", sess),
        count: items.len(),
        items: items
            .iter()
            .map(|i| ConfirmItem {
                id: i.id,
                title: sanitize_text(&i.title, MAX_TITLE_BYTES),
                category: u16::try_from(i.category_id)
                    .ok()
                    .and_then(|c| tax.get(c))
                    .map_or_else(|| "Unknown".to_owned(), |c| c.name.clone()),
            })
            .collect(),
        total_size: human_bytes(total),
        sel: selection_digest(items),
        word: DELETE_WORD,
        error,
    }
}

// ---------------------------------------------------------------------------------------------
// POST /releases/bulk (admin only, D40)

async fn post_bulk(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    // Role, CSRF and Origin were verified by the session gate. Every edit request of an account
    // spends its bulk budget, whatever its outcome.
    if let Decision::Deny { retry_after_secs } = st.edits.check(sess.user_id) {
        return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
            .retry_after(retry_after_secs)
            .into_response();
    }
    let Some(form) = csrf::parse_form_strict(&body, MAX_FORM_FIELDS) else {
        return bad("BAD_REQUEST");
    };
    if !csrf::singletons_ok(&form, EDIT_SINGLETONS) {
        return bad("BAD_REQUEST");
    }
    let action = csrf::form_get(&form, "action");
    if !matches!(action, Some("category" | "source")) {
        return bad("BAD_ACTION");
    }
    let ids = match selection(&form) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let hidden = &sess.hidden_categories;
    let ip_text = ip.to_string();
    let now = st.deps.clock.now_secs();
    let db = &st.deps.env.db;
    let actor = sess.actor();
    if action == Some("category") {
        // Input checks first (a typo or a hidden target is 400 whatever the ids are).
        let Some(cat) = csrf::form_get(&form, "category")
            .and_then(|v| st.deps.taxonomy.resolve(v))
            .filter(|c| !sess.hides_category(u32::from(*c)))
        else {
            return bad("INVALID_CATEGORY");
        };
        return match db
            .bulk_set_category_as(&actor, &ids, u32::from(cat), hidden, Some(&ip_text), now)
            .await
        {
            Ok(n) => {
                sess.library_gen.note_change(now);
                let name = st
                    .deps
                    .taxonomy
                    .get(cat)
                    .map_or_else(|| "Unknown".to_owned(), |c| c.name.clone());
                render(&ResultPage {
                    layout: Layout::for_session("Category updated", &sess),
                    heading: "Category updated",
                    summary: format!("Category set to {name} for {n} {}.", plural(n)),
                    items: Vec::new(),
                    cleanup_link: false,
                })
            }
            // A role lost between the gate and the write is the uniform refusal.
            Err(StoreError::NotFound | StoreError::Account(_)) => not_found(),
            Err(StoreError::UnknownCategory) => bad("INVALID_CATEGORY"),
            Err(e) => {
                tracing::error!(error = %e, "bulk category edit failed");
                internal()
            }
        };
    }
    // The field must be present (a blank value clears the label); anything over the cap is
    // refused instead of silently truncated, like the single edit.
    let Some(raw) = csrf::form_get(&form, "source").filter(|v| v.len() <= MAX_SOURCE_FORM_BYTES)
    else {
        return bad("BAD_REQUEST");
    };
    match db
        .bulk_set_source_label_as(&actor, &ids, raw, hidden, Some(&ip_text), now)
        .await
    {
        Ok((n, label)) => render(&ResultPage {
            layout: Layout::for_session("Source updated", &sess),
            heading: "Source updated",
            summary: match label {
                Some(l) => format!(
                    "Source label set to \u{201c}{}\u{201d} for {n} {}.",
                    sanitize_text(&l, MAX_TITLE_BYTES),
                    plural(n)
                ),
                None => format!("Source label cleared for {n} {}.", plural(n)),
            },
            items: Vec::new(),
            cleanup_link: false,
        }),
        Err(StoreError::NotFound | StoreError::Account(_)) => not_found(),
        Err(e) => {
            tracing::error!(error = %e, "bulk source edit failed");
            internal()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// POST /releases/bulk/delete/confirm (admin)

async fn post_confirm(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    let ids = match parse(&body) {
        Ok((_, ids)) => ids,
        Err(r) => return r,
    };
    match load(&st, &sess, &ids).await {
        Ok(items) => render(&confirm_page(&st, &sess, &items, None)),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------------------------
// POST /releases/bulk/delete (admin, re-authenticated)

async fn post_delete(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    body: Bytes,
) -> Response {
    let (form, ids) = match parse(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Existence and visibility first, for the whole selection: a hidden or unknown id answers
    // the uniform 404 without touching the re-authentication counters.
    let items = match load(&st, &sess, &ids).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Bound to what the admin saw (M1): the selection must still be exactly the listed releases
    // (same ids, same digests). Checked before the typed word and re-authentication, so a
    // mismatch consumes nothing; the page is shown again for the current selection.
    if csrf::form_get(&form, "sel") != Some(selection_digest(&items).as_str()) {
        return render(&confirm_page(&st, &sess, &items, Some(SELECTION_CHANGED)));
    }
    // Input-only check before re-authentication: it must not burn the user's TOTP step.
    if csrf::form_get(&form, "confirm").map(str::trim) != Some(DELETE_WORD) {
        return render(&confirm_page(
            &st,
            &sess,
            &items,
            Some("Type the word DELETE exactly to confirm."),
        ));
    }
    let ip_text = ip.to_string();
    match reauth(&st.auth, &sess, &ip_text, "bulk_delete", &form).await {
        Ok(true) => {}
        Ok(false) => return render(&confirm_page(&st, &sess, &items, Some(REAUTH_FAILED))),
        Err(r) => return r,
    }
    let job = tokio::spawn(run_deletes(
        st.deps.env.clone(),
        st.deps.clock.clone(),
        items,
        sess.actor(),
        ip_text,
        Arc::clone(&sess.library_gen),
    ));
    match job.await {
        // The actor lost its authority mid-run: the uniform refusal, not a results page.
        Ok(run) if run.aborted => not_found(),
        Ok(run) => render(&ResultPage {
            layout: Layout::for_session("Releases deleted", &sess),
            heading: "Bulk delete finished",
            summary: format!(
                "Deleted {}, kept {}, failed {}.",
                run.deleted, run.kept, run.failed
            ),
            items: run.lines,
            cleanup_link: true,
        }),
        Err(e) => {
            // The task panicked or was cancelled: some releases may already be in the trash. The
            // stable code has its own fixed text on the error page (review L3 of the 1.x branch).
            tracing::error!(error = %e, "bulk delete task did not finish");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "BULK_RESULT_UNKNOWN").into_response()
        }
    }
}

/// Outcome of the per-release moves.
struct DeleteRun {
    lines: Vec<ResultItem>,
    deleted: usize,
    kept: usize,
    failed: usize,
    /// The actor stopped being a live, enabled admin; the remaining releases were left alone.
    aborted: bool,
}

/// Moves each release to the trash in turn (the T081 protocol, bound to the loaded digest), then
/// writes the `bulk_delete` summary audit row. Runs in an owned task so it completes even when the
/// client disconnects.
async fn run_deletes(
    env: CleanupEnv,
    clock: Arc<dyn WallClock>,
    items: Vec<BulkItem>,
    actor: AccountActor,
    ip_text: String,
    library_gen: Arc<crate::stats::LibraryGeneration>,
) -> DeleteRun {
    let mut run = DeleteRun {
        lines: Vec::with_capacity(items.len()),
        deleted: 0,
        kept: 0,
        failed: 0,
        aborted: false,
    };
    for item in &items {
        let r = trash_one(
            &env,
            &actor,
            item.id,
            item.sha256,
            clock.now_secs(),
            Some(&ip_text),
        )
        .await;
        let status = match r {
            Ok(t) => {
                run.deleted = run.deleted.saturating_add(1);
                // Inside the task, so a client that went away does not skip it (Statistics cache, review 47 L2).
                library_gen.note_change(clock.now_secs());
                if t.staged {
                    format!(
                        "Moved to the trash (trash id {}); restore with nzbd trash restore {}.",
                        t.row.id, t.row.id
                    )
                } else {
                    "Removed from the index; no NZB file was found in the store, so there is \
                     nothing to restore."
                        .to_owned()
                }
            }
            Err(TrashError::Gone) => {
                run.kept = run.kept.saturating_add(1);
                "Kept: it was already gone, or its id now belongs to a different NZB.".to_owned()
            }
            Err(TrashError::Failed) => {
                run.failed = run.failed.saturating_add(1);
                "Failed: not deleted, still in the index. See the server log.".to_owned()
            }
            Err(TrashError::Refused) => {
                run.aborted = true;
                break;
            }
        };
        run.lines.push(ResultItem {
            title: sanitize_text(&item.title, MAX_TITLE_BYTES),
            status,
        });
    }
    let mut detail = format!(
        "count={} deleted={} kept={} failed={}",
        items.len(),
        run.deleted,
        run.kept,
        run.failed
    );
    if run.aborted {
        detail.push_str(" aborted=1");
    }
    let entry = AuditEntry {
        who: nzb_store::AuditActor::account(actor.user_id, actor.role, &actor.username),
        event: "bulk_delete",
        detail: Some(&detail),
        ip: Some(&ip_text),
        target_id: None,
    };
    if let Err(e) = env.db.audit_entry(&entry, clock.now_secs()).await {
        tracing::error!(error = %e, "audit write failed");
    }
    run
}

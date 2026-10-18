//! `GET /admin` (`docs/UI_SPEC.md`): health, counters, recent ingest log, the `failed/` listing,
//! the audit tail and a non-secret configuration summary. Read-only: there is no action on this
//! page, so no CSRF form and no state change (retry of failed files stays a CLI operation).
//!
//! Rendering is whitelist-based so that a secret cannot appear by accident:
//!
//! * only named columns are read (no hashes, no key material, no session ids);
//! * every stored text goes through `sanitize_text` and askama auto-escaping;
//! * audit and ingest `detail` strings are shown only when they parse into the fixed grammar of
//!   [`safe_detail`] (known `key=value` tokens and short lowercase words), otherwise `(hidden)`;
//! * configuration comes in as pre-built `(label, value)` pairs from `nzbd`, which builds them
//!   from typed, non-secret fields (the TOTP key is only ever "configured").
//!
//! Cost control: the log is paged by `LIMIT/OFFSET` on the `ingest_ts` index (page and offset
//! capped, no total count), the audit tail is a fixed `LIMIT`, and the three potentially
//! expensive items (table totals, newest successful ingest, `failed/` directory walk) are
//! computed at most once per [`CACHE_SECS`] behind a single async mutex.

use nzb_store::prelude::*;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use nzb_core::sanitize_text;
use nzb_store::{AuditRow, IngestLogRow, LogOutcome, ReleaseTotals, Store};
use tokio::sync::Mutex;

use crate::account::fmt_utc;
use crate::assets::Layout;
use crate::auth::{SessionCtx, WallClock};
use crate::csrf;
use crate::error::ApiError;
use crate::index::human_bytes;

/// Ingest log rows per page.
pub const LOG_PAGE_SIZE: u32 = 25;
/// Highest page accepted (bounds the SQL `OFFSET` to 25 000 rows).
pub const MAX_LOG_PAGE: u32 = 1000;
/// Audit events shown.
pub const AUDIT_ROWS: u32 = 25;
/// `failed/` entries shown (newest first).
pub const FAILED_ROWS: usize = 50;
/// Seconds the expensive aggregates are reused.
pub const CACHE_SECS: i64 = 15;

/// Live state from the ingest side, read without I/O.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveStatus {
    /// Unix seconds of the last completed scan cycle.
    pub heartbeat_last: Option<i64>,
    /// Scan interval in seconds (staleness threshold is three intervals).
    pub scan_interval_secs: u64,
    /// Releases indexed since start.
    pub ingested_ok: u64,
    /// Duplicates seen since start.
    pub duplicates: u64,
    /// Failed submissions since start.
    pub failed: u64,
    /// Unix seconds of the last success or duplicate since start.
    pub last_success_at: Option<i64>,
    /// Configured ingest workers.
    pub workers: u32,
}

/// One quarantined file, already reduced to displayable fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedItem {
    /// Generated file name inside `failed/` (never a path).
    pub name: String,
    /// Stable error code from the sidecar, if one exists.
    pub code: Option<String>,
    /// Unix seconds of the failure, if known.
    pub at: Option<i64>,
    /// Size in bytes.
    pub size: u64,
}

/// Result of listing `failed/`: total entries and the newest [`FAILED_ROWS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FailedListing {
    /// Number of quarantined files.
    pub total: usize,
    /// Newest first, at most [`FAILED_ROWS`].
    pub items: Vec<FailedItem>,
}

/// Provider of [`LiveStatus`] (cheap, non-blocking).
pub type StatusFn = Arc<dyn Fn() -> LiveStatus + Send + Sync>;
/// Provider of the `failed/` listing (blocking file I/O; run on a blocking thread).
/// `Err` means the directory could not be read.
pub type FailedFn = Arc<dyn Fn() -> Result<FailedListing, ()> + Send + Sync>;

/// Everything the admin page needs from the rest of the process.
#[derive(Clone)]
pub struct AdminDeps {
    /// Database handle.
    pub db: Store,
    /// Wall clock (deterministic in tests).
    pub clock: Arc<dyn WallClock>,
    /// Live ingest state.
    pub status: StatusFn,
    /// `failed/` lister; `None` shows "not configured".
    pub failed: Option<FailedFn>,
    /// Non-secret configuration rows (`label`, `value`), built by the caller.
    pub config: Arc<Vec<(&'static str, String)>>,
}

#[derive(Clone)]
struct Snapshot {
    at: i64,
    totals: Option<ReleaseTotals>,
    last_ok: Option<i64>,
    failed: Option<FailedListing>,
}

#[derive(Clone)]
struct AdminState {
    deps: AdminDeps,
    cache: Arc<Mutex<Option<Snapshot>>>,
}

/// Routes of the admin page; merge them into the `session_routes` of
/// [`crate::router_with_auth`].
pub fn routes(deps: AdminDeps) -> Router {
    // The Activity page (T138) rides along: same admin gate, same database.
    let activity = crate::activity::routes(deps.db.clone());
    Router::new()
        .route("/admin", get(admin))
        .with_state(AdminState {
            deps,
            cache: Arc::new(Mutex::new(None)),
        })
        .merge(activity)
}

/// Strict query: only `page` is known (1..=[`MAX_LOG_PAGE`], digits only, blank = 1). Unknown
/// parameters are ignored; the first occurrence wins.
fn parse_page(raw: Option<&str>) -> Result<u32, ()> {
    let form = csrf::parse_form(raw.unwrap_or_default().as_bytes());
    let Some(v) = csrf::form_get(&form, "page").filter(|v| !v.is_empty()) else {
        return Ok(1);
    };
    if v.len() > 4 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let n: u32 = v.parse().map_err(|_| ())?;
    if (1..=MAX_LOG_PAGE).contains(&n) {
        Ok(n)
    } else {
        Err(())
    }
}

/// Keys allowed in a displayed `detail`. Shared by the ingest log and `audit_detail` (review 41 I4): a key
/// added for one (for example `rule`, T126) also renders on the other; values keep the same charset.
const DETAIL_KEYS: &[&str] = &[
    "id",
    "prefix",
    "sessions_revoked",
    "api_keys_revoked",
    "count",
    "purpose",
    "reason",
    "release",
    "category",
    "hint",
    "scene",
    "sha8",
    "bucket",
    "bytes",
    "skipped",
    "trash",
    // v2 (T101b): fixed keys of the account-lifecycle rows; values are ids, role names, `-` and
    // default display handles, never free text.
    "invite",
    "role",
    "old",
    "new",
    "needs",
    "issued_by",
    "action",
    "codes_revoked",
    "keys_revoked",
    "owner",
    "failures",
    "class",
    // Bulk delete summary and an aborted purge or bulk delete (T119).
    "deleted",
    "kept",
    "failed",
    "aborted",
    // Route-class token of an `authz_denied` row (T119 review I3).
    "route",
    // Number of the watch-folder rule that matched an ingest row (T126).
    "rule",
];

/// Keys whose value may also contain `-` (`user-3`, `-` for "none").
const DASH_KEYS: &[&str] = &["old", "new", "issued_by"];

/// Returns `detail` only if every space-separated token is either a known `key=value` (value
/// `[a-z0-9_]{1,24}`, or `[A-Za-z0-9_-]{1,12}` for `prefix`) or a bare lowercase word
/// (`[a-z_]{1,24}`), at most 8 tokens. Anything else, in particular long or mixed-case
/// high-entropy strings, is withheld.
fn safe_detail(detail: &str) -> Option<String> {
    let mut out = Vec::new();
    for tok in detail.split(' ') {
        if out.len() >= 8 {
            return None;
        }
        let ok = if let Some((k, v)) = tok.split_once('=') {
            let (max, ext) = if k == "prefix" {
                (12, true)
            } else {
                (24, DASH_KEYS.contains(&k))
            };
            DETAIL_KEYS.contains(&k)
                && !v.is_empty()
                && v.len() <= max
                && v.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'_'
                        || (ext && (b.is_ascii_uppercase() || b == b'-'))
                })
        } else {
            !tok.is_empty()
                && tok.len() <= 24
                && tok.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        };
        if !ok {
            return None;
        }
        out.push(tok);
    }
    Some(out.join(" "))
}

fn detail_text(d: Option<&str>) -> String {
    match d {
        None => String::new(),
        Some(d) => safe_detail(d).unwrap_or_else(|| "(hidden)".to_owned()),
    }
}

struct LogView {
    time: String,
    source: &'static str,
    outcome: &'static str,
    name: String,
    code: String,
    detail: String,
    release_id: Option<i64>,
}

fn log_view(r: &IngestLogRow) -> LogView {
    let outcome = match r.outcome {
        LogOutcome::Ok => "OK",
        LogOutcome::Duplicate => "Duplicate",
        LogOutcome::Failed => "Failed",
    };
    LogView {
        time: fmt_utc(r.ts),
        source: match r.source.as_str() {
            "watch" => "Watch folder",
            "upload_ui" => "Web upload",
            "upload_api" => "API upload",
            _ => "Unknown",
        },
        outcome,
        // Display name only: sanitized again (rows from older versions), escaped by askama.
        name: r
            .source_name
            .as_deref()
            .map(|n| sanitize_text(n, 255))
            .unwrap_or_default(),
        code: r
            .error_code
            .as_deref()
            .map(|c| sanitize_text(c, 64))
            .unwrap_or_default(),
        detail: detail_text(r.detail.as_deref()),
        release_id: r.release_id,
    }
}

struct AuditView {
    time: String,
    actor: String,
    event: String,
    target: String,
    detail: String,
    ip: String,
}

/// The actor cell: the recorded name with its KIND (and role), so a login name equal to a
/// reserved actor name (`cli`, `system`) cannot pass as that actor (review R3).
pub(crate) fn actor_text(r: &AuditRow) -> String {
    let name = r
        .actor
        .as_deref()
        .map(|a| sanitize_text(a, 64))
        .unwrap_or_default();
    let kind = match r.actor_kind.as_deref() {
        Some("user") => "user",
        Some("cli") => "cli",
        Some("system") => "system",
        Some("api_key") => "api key",
        Some("anonymous") => "anonymous",
        _ => return name,
    };
    let role = match (kind, r.actor_role.as_deref()) {
        ("user" | "api key", Some(role @ ("admin" | "uploader" | "viewer"))) => format!(", {role}"),
        _ => String::new(),
    };
    if name.is_empty() {
        format!("({kind}{role})")
    } else {
        format!("{name} ({kind}{role})")
    }
}

/// The detail cell. Fixed-key rows go through [`safe_detail`]; the two rows with user-entered
/// text (a release's source label and an account's display name) are parsed and shown only
/// after `sanitize_text` (askama escapes on output). Anything else unknown stays `(hidden)`.
pub(crate) fn audit_detail(r: &AuditRow) -> String {
    let Some(d) = r.detail.as_deref() else {
        return String::new();
    };
    match r.event.as_str() {
        "source_label_edit" => {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(d) else {
                return "(hidden)".to_owned();
            };
            let text = |k: &str| {
                v.get(k)
                    .and_then(serde_json::Value::as_str)
                    .map_or_else(|| "-".to_owned(), |t| sanitize_text(t, 64))
            };
            let rel = v.get("release").and_then(serde_json::Value::as_i64);
            match rel {
                Some(id) => format!(
                    "release={id} old=\"{}\" new=\"{}\"",
                    text("old"),
                    text("new")
                ),
                None => "(hidden)".to_owned(),
            }
        }
        "user_display_name" => match d
            .strip_prefix("old=")
            .and_then(|rest| rest.split_once(" new="))
        {
            Some((old, new)) => format!(
                "old=\"{}\" new=\"{}\"",
                sanitize_text(old, 40),
                sanitize_text(new, 40)
            ),
            None => "(hidden)".to_owned(),
        },
        // T120: the changed preference key names only (never values); a fixed set.
        "pref_change" => match d.strip_prefix("keys=") {
            Some(k) if !k.is_empty() && k.split(',').all(|x| matches!(x, "hide_xxx" | "theme")) => {
                format!("keys={k}")
            }
            _ => "(hidden)".to_owned(),
        },
        "nzb_upload" | "nzb_upload_dup" | "nzb_upload_reject" | "release_delete" => {
            upload_detail(d).unwrap_or_else(|| "(hidden)".to_owned())
        }
        _ => detail_text(Some(d)),
    }
}

/// T138: renders the detail of an upload or delete row. Fixed `key=value` tokens are validated one
/// by one; the free text that may follow (`label=` of an upload, `title=` of a delete) is the last
/// field, comes from an NZB, and is shown sanitized, cut and quoted. Anything else hides the row.
fn upload_detail(d: &str) -> Option<String> {
    let (fixed, free) = match d.find(" label=").or_else(|| d.find(" title=")) {
        Some(i) => (d.get(..i)?, d.get(i + 1..)),
        None => (d, None),
    };
    let mut out: Vec<String> = Vec::new();
    for tok in fixed.split(' ') {
        let (k, v) = tok.split_once('=')?;
        let digits =
            |max: usize| !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_digit());
        let ok = match k {
            "release" | "key" => digits(15),
            "size" => digits(18),
            "sha8" | "sha12" => {
                (1..=12).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_hexdigit())
            }
            "via" => matches!(v, "ui" | "api"),
            "reason" => {
                !v.is_empty()
                    && v.len() <= 32
                    && v.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            }
            "added_by" => {
                v == "none"
                    || v.strip_prefix("user:").is_some_and(|n| {
                        !n.is_empty() && n.len() <= 15 && n.bytes().all(|b| b.is_ascii_digit())
                    })
            }
            _ => false,
        };
        if !ok || out.len() >= 8 {
            return None;
        }
        out.push(tok.to_owned());
    }
    if let Some(f) = free {
        let (k, v) = f.split_once('=')?;
        out.push(format!("{k}=\"{}\"", sanitize_text(v, 80)));
    }
    Some(out.join(" "))
}

/// Targets are shown by display handle, never by login name (D26 d). A failed lookup only loses
/// the handles.
fn target_handles(
    accounts: Result<Vec<nzb_store::AccountRow>, nzb_store::StoreError>,
) -> std::collections::HashMap<i64, String> {
    accounts
        .unwrap_or_default()
        .iter()
        .map(|a| (a.id, a.handle()))
        .collect()
}

fn audit_view(r: &AuditRow, handles: &std::collections::HashMap<i64, String>) -> AuditView {
    AuditView {
        time: fmt_utc(r.ts),
        actor: actor_text(r),
        event: sanitize_text(&r.event, 64),
        target: r.target_id.map_or_else(String::new, |t| {
            handles
                .get(&t)
                .cloned()
                .unwrap_or_else(|| format!("account #{t}"))
        }),
        detail: audit_detail(r),
        ip: r
            .ip
            .as_deref()
            .map(|i| sanitize_text(i, 64))
            .unwrap_or_default(),
    }
}

struct FailedView {
    name: String,
    code: String,
    time: String,
    size: String,
}

fn failed_view(f: &FailedItem) -> FailedView {
    FailedView {
        name: sanitize_text(&f.name, 255),
        code: f
            .code
            .as_deref()
            .map_or_else(|| "-".to_owned(), |c| sanitize_text(c, 64)),
        time: f.at.map_or_else(|| "-".to_owned(), fmt_utc),
        size: human_bytes(f.size),
    }
}

struct ConfigView {
    label: &'static str,
    value: String,
}

struct HealthView {
    db_ok: bool,
    scan_ok: bool,
    scan_age: String,
    last_ingest: String,
    workers: u32,
}

struct CounterView {
    releases: String,
    files: String,
    bytes: String,
    ok: u64,
    duplicates: u64,
    failed: u64,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminPage {
    layout: Layout,
    health: HealthView,
    counters: CounterView,
    totals_known: bool,
    log: Vec<LogView>,
    page: u32,
    prev_page: Option<u32>,
    next_page: Option<u32>,
    audit: Vec<AuditView>,
    failed_known: bool,
    failed_total: usize,
    failed: Vec<FailedView>,
    config: Vec<ConfigView>,
}

fn age_text(secs: i64) -> String {
    let s = secs.max(0);
    if s < 120 {
        format!("{s} s ago")
    } else if s < 7200 {
        format!("{} min ago", s / 60)
    } else if s < 172_800 {
        format!("{} h ago", s / 3600)
    } else {
        format!("{} d ago", s / 86_400)
    }
}

impl AdminState {
    /// Cached expensive aggregates. A failing part degrades to "unavailable", never an error.
    ///
    /// The refresh runs in an owned task that holds the cache lock until it is done, so a
    /// request that times out or disconnects cannot leave a second `failed/` walk running next
    /// to a new one (single-flight); the finished result still lands in the cache.
    async fn snapshot(&self, now: i64) -> Snapshot {
        let this = self.clone();
        let job = tokio::spawn(async move {
            let mut guard = this.cache.lock().await;
            if let Some(s) = guard.as_ref()
                && (0..CACHE_SECS).contains(&now.saturating_sub(s.at))
            {
                return s.clone();
            }
            let db = &this.deps.db;
            let totals = db.release_totals().await.ok();
            let last_ok = db.last_ok_ingest_ts().await.ok().flatten();
            let failed = match this.deps.failed.clone() {
                None => None,
                Some(f) => tokio::task::spawn_blocking(move || f())
                    .await
                    .ok()
                    .and_then(Result::ok),
            };
            let snap = Snapshot {
                at: now,
                totals,
                last_ok,
                failed,
            };
            *guard = Some(snap.clone());
            snap
        });
        job.await.unwrap_or(Snapshot {
            at: now,
            totals: None,
            last_ok: None,
            failed: None,
        })
    }
}

fn internal() -> Response {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
}

async fn admin(
    State(st): State<AdminState>,
    Extension(sess): Extension<SessionCtx>,
    uri: Uri,
) -> Response {
    let Ok(page) = parse_page(uri.query()) else {
        return ApiError::new(StatusCode::BAD_REQUEST, "BAD_QUERY").into_response();
    };
    let db = &st.deps.db;
    let now = st.deps.clock.now_secs();
    let offset = (page - 1).saturating_mul(LOG_PAGE_SIZE);
    // One extra row tells whether a next page exists without a COUNT over the log.
    let (log, audit, db_ok, accounts) = tokio::join!(
        db.ingest_log_page(LOG_PAGE_SIZE + 1, offset),
        db.recent_audit(AUDIT_ROWS),
        db.ping(),
        db.list_accounts(true),
    );
    let handles = target_handles(accounts);
    let (Ok(mut log), Ok(audit)) = (log, audit) else {
        tracing::error!("admin page queries failed");
        return internal();
    };
    let has_next = log.len() > LOG_PAGE_SIZE as usize;
    log.truncate(LOG_PAGE_SIZE as usize);
    // Operator view: rows stay unfiltered, but a link to a release hidden from the UI
    // (`ui.show_xxx = false`) would only answer 404, so it is rendered as plain text.
    let ids: Vec<i64> = log.iter().filter_map(|r| r.release_id).collect();
    let hidden_rel = db
        .release_ids_in_categories(&ids, &sess.hidden_ids())
        .await
        .unwrap_or_default();
    let snap = st.snapshot(now).await;
    let live = (st.deps.status)();
    let scan_ok = live.heartbeat_last.is_some_and(|t| {
        let limit = i64::try_from(live.scan_interval_secs)
            .unwrap_or(i64::MAX)
            .saturating_mul(3);
        now.saturating_sub(t) <= limit
    });
    let last_ingest = live
        .last_success_at
        .or(snap.last_ok)
        .map_or_else(|| "never".to_owned(), fmt_utc);
    let totals = snap.totals.unwrap_or_default();
    let (failed_known, failed_total, failed) = snap.failed.as_ref().map_or_else(
        || (false, 0, Vec::new()),
        |f| (true, f.total, f.items.iter().map(failed_view).collect()),
    );
    let view = AdminPage {
        layout: Layout::for_session("Admin", &sess),
        health: HealthView {
            db_ok: db_ok.is_ok(),
            scan_ok,
            scan_age: live
                .heartbeat_last
                .map_or_else(|| "never".to_owned(), |t| age_text(now.saturating_sub(t))),
            last_ingest,
            workers: live.workers,
        },
        counters: CounterView {
            releases: totals.releases.to_string(),
            files: totals.files.to_string(),
            bytes: human_bytes(totals.bytes),
            ok: live.ingested_ok,
            duplicates: live.duplicates,
            failed: live.failed,
        },
        totals_known: snap.totals.is_some(),
        log: log
            .iter()
            .map(|r| {
                let mut v = log_view(r);
                if v.release_id.is_some_and(|id| hidden_rel.contains(&id)) {
                    v.release_id = None;
                }
                v
            })
            .collect(),
        page,
        prev_page: (page > 1).then(|| page - 1),
        next_page: (has_next && page < MAX_LOG_PAGE).then(|| page + 1),
        audit: audit.iter().map(|r| audit_view(r, &handles)).collect(),
        failed_known,
        failed_total,
        failed,
        config: st
            .deps
            .config
            .iter()
            .map(|(label, value)| ConfigView {
                label,
                value: sanitize_text(value, 256),
            })
            .collect(),
    };
    match view.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "admin render failed");
            internal()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_detail_shows_fixed_keys_and_escapes_free_text() {
        assert_eq!(
            upload_detail("release=7 sha12=0123456789ab size=1024 via=api key=3 label=my group")
                .as_deref(),
            Some("release=7 sha12=0123456789ab size=1024 via=api key=3 label=\"my group\"")
        );
        assert_eq!(
            upload_detail("release=7 sha8=01234567 added_by=user:2 title=A b").as_deref(),
            // Markup characters stay as text here: askama escapes them when the page renders.
            Some("release=7 sha8=01234567 added_by=user:2 title=\"A b\"")
        );
        assert_eq!(
            upload_detail("reason=FILE_TOO_LARGE size=9 via=ui").as_deref(),
            Some("reason=FILE_TOO_LARGE size=9 via=ui")
        );
        for bad in [
            "evil=1",
            "release=x",
            "via=ftp",
            "added_by=root",
            "sha8=zz",
            "release",
        ] {
            assert!(upload_detail(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn page_param_is_strict() {
        assert_eq!(parse_page(None), Ok(1));
        assert_eq!(parse_page(Some("page=")), Ok(1));
        assert_eq!(parse_page(Some("page=7&x=1")), Ok(7));
        assert_eq!(parse_page(Some("page=1000")), Ok(1000));
        for bad in [
            "page=0",
            "page=1001",
            "page=-1",
            "page=1e2",
            "page=%2B1",
            "page=99999",
            "page=a",
        ] {
            assert_eq!(parse_page(Some(bad)), Err(()), "{bad}");
        }
    }

    #[test]
    fn detail_whitelist() {
        assert_eq!(
            safe_detail("id=3 prefix=Ab-9"),
            Some("id=3 prefix=Ab-9".into())
        );
        assert_eq!(
            safe_detail("hint_disagreement hint=8010 scene=5040"),
            Some("hint_disagreement hint=8010 scene=5040".into())
        );
        assert_eq!(
            safe_detail("rule=3 hint_disagreement hint=8010 scene=5040"),
            Some("rule=3 hint_disagreement hint=8010 scene=5040".into())
        );
        assert!(safe_detail("purpose=enroll reason=bad_code").is_some());
        for bad in [
            "nzbd_AbCdEf0123456789AbCdEf0123456789",
            "password=hunter2",
            "id=<script>",
            "token=abc",
            "Locked",
            "",
            "a b c d e f g h i",
            "prefix=0123456789abc",
        ] {
            assert_eq!(safe_detail(bad), None, "{bad}");
        }
    }
}

//! `GET /admin/health` and `POST /admin/health/deep` (`docs/UI_SPEC.md` Health page).
//!
//! The page renders a list of [`Check`]s produced elsewhere (`nzbd/src/health.rs`, which also
//! feeds the `nzbd health` CLI) through the [`CollectFn`] closures in [`HealthDeps`]. Keeping
//! the engine out of this crate keeps the web layer decoupled from the config, the filesystem
//! layout and the ingest internals (same pattern as [`crate::admin`]).
//!
//! Safety properties, all covered by tests:
//!
//! * read-only: no check modifies data, and the page itself has no state-changing action other
//!   than the deep-check button;
//! * nothing secret is rendered: a [`Check`] carries only a fixed name, a status, a short
//!   value and a hint, every string goes through `sanitize_text` and askama auto-escaping, and
//!   CSS classes come from a fixed `match`, never from data;
//! * cost control: the cheap checks run at most once per [`CACHE_SECS`] behind a single-flight
//!   lock (an owned task, so a cancelled request cannot start a second collection); the
//!   deep check is a separate `POST` (session + CSRF + Origin through the shared gate, login
//!   rate class), runs in an owned task holding a one-permit semaphore under a deadline, and
//!   its result is shown for [`DEEP_TTL_SECS`].

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use askama::Template;
use axum::Router;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use nzb_core::sanitize_text;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use crate::account::fmt_utc;
use crate::assets::Layout;
use crate::auth::{SessionCtx, WallClock};
use crate::csrf;
use crate::error::ApiError;
use crate::session::see_other;

/// Seconds the cheap checks are reused.
pub const CACHE_SECS: i64 = 15;
/// Seconds a finished deep check stays on the page.
pub const DEEP_TTL_SECS: i64 = 600;
/// Minimum seconds between two deep runs (the rate limiter is per minute; this also guards
/// repeated clicks from different sessions).
pub const DEEP_COOLDOWN_SECS: i64 = 30;
/// Hard deadline of one deep run.
pub const DEEP_DEADLINE: Duration = Duration::from_secs(60);
/// Deadline of one cheap collection.
pub const CHEAP_DEADLINE: Duration = Duration::from_secs(10);

/// Outcome of one check. Always rendered as text; colour is only a second cue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Healthy.
    Ok,
    /// Works but needs attention.
    Warn,
    /// Broken or unsafe.
    Fail,
    /// Informational value, never counted in the banner.
    Info,
}

impl Status {
    /// Badge text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Info => "INFO",
        }
    }

    /// CSS class from the fixed design system.
    const fn class(self) -> &'static str {
        match self {
            Self::Ok => "st-ok",
            Self::Warn => "st-warn",
            Self::Fail => "st-bad",
            Self::Info => "",
        }
    }
}

/// Section of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// Process facts.
    App,
    /// SQLite.
    Database,
    /// Watch folder, workers, counters.
    Ingest,
    /// Directories and the blob store.
    Storage,
    /// Configuration and account hygiene.
    Security,
    /// Self-check of the HTTP side.
    Http,
    /// Results of the on-demand deep check.
    Deep,
}

impl Group {
    /// Section title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::App => "Application",
            Self::Database => "Database",
            Self::Ingest => "Ingest",
            Self::Storage => "Storage",
            Self::Security => "Security and configuration",
            Self::Http => "HTTP",
            Self::Deep => "Deep check",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Database => "db",
            Self::Ingest => "ingest",
            Self::Storage => "storage",
            Self::Security => "security",
            Self::Http => "http",
            Self::Deep => "deep",
        }
    }

    /// Groups in display order (without [`Group::Deep`], which has its own section).
    pub const ALL: [Self; 6] = [
        Self::App,
        Self::Database,
        Self::Ingest,
        Self::Storage,
        Self::Security,
        Self::Http,
    ];
}

/// One row of the page. `value` and `hint` are display text only (no markup, no paths, no
/// secrets): the producer builds them from typed facts, the renderer sanitizes and escapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Section.
    pub group: Group,
    /// Fixed human name.
    pub name: &'static str,
    /// Result.
    pub status: Status,
    /// Short value or detail.
    pub value: String,
    /// One-line "what to do"; empty when nothing is needed.
    pub hint: String,
}

impl Check {
    /// Builds a check.
    #[must_use]
    pub fn new(
        group: Group,
        name: &'static str,
        status: Status,
        value: impl Into<String>,
        hint: &str,
    ) -> Self {
        Self {
            group,
            name,
            status,
            value: value.into(),
            hint: hint.to_owned(),
        }
    }
}

/// Counts for the banner and the CLI exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    /// Number of `WARN` rows.
    pub warnings: usize,
    /// Number of `FAIL` rows.
    pub failures: usize,
}

impl Summary {
    /// Counts `checks`.
    #[must_use]
    pub fn of(checks: &[Check]) -> Self {
        let n = |s: Status| checks.iter().filter(|c| c.status == s).count();
        Self {
            warnings: n(Status::Warn),
            failures: n(Status::Fail),
        }
    }

    /// Process exit code of `nzbd health`: 0 all OK, 1 warnings, 2 failures.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        if self.failures > 0 {
            2
        } else if self.warnings > 0 {
            1
        } else {
            0
        }
    }

    fn banner(self) -> (&'static str, &'static str, String) {
        if self.failures > 0 {
            (
                "st-bad",
                "FAIL",
                format!(
                    "{} failure(s) and {} warning(s). Fix the failures first.",
                    self.failures, self.warnings
                ),
            )
        } else if self.warnings > 0 {
            (
                "st-warn",
                "WARN",
                format!("{} warning(s). Nothing is broken.", self.warnings),
            )
        } else {
            ("st-ok", "ALL OK", "Every check passed.".to_owned())
        }
    }
}

/// Boxed future (the collectors are plain closures, no `async_trait`).
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// Produces checks for the given unix time. Must be read-only.
pub type CollectFn = Arc<dyn Fn(i64) -> BoxFut<Vec<Check>> + Send + Sync>;

/// Everything the health routes need from the rest of the process.
#[derive(Clone)]
pub struct HealthDeps {
    /// Wall clock (deterministic in tests).
    pub clock: Arc<dyn WallClock>,
    /// Cheap checks, cached for [`CACHE_SECS`].
    pub cheap: CollectFn,
    /// Deep checks; `None` hides the button.
    pub deep: Option<CollectFn>,
    /// Deadline of one deep run ([`DEEP_DEADLINE`] in production).
    pub deep_deadline: Duration,
}

impl HealthDeps {
    /// Deps with the production deadline.
    #[must_use]
    pub fn new(clock: Arc<dyn WallClock>, cheap: CollectFn, deep: Option<CollectFn>) -> Self {
        Self {
            clock,
            cheap,
            deep,
            deep_deadline: DEEP_DEADLINE,
        }
    }
}

#[derive(Clone)]
enum DeepState {
    Idle,
    Running { since: i64 },
    Done { at: i64, checks: Arc<Vec<Check>> },
}

/// Cheap checks with the time they were collected.
type CachedChecks = Option<(i64, Arc<Vec<Check>>)>;

#[derive(Clone)]
struct HealthState {
    deps: HealthDeps,
    cache: Arc<AsyncMutex<CachedChecks>>,
    deep: Arc<Mutex<DeepState>>,
    permit: Arc<Semaphore>,
}

impl HealthState {
    fn deep_state(&self) -> DeepState {
        self.deep
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_deep(&self, s: DeepState) {
        *self.deep.lock().unwrap_or_else(PoisonError::into_inner) = s;
    }

    /// Cheap checks, reused for [`CACHE_SECS`]. The refresh runs in an owned task that holds
    /// the cache lock until done (single flight; a disconnecting client cannot start a second
    /// collection) and is bounded by [`CHEAP_DEADLINE`].
    async fn cheap(&self, now: i64) -> Arc<Vec<Check>> {
        let this = self.clone();
        let job = tokio::spawn(async move {
            let mut guard = this.cache.lock().await;
            if let Some((at, checks)) = guard.as_ref()
                && (0..CACHE_SECS).contains(&now.saturating_sub(*at))
            {
                return Arc::clone(checks);
            }
            let fut = (this.deps.cheap)(now);
            let checks = tokio::time::timeout(CHEAP_DEADLINE, fut)
                .await
                .unwrap_or_else(|_| {
                    vec![Check::new(
                        Group::App,
                        "Health collection",
                        Status::Fail,
                        "timed out",
                        "A probe is hanging, usually a stuck disk or network mount. Check the host.",
                    )]
                });
            let checks = Arc::new(checks);
            *guard = Some((now, Arc::clone(&checks)));
            checks
        });
        job.await.unwrap_or_else(|_| {
            Arc::new(vec![Check::new(
                Group::App,
                "Health collection",
                Status::Fail,
                "failed internally",
                "See the server log.",
            )])
        })
    }
}

/// Routes of the health page; merge them into the `session_routes` of
/// [`crate::router_with_auth`].
pub fn routes(deps: HealthDeps) -> Router {
    Router::new()
        .route("/admin/health", get(page))
        .route("/admin/health/deep", post(run_deep))
        .with_state(HealthState {
            deps,
            cache: Arc::new(AsyncMutex::new(None)),
            deep: Arc::new(Mutex::new(DeepState::Idle)),
            permit: Arc::new(Semaphore::new(1)),
        })
}

struct RowView {
    name: String,
    class: &'static str,
    label: &'static str,
    value: String,
    hint: String,
}

fn row_view(c: &Check) -> RowView {
    RowView {
        name: sanitize_text(c.name, 80),
        class: c.status.class(),
        label: c.status.label(),
        value: sanitize_text(&c.value, 300),
        hint: sanitize_text(&c.hint, 300),
    }
}

struct GroupView {
    id: &'static str,
    title: &'static str,
    rows: Vec<RowView>,
}

fn group_views(checks: &[Check]) -> Vec<GroupView> {
    Group::ALL
        .iter()
        .filter_map(|g| {
            let rows: Vec<RowView> = checks
                .iter()
                .filter(|c| c.group == *g)
                .map(row_view)
                .collect();
            (!rows.is_empty()).then_some(GroupView {
                id: g.id(),
                title: g.title(),
                rows,
            })
        })
        .collect()
}

#[derive(Template)]
#[template(path = "health.html")]
struct HealthPage {
    layout: Layout,
    banner_class: &'static str,
    banner_label: &'static str,
    banner_text: String,
    checked_at: String,
    groups: Vec<GroupView>,
    deep_enabled: bool,
    deep_status: &'static str,
    deep_notice: &'static str,
    deep_at: String,
    deep_rows: Vec<RowView>,
}

/// Fixed notice for the `?deep=` redirect marker; the query value is never echoed.
fn notice(raw: Option<&str>) -> &'static str {
    let form = csrf::parse_form(raw.unwrap_or_default().as_bytes());
    match csrf::form_get(&form, "deep") {
        Some("started") => "Deep check started. Reload this page in a minute to see the result.",
        Some("busy") => "A deep check is already running.",
        Some("wait") => "A deep check finished moments ago. Try again in a few seconds.",
        _ => "",
    }
}

async fn page(
    State(st): State<HealthState>,
    Extension(sess): Extension<SessionCtx>,
    uri: Uri,
) -> Response {
    let now = st.deps.clock.now_secs();
    let checks = st.cheap(now).await;
    let mut all = Summary::of(&checks);
    let (deep_status, deep_at, deep_rows) = match st.deep_state() {
        DeepState::Running { since } => ("running", fmt_utc(since), Vec::new()),
        DeepState::Done { at, checks } if now.saturating_sub(at) <= DEEP_TTL_SECS => {
            let s = Summary::of(&checks);
            all.warnings = all.warnings.saturating_add(s.warnings);
            all.failures = all.failures.saturating_add(s.failures);
            ("done", fmt_utc(at), checks.iter().map(row_view).collect())
        }
        _ => ("none", String::new(), Vec::new()),
    };
    let (banner_class, banner_label, banner_text) = all.banner();
    let view = HealthPage {
        layout: Layout::for_session("Health", &sess),
        banner_class,
        banner_label,
        banner_text,
        checked_at: fmt_utc(now),
        groups: group_views(&checks),
        deep_enabled: st.deps.deep.is_some(),
        deep_status,
        deep_notice: notice(uri.query()),
        deep_at,
        deep_rows,
    };
    match view.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health render failed");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL").into_response()
        }
    }
}

/// Publishes a `Done` state when dropped before the run completed (panic or cancellation), so
/// the page never stays on "running" and the failure is visible.
struct RunGuard {
    st: HealthState,
    armed: bool,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if self.armed {
            let at = self.st.deps.clock.now_secs();
            self.st.set_deep(DeepState::Done {
                at,
                checks: Arc::new(vec![aborted()]),
            });
        }
    }
}

fn aborted() -> Check {
    Check::new(
        Group::Deep,
        "Deep check",
        Status::Fail,
        "aborted",
        "The run ended unexpectedly. See the server log, then run it again.",
    )
}

async fn run_deep(State(st): State<HealthState>) -> Response {
    let Some(deep) = st.deps.deep.clone() else {
        return ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response();
    };
    let now = st.deps.clock.now_secs();
    // One permit: a second click while running, or from a second session, is refused.
    let Ok(permit) = Arc::clone(&st.permit).try_acquire_owned() else {
        return see_other("/admin/health?deep=busy", None);
    };
    if let DeepState::Done { at, .. } = st.deep_state()
        && (0..DEEP_COOLDOWN_SECS).contains(&now.saturating_sub(at))
    {
        return see_other("/admin/health?deep=wait", None);
    }
    st.set_deep(DeepState::Running { since: now });
    let deadline = st.deps.deep_deadline;
    // Owned task: it keeps the permit until the work is done even if the client disconnects,
    // and the permit is released when the task ends by any path (panic included).
    tokio::spawn(async move {
        let _permit = permit;
        let mut guard = RunGuard {
            st: st.clone(),
            armed: true,
        };
        let checks = match tokio::time::timeout(deadline, deep(now)).await {
            Ok(c) => c,
            Err(_) => vec![Check::new(
                Group::Deep,
                "Deep check",
                Status::Fail,
                "deadline exceeded",
                "The store or database is very slow. Run `nzbd store verify --quick` on the host.",
            )],
        };
        guard.armed = false;
        let at = st.deps.clock.now_secs();
        st.set_deep(DeepState::Done {
            at,
            checks: Arc::new(checks),
        });
    });
    see_other("/admin/health?deep=started", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: Status) -> Check {
        Check::new(Group::App, "x", s, "v", "")
    }

    #[test]
    fn summary_and_exit_codes() {
        assert_eq!(
            Summary::of(&[c(Status::Ok), c(Status::Info)]).exit_code(),
            0
        );
        assert_eq!(
            Summary::of(&[c(Status::Ok), c(Status::Warn)]).exit_code(),
            1
        );
        assert_eq!(
            Summary::of(&[c(Status::Warn), c(Status::Fail), c(Status::Fail)]).exit_code(),
            2
        );
        let s = Summary::of(&[c(Status::Warn), c(Status::Fail), c(Status::Fail)]);
        assert_eq!((s.warnings, s.failures), (1, 2));
    }

    #[test]
    fn banner_text_is_always_present() {
        for (s, label) in [
            (Summary::default(), "ALL OK"),
            (
                Summary {
                    warnings: 2,
                    failures: 0,
                },
                "WARN",
            ),
            (
                Summary {
                    warnings: 0,
                    failures: 1,
                },
                "FAIL",
            ),
        ] {
            let (class, l, text) = s.banner();
            assert_eq!(l, label);
            assert_ne!(text, "");
            assert!(class.starts_with("st-"));
        }
    }

    #[test]
    fn notice_never_echoes_the_query() {
        assert_eq!(notice(Some("deep=<script>")), "");
        assert!(notice(Some("deep=started")).contains("started"));
        assert_eq!(notice(None), "");
    }
}

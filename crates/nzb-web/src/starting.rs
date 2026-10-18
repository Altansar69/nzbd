//! Startup gate (T088): the listener is bound and answering *before* the database is open.
//!
//! `nzbd serve` binds the socket, hands [`StartGate::router`] to the HTTP server at once, and only
//! then opens/migrates the database (minutes on a large library). Until [`StartGate::open`] is
//! called every request is answered by a static `503 STARTING` page with `Retry-After`; no
//! handler, session lookup, database access or secret is reachable. The page goes through the
//! same hardening stack as the real app (security headers, CSP, request id, size limits), so
//! the headers are intact. After `open` the very next request is dispatched to the real router
//! (keep-alive connections included), so there is no rebind and no gap.

use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower::ServiceExt as _;

use crate::{ApiError, WebConfig, assets};

/// Seconds suggested by `Retry-After` and the `Refresh` header of the starting page.
const RETRY_SECS: u64 = 5;

/// Stable error code of the starting response (JSON `error.code`, read by `nzbd healthcheck`).
pub const STARTING_CODE: &str = "STARTING";

/// Shared switch between the "starting" page and the real application router.
#[derive(Clone)]
pub struct StartGate {
    app: Arc<OnceLock<Router>>,
    starting: Router,
}

impl StartGate {
    /// Builds the gate in the *starting* state. `cfg` supplies the hardening settings of the
    /// starting page (trusted proxies, limits); it must not carry anything secret.
    #[must_use]
    pub fn new(cfg: &WebConfig) -> Self {
        // Only the vendored stylesheet is routable besides the fallback: embedded bytes, no state.
        let starting = Router::new()
            .route("/static/{*path}", get(assets::serve))
            .fallback(starting_response);
        Self {
            app: Arc::new(OnceLock::new()),
            starting: crate::harden(starting, cfg),
        }
    }

    /// Switches to the real application. Returns `false` (and drops `app`) when already open.
    #[must_use]
    pub fn open(&self, app: Router) -> bool {
        self.app.set(app).is_ok()
    }

    /// Whether the real application is serving.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.app.get().is_some()
    }

    /// The router to serve: dispatches each request to the real app once open, else to the
    /// starting page. It adds no layers of its own (the real app keeps its own limits and rate
    /// limiter state).
    pub fn router(&self) -> Router {
        Router::new().fallback(dispatch).with_state(self.clone())
    }
}

async fn dispatch(State(gate): State<StartGate>, req: Request) -> Response {
    let target = gate.app.get().unwrap_or(&gate.starting).clone();
    match target.oneshot(req).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    }
}

/// The 503 itself. `finalize` (inside the hardening stack) renders the body: the HTML error page
/// for browsers, the uniform JSON error otherwise.
async fn starting_response() -> Response {
    let mut resp = ApiError::new(StatusCode::SERVICE_UNAVAILABLE, STARTING_CODE)
        .retry_after(RETRY_SECS)
        .into_response();
    // Browsers reload the page on their own until the app is up.
    resp.headers_mut()
        .insert(header::REFRESH, HeaderValue::from(RETRY_SECS));
    resp
}

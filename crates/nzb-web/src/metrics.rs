//! Internal-only plaintext metrics (T105; SEC-083, SEC-084; `DEPLOYMENT` "Metrics").
//!
//! This router is served by its **own listener** (`[metrics] listen`), never merged into the application router, so
//! no path of the app the proxy forwards to can reach it. Defence in depth, each covered by a test:
//!
//! * only `GET`/`HEAD /metrics` answers; anything else is the same bare `404`;
//! * a request that carries any forwarding header (`X-Forwarded-*`, `Forwarded`, `X-Real-IP`: every reverse proxy
//!   adds them) or comes from a configured trusted proxy is refused with that `404`, so a proxy route added by
//!   mistake yields nothing;
//! * an unknown peer address fails closed;
//! * the body is rendered by the caller from counters and gauges only (no per-user or NZB-derived strings, no
//!   unbounded label values), cached for [`CACHE_SECS`] so scraping cannot be turned into database load, and at most
//!   [`MAX_INFLIGHT`] renders run at once.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use tokio::sync::{Mutex, Semaphore};

use crate::listener::PeerAddr;

/// Seconds a rendered body is reused.
pub const CACHE_SECS: u64 = 5;
/// Concurrent renders.
pub const MAX_INFLIGHT: usize = 2;
/// Deadline of one render.
const RENDER_DEADLINE: Duration = Duration::from_secs(10);
/// Headers a reverse proxy adds; their presence means the request did not come from a local scraper.
const FORWARDING_HEADERS: [&str; 6] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "forwarded",
    "x-real-ip",
];

/// Produces the exposition text.
pub type RenderFn = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = String> + Send>> + Send + Sync>;

/// What the metrics listener needs.
#[derive(Clone)]
pub struct MetricsDeps {
    /// Renders the plaintext body.
    pub render: RenderFn,
    /// `server.trusted_proxies`: requests from these peers are refused.
    pub trusted_proxies: Arc<[IpAddr]>,
}

/// The last rendered body and when it was rendered.
type Cached = Option<(Instant, Arc<String>)>;

#[derive(Clone)]
struct MetricsState {
    deps: MetricsDeps,
    cache: Arc<Mutex<Cached>>,
    permits: Arc<Semaphore>,
}

/// The router for the metrics listener (serve it with `into_make_service_with_connect_info::<PeerAddr>()`).
pub fn router(deps: MetricsDeps) -> Router {
    let st = MetricsState {
        deps,
        cache: Arc::new(Mutex::new(None)),
        permits: Arc::new(Semaphore::new(MAX_INFLIGHT)),
    };
    Router::new().fallback(handle).with_state(st)
}

/// `localhost`, an IPv4 literal or a bracketed IPv6 literal, each with an optional `:port`.
fn host_is_local_literal(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    let port_ok = |p: &str| p.is_empty() || (p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    if let Some(rest) = h.strip_prefix('[') {
        let Some((inner, tail)) = rest.split_once(']') else {
            return false;
        };
        let tail_ok = tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && port_ok(p));
        return inner.parse::<std::net::Ipv6Addr>().is_ok() && tail_ok;
    }
    let (name, port) = match h.split_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (h.as_str(), None),
    };
    port.is_none_or(|p| !p.is_empty() && port_ok(p))
        && (name == "localhost" || name.parse::<std::net::Ipv4Addr>().is_ok())
}

fn plain(status: StatusCode, body: &'static str) -> Response {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

fn not_found() -> Response {
    plain(StatusCode::NOT_FOUND, "not found\n")
}

async fn handle(State(st): State<MetricsState>, req: Request) -> Response {
    let head = req.method() == Method::HEAD;
    if !(req.method() == Method::GET || head) || req.uri().path() != "/metrics" {
        return not_found();
    }
    let Some(peer) = req.extensions().get::<ConnectInfo<PeerAddr>>() else {
        return not_found();
    };
    // Both sides canonical: an IPv4 peer arrives as `::ffff:a.b.c.d` on a dual-stack `[::]` bind (T105 M2).
    let ip = peer.0.0.ip().to_canonical();
    // Host: an IP literal or `localhost` only, so a rebinding name cannot reach the listener from a browser (L4).
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(host_is_local_literal);
    if !host_ok
        || st
            .deps
            .trusted_proxies
            .iter()
            .any(|t| t.to_canonical() == ip)
        || FORWARDING_HEADERS
            .iter()
            .any(|h| req.headers().contains_key(*h))
    {
        return not_found();
    }
    let Ok(_permit) = st.permits.try_acquire() else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
    };
    let body = {
        let mut guard = st.cache.lock().await;
        match guard.as_ref() {
            Some((at, b)) if at.elapsed() < Duration::from_secs(CACHE_SECS) => Arc::clone(b),
            _ => {
                let fut = (st.deps.render)();
                let Ok(text) = tokio::time::timeout(RENDER_DEADLINE, fut).await else {
                    return plain(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
                };
                let b = Arc::new(text);
                *guard = Some((Instant::now(), Arc::clone(&b)));
                b
            }
        }
    };
    let mut r = Response::new(if head {
        Body::empty()
    } else {
        Body::from(body.as_str().to_owned())
    });
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

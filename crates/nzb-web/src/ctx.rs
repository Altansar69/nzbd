//! Per-request context: request id and the effective client address (SEC-031, SEC-034).

use std::fmt::Write as _;
use std::io::Read as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::HeaderMap;

/// Opaque identifier attached to every request, response (`X-Request-Id`) and log line.
///
/// Always generated server-side: a client-supplied `X-Request-Id` is ignored so it can never
/// reach logs or error bodies (log injection).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(pub String);

impl RequestId {
    /// 128 random bits as lowercase hex. Falls back to a process-unique counter if the OS
    /// random device is unavailable (the id is a correlation handle, not a secret).
    #[must_use]
    pub fn generate() -> Self {
        static FALLBACK: AtomicU64 = AtomicU64::new(1);
        let mut buf = [0_u8; 16];
        let ok = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .is_ok();
        if !ok {
            buf = [0_u8; 16];
            let n = FALLBACK.fetch_add(1, Ordering::Relaxed).to_be_bytes();
            for (dst, src) in buf.iter_mut().skip(8).zip(n) {
                *dst = src;
            }
        }
        let mut s = String::with_capacity(32);
        for b in buf {
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
        }
        Self(s)
    }
}

/// Effective client address: the socket peer, or the last `X-Forwarded-For` hop when the peer
/// is a configured trusted proxy. Used for rate limiting, throttling and audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// True when the request reached the proxy over TLS (`X-Forwarded-Proto: https` from a trusted
/// proxy). Drives HSTS and, later, cookie decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViaTls(pub bool);

/// Resolves the effective client address and TLS flag for a request (SEC-031).
///
/// `X-Forwarded-*` is honoured only when `peer` is in `trusted`; otherwise it is ignored
/// entirely. Unparseable forwarded values fall back to the peer address.
#[must_use]
pub fn resolve_client(peer: IpAddr, trusted: &[IpAddr], headers: &HeaderMap) -> (IpAddr, bool) {
    let peer = peer.to_canonical();
    if !trusted.iter().any(|t| t.to_canonical() == peer) {
        return (peer, false);
    }
    let joined = |name: &str| -> String {
        headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(",")
    };
    let ip = joined("x-forwarded-for")
        .rsplit(',')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map_or(peer, |ip| ip.to_canonical());
    let tls = joined("x-forwarded-proto")
        .rsplit(',')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .is_some_and(|s| s.eq_ignore_ascii_case("https"));
    (ip, tls)
}

//! Per-IP request rate limiting (SEC-029) with an injectable clock.
//!
//! Sliding-window counter: the previous window's count is weighted by how much of it still
//! overlaps the last 60 s, which avoids the 2x burst of a plain fixed window while using
//! two integers per key. Integer math only.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

const WINDOW_MS: u64 = 60_000;
/// Upper bound on tracked keys; beyond it stale entries are pruned, then new keys are denied.
const MAX_KEYS: usize = 50_000;

/// Monotonic millisecond clock (injected so tests are deterministic).
pub trait Clock: Send + Sync + 'static {
    /// Milliseconds since an arbitrary fixed origin; never decreases.
    fn now_ms(&self) -> u64;
}

/// Production clock based on [`Instant`].
#[derive(Debug)]
pub struct SystemClock(Instant);

impl SystemClock {
    /// Starts counting from now.
    #[must_use]
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Test clock advanced by hand.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// Moves time forward.
    pub fn advance_secs(&self, secs: u64) {
        self.0
            .fetch_add(secs.saturating_mul(1000), Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Route classes with their own budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Everything behind the UI (and the login pages).
    Ui,
    /// `GET /release/{id}/download`.
    Download,
    /// `POST /upload` and `POST /api/v1/nzb` (per-IP part; per-key/session buckets: [`KeyedLimiter`]).
    Upload,
    /// Credential-bearing POSTs (`/login`, `/login/mfa`, `/mfa/enroll`, `/invite`): 10/min/IP
    /// (SEC-026).
    Login,
    /// The enclosing IPv6 /48 of a [`Class::Login`] request (N1): one customer prefix holds 65,536
    /// /64s, so without it rotating /64s would multiply the per-address budget. Internal; applies
    /// to IPv6 clients only, with six times the per-address budget.
    LoginPrefix,
    /// `POST /releases/bulk/download` (T130): [`BULK_DOWNLOADS_PER_MIN`] per IP, charged by the
    /// handler after its capacity check, on top of [`Class::Download`].
    BulkDownload,
}

/// Bulk downloads (`POST /releases/bulk/download`, up to 100 NZBs and 1 GiB each) per minute, per
/// client IP and per account (T130). A constant on purpose: there is no per-account limits section
/// in the configuration, and one bulk download already moves up to 100 NZBs.
pub const BULK_DOWNLOADS_PER_MIN: u32 = 2;

/// Requests per minute per client IP, by class (SEC-029 defaults: 300 / 30 / 60).
#[derive(Clone, Copy, Debug)]
pub struct RateLimits {
    /// UI routes.
    pub ui: u32,
    /// Downloads.
    pub download: u32,
    /// Uploads.
    pub upload: u32,
    /// Login attempts (POSTs to the login-flow routes).
    pub login: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            ui: 300,
            download: 30,
            upload: 60,
            login: 10,
        }
    }
}

/// Outcome of a rate-limit check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Request may proceed.
    Allow,
    /// Budget exhausted; retry after this many seconds (>= 1).
    Deny {
        /// Value for the `Retry-After` header.
        retry_after_secs: u64,
    },
}

#[derive(Clone, Copy)]
struct Window {
    start_ms: u64,
    cur: u64,
    prev: u64,
}

/// The per-IP upload bucket of one request, handed to the upload handler by the rate-limit
/// layer so a multi-file UI request can spend one per-IP token per file (T083, residual-risk
/// L-12). The layer already spent the first token for the request itself.
#[derive(Clone)]
pub struct IpUploadBucket {
    limiter: Arc<RateLimiter>,
    ip: IpAddr,
}

impl IpUploadBucket {
    pub(crate) fn new(limiter: Arc<RateLimiter>, ip: IpAddr) -> Self {
        Self { limiter, ip }
    }

    /// Spends one more upload token of this client address.
    #[must_use]
    pub fn charge(&self) -> Decision {
        self.limiter.check(Class::Upload, self.ip)
    }
}

/// Keyed sliding-window limiter.
pub struct RateLimiter {
    clock: Arc<dyn Clock>,
    limits: RateLimits,
    state: Mutex<HashMap<(Class, IpAddr), Window>>,
    max_keys: usize,
}

/// Budget of the /48 login bucket relative to the per-address one (10/min -> 60/min).
const PREFIX_FACTOR: u32 = 6;

/// IPv6 clients are bucketed per /64 (a single host owns a whole /64), IPv4 per address.
fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The enclosing /48 of an IPv6 client; `None` for IPv4.
fn prefix48_key(ip: IpAddr) -> Option<IpAddr> {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 80);
            Some(IpAddr::V6(Ipv6Addr::from(masked)))
        }
        IpAddr::V4(_) => None,
    }
}

/// The address key the persisted per-(account, address) locks and the known-address set use:
/// the IPv4 text or the IPv6 /64 prefix, exactly the bucket the limiter applies (SEC-066).
#[must_use]
pub fn ip_key(ip: IpAddr) -> String {
    bucket_key(ip).to_string()
}

impl RateLimiter {
    /// Creates a limiter with the given budgets and clock.
    #[must_use]
    pub fn new(limits: RateLimits, clock: Arc<dyn Clock>) -> Self {
        Self::with_max_keys(limits, clock, MAX_KEYS)
    }

    /// Like [`RateLimiter::new`] with an explicit bound on tracked keys.
    #[must_use]
    pub fn with_max_keys(limits: RateLimits, clock: Arc<dyn Clock>, max_keys: usize) -> Self {
        Self {
            clock,
            limits,
            state: Mutex::new(HashMap::new()),
            max_keys: max_keys.max(1),
        }
    }

    fn limit_for(&self, class: Class) -> u64 {
        u64::from(match class {
            Class::Ui => self.limits.ui,
            Class::Download => self.limits.download,
            Class::Upload => self.limits.upload,
            Class::Login => self.limits.login,
            Class::LoginPrefix => self.limits.login.saturating_mul(PREFIX_FACTOR),
            Class::BulkDownload => BULK_DOWNLOADS_PER_MIN,
        })
    }

    /// Records one request from `ip` in `class` and decides whether it may proceed.
    #[must_use]
    pub fn check(&self, class: Class, ip: IpAddr) -> Decision {
        let first = self.check_key(class, bucket_key(ip));
        if class == Class::Login
            && first == Decision::Allow
            && let Some(prefix) = prefix48_key(ip)
        {
            return self.check_key(Class::LoginPrefix, prefix);
        }
        first
    }

    fn check_key(&self, class: Class, bucket: IpAddr) -> Decision {
        let now = self.clock.now_ms();
        let limit = self.limit_for(class);
        let mut map = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (class, bucket);
        if map.len() >= self.max_keys && !map.contains_key(&key) {
            map.retain(|_, w| now.saturating_sub(w.start_ms) < 2 * WINDOW_MS);
            if map.len() >= self.max_keys {
                // Table full of live clients: fail closed for *new* keys. Wiping the table
                // would hand an attacker with many source addresses a free budget reset;
                // existing keys keep being counted, and entries expire after 2 windows.
                return Decision::Deny {
                    retry_after_secs: WINDOW_MS.div_ceil(1000),
                };
            }
        }
        let w = map.entry(key).or_insert(Window {
            start_ms: now,
            cur: 0,
            prev: 0,
        });
        w.hit(now, limit)
    }
}

impl Window {
    /// Counts one hit at `now` against `limit` per window (sliding-window estimate).
    fn hit(&mut self, now: u64, limit: u64) -> Decision {
        let w = self;
        let mut elapsed = now.saturating_sub(w.start_ms);
        if elapsed >= 2 * WINDOW_MS {
            *w = Window {
                start_ms: now,
                cur: 0,
                prev: 0,
            };
            elapsed = 0;
        } else if elapsed >= WINDOW_MS {
            w.prev = w.cur;
            w.cur = 0;
            w.start_ms = w.start_ms.saturating_add(WINDOW_MS);
            elapsed = now.saturating_sub(w.start_ms);
        }
        let weighted = w
            .prev
            .saturating_mul(WINDOW_MS.saturating_sub(elapsed))
            .checked_div(WINDOW_MS)
            .unwrap_or(0)
            .saturating_add(w.cur);
        if weighted >= limit {
            let remaining_ms = WINDOW_MS.saturating_sub(elapsed);
            Decision::Deny {
                retry_after_secs: remaining_ms.div_ceil(1000).max(1),
            }
        } else {
            w.cur = w.cur.saturating_add(1);
            Decision::Allow
        }
    }
}

/// Sliding-window limiter for authenticated subjects (an API key id, a session): the SEC-029
/// "per key / per session" upload budget. Keyed only *after* authentication, so unauthenticated
/// requests can never spend a valid subject's budget. The table is bounded; when it is full of
/// live subjects, unknown subjects are refused (fail closed) instead of wiping known counters.
pub struct KeyedLimiter<K> {
    clock: Arc<dyn Clock>,
    limit: u64,
    max_keys: usize,
    state: Mutex<HashMap<K, Window>>,
}

impl<K: std::hash::Hash + Eq> KeyedLimiter<K> {
    /// `per_minute` hits per key per window, at most `max_keys` tracked keys.
    #[must_use]
    pub fn new(per_minute: u32, max_keys: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            limit: u64::from(per_minute),
            max_keys: max_keys.max(1),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Records one hit for `key` and decides whether it may proceed.
    #[must_use]
    pub fn check(&self, key: K) -> Decision {
        self.check_limited(key, u32::MAX)
    }

    /// Like [`KeyedLimiter::check`] with a per-subject budget that can only LOWER the limiter's own
    /// (a per-API-key budget stored in the database never exceeds the instance setting).
    #[must_use]
    pub fn check_limited(&self, key: K, per_minute: u32) -> Decision {
        let limit = self.limit.min(u64::from(per_minute));
        let now = self.clock.now_ms();
        let mut map = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= self.max_keys && !map.contains_key(&key) {
            map.retain(|_, w| now.saturating_sub(w.start_ms) < 2 * WINDOW_MS);
            if map.len() >= self.max_keys {
                return Decision::Deny {
                    retry_after_secs: WINDOW_MS.div_ceil(1000),
                };
            }
        }
        map.entry(key)
            .or_insert(Window {
                start_ms: now,
                cur: 0,
                prev: 0,
            })
            .hit(now, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
    }

    #[test]
    fn denies_after_budget_and_recovers() {
        let clock = Arc::new(ManualClock::default());
        let rl = RateLimiter::new(RateLimits::default(), clock.clone());
        for _ in 0..30 {
            assert_eq!(rl.check(Class::Download, ip("10.0.0.1")), Decision::Allow);
        }
        assert!(matches!(
            rl.check(Class::Download, ip("10.0.0.1")),
            Decision::Deny {
                retry_after_secs: 60
            }
        ));
        assert_eq!(rl.check(Class::Download, ip("10.0.0.2")), Decision::Allow);
        clock.advance_secs(121);
        assert_eq!(rl.check(Class::Download, ip("10.0.0.1")), Decision::Allow);
    }

    #[test]
    fn sec_029_full_table_fails_closed_without_resetting_existing_counters() {
        let clock = Arc::new(ManualClock::default());
        let limits = RateLimits {
            ui: 2,
            download: 2,
            upload: 2,
            login: 2,
        };
        let rl = RateLimiter::with_max_keys(limits, clock.clone(), 3);
        // The attacker's own key is exhausted, then the table is filled with other keys.
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.1")), Decision::Allow);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.1")), Decision::Allow);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.2")), Decision::Allow);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.3")), Decision::Allow);
        // A new key cannot trigger a wipe: it is denied, and the attacker is still limited.
        assert!(matches!(
            rl.check(Class::Ui, ip("10.0.0.4")),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            rl.check(Class::Ui, ip("10.0.0.1")),
            Decision::Deny { .. }
        ));
        // Known keys keep working, and stale entries free room later.
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.2")), Decision::Allow);
        clock.advance_secs(121);
        assert_eq!(rl.check(Class::Ui, ip("10.0.0.4")), Decision::Allow);
    }

    #[test]
    fn sec_029_keyed_limiter_is_bounded_fails_closed_and_evicts_expired_subjects() {
        let clock = Arc::new(ManualClock::default());
        let rl: KeyedLimiter<i64> = KeyedLimiter::new(2, 2, clock.clone());
        assert_eq!(rl.check(1), Decision::Allow);
        assert_eq!(rl.check(1), Decision::Allow);
        assert!(matches!(rl.check(1), Decision::Deny { .. }));
        assert_eq!(rl.check(2), Decision::Allow);
        // Table full of live subjects: a new one is refused, known ones keep their counters.
        assert!(matches!(rl.check(3), Decision::Deny { .. }));
        assert!(matches!(rl.check(1), Decision::Deny { .. }));
        // Expired entries are evicted to make room.
        clock.advance_secs(121);
        assert_eq!(rl.check(3), Decision::Allow);
        assert_eq!(rl.check(1), Decision::Allow);
    }

    #[test]
    fn ipv6_shares_a_slash_64() {
        assert_eq!(
            bucket_key(ip("2001:db8::1")),
            bucket_key(ip("2001:db8::ffff"))
        );
        assert_ne!(bucket_key(ip("2001:db8::1")), bucket_key(ip("2001:db9::1")));
    }
}

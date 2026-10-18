//! Abuse guards of the upload routes (T052, `SECURITY_REVIEW` T051 M1/M2).
//!
//! * [`UploadLimiter`]: SEC-029 per-API-key and per-session buckets, keyed after authentication;
//! * [`StorageGuard`]: refuses uploads while a volume is below its free-space floor (M2);
//! * [`Metered`] / [`Meter`]: bounds the memory the multipart parser (multer) may buffer for
//!   framing (preamble, part headers) that no per-part cap can see (M1).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::Bytes;
use http_body::{Body, Frame, SizeHint};

use crate::ratelimit::{Clock, Decision, KeyedLimiter};

/// SEC-029 default: uploads (files) per minute per API key and per session.
pub const DEFAULT_UPLOADS_PER_MIN: u32 = 30;
/// Bound on tracked subjects per bucket table (API keys are capped at 10 active, sessions are
/// few); beyond it new subjects are refused rather than counters wiped.
const MAX_SUBJECTS: usize = 1024;

/// Per-key and per-session upload buckets. A subject only gets here after authentication, so an
/// unauthenticated request can never consume a valid key's or session's budget (it only counts
/// in the per-IP bucket of the rate-limit layer).
pub struct UploadLimiter {
    by_key: KeyedLimiter<i64>,
    by_session: KeyedLimiter<[u8; 32]>,
}

impl UploadLimiter {
    /// Budgets in uploads (files) per minute.
    #[must_use]
    pub fn new(per_key: u32, per_session: u32, clock: &Arc<dyn Clock>) -> Self {
        Self {
            by_key: KeyedLimiter::new(per_key, MAX_SUBJECTS, Arc::clone(clock)),
            by_session: KeyedLimiter::new(per_session, MAX_SUBJECTS, Arc::clone(clock)),
        }
    }

    /// Spends one token of API key `id`. `own_budget` is the key's stored per-minute budget; it
    /// can only lower the instance budget (T103).
    #[must_use]
    pub fn check_key(&self, id: i64, own_budget: Option<u32>) -> Decision {
        self.by_key
            .check_limited(id, own_budget.unwrap_or(u32::MAX))
    }

    /// Spends one token of the session with id hash `id_hash`.
    #[must_use]
    pub fn check_session(&self, id_hash: [u8; 32]) -> Decision {
        self.by_session.check(id_hash)
    }
}

// ---------------------------------------------------------------------------------------------
// Storage guard

/// Free and total bytes of one volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    /// Bytes available to an unprivileged writer.
    pub free: u64,
    /// Volume size.
    pub total: u64,
}

/// Reports the volumes uploads write to (`paths.tmp`, `paths.store`). A volume that cannot be
/// measured is left out of the answer: the guard then does not refuse on its behalf (staging
/// itself fails closed on a real I/O error, and the health dashboard reports the volume).
pub type SpaceProvider = Arc<dyn Fn() -> Vec<Space> + Send + Sync>;

/// Refuses uploads while any volume has less than `max(floor_bytes, floor_percent % of total)`
/// free. The verdict is cached for [`StorageGuard::TTL_MS`] so a flood does not turn into a flood
/// of `statvfs` calls.
pub struct StorageGuard {
    provider: SpaceProvider,
    floor_bytes: u64,
    floor_percent: u64,
    clock: Arc<dyn Clock>,
    cache: Mutex<Option<(u64, bool)>>,
}

impl StorageGuard {
    /// How long a verdict is reused.
    pub const TTL_MS: u64 = 5_000;

    /// `floor_percent` is clamped to 100.
    #[must_use]
    pub fn new(
        provider: SpaceProvider,
        floor_bytes: u64,
        floor_percent: u8,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            provider,
            floor_bytes,
            floor_percent: u64::from(floor_percent.min(100)),
            clock,
            cache: Mutex::new(None),
        }
    }

    /// Whether `s` is below the floor.
    fn below(&self, s: Space) -> bool {
        let pct = s.total.saturating_mul(self.floor_percent) / 100;
        s.free < self.floor_bytes.max(pct)
    }

    /// `true` when every measurable volume has room.
    #[must_use]
    pub fn has_room(&self) -> bool {
        let now = self.clock.now_ms();
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, ok)) = *cache
            && now.saturating_sub(at) < Self::TTL_MS
        {
            return ok;
        }
        let ok = !(self.provider)().into_iter().any(|s| self.below(s));
        *cache = Some((now, ok));
        ok
    }
}

// ---------------------------------------------------------------------------------------------
// Framing meter

/// The multipart framing outgrew its allowance (see [`Metered`]); reported like the body ceiling.
#[derive(Debug)]
pub struct FramingLimitError;

impl std::fmt::Display for FramingLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("multipart framing exceeds its allowance")
    }
}

impl std::error::Error for FramingLimitError {}

/// Whether `e` (or anything in its source chain) is a body-size limit: the ceiling of the limits
/// layer or the framing allowance of [`Metered`].
pub(crate) fn chain_has_limit(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(e);
    while let Some(c) = cur {
        if c.is::<http_body_util::LengthLimitError>() || c.is::<FramingLimitError>() {
            return true;
        }
        cur = c.source();
    }
    false
}

/// Bytes the parser may hold unconsumed before the first part.
const MARGIN: u64 = 64 * 1024;
/// Extra allowance per multipart part for its boundary and header block (far above the real
/// size of a legitimate one).
const PART_ALLOWANCE: u64 = 4 * 1024;

/// Shared counters between [`Metered`] (bytes pulled from the socket) and the handler (bytes it
/// took out of the parser).
#[derive(Debug)]
pub struct Meter {
    pulled: AtomicU64,
    /// Bytes the handler consumed plus the allowance of every part header seen.
    credit: AtomicU64,
    /// `credit` at the last poll that found the buffer over its allowance.
    stuck_at: AtomicU64,
    /// A size limit ended the body (multer wraps stream errors without a source chain, so the
    /// handler asks the meter instead of walking the error).
    limit: AtomicBool,
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            pulled: AtomicU64::new(0),
            credit: AtomicU64::new(0),
            stuck_at: AtomicU64::new(u64::MAX),
            limit: AtomicBool::new(false),
        }
    }
}

impl Meter {
    /// The handler took `n` bytes of part data out of the parser.
    pub fn consumed(&self, n: usize) {
        self.credit
            .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// A part header was parsed: its framing is accounted for.
    pub fn part(&self) {
        self.credit.fetch_add(PART_ALLOWANCE, Ordering::Relaxed);
    }

    /// Whether a size limit (ceiling or framing allowance) ended the body.
    #[must_use]
    pub fn limit_hit(&self) -> bool {
        self.limit.load(Ordering::Relaxed)
    }

    /// Total bytes pulled from the underlying body so far.
    #[must_use]
    pub fn pulled(&self) -> u64 {
        self.pulled.load(Ordering::Relaxed)
    }
}

/// Body adapter that applies back-pressure to the multipart parser.
///
/// multer drains every frame the socket has ready on each poll and keeps the preamble and a part
/// header block that never terminates in memory, bounded only by the whole-body ceiling
/// (1.25 GiB at the old UI default). `Metered` lets at most `MARGIN + PART_ALLOWANCE x parts`
/// bytes sit between the socket and the handler. Above that it first yields `Pending` (so the
/// parser digests what it has and the handler consumes it: a legitimate stream makes progress and
/// continues); if the handler consumed nothing since the previous such stall, the framing is
/// hostile (or the sender is stuck) and the body fails with [`FramingLimitError`], which the handlers report as 413 like the body ceiling.
pub struct Metered<B> {
    inner: B,
    meter: Arc<Meter>,
}

impl<B> Metered<B> {
    /// Wraps `inner`; the handler advances `meter` as it consumes.
    pub fn new(inner: B, meter: Arc<Meter>) -> Self {
        Self { inner, meter }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<B> Body for Metered<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let m = Arc::clone(&self.meter);
        let credit = m.credit.load(Ordering::Relaxed);
        let outstanding = m.pulled.load(Ordering::Relaxed).saturating_sub(credit);
        if outstanding > MARGIN {
            if m.stuck_at.swap(credit, Ordering::Relaxed) == credit {
                m.limit.store(true, Ordering::Relaxed);
                return Poll::Ready(Some(Err(Box::new(FramingLimitError))));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    m.pulled.fetch_add(
                        u64::try_from(d.len()).unwrap_or(u64::MAX),
                        Ordering::Relaxed,
                    );
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                if chain_has_limit(&e) {
                    m.limit.store(true, Ordering::Relaxed);
                }
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratelimit::ManualClock;

    #[test]
    fn storage_floor_is_the_larger_of_bytes_and_percent() {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::default());
        let provider: SpaceProvider = Arc::new(Vec::new);
        let g = StorageGuard::new(provider, 1000, 5, clock);
        // 5 % of 100_000 = 5000 beats the 1000 byte floor.
        assert!(g.below(Space {
            free: 4999,
            total: 100_000
        }));
        assert!(!g.below(Space {
            free: 5000,
            total: 100_000
        }));
        // Tiny volume: the absolute floor wins.
        assert!(g.below(Space {
            free: 999,
            total: 2000
        }));
    }
}

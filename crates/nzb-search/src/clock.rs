//! Monotonic time behind a trait, so deadlines and count budgets are deterministic in tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::error::SearchError;

/// A monotonic millisecond clock.
pub trait Clock: Send + Sync + 'static {
    /// Milliseconds since an arbitrary, fixed origin; never goes backwards.
    fn now_ms(&self) -> u64;
}

/// The real monotonic clock.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Test clock: returns the stored time and then adds `step` to it on every reading, so a computation
/// that reads the clock `n` times "takes" `n * step` ms.
#[derive(Debug, Default)]
pub struct StepClock {
    now: AtomicU64,
    step: AtomicU64,
}

impl StepClock {
    /// A clock at 0 advancing `step` ms per reading.
    #[must_use]
    pub fn new(step: u64) -> Self {
        Self {
            now: AtomicU64::new(0),
            step: AtomicU64::new(step),
        }
    }

    /// Moves the clock forward by `ms`.
    pub fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    /// Changes the per-reading step.
    pub fn set_step(&self, step: u64) {
        self.step.store(step, Ordering::SeqCst);
    }
}

impl Clock for StepClock {
    fn now_ms(&self) -> u64 {
        let step = self.step.load(Ordering::SeqCst);
        self.now.fetch_add(step, Ordering::SeqCst)
    }
}

/// A point in time after which the current search must stop (`search.query_deadline_ms`).
#[derive(Clone)]
pub struct Deadline {
    clock: Arc<dyn Clock>,
    at_ms: u64,
}

impl std::fmt::Debug for Deadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deadline")
            .field("at_ms", &self.at_ms)
            .finish_non_exhaustive()
    }
}

impl Deadline {
    /// `budget_ms` from now on `clock`.
    #[must_use]
    pub fn after(clock: Arc<dyn Clock>, budget_ms: u64) -> Self {
        let at_ms = clock.now_ms().saturating_add(budget_ms);
        Self { clock, at_ms }
    }

    /// True once the deadline has passed.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.clock.now_ms() > self.at_ms
    }

    /// `Err(Deadline)` once the deadline has passed.
    ///
    /// # Errors
    /// [`SearchError::Deadline`].
    pub fn check(&self) -> Result<(), SearchError> {
        if self.expired() {
            Err(SearchError::Deadline)
        } else {
            Ok(())
        }
    }

    /// A sub-budget ending `budget_ms` from now, but never after this deadline.
    #[must_use]
    pub fn sub(&self, budget_ms: u64) -> Self {
        let at = self.clock.now_ms().saturating_add(budget_ms);
        Self {
            clock: Arc::clone(&self.clock),
            at_ms: at.min(self.at_ms),
        }
    }
}

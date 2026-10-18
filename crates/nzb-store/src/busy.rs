//! The uniform `503 BUSY` (SEC-095, review 35 L8): which store errors mean "the database is busy, try again" and a
//! per-request note the web layer reads.
//!
//! A busy condition is not a bug: an exhausted pool (acquire timeout), a Postgres statement or lock timeout, a
//! SQLite writer that stayed busy past `busy_timeout`, or a reader statement stopped by its deadline. Every handler
//! keeps mapping store errors to its fixed `500 INTERNAL` (no change in 111 places); the [`Store`](crate::Store)
//! dispatch notes a busy error in the request's [`scope`], and the web layer's error finalizer turns that request's
//! 500 into `503 BUSY` with `Retry-After`. Nothing about the error reaches the client either way.

use std::cell::Cell;
use std::future::Future;

use crate::StoreError;

tokio::task_local! {
    static BUSY: Cell<bool>;
}

impl StoreError {
    /// True for errors that mean the database is busy (retry later), not that something is wrong.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        let e = match self {
            Self::Db(e) => e,
            // The search engine's deadline and semaphore (nzb-search maps them to these I/O kinds).
            Self::Io(io) => {
                return matches!(
                    io.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::ResourceBusy
                );
            }
            _ => return false,
        };
        match e {
            sqlx::Error::PoolTimedOut => true,
            // The code spaces overlap (an all-digit SQLSTATE parses as a number), so the backend decides.
            sqlx::Error::Database(d) => {
                let code = d.code().unwrap_or_default();
                if d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                    .is_some()
                {
                    pg_busy(&code)
                } else {
                    sqlite_busy(&code)
                }
            }
            _ => false,
        }
    }
}

/// Postgres SQLSTATE `57014` (statement timeout / cancel) and `55P03` (lock timeout).
fn pg_busy(code: &str) -> bool {
    code == "57014" || code == "55P03"
}

/// SQLite result codes `SQLITE_BUSY` (5), `SQLITE_LOCKED` (6) and `SQLITE_INTERRUPT` (9, the reader deadline),
/// extended codes included (the primary code is the low byte).
fn sqlite_busy(code: &str) -> bool {
    code.parse::<u32>()
        .is_ok_and(|n| matches!(n & 0xff, 5 | 6 | 9))
}

/// Runs `f` with a fresh busy note; returns its output and whether a store call inside it failed busy.
pub async fn scope<F: Future>(f: F) -> (F::Output, bool) {
    BUSY.scope(Cell::new(false), async move {
        let out = f.await;
        let busy = BUSY.try_with(Cell::get).unwrap_or(false);
        (out, busy)
    })
    .await
}

/// Records `e` in the current request's note when it is a busy error (no-op outside a [`scope`]). Called by the
/// [`Store`](crate::Store) dispatch and by the search engine's error conversion.
pub fn note(e: &StoreError) {
    if e.is_busy() {
        let _ = BUSY.try_with(|b| b.set(true));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn busy_codes() {
        for c in ["5", "6", "9", "517", "262"] {
            assert!(sqlite_busy(c), "{c}");
        }
        for c in ["19", "275", "2067", "x"] {
            assert!(!sqlite_busy(c), "{c}");
        }
        for c in ["57014", "55P03"] {
            assert!(pg_busy(c), "{c}");
        }
        // 42501 (insufficient privilege) would be "busy" if read as a SQLite number: never mixed up.
        for c in ["23505", "42501", "40001", "5"] {
            assert!(!pg_busy(c), "{c}");
        }
        assert!(StoreError::Db(sqlx::Error::PoolTimedOut).is_busy());
        assert!(!StoreError::NotFound.is_busy());
        for k in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::ResourceBusy,
        ] {
            assert!(StoreError::Io(std::io::Error::from(k)).is_busy());
        }
        assert!(!StoreError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)).is_busy());
    }

    #[tokio::test]
    async fn the_note_is_per_scope() {
        let ((), busy) = scope(async { note(&StoreError::Db(sqlx::Error::PoolTimedOut)) }).await;
        assert!(busy);
        let ((), busy) = scope(async { note(&StoreError::NotFound) }).await;
        assert!(!busy);
        // Outside a scope nothing happens (and nothing panics).
        note(&StoreError::Db(sqlx::Error::PoolTimedOut));
    }
}

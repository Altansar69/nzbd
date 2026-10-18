//! Search error type. Messages are fixed strings: no query text, no NZB data, no expanded term (I2).

use nzb_store::StoreError;

/// Errors of the search engine.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    /// Tantivy failed (I/O, corrupt segment, writer poisoned by a panic).
    #[error("search engine error")]
    Engine(#[from] tantivy::TantivyError),
    /// The query deadline passed (`search.query_deadline_ms`): expansion, weight builds or collection.
    #[error("search deadline exceeded")]
    Deadline,
    /// No search slot within the wait limit (`search.max_concurrent_searches`): uniform `503 BUSY`.
    #[error("search busy")]
    Busy,
    /// The index must not be served (epoch/schema mismatch, ahead of the database, unreadable payload).
    #[error("index not servable: {0}")]
    NotServable(&'static str),
    /// The cursor or paging request cannot be served (other sort order, offset beyond the cap).
    #[error("out of range: {0}")]
    OutOfRange(&'static str),
    /// The document source or the hydrator failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// Filesystem error in the index directory.
    #[error("index io error")]
    Io(#[from] std::io::Error),
    /// The writer is gone (after a panic it is reopened; see the indexer).
    #[error("index writer unavailable")]
    WriterUnavailable,
    /// A blocking task was cancelled or panicked.
    #[error("search task failed")]
    Task,
    /// Test-only injected crash (fault injection); never produced in production builds.
    #[cfg(test)]
    #[error("injected crash")]
    Injected,
}

impl From<tantivy::directory::error::OpenReadError> for SearchError {
    fn from(e: tantivy::directory::error::OpenReadError) -> Self {
        Self::Engine(e.into())
    }
}

/// The trait methods of `SearchIndex` return [`StoreError`]; engine conditions map to I/O kinds the web
/// layer can recognise (`TimedOut`/`ResourceBusy` -> uniform `503 BUSY`).
impl From<SearchError> for StoreError {
    fn from(e: SearchError) -> Self {
        use std::io::{Error, ErrorKind};
        let s = match e {
            SearchError::Store(s) => s,
            SearchError::OutOfRange(what) => Self::OutOfRange(what),
            SearchError::Deadline => Self::Io(Error::new(ErrorKind::TimedOut, "search deadline")),
            SearchError::Busy => Self::Io(Error::new(ErrorKind::ResourceBusy, "search busy")),
            SearchError::Io(io) => Self::Io(io),
            SearchError::NotServable(what) => Self::Integrity(format!("search index: {what}")),
            other => Self::Io(Error::other(other.to_string())),
        };
        // A busy or timed-out search answers the uniform 503 BUSY in the web layer (SEC-095), like a busy database.
        nzb_store::busy::note(&s);
        s
    }
}

#[cfg(test)]
mod busy_tests {
    use super::*;

    /// SEC-095: the engine's deadline and semaphore become the uniform 503 BUSY (the web layer reads the note).
    #[tokio::test]
    async fn sec_095_search_busy_and_deadline_are_noted_as_busy() {
        for e in [SearchError::Busy, SearchError::Deadline] {
            let (s, busy) = nzb_store::busy::scope(async { StoreError::from(e) }).await;
            assert!(busy && s.is_busy());
        }
        let (_, busy) =
            nzb_store::busy::scope(async { StoreError::from(SearchError::OutOfRange("x")) }).await;
        assert!(!busy);
    }
}

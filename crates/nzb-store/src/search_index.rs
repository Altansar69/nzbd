//! The search/listing seam (`docs/DATA_MODEL.md` section "Search index contract", T091).
//!
//! [`SearchIndex`] is everything the web layer needs from search and listing: offset pages, keyset
//! pages, totals and the two maintenance hooks. v3: the Tantivy index of `nzb-search` is the one
//! implementation for both backends (D35 c; the 2.x SQLite FTS5 engine is retired).
//!
//! Dispatch choice: the trait uses native `async fn`-in-trait style signatures
//! (`-> impl Future + Send`), so it is **not** dyn-compatible, and consumers are generic
//! (`fn routes_with<S: SearchIndex>(..)`). That avoids boxing every future by hand and needs no
//! `async-trait` dependency; the engine is chosen once at start-up (in `nzbd`), so static dispatch costs
//! nothing and a second engine is a type parameter, not a vtable.

use std::future::Future;

use crate::StoreError;
use crate::release::{KeysetPage, Page, PageCursor, ReleaseRow, SearchQuery, SeekDir};

/// The searchable text of one release; what an engine indexes.
#[derive(Debug, Clone, Copy)]
pub struct SearchDoc<'a> {
    /// `release.id`; also the engine's document key.
    pub release_id: i64,
    /// Display title.
    pub title: &'a str,
    /// File names of the release, space separated.
    pub filenames: &'a str,
    /// Poster (empty when unknown).
    pub poster: &'a str,
}

/// What a search engine must provide. See `docs/DATA_MODEL.md` for the guarantees an implementation
/// has to keep; the conformance suite (`search_index_conformance`, test-only in this crate) checks them.
pub trait SearchIndex: Clone + Send + Sync + 'static {
    /// One offset page of the listing of `q` (filters, text, `exclude_categories`, sort, offset, limit)
    /// with the exact total of matches.
    ///
    /// # Errors
    /// Engine/database errors only; hostile `q.q` text must not be able to fail the query.
    fn search(
        &self,
        q: &SearchQuery,
    ) -> impl Future<Output = Result<Page<ReleaseRow>, StoreError>> + Send;

    /// The page next to the cursor `at` ([`SeekDir::After`] / [`SeekDir::Before`]); `q.offset` is
    /// ignored; same rows, order and total as [`SearchIndex::search`].
    ///
    /// # Errors
    /// As [`SearchIndex::search`]; [`StoreError::OutOfRange`] if `at` was made for another sort order.
    fn search_keyset(
        &self,
        q: &SearchQuery,
        dir: SeekDir,
        at: &PageCursor,
    ) -> impl Future<Output = Result<KeysetPage, StoreError>> + Send;

    /// Exact number of releases matching `q` (paging fields ignored).
    ///
    /// # Errors
    /// As [`SearchIndex::search`].
    fn count(&self, q: &SearchQuery) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Insert or replace the searchable text of one release (idempotent).
    ///
    /// For an engine inside the release database the store's own write paths do this in the release's
    /// transaction; this standalone form is the re-index / reconciliation hook for the others.
    ///
    /// # Errors
    /// Engine/database errors.
    fn upsert(&self, doc: &SearchDoc<'_>) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Drop a release from the index (idempotent: an unknown id is not an error).
    ///
    /// # Errors
    /// Engine/database errors.
    fn remove(&self, release_id: i64) -> impl Future<Output = Result<(), StoreError>> + Send;
}

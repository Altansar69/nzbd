//! Saved searches with a "new since last visit" badge (T127, D38; `docs/UI_SPEC.md` "Saved searches").
//!
//! * **Stored form.** The validated, structured filter set of the index page: the canonical parameter pairs of
//!   [`IndexParams::canonical_pairs`] as a JSON object of strings (`{"q":"...","cat":"tv.hd","sort":"size_asc"}`).
//!   Every use (open, count, list) rebuilds a query string from exactly the allowlisted names in [`SAVED_KEYS`] and
//!   runs it through [`parse_params`], the parser of the index query string; anything it refuses makes the saved
//!   search unusable (`400 BAD_QUERY` on open, no badge, "not available" on the list). It is never search-engine
//!   syntax and never a URL; paging and cursors are not part of it.
//! * **Privacy.** Every read and write is scoped by the session's account id in the store; another account's id, an
//!   unknown id and a malformed id are the same uniform 404. There is no admin view.
//! * **Hidden categories.** A saved search whose category is hidden for the caller (instance `ui.show_xxx = false`
//!   or the caller's "Hide XXX for me") is neither counted nor opened (`400 BAD_QUERY`, like `/?cat=<hidden>`); every
//!   count carries the caller's exclusion set exactly like the result list, so a badge never counts a hidden release.
//! * **Badges.** "N new" = releases matching the search with `ingested_at >= last_seen_at`, counted by the search
//!   engine (`SearchIndexV3::count_total` with `ingested_since`, both backends), shown capped at `99+`. All counts of
//!   one page share one time budget ([`SAVED_COUNT_BUDGET`], D35 Q1): a search not counted in time shows no badge.
//! * **Writes.** `POST` only, session + CSRF + Origin (the access gate), owner only; the store enforces the limit
//!   (`SAVED_SEARCH_LIMIT`) and unique names (`SAVED_SEARCH_DUPLICATE`).

use std::time::{Duration, Instant};

use askama::Template;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use nzb_search::SearchIndexV3;
use nzb_search::request::{MatchMode, SearchRequest, Total};
use nzb_store::prelude::*;
use nzb_store::{
    MAX_SAVED_SEARCHES, SavedSearch, SavedSearchError, StoreError, clean_saved_search_name,
};

use crate::assets::{Layout, SavedLink};
use crate::auth::SessionCtx;
use crate::csrf;
use crate::error::ApiError;
use crate::index::{BadQuery, IndexParams, IndexState, parse_params, pct_encode};

/// Total time all badge counts of one index page may take (D35 Q1: counts over 150 ms are not waited for).
pub const SAVED_COUNT_BUDGET: Duration = Duration::from_millis(150);
/// Largest badge number shown; more reads `99+`.
pub const BADGE_CAP: u64 = 99;
/// The index parameter names a stored filter set may carry (the canonical pairs; no paging, no cursor).
pub const SAVED_KEYS: &[&str] = &[
    "q",
    "cat",
    "from",
    "to",
    "min_mib",
    "max_mib",
    "incomplete",
    "par2",
    "obfuscated",
    "family",
    "res",
    "source",
    "year",
    "group",
    "sort",
];
/// Fields the save form may carry at most (token, name, the filter names, slack); more is `400 BAD_REQUEST`.
const SAVE_MAX_FIELDS: usize = 24;
/// Fields the rename and delete forms may carry at most.
const SMALL_FORM_MAX_FIELDS: usize = 4;

fn fail(status: StatusCode, code: &'static str) -> Response {
    ApiError::new(status, code).into_response()
}

fn not_found() -> Response {
    fail(StatusCode::NOT_FOUND, "NOT_FOUND")
}

fn bad_query() -> Response {
    fail(StatusCode::BAD_REQUEST, "BAD_QUERY")
}

fn bad_request() -> Response {
    fail(StatusCode::BAD_REQUEST, "BAD_REQUEST")
}

fn internal() -> Response {
    fail(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
}

/// `303 See Other` to a location built by this module (an index href of validated, percent-encoded values, or a
/// fixed path): ASCII only, so the header value cannot fail; a failure is an internal error, never a partial header.
pub(crate) fn see_other(location: &str) -> Response {
    let Ok(v) = HeaderValue::from_str(location) else {
        return internal();
    };
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(header::LOCATION, v);
    // The open redirect records a visit (review 42 I1): no cache or intermediary may replay it.
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The store's refusal as the client answer (stable codes; another account's row is the uniform 404).
fn store_error(e: StoreError) -> Response {
    match e {
        StoreError::SavedSearch(r) => {
            let status = match r {
                SavedSearchError::Limit | SavedSearchError::Duplicate => StatusCode::CONFLICT,
                SavedSearchError::InvalidName | SavedSearchError::InvalidFilters => {
                    StatusCode::BAD_REQUEST
                }
            };
            fail(status, r.code())
        }
        StoreError::NotFound | StoreError::Account(_) => not_found(),
        other => {
            tracing::error!(error = %other, "saved search operation failed");
            internal()
        }
    }
}

/// A query string of `pairs` restricted to [`SAVED_KEYS`] (values percent-encoded; the names are fixed identifiers).
pub(crate) fn saved_query<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    pairs
        .filter(|(k, _)| SAVED_KEYS.contains(k))
        .map(|(k, v)| format!("{k}={}", pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The stored form of validated parameters: their canonical pairs as a JSON object of strings.
#[must_use]
pub fn to_stored(p: &IndexParams, tax: &nzb_core::Taxonomy) -> String {
    let map: serde_json::Map<String, serde_json::Value> = p
        .canonical_pairs(tax, p.sort, true)
        .into_iter()
        .map(|(k, v)| (k.to_owned(), serde_json::Value::String(v)))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// Re-validates a stored filter set through the index parser.
///
/// # Errors
/// [`BadQuery`] for anything but a JSON object of strings with names from [`SAVED_KEYS`], or for values the index
/// parser refuses (an unknown category after a taxonomy change, for example).
pub fn from_stored(json: &str, tax: &nzb_core::Taxonomy) -> Result<IndexParams, BadQuery> {
    let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(json) else {
        return Err(BadQuery);
    };
    let mut pairs = Vec::with_capacity(m.len());
    for (k, v) in &m {
        let serde_json::Value::String(v) = v else {
            return Err(BadQuery);
        };
        if !SAVED_KEYS.contains(&k.as_str()) {
            return Err(BadQuery);
        }
        pairs.push((k.as_str(), v.as_str()));
    }
    parse_params(Some(&saved_query(pairs.into_iter())), tax)
}

/// Badge text of a count: empty for none, the number up to [`BADGE_CAP`], `99+` beyond; a lower bound below the cap
/// reads `n+`.
#[must_use]
pub fn badge_text(t: Total) -> String {
    match t {
        Total::Exact(0) | Total::AtLeast(0) => String::new(),
        Total::Exact(n) if n <= BADGE_CAP => n.to_string(),
        Total::AtLeast(n) if n < BADGE_CAP => format!("{n}+"),
        _ => format!("{BADGE_CAP}+"),
    }
}

/// Validated parameters of a saved search, or `None` when it cannot be used by this caller (refused by the parser,
/// or its category is hidden for the caller).
fn usable(s: &SavedSearch, sess: &SessionCtx, tax: &nzb_core::Taxonomy) -> Option<IndexParams> {
    let p = from_stored(&s.filters, tax).ok()?;
    if p.category
        .is_some_and(|c| sess.hidden_categories.contains(&c))
    {
        return None;
    }
    Some(p)
}

/// The count request of a saved search's badge: its filters, the caller's exclusion set (exactly as the result
/// list), releases ingested at or after the second of the last visit (inclusive, so a release of that very second
/// is counted once more rather than never), one row.
fn new_request(p: &IndexParams, s: &SavedSearch, hidden: &[u32]) -> Option<SearchRequest> {
    let mut query = p.to_search(1).ok()?;
    query.exclude_categories = hidden.to_vec();
    query.offset = 0;
    query.limit = 1;
    Some(SearchRequest {
        query,
        // The index list's matching (prefix on the last word); the count never runs the fuzzy fallback.
        match_mode: MatchMode::Prefix,
        ingested_since: Some(s.last_seen_at),
        ..SearchRequest::default()
    })
}

/// The sidebar links of the caller's saved searches with their badges. Never fails the page: a store error shows
/// no section entries, a count error or a count beyond the shared budget shows no badge.
pub(crate) async fn sidebar_links<S: SearchIndexV3>(
    st: &IndexState<S>,
    sess: &SessionCtx,
) -> Vec<SavedLink> {
    let list = match st.db.saved_searches(sess.user_id).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "saved searches unavailable");
            return Vec::new();
        }
    };
    let tax = st.taxonomy.as_ref();
    let hidden = sess.hidden_ids();
    let started = Instant::now();
    let mut out = Vec::with_capacity(list.len());
    for s in list {
        let left = SAVED_COUNT_BUDGET.saturating_sub(started.elapsed());
        let req = usable(&s, sess, tax).and_then(|p| new_request(&p, &s, &hidden));
        let badge = match req {
            Some(mut req) if !left.is_zero() => {
                // The remaining budget is also the engine's deadline and the slot is never waited for (review 42
                // L1): a count the page stops waiting for stops itself and frees its search slot.
                req.caller_deadline_ms = Some(u64::try_from(left.as_millis()).unwrap_or(1).max(1));
                match tokio::time::timeout(left, st.search.count_total(&req)).await {
                    Ok(Ok(t)) => badge_text(t),
                    // An engine error (degraded, busy) or the budget: no badge rather than a slower page.
                    Ok(Err(_)) | Err(_) => String::new(),
                }
            }
            _ => String::new(),
        };
        out.push(SavedLink {
            href: format!("/search/saved/{}", s.id),
            name: s.name,
            badge,
        });
    }
    out
}

/// Strict saved-search id: 1-15 ASCII digits, positive. Anything else is the uniform 404.
fn parse_id(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 15 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok().filter(|n| *n > 0)
}

/// `POST /search/saved`: saves the search carried by the form (the index page's hidden fields) under `name`.
/// Strict form (at most 24 fields, no repeated field: `400 BAD_REQUEST`); the name is cleaned and must be 1-60
/// characters (`400 SAVED_SEARCH_NAME`); the filters go through the index parser (`400 BAD_QUERY`, also for a hidden
/// category); then the store's limit and uniqueness (`409 SAVED_SEARCH_LIMIT` / `409 SAVED_SEARCH_DUPLICATE`).
/// Success: `303` to the index with the saved filters.
pub(crate) async fn create<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
    body: Bytes,
) -> Response {
    let tax = st.taxonomy.as_ref();
    let Some(form) = csrf::parse_form_strict(&body, SAVE_MAX_FIELDS) else {
        return bad_request();
    };
    let singles: Vec<&str> = ["csrf_token", "name"]
        .iter()
        .chain(SAVED_KEYS.iter())
        .copied()
        .collect();
    if !csrf::singletons_ok(&form, &singles) {
        return bad_request();
    }
    let Some(name) = csrf::form_get(&form, "name").and_then(clean_saved_search_name) else {
        return fail(
            StatusCode::BAD_REQUEST,
            SavedSearchError::InvalidName.code(),
        );
    };
    let query = saved_query(form.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let Ok(p) = parse_params(Some(&query), tax) else {
        return bad_query();
    };
    if p.category
        .is_some_and(|c| sess.hidden_categories.contains(&c))
    {
        return bad_query();
    }
    match st
        .db
        .create_saved_search(
            sess.user_id,
            &name,
            &to_stored(&p, tax),
            st.clock.now_secs(),
        )
        .await
    {
        Ok(_) => see_other(&p.href(tax, p.sort, 1, true)),
        Err(e) => store_error(e),
    }
}

/// `GET /search/saved/{id}` (owner only, uniform 404 otherwise): re-validates the stored filters, records the visit
/// (`last_seen_at`, which resets the badge) and redirects (`303`) to the index with those filters. A filter set the
/// parser now refuses, or one whose category is hidden for the caller, is `400 BAD_QUERY` and records nothing.
pub(crate) async fn open<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
    Path(raw): Path<String>,
) -> Response {
    let tax = st.taxonomy.as_ref();
    let Some(id) = parse_id(&raw) else {
        return not_found();
    };
    let list = match st.db.saved_searches(sess.user_id).await {
        Ok(l) => l,
        Err(e) => return store_error(e),
    };
    let Some(s) = list.into_iter().find(|s| s.id == id) else {
        return not_found();
    };
    let Some(p) = usable(&s, &sess, tax) else {
        return bad_query();
    };
    match st
        .db
        .open_saved_search(sess.user_id, id, st.clock.now_secs())
        .await
    {
        Ok(Some(_)) => see_other(&p.href(tax, p.sort, 1, true)),
        Ok(None) => not_found(),
        Err(e) => store_error(e),
    }
}

/// `POST /search/saved/{id}/rename` (owner only): `name` cleaned, 1-60 characters, unique among the caller's saved
/// searches. Success: `303` to the Saved searches page.
pub(crate) async fn rename<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let Some(id) = parse_id(&raw) else {
        return not_found();
    };
    let Some(form) = csrf::parse_form_strict(&body, SMALL_FORM_MAX_FIELDS) else {
        return bad_request();
    };
    if !csrf::singletons_ok(&form, &["csrf_token", "name"]) {
        return bad_request();
    }
    let Some(name) = csrf::form_get(&form, "name").and_then(clean_saved_search_name) else {
        return fail(
            StatusCode::BAD_REQUEST,
            SavedSearchError::InvalidName.code(),
        );
    };
    match st.db.rename_saved_search(sess.user_id, id, &name).await {
        Ok(()) => see_other("/search/saved"),
        Err(e) => store_error(e),
    }
}

/// `POST /search/saved/{id}/delete` (owner only). Success: `303` to the Saved searches page.
pub(crate) async fn delete<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let Some(id) = parse_id(&raw) else {
        return not_found();
    };
    if csrf::parse_form_strict(&body, SMALL_FORM_MAX_FIELDS).is_none() {
        return bad_request();
    }
    match st.db.delete_saved_search(sess.user_id, id).await {
        Ok(()) => see_other("/search/saved"),
        Err(e) => store_error(e),
    }
}

/// One row of the Saved searches page.
struct Row {
    id: i64,
    name: String,
    /// What the search filters on (fixed labels plus the account's own values, escaped by askama); for an unusable
    /// search a fixed note.
    summary: String,
    /// The search can be opened (its filters pass the parser and its category is visible to the caller).
    usable: bool,
}

#[derive(Template)]
#[template(path = "saved_searches.html")]
struct SavedPage {
    layout: Layout,
    rows: Vec<Row>,
    max: i64,
}

/// What a usable search filters on, in the words of the index's filter chips.
fn summary(p: &IndexParams, tax: &nzb_core::Taxonomy) -> String {
    let labels: Vec<String> = p.chips(tax).into_iter().map(|c| c.label).collect();
    if labels.is_empty() {
        "All releases".to_owned()
    } else {
        labels.join(" \u{b7} ")
    }
}

/// `GET /search/saved`: the caller's saved searches with open, rename and delete (no JavaScript).
pub(crate) async fn list_page<S: SearchIndexV3>(
    State(st): State<IndexState<S>>,
    Extension(sess): Extension<SessionCtx>,
) -> Response {
    let tax = st.taxonomy.as_ref();
    let list = match st.db.saved_searches(sess.user_id).await {
        Ok(l) => l,
        Err(e) => return store_error(e),
    };
    let rows = list
        .into_iter()
        .map(|s| {
            let p = usable(&s, &sess, tax);
            Row {
                id: s.id,
                summary: p.as_ref().map_or_else(
                    || "This search can no longer be opened (a filter is not valid or not available).".to_owned(),
                    |p| summary(p, tax),
                ),
                usable: p.is_some(),
                name: s.name,
            }
        })
        .collect();
    let page = SavedPage {
        layout: Layout::for_session("Saved searches", &sess),
        rows,
        max: MAX_SAVED_SEARCHES,
    };
    match page.render() {
        Ok(body) => Html(body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "saved searches render failed");
            internal()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tax() -> nzb_core::Taxonomy {
        nzb_core::Taxonomy::builtin().unwrap()
    }

    #[test]
    fn stored_form_round_trips_through_the_index_parser() {
        let t = tax();
        let p = parse_params(
            Some("q=a%26b%3D%22%3Cx%3E&cat=tv.hd&group=A+B&year=2020&par2=1&sort=size_asc&page=4"),
            &t,
        )
        .unwrap();
        let json = to_stored(&p, &t);
        // Paging is not part of a saved search.
        assert!(!json.contains("page"), "{json}");
        let back = from_stored(&json, &t).unwrap();
        assert_eq!(back.q, p.q);
        assert_eq!(back.category, p.category);
        assert_eq!(back.group, p.group);
        assert_eq!(back.year, p.year);
        assert!(back.par2);
        assert_eq!(back.sort, p.sort);
        assert_eq!(back.page, 1);
        assert_eq!(back.cursor, None);
        assert_eq!(to_stored(&back, &t), json);
    }

    #[test]
    fn stored_form_is_strict() {
        let t = tax();
        for bad in [
            "[]",
            "{\"q\":1}",
            "{\"page\":\"2\"}",
            "{\"after\":\"00\"}",
            "{\"cat\":\"nope\"}",
            "{\"year\":\"20x0\"}",
            "{\"q\":\"x\",\"evil\":\"1\"}",
            "not json",
        ] {
            assert!(from_stored(bad, &t).is_err(), "{bad}");
        }
        assert_eq!(from_stored("{}", &t).unwrap().page, 1);
    }

    #[test]
    fn badges_are_capped() {
        assert_eq!(badge_text(Total::Exact(0)), "");
        assert_eq!(badge_text(Total::Exact(7)), "7");
        assert_eq!(badge_text(Total::Exact(99)), "99");
        assert_eq!(badge_text(Total::Exact(100)), "99+");
        assert_eq!(badge_text(Total::AtLeast(0)), "");
        assert_eq!(badge_text(Total::AtLeast(12)), "12+");
        assert_eq!(badge_text(Total::AtLeast(500)), "99+");
    }

    #[test]
    fn ids_are_strict() {
        assert_eq!(parse_id("12"), Some(12));
        for bad in ["", "0", "-1", "1e3", "12a", "1234567890123456", " 1"] {
            assert_eq!(parse_id(bad), None, "{bad:?}");
        }
    }
}

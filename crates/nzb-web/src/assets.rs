//! Vendored static assets (SEC-043) and the shared template layout context.
//!
//! Assets are compiled into the binary (`include_bytes!`), so the app never reads arbitrary
//! files from disk and never fetches anything. Each asset has a pinned SHA-256 that a test
//! verifies; changing an asset therefore requires an explicit, reviewable hash update.
//! Pages reference assets as `/static/<name>?v=<hash prefix>`, which makes the
//! `immutable` cache lifetime safe across upgrades.

use std::fmt::Write as _;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// One vendored file.
pub struct Asset {
    /// File name under `/static/`.
    pub name: &'static str,
    /// `Content-Type` value.
    pub mime: &'static str,
    /// Embedded bytes.
    pub bytes: &'static [u8],
    /// Pinned lowercase hex SHA-256 of `bytes`; verified by tests.
    pub sha256: &'static str,
}

/// Every servable asset. `htmx.min.js` is htmx 2.0.11 (0BSD) exactly as published in the npm
/// package `htmx.org@2.0.11` (`package/dist/htmx.min.js`); to upgrade, replace the file and the
/// hash below in one reviewable change.
pub const ASSETS: &[Asset] = &[
    Asset {
        name: "app.css",
        mime: "text/css; charset=utf-8",
        bytes: include_bytes!("../../../static/app.css"),
        sha256: "dca541b682c2ca5bc70a54aca51fdb660c4ebfd5865c328c55eb0206dd4021f0",
    },
    Asset {
        name: "app.js",
        mime: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../../static/app.js"),
        sha256: "9980b6990e86203ba1e996790885019584dc867ab167953a7645621b6114d825",
    },
    Asset {
        name: "htmx.min.js",
        mime: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../../static/htmx.min.js"),
        sha256: "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717",
    },
];

fn hex(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len().saturating_mul(2));
    for b in digest {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Looks up an asset by exact name.
#[must_use]
pub fn find(name: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.name == name)
}

/// Cache-busting version (first 12 hex chars of the pinned hash) for templates.
fn version(name: &str) -> Option<String> {
    static VERSIONS: OnceLock<Vec<(&'static str, String)>> = OnceLock::new();
    let table = VERSIONS.get_or_init(|| {
        ASSETS
            .iter()
            .map(|a| (a.name, sha256_hex(a.bytes).chars().take(12).collect()))
            .collect()
    });
    table
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.clone())
}

/// Values every page needs from the base layout (`templates/base.html`).
#[allow(clippy::struct_excessive_bools)] // independent display flags of one template
pub struct Layout {
    /// Page title (static English text; never NZB-derived).
    pub title: &'static str,
    /// CSRF token for the `<meta>` tag and the logout form; `None` on unauthenticated pages.
    pub csrf_token: Option<String>,
    /// Shows the navigation bar.
    pub authenticated: bool,
    /// Cache-busting version of `app.css`.
    pub css_ver: String,
    /// Cache-busting version of `app.js`.
    pub js_ver: String,
    /// Version of `htmx.min.js`; `None` when the asset is not vendored (pages work without JS).
    pub htmx_ver: Option<String>,
    /// Which navigation entry is current (`index`, `upload`, `stats`, `admin`, `cleanup`, `health`, `account`, or empty);
    /// derived from the title so handlers need no extra plumbing.
    pub nav: &'static str,
    /// Human label of the current navigation entry (breadcrumb); empty when none.
    pub nav_label: &'static str,
    /// Application version shown in the footer.
    pub version: &'static str,
    /// Sidebar quick-links to the top-level taxonomy categories (fixed list, built once).
    pub browse: Vec<BrowseLink>,
    /// Slug of the top-level category whose filter is active on the index (`aria-current`);
    /// empty otherwise. Always a taxonomy slug, never request data.
    pub browse_cur: String,
    /// The caller's own display name (never the login name; escaped by askama). Empty on
    /// unauthenticated pages.
    pub who: String,
    /// Text of the role badge (`Viewer` / `Uploader` / `Admin`); empty on unauthenticated pages.
    pub role_label: &'static str,
    /// Navigation: the Upload entry (uploader and admin). Cosmetic: every route is enforced.
    pub can_upload: bool,
    /// Navigation: the Manage entries (admin).
    pub is_admin: bool,
    /// Navigation: the Users entry (admin, only while `security.multi_user` is on).
    pub users_link: bool,
    /// `data-theme` of `<html>` (T120): `auto` (follow the OS), `light` or `dark`. Always one of these
    /// three fixed strings ([`nzb_store::Theme::as_str`]), never request data. Pages without a session
    /// (sign-in, errors, the uniform 404) are always `auto`.
    pub theme: &'static str,
    /// Shows the "Saved searches" sidebar section (T127): the index page only.
    pub saved_section: bool,
    /// The caller's own saved searches for that section (empty on every other page).
    pub saved: Vec<SavedLink>,
}

/// One sidebar saved-search link (T127): `/search/saved/<id>` with the account's own name and its badge.
#[derive(Debug, Clone)]
pub struct SavedLink {
    /// `/search/saved/<id>` (a decimal id; never request data).
    pub href: String,
    /// The name the account chose (sanitized when saved; escaped by askama).
    pub name: String,
    /// Releases matching the search ingested since the last visit: `3`, `99+`, or empty for no badge (none new,
    /// not counted within the time budget, or not countable).
    pub badge: String,
}

/// One sidebar category link: `/?cat=<slug>` with a slug from the built-in taxonomy.
#[derive(Debug, Clone)]
pub struct BrowseLink {
    /// Taxonomy id (used to drop hidden categories).
    pub id: u16,
    /// Taxonomy slug (`[a-z0-9.]`, validated at taxonomy load).
    pub slug: String,
    /// Taxonomy display name.
    pub name: String,
    /// Releases in this category and its children, with thousands separators (T124 U14). Empty when not known:
    /// only the index page reads the per-category totals, every other page shows the plain link.
    pub count: String,
}

/// Top-level categories of the built-in taxonomy (the only taxonomy the app loads).
fn browse_links() -> &'static [BrowseLink] {
    static LINKS: std::sync::OnceLock<Vec<BrowseLink>> = std::sync::OnceLock::new();
    LINKS.get_or_init(|| {
        nzb_core::Taxonomy::builtin()
            .map(|t| {
                t.entries()
                    .iter()
                    .filter(|c| c.parent.is_none())
                    .map(|c| BrowseLink {
                        id: c.id,
                        slug: c.slug.clone(),
                        name: c.name.clone(),
                        count: String::new(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn nav_label(nav: &str) -> &'static str {
    match nav {
        "index" => "Index",
        "upload" => "Upload",
        "admin" => "Admin",
        "users" => "Users",
        "cleanup" => "Cleanup",
        "activity" => "Activity",
        "health" => "Health",
        "account" => "Account",
        "stats" => "Statistics",
        _ => "",
    }
}

/// Maps a page title to its navigation entry (`aria-current="page"`).
fn nav_for(title: &str) -> &'static str {
    match title {
        "Index" | "Release" | "Segments" | "Delete release" | "Release deleted"
        | "Delete releases" | "Releases deleted" | "Category updated" | "Source updated"
        | "Saved searches" => "index",
        "Upload" | "Upload results" => "upload",
        "Admin" => "admin",
        "Users" | "User action" | "Invitation created" | "Invite a user" => "users",
        "Cleanup" | "Purge" | "Purge result" => "cleanup",
        "Health" => "health",
        "Activity" => "activity",
        "Statistics" => "stats",
        "Account" | "New API key" | "Recovery codes" => "account",
        _ => "",
    }
}

impl Layout {
    /// Layout for an unauthenticated page.
    #[must_use]
    pub fn new(title: &'static str) -> Self {
        Self {
            title,
            csrf_token: None,
            authenticated: false,
            css_ver: version("app.css").unwrap_or_default(),
            js_ver: version("app.js").unwrap_or_default(),
            htmx_ver: version("htmx.min.js"),
            nav: nav_for(title),
            nav_label: nav_label(nav_for(title)),
            version: env!("CARGO_PKG_VERSION"),
            browse: browse_links().to_vec(),
            browse_cur: String::new(),
            who: String::new(),
            role_label: "",
            can_upload: false,
            is_admin: false,
            users_link: false,
            theme: nzb_store::Theme::Auto.as_str(),
            saved_section: false,
            saved: Vec::new(),
        }
    }

    /// Authenticated layout for `sess`: CSRF token plus a sidebar without hidden categories
    /// (`ui.show_xxx = false`).
    #[must_use]
    pub fn for_session(title: &'static str, sess: &crate::SessionCtx) -> Self {
        let mut l = Self::authed(title, sess.csrf_token.clone()).hiding(&sess.hidden_categories);
        l.who.clone_from(&sess.display_name);
        l.role_label = crate::account::role_label(sess.role);
        l.can_upload = sess.role >= nzb_store::Role::Uploader;
        l.is_admin = sess.role >= nzb_store::Role::Admin;
        l.users_link = l.is_admin && sess.multi_user;
        l.theme = sess.prefs.theme.as_str();
        l
    }

    /// Uses the account's theme (T120).
    #[must_use]
    pub const fn themed(mut self, theme: nzb_store::Theme) -> Self {
        self.theme = theme.as_str();
        self
    }

    /// Sets the per-category counts of the sidebar links (T124 U14). `count_of` answers for a top-level category id;
    /// the caller has already left out every hidden category, so a count never includes a hidden release.
    pub fn with_browse_counts(&mut self, count_of: impl Fn(u16) -> String) {
        for b in &mut self.browse {
            b.count = count_of(b.id);
        }
    }

    /// Drops the sidebar links of the given category ids.
    #[must_use]
    pub fn hiding(mut self, hidden: &[u16]) -> Self {
        self.browse.retain(|b| !hidden.contains(&b.id));
        self
    }

    /// Layout for an authenticated page carrying the session's CSRF token.
    #[must_use]
    pub fn authed(title: &'static str, csrf_token: String) -> Self {
        Self {
            csrf_token: Some(csrf_token),
            authenticated: true,
            ..Self::new(title)
        }
    }
}

/// `GET /static/{*path}`: serves an embedded asset by exact name (no filesystem access, so no
/// traversal surface). Supports `If-None-Match`.
pub(crate) async fn serve(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let name = uri.path().strip_prefix("/static/").unwrap_or_default();
    let Some(asset) = find(name) else {
        return ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND").into_response();
    };
    let etag = format!("\"{}\"", asset.sha256);
    let cache = HeaderValue::from_static("public, max-age=31536000, immutable");
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    let mut resp = if fresh {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let body = if method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(asset.bytes)
        };
        let mut r = Response::new(body);
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.mime));
        r
    };
    resp.headers_mut().insert(header::CACHE_CONTROL, cache);
    if let Ok(v) = HeaderValue::from_str(&etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp
}

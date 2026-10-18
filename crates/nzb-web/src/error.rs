//! Generic client-facing errors (SEC-034).
//!
//! Handlers and layers produce an [`ApiError`] (or any 4xx/5xx response); the outermost
//! middleware replaces the body with a uniform JSON or HTML document that carries only a
//! stable `code` and the `request_id`. Details belong in logs, never in responses.

use askama::Template;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::assets::Layout;

/// Stable machine-readable error code attached to a response by [`ApiError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorCode(pub &'static str);

/// An error response with a stable code. The body is rendered later by the context layer.
#[derive(Clone, Copy, Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    retry_after: Option<u64>,
}

impl ApiError {
    /// Error with an explicit status and stable code (`UPPER_SNAKE_CASE`).
    #[must_use]
    pub const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after: None,
        }
    }

    /// Adds a `Retry-After` header (seconds).
    #[must_use]
    pub const fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = Response::new(axum::body::Body::empty());
        *resp.status_mut() = self.status;
        resp.extensions_mut().insert(ErrorCode(self.code));
        if let Some(secs) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&secs.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

/// Default stable code for a status produced without an explicit [`ErrorCode`]
/// (router 404/405, layer-generated 413, ...).
#[must_use]
pub fn code_for_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "BAD_REQUEST",
        401 => "UNAUTHORIZED",
        403 => "FORBIDDEN",
        404 => "NOT_FOUND",
        405 => "METHOD_NOT_ALLOWED",
        408 | 504 => "TIMEOUT",
        413 => "FILE_TOO_LARGE",
        414 | 431 => "REQUEST_TOO_LARGE",
        415 => "UNSUPPORTED_MEDIA_TYPE",
        422 => "UNPROCESSABLE",
        429 => "RATE_LIMITED",
        503 => "BUSY",
        507 => "INSUFFICIENT_STORAGE",
        _ if status.is_server_error() => "INTERNAL",
        _ => "BAD_REQUEST",
    }
}

/// Short neutral English text for a code (never request-derived).
fn text_for(code: &str) -> (&'static str, &'static str) {
    match code {
        "NOT_FOUND" => ("Not found", "The page you asked for does not exist."),
        "UNAUTHORIZED" => ("Sign in required", "You need to sign in to do that."),
        "FORBIDDEN" => ("Forbidden", "You are not allowed to do that."),
        "RATE_LIMITED" => ("Too many requests", "Slow down and try again shortly."),
        "BUSY" => ("Busy", "The server is busy. Try again shortly."),
        "STARTING" => (
            "Starting",
            "nzbd is starting or migrating its database. This page reloads on its own; please wait.",
        ),
        "INSUFFICIENT_STORAGE" => (
            "Storage low",
            "The server is low on disk space. Try again later.",
        ),
        "TIMEOUT" => ("Timed out", "The request took too long."),
        "FILE_TOO_LARGE" | "REQUEST_TOO_LARGE" => {
            ("Request too large", "The request exceeds the allowed size.")
        }
        "METHOD_NOT_ALLOWED" => ("Method not allowed", "That action is not supported here."),
        "BAD_QUERY" => ("Invalid request", "A request parameter is not valid."),
        "BLOB_UNAVAILABLE" => (
            "NZB unavailable",
            "The stored NZB file could not be read. Ask the administrator to check the store.",
        ),
        "NZB_UNREADABLE" => ("NZB unreadable", "The stored NZB could not be parsed."),
        "INVALID_CATEGORY" => ("Invalid category", "That category does not exist."),
        // Partial download (T125).
        "NO_FILES_SELECTED" => (
            "Nothing selected",
            "Tick at least one file, then choose Download selected.",
        ),
        "BAD_FILE_INDEX" => (
            "Invalid request",
            "A selected file is not part of this release.",
        ),
        "PARTIAL_TOO_LARGE" => (
            "Selection too large",
            "The NZB for these files would exceed the size limit. Select fewer files.",
        ),
        // Bulk download (T130).
        "BULK_DOWNLOAD_TOO_LARGE" => (
            "Selection too large",
            "Together these NZB files exceed the 1 GiB limit of one download. Select fewer releases.",
        ),
        // Bulk actions (T119).
        "NO_SELECTION" => ("Nothing selected", "Select at least one release first."),
        "TOO_MANY_IDS" => (
            "Too many releases",
            "Select at most 100 releases per action.",
        ),
        "INVALID_ID" => ("Invalid request", "A selected release id is not valid."),
        "BAD_ACTION" => ("Invalid request", "That action is not supported here."),
        "BULK_RESULT_UNKNOWN" => (
            "Bulk delete: result unknown",
            "The delete did not finish cleanly, so the outcome is unknown. Some of the selected releases may already be in the trash. Check the trash list on Admin > Cleanup and the audit log, then reload the index.",
        ),
        // Saved searches (T127).
        "SAVED_SEARCH_LIMIT" => (
            "Too many saved searches",
            "You can keep up to 25 saved searches. Delete one on the Saved searches page first.",
        ),
        "SAVED_SEARCH_DUPLICATE" => (
            "Name already used",
            "You already have a saved search with this name. Choose another name.",
        ),
        "SAVED_SEARCH_NAME" => (
            "Invalid name",
            "Give the saved search a name of 1 to 60 characters.",
        ),
        "INTERNAL" => ("Something went wrong", "An internal error occurred."),
        _ => ("Request rejected", "The request could not be processed."),
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    layout: Layout,
    heading: &'a str,
    message: &'a str,
    code: &'a str,
    request_id: &'a str,
}

/// Marker extension: the handler built a complete, fixed-text HTML page for a refusal (the Users
/// page `409` with its alert, `AUTH_SPEC` "Target rules") and [`finalize`] must not replace it
/// with the uniform error body. Only handlers whose page carries no request-derived text set it.
///
/// The marker carries the status it was issued for and is honoured only for `409 Conflict`: a
/// 401/403/404 can never bypass the uniform error body (review R8).
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeepBody(pub(crate) StatusCode);

/// Rewrites an error response into the uniform body. Non-errors pass through untouched.
pub(crate) fn finalize(resp: Response, request_id: &str, html: bool) -> Response {
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error())
        || (status == StatusCode::CONFLICT
            && resp
                .extensions()
                .get::<KeepBody>()
                .is_some_and(|k| k.0 == StatusCode::CONFLICT))
    {
        return resp;
    }
    let code = resp
        .extensions()
        .get::<ErrorCode>()
        .map_or_else(|| code_for_status(status), |c| c.0);
    let (mut parts, _) = resp.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_TYPE);
    let (ctype, body) = match html.then(|| render_html(code, request_id)).flatten() {
        Some(page) => ("text/html; charset=utf-8", page),
        None => (
            "application/json",
            // `code` is a static identifier and `request_id` is server-generated hex.
            format!("{{\"error\":{{\"code\":\"{code}\",\"request_id\":\"{request_id}\"}}}}"),
        ),
    };
    parts
        .headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    Response::from_parts(parts, axum::body::Body::from(body))
}

fn render_html(code: &str, request_id: &str) -> Option<String> {
    let (heading, message) = text_for(code);
    ErrorPage {
        layout: Layout::new("Error"),
        heading,
        message,
        code,
        request_id,
    }
    .render()
    .ok()
}

#[cfg(test)]
mod keep_body_tests {
    use super::*;

    fn marked(status: StatusCode) -> Response {
        let mut r = Response::new(axum::body::Body::from("page"));
        *r.status_mut() = status;
        r.extensions_mut().insert(KeepBody(status));
        r
    }

    #[test]
    fn only_a_conflict_page_survives_finalize() {
        assert_eq!(
            finalize(marked(StatusCode::CONFLICT), "rid", false)
                .headers()
                .get(header::CONTENT_TYPE),
            None
        );
        for s in [
            StatusCode::NOT_FOUND,
            StatusCode::FORBIDDEN,
            StatusCode::UNAUTHORIZED,
        ] {
            let r = finalize(marked(s), "rid", false);
            assert_eq!(
                r.headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json"),
                "{s}"
            );
        }
    }
}

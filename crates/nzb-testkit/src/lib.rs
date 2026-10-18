//! `nzb-testkit` — dev-only builders and hostile inputs for the NZB parser.
//!
//! Pure and dependency-free on purpose: it must not depend on `nzb-core` (which will dev-depend on
//! it). Expected results are therefore plain JSON strings (see [`NzbBuilder::expected_json`]
//! and [`Case`]). Large hostile inputs are generated on demand and never committed.
#![forbid(unsafe_code)]
// Dev-only crate: readable string building and one long catalogue function beat micro-lints.
#![allow(
    clippy::format_push_string,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

pub mod builder;
pub mod fs_tick;
pub mod hostile;

pub use builder::{FileSpec, NzbBuilder};
pub use fs_tick::wait_for_ctime_tick;
pub use hostile::Case;

/// Escape `s` as the contents of a JSON string (no surrounding quotes).
#[must_use]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// Escape `s` for use inside an XML attribute or text node.
#[must_use]
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

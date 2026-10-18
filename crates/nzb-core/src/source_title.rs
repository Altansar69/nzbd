//! Release title from the `.nzb` file name (owner decision D39, T131; `PARSER_SPEC` §Analysis "title").
//!
//! Many NZBs are fully obfuscated inside (random file names, no meta), while the file the user dropped or uploaded
//! carries the real release name. The ingest pipeline therefore prefers the source file name stem as the title
//! **when it is usable**, then the analyzer's title (meta title / name, derived title, `untitled-<sha8>`).
//!
//! The file name is hostile display data: it is sanitized and capped here and never used as a path. Pure code, no
//! I/O: the pipeline passes the name in.
//!
//! # The "usable" rule
//! Cleanup: last `/`/`\` path component, [`sanitize_text`] (controls, bidi and invisible characters removed,
//! whitespace collapsed, capped at [`SOURCE_TITLE_BYTES`]), trailing `.nzb` removed (ASCII case-insensitive, up
//! to four times: `x.nzb.nzb`), trailing ` `, `.`, `_`, `-` trimmed. The stem is **not** usable when it is
//! 1. empty or without any alphanumeric character that is not a combining mark (a stem of only combining marks, such
//!    as a lone U+0345, is near-invisible);
//! 2. digits only (ignoring `.`, `_`, `-`, space and parentheses): `12345`, `2024-10-17`;
//! 3. a generic browser/download name: `download`, `nzb`, `file`, `get`, `index`, `api`, `untitled`
//!    (ASCII case-insensitive), alone or followed by up to four duplicate suffixes ` (N)`, `(N)`, `-N` or ` -N`
//!    (`download (1)`, `download (1)(2)`, `Download -1`), or the analyzer's own fallback form `untitled-<8 hex>` (a
//!    file name must not pass for another release's fallback title);
//! 4. hash-like: at least 16 characters, only `[A-Za-z0-9_-]` (the per-file `OBFUSCATED` alphabet, see
//!    [`crate::looks_obfuscated`]), and one of: no `_`/`-` at all and at least one digit (hex, base64, a UUID
//!    without dashes); every `_`/`-`-separated part made of hex digits only and one of them at least 8 long (UUIDs,
//!    chunked hashes); some part of at
//!    least 16 characters mixing letters and digits (a random token). The check ignores up to four trailing dot
//!    components of at most 6 characters (`a8f3...9c0e.part01` is hash-like). Scene names such as
//!    `Some_Movie_2024_1080p-GRP` stay usable: their parts are short words. A single long camel-case word with a
//!    digit and no separator (`TheShow2024Remaster`) is refused too; the meta or derived title is used instead.

use crate::sanitize::sanitize_text;
use crate::types::{Analysis, ReleaseFlags};

/// Longest title taken from a file name, in bytes (the analyzer's title cap).
pub const SOURCE_TITLE_BYTES: usize = 512;

/// Generic names browsers and sites give a downloaded file (rule 3).
const GENERIC_NAMES: [&str; 7] = ["download", "nzb", "file", "get", "index", "api", "untitled"];
/// Shortest hash-like stem (rule 4), as in the per-file obfuscation heuristic.
const HASH_MIN_CHARS: usize = 16;
/// Shortest hex part that makes an all-hex separated stem hash-like (the first UUID group).
const HEX_CHUNK_MIN: usize = 8;
/// Duplicate suffixes stripped at most (rule 3).
const MAX_DUP_STRIPS: usize = 4;
/// Hex digits of the analyzer's `untitled-<sha8>` fallback.
const FALLBACK_HEX: usize = 8;
/// Longest trailing dot component ignored by the hash check (`part01`).
const SHORT_EXT_CHARS: usize = 6;
/// `.nzb` extensions stripped at most.
const MAX_EXT_STRIPS: usize = 4;

/// The cleaned stem of a submitted file name, usable or not (cleanup of the module docs).
#[must_use]
pub fn source_stem(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let clean = sanitize_text(base, SOURCE_TITLE_BYTES);
    let mut s = clean.as_str();
    for _ in 0..MAX_EXT_STRIPS {
        let Some(cut) = s.len().checked_sub(4) else {
            break;
        };
        match (s.get(..cut), s.get(cut..)) {
            (Some(head), Some(ext)) if ext.eq_ignore_ascii_case(".nzb") => s = head,
            _ => break,
        }
    }
    s.trim_end_matches([' ', '.', '_', '-']).to_owned()
}

/// The release title the file name `raw` gives, or `None` when its stem is not usable (module docs).
#[must_use]
pub fn source_title(raw: &str) -> Option<String> {
    let stem = source_stem(raw);
    is_usable(&stem).then_some(stem)
}

/// Applies the D39 order to an analysis: a usable file-name title replaces the analyzer's title (which already
/// follows meta title / name, derived title, `untitled-<sha8>`). A file-name title that hints at a password sets
/// `PASSWORD_HINT` like a meta title does. Returns whether the title came from the file name.
pub fn apply_source_title(analysis: &mut Analysis, source_name: Option<&str>) -> bool {
    let Some(title) = source_name.and_then(source_title) else {
        return false;
    };
    if crate::analyzer::title_hints_password(&title) {
        analysis.flags |= ReleaseFlags::PASSWORD_HINT;
    }
    analysis.title = title;
    true
}

fn is_usable(stem: &str) -> bool {
    stem.chars()
        .any(|c| c.is_alphanumeric() && !unicode_normalization::char::is_combining_mark(c))
        && !is_digits_only(stem)
        && !is_generic(stem)
        && !is_hash_like(stem)
}

fn is_digits_only(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | ' ' | '(' | ')'))
}

fn is_generic(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let mut head = lower.trim();
    for _ in 0..MAX_DUP_STRIPS {
        match strip_duplicate_suffix(head) {
            Some(h) => head = h.trim_end(),
            None => break,
        }
    }
    GENERIC_NAMES.contains(&head) || is_fallback_title(head)
}

/// `untitled-<8 hex>`: the analyzer's fallback title form.
fn is_fallback_title(s: &str) -> bool {
    s.strip_prefix("untitled-")
        .is_some_and(|h| h.len() == FALLBACK_HEX && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// One duplicate suffix `(N)` or `-N` removed (the caller trims spaces before it); `None` when there is none.
fn strip_duplicate_suffix(s: &str) -> Option<&str> {
    let digits = |d: &str| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit());
    if let Some(inner) = s.strip_suffix(')')
        && let Some((head, n)) = inner.rsplit_once('(')
        && digits(n)
    {
        return Some(head);
    }
    if let Some((head, n)) = s.rsplit_once('-')
        && digits(n)
    {
        return Some(head);
    }
    None
}

/// Rule 4 on the stem without up to four trailing dot components of at most six characters (`.part01`, `.rar`,
/// `.7z`, `.vol00`): an obfuscated archive name keeps its volume suffix in the `.nzb` name.
fn is_hash_like(s: &str) -> bool {
    let mut head = s;
    for _ in 0..MAX_EXT_STRIPS {
        match head.rsplit_once('.') {
            Some((h, ext)) if !h.is_empty() && ext.chars().count() <= SHORT_EXT_CHARS => head = h,
            _ => break,
        }
    }
    is_hash_token(head)
}

fn is_hash_token(s: &str) -> bool {
    if s.chars().count() < HASH_MIN_CHARS
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return false;
    }
    let has_digit = |p: &str| p.bytes().any(|b| b.is_ascii_digit());
    let has_alpha = |p: &str| p.bytes().any(|b| b.is_ascii_alphabetic());
    if !s.contains(['_', '-']) {
        return has_digit(s);
    }
    let parts = || s.split(['_', '-']).filter(|p| !p.is_empty());
    // Hex chunks with at least one of UUID length (8+): short hex-looking words (`Bad_Face_2024`) stay usable.
    let all_hex = parts().all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
        && parts().any(|p| p.len() >= HEX_CHUNK_MIN);
    all_hex || parts().any(|p| p.len() >= HASH_MIN_CHARS && has_alpha(p) && has_digit(p))
}

#[cfg(test)]
mod tests;

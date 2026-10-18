//! Subject parsing, file-kind classification and the per-file obfuscation heuristic.
//!
//! Everything here is pure, panic-free and linear-time: the `regex` crate guarantees
//! `O(pattern * input)` matching (finite automata, no backtracking), and the input is capped at
//! [`Limits::max_subject_bytes`] before any matching starts. All outputs are *display data only*:
//! a filename extracted here is never a path (SEC-005); directory components are stripped and
//! `.`/`..` are rejected so that even careless display code cannot be tricked.

use std::sync::LazyLock;

use regex::Regex;

use crate::{FileKind, Limits};

/// Result of [`parse_subject`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSubject {
    /// Extracted filename (display-only, no directory components); `None` if obfuscated.
    pub filename: Option<String>,
    /// `m` of the `(n/m)` segment counter, if within `1..=max_segments_per_file`.
    pub declared_segments: Option<u32>,
    /// `(n, m)` of a leading `[nn/mm]` file counter, if `1 <= n <= m <= max_files`.
    pub file_index: Option<(u32, u32)>,
}

// Patterns are compiled once. A failed compile (impossible; covered by a test) degrades to `None`
// and the corresponding rule is simply skipped, so no panic path exists.
fn compile(p: &str) -> Option<Regex> {
    Regex::new(p).ok()
}

static QUOTED: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r#""([^"]{1,255})""#));
static PAREN_COUNT: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\(([0-9]{1,10})/([0-9]{1,10})\)"));
static LEAD_INDEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"^\s*\[([0-9]{1,10})/([0-9]{1,10})\]"));
/// A counter at the very end of the subject (optionally followed by a size), for subjects with
/// no recognisable filename (obfuscated releases).
static TAIL_COUNT: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\(([0-9]{1,10})/([0-9]{1,10})\)(?:\s+[0-9]{1,20})?\s*$"));
static FALLBACK_PAREN: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r#"^(?:\s*\[[0-9]{1,10}/[0-9]{1,10}\])?[\s-]*([^"]{1,255}?\.[A-Za-z0-9]{1,8})\s+(?:yEnc\s+)?\(([0-9]{1,10})/([0-9]{1,10})\)"#,
    )
});
static FALLBACK_BRACKET: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"^[\s-]*([^\s\[\]][^\[\]]{0,254}?\.[A-Za-z0-9]{1,8})\s+(?:yEnc\s+)?\[([0-9]{1,10})/([0-9]{1,10})\]",
    )
});

/// Cut `s` to at most `max` bytes on a char boundary.
fn cap(s: &str, max: usize) -> &str {
    let mut n = max.min(s.len());
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s.get(..n).unwrap_or("")
}

/// Last path component (both separator styles), trimmed; `None` if empty or `.`/`..`.
fn display_name(raw: &str) -> Option<String> {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if last.is_empty() || last == "." || last == ".." {
        return None;
    }
    Some(last.to_owned())
}

/// True if `name` ends with `.ext` where ext is 1..=8 ASCII alphanumerics and the stem is non-empty.
fn looks_like_filename(name: &str) -> bool {
    let name = name.trim();
    match name.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.trim().is_empty()
                && (1..=8).contains(&ext.len())
                && ext.bytes().all(|b| b.is_ascii_alphanumeric())
        }
        None => false,
    }
}

fn num(s: Option<regex::Match<'_>>) -> Option<u32> {
    s?.as_str().parse().ok()
}

/// Extract filename and counters from a (sanitized) subject. Never fails; unknown parts are `None`.
///
/// Order of preference: first quoted token that looks like a filename, then the unquoted
/// `name.ext (n/m)` / `name.ext [n/m]` fallbacks, else obfuscated (`filename == None`).
#[must_use]
pub fn parse_subject(subject: &str, limits: &Limits) -> ParsedSubject {
    let max_len = usize::try_from(limits.max_subject_bytes).unwrap_or(usize::MAX);
    let s = cap(subject, max_len);
    let mut out = ParsedSubject::default();
    let valid_total = |m: u32| (1..=limits.max_segments_per_file).contains(&m);

    if let Some(re) = LEAD_INDEX.as_ref()
        && let Some(c) = re.captures(s)
        && let (Some(n), Some(m)) = (num(c.get(1)), num(c.get(2)))
        && n >= 1
        && n <= m
        && m <= limits.max_files
    {
        out.file_index = Some((n, m));
    }

    // A declared total is only trusted when the counter belongs to the yEnc part of the subject,
    // never when `(n/m)` is merely part of a name such as `Movie (1/2).mkv` (review L1).
    let pair = |n: Option<u32>, m: Option<u32>| match (n, m) {
        (Some(n), Some(m)) if n >= 1 && n <= m && valid_total(m) => Some(m),
        _ => None,
    };

    if let Some(re) = QUOTED.as_ref() {
        for c in re.captures_iter(s) {
            if let Some(g) = c.get(1)
                && looks_like_filename(g.as_str())
                && let Some(name) = display_name(g.as_str()).filter(|n| looks_like_filename(n))
            {
                out.filename = Some(name);
                // Last `(n/m)` after the closing quote.
                let rest = s.get(g.end()..).unwrap_or_default();
                out.declared_segments = PAREN_COUNT
                    .as_ref()
                    .and_then(|re| re.captures_iter(rest).last())
                    .and_then(|c| pair(num(c.get(1)), num(c.get(2))));
                return out;
            }
        }
    }

    // Unquoted `name.ext (n/m)` / `name.ext [n/m]`: the counter must directly follow the name.
    for re in [&FALLBACK_PAREN, &FALLBACK_BRACKET] {
        if let Some(c) = re.as_ref().and_then(|re| re.captures(s)) {
            let name = c.get(1).and_then(|g| display_name(g.as_str()));
            if let Some(name) = name.filter(|n| looks_like_filename(n)) {
                out.filename = Some(name);
                out.declared_segments = pair(num(c.get(2)), num(c.get(3)));
                return out;
            }
        }
    }

    out.declared_segments = TAIL_COUNT
        .as_ref()
        .and_then(|re| re.captures(s))
        .and_then(|c| pair(num(c.get(1)), num(c.get(2))));
    out
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Classify by the lowercase extension of `filename`. `None` (obfuscated) is [`FileKind::Other`].
#[must_use]
pub fn classify_kind(filename: Option<&str>) -> FileKind {
    let Some(name) = filename else {
        return FileKind::Other;
    };
    let lower = name.trim().to_ascii_lowercase();
    let Some((stem, ext)) = lower.rsplit_once('.') else {
        return FileKind::Other;
    };
    if stem.is_empty() && ext != "nzb" {
        // ".bashrc"-style dotfiles carry no extension.
        return FileKind::Other;
    }
    match ext {
        "mkv" | "mp4" | "avi" | "m4v" | "ts" | "wmv" | "mov" | "mpg" | "mpeg" => FileKind::Video,
        "mp3" | "flac" | "m4a" | "aac" | "ogg" | "wav" | "opus" => FileKind::Audio,
        "rar" | "7z" | "zip" => FileKind::Archive,
        "par2" => FileKind::Par2,
        "nfo" | "diz" => FileKind::Nfo,
        "sfv" => FileKind::Sfv,
        "srt" | "sub" | "idx" | "ass" => FileKind::Subtitle,
        "jpg" | "jpeg" | "png" | "gif" | "webp" => FileKind::Image,
        "nzb" => FileKind::Nzb,
        "exe" | "scr" | "bat" | "cmd" | "com" | "msi" | "ps1" | "vbs" | "js" | "jar" | "lnk" => {
            FileKind::Executable
        }
        _ => {
            let b = ext.as_bytes();
            let split_rar = ext
                .strip_prefix('r')
                .is_some_and(|d| (2..=3).contains(&d.len()) && all_digits(d));
            let split_zip = ext
                .strip_prefix('z')
                .is_some_and(|d| d.len() == 2 && all_digits(d));
            let split_num = b.len() == 3 && all_digits(ext);
            if split_rar || split_zip || split_num {
                FileKind::Archive
            } else {
                FileKind::Other
            }
        }
    }
}

/// Recovery block count of `*.volNN+MM.par2` (returns `MM`); `None` for index files or other names.
#[must_use]
pub fn par2_blocks(filename: &str) -> Option<u32> {
    let lower = filename.trim().to_ascii_lowercase();
    let base = lower.strip_suffix(".par2")?;
    let (head, blocks) = base.rsplit_once('+')?;
    if !all_digits(blocks) {
        return None;
    }
    let (pre, first) = head.rsplit_once("vol")?;
    if !all_digits(first) || !(pre.is_empty() || pre.ends_with('.')) {
        return None;
    }
    blocks.parse().ok()
}

/// Per-file obfuscation heuristic (`PARSER_SPEC`): no filename, or no extension and the whole name
/// matches `^[A-Za-z0-9_-]{16,}$`. The release-level `OBFUSCATED` flag (>= 50% of non-par2
/// files) is computed by the analyzer.
#[must_use]
pub fn looks_obfuscated(filename: Option<&str>) -> bool {
    match filename {
        None => true,
        Some(n) => {
            n.len() >= 16
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        }
    }
}

#[cfg(test)]
mod tests;

//! The analyzer: turns a parsed NZB into an [`Analysis`] (`PARSER_SPEC` §Analysis output).
//!
//! Pure logic on top of [`parse`]: title derivation, poster, dates, per-file kind and filename,
//! par2 blocks, release flags, multi-volume gap detection and the informational repairability
//! estimate. Every string that reaches [`Analysis`] is sanitized and length-capped (SEC-004);
//! none of them is ever used as a path (SEC-005).

use crate::error::{LimitName, NzbError};
use crate::limits::Limits;
use crate::parser::{Clock, MetaEntry, ParsedFile, ParsedNzb, SystemClock, parse};
use crate::sanitize::sanitize_text;
use crate::subject::{classify_kind, looks_obfuscated, par2_blocks, parse_subject};
use crate::types::{Analysis, FileInfo, FileKind, ReleaseFlags, Sha256};
use sha2::{Digest, Sha256 as Hasher};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Longest title / release-name candidate in bytes.
const TITLE_BYTES: usize = 512;
/// Longest derived filename in bytes.
const FILENAME_BYTES: usize = 255;
/// Shortest common prefix (bytes, after trimming separators) accepted as a title.
const MIN_PREFIX_BYTES: usize = 4;
/// The deadline is re-checked every this many files while analysing.
const FILE_CHECK_INTERVAL: usize = 64;
/// Longest run of digits accepted in a volume number.
const MAX_VOLUME_DIGITS: usize = 6;

/// Clock enforcing an absolute [`Instant`] deadline on top of `Limits::parse_deadline`.
struct DeadlineClock {
    system: SystemClock,
    start: Instant,
    deadline: Instant,
    limit: Duration,
}

impl Clock for DeadlineClock {
    fn elapsed(&self) -> Duration {
        let now = Instant::now();
        let real = now.saturating_duration_since(self.start);
        if now >= self.deadline {
            real.max(self.limit)
        } else {
            real
        }
    }

    fn now_unix(&self) -> i64 {
        self.system.now_unix()
    }
}

/// Parses and analyses `bytes`, giving up with [`NzbError::Timeout`] once `deadline` passes or
/// `limits.parse_deadline` elapses, whichever comes first.
///
/// # Errors
/// Everything [`parse`] returns, plus `Timeout` from the analysis phase.
pub fn analyze(bytes: &[u8], limits: &Limits, deadline: Instant) -> Result<Analysis, NzbError> {
    let limits = limits.clamped_to_ceilings();
    let clock = DeadlineClock {
        system: SystemClock::new(),
        start: Instant::now(),
        deadline,
        limit: limits.parse_deadline,
    };
    analyze_with_clock(bytes, &limits, &clock)
}

/// Like [`analyze`] with an injected [`Clock`] (deterministic tests).
///
/// # Errors
/// As [`analyze`].
pub fn analyze_with_clock(
    bytes: &[u8],
    limits: &Limits,
    clock: &dyn Clock,
) -> Result<Analysis, NzbError> {
    let limits = limits.clamped_to_ceilings();
    let parsed = parse(bytes, &limits, clock)?;
    let sha256 = Sha256(Hasher::digest(bytes).into());
    build(sha256, parsed, &limits, clock)
}

fn timed_out(limits: &Limits, clock: &dyn Clock) -> bool {
    clock.elapsed() >= limits.parse_deadline
}

fn build(
    sha256: Sha256,
    parsed: ParsedNzb,
    limits: &Limits,
    clock: &dyn Clock,
) -> Result<Analysis, NzbError> {
    let ParsedNzb {
        meta,
        files,
        total_bytes,
        segment_count,
        duplicate_segments,
    } = parsed;

    let mut infos = Vec::with_capacity(files.len());
    for (i, f) in files.into_iter().enumerate() {
        if i % FILE_CHECK_INTERVAL == 0 && timed_out(limits, clock) {
            return Err(NzbError::Timeout);
        }
        infos.push(file_info(f, limits));
    }

    let meta_title = meta_value(&meta, "title");
    let meta_name = meta_value(&meta, "name");
    let meta_category = meta_value(&meta, "category");
    let has_password_meta = meta_value(&meta, "password").is_some();

    let derived = derive_title(&infos);
    let largest = largest_data_file(&infos).and_then(|f| f.filename.as_deref());
    let title = meta_title
        .clone()
        .or_else(|| meta_name.clone())
        .or_else(|| derived.clone())
        .unwrap_or_else(|| format!("untitled-{}", sha256.short()));

    let (name_candidates, meta_name_candidates) = build_candidates(
        [meta_name.as_deref(), meta_title.as_deref()],
        [derived.as_deref(), largest],
    );

    let poster = most_frequent_poster(&infos);
    let posted_at = infos.iter().filter_map(|f| f.posted_at).max();
    let par2_total = infos
        .iter()
        .filter_map(|f| f.par2_blocks)
        .fold(0u64, |a, b| a.saturating_add(u64::from(b)));

    let mut flags = ReleaseFlags::EMPTY;
    if infos.iter().any(|f| f.kind == FileKind::Par2) {
        flags |= ReleaseFlags::HAS_PAR2;
    }
    if infos.iter().any(|f| f.par2_blocks.is_some()) {
        flags |= ReleaseFlags::PAR2_BLOCKS;
    }
    if infos.iter().any(|f| !f.missing_ranges.is_empty()) {
        flags |= ReleaseFlags::INCOMPLETE;
    }
    if duplicate_segments > 0 {
        flags |= ReleaseFlags::DUPLICATE_SEGMENTS;
    }
    if infos.iter().any(|f| f.kind == FileKind::Executable) {
        flags |= ReleaseFlags::HAS_EXECUTABLE;
    }
    if !infos
        .iter()
        .any(|f| matches!(f.kind, FileKind::Archive | FileKind::Video))
    {
        flags |= ReleaseFlags::NO_ARCHIVE_OR_VIDEO;
    }
    if is_obfuscated_release(&infos) {
        flags |= ReleaseFlags::OBFUSCATED;
    }
    if has_volume_gap(&infos) {
        flags |= ReleaseFlags::MULTIVOLUME_GAP;
    }
    if has_password_meta || title_hints_password(&title) {
        flags |= ReleaseFlags::PASSWORD_HINT;
    }

    let repairable_estimate = repairable(&infos);
    let file_count = u32::try_from(infos.len()).map_err(|_| NzbError::LimitExceeded {
        which: LimitName::Files,
    })?;

    if timed_out(limits, clock) {
        return Err(NzbError::Timeout);
    }
    Ok(Analysis {
        sha256,
        name_candidates,
        meta_name_candidates,
        title,
        poster,
        posted_at,
        total_bytes,
        file_count,
        segment_count,
        duplicate_segments,
        par2_blocks: par2_total,
        flags,
        meta_category,
        repairable_estimate,
        files: infos,
    })
}

/// Order of `PARSER_SPEC` §Release-name candidates: meta name, meta title, derived title, largest
/// archive/video stem. The source file stem (3) is only known to the ingest pipeline; the
/// categorizer inserts it after the leading `meta_count` entries returned here.
fn build_candidates(meta: [Option<&str>; 2], files: [Option<&str>; 2]) -> (Vec<String>, u8) {
    let mut out: Vec<String> = Vec::new();
    let mut meta_count = 0u8;
    for (raw, from_filename, is_meta) in meta
        .into_iter()
        .map(|r| (r, false, true))
        .chain(files.into_iter().map(|r| (r, true, false)))
    {
        let Some(raw) = raw else { continue };
        let cand = sanitize_text(strip_release_suffix(raw, from_filename), TITLE_BYTES);
        if !cand.is_empty() && !out.contains(&cand) {
            out.push(cand);
            if is_meta {
                meta_count = meta_count.saturating_add(1);
            }
        }
    }
    (out, meta_count)
}

/// Sanitized, capped value of the first non-empty `<meta type=kind>` (case-insensitive).
fn meta_value(meta: &[MetaEntry], kind: &str) -> Option<String> {
    meta.iter()
        .filter(|m| m.kind.eq_ignore_ascii_case(kind))
        .map(|m| sanitize_text(&m.value, TITLE_BYTES))
        .find(|v| !v.is_empty())
}

fn file_info(f: ParsedFile, limits: &Limits) -> FileInfo {
    let parsed = parse_subject(&f.subject, limits);
    // The subject is already sanitized; the filename is sanitized again after path stripping so
    // it is independently safe and bounded.
    let filename = parsed
        .filename
        .map(|n| sanitize_text(&n, FILENAME_BYTES))
        .filter(|n| !n.is_empty());
    let kind = classify_kind(filename.as_deref());
    let blocks = if kind == FileKind::Par2 {
        filename.as_deref().and_then(par2_blocks)
    } else {
        None
    };
    FileInfo {
        idx: f.idx,
        subject: f.subject,
        filename,
        kind,
        poster: f.poster,
        posted_at: f.posted_at,
        bytes: f.bytes,
        segment_count: f.segment_count,
        declared_segments: f.declared_segments,
        missing_ranges: f.missing_ranges,
        missing_truncated: f.missing_truncated,
        par2_blocks: blocks,
        groups: f.groups,
    }
}

// --- title derivation --------------------------------------------------------------------------

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Extensions removed from names that are not necessarily real filenames.
fn is_container_ext(ext: &str) -> bool {
    ["nzb", "rar", "par2", "7z", "zip"]
        .iter()
        .any(|e| ext.eq_ignore_ascii_case(e))
}

/// Strips one trailing extension. `all_known` additionally strips every extension known to
/// [`classify_kind`] (and a few common data extensions); otherwise only container extensions go,
/// so release names such as `Movie.2020.TS` stay intact.
fn strip_ext(s: &str, all_known: bool) -> &str {
    let Some((stem, ext)) = s.rsplit_once('.') else {
        return s;
    };
    if stem.is_empty() {
        return s;
    }
    let known = is_container_ext(ext)
        || (all_known
            && (classify_kind(Some(s)) != FileKind::Other
                || [
                    "iso", "txt", "tar", "gz", "bin", "img", "pdf", "epub", "m4b",
                ]
                .iter()
                .any(|e| ext.eq_ignore_ascii_case(e))));
    if known { stem } else { s }
}

/// Strips an inner `.7z`/`.rar`/`.tar`..., `.partNN` or `.volNN+MM` left after the extension.
fn strip_inner(s: &str) -> &str {
    let Some((head, tail)) = s.rsplit_once('.') else {
        return s;
    };
    if head.is_empty() {
        return s;
    }
    let lower = tail.to_ascii_lowercase();
    let is_part = lower
        .strip_prefix("part")
        .is_some_and(|d| d.len() <= MAX_VOLUME_DIGITS && is_digits(d));
    let is_vol = lower.strip_prefix("vol").is_some_and(|r| {
        r.split_once(['+', '-'])
            .is_some_and(|(a, b)| is_digits(a) && is_digits(b))
    });
    if is_part || is_vol || is_container_ext(&lower) || lower == "tar" {
        head
    } else {
        s
    }
}

/// Removes the extension and part/volume decorations: `Name.part01.rar` and
/// `Name.vol03+04.par2` both give `Name`.
fn strip_release_suffix(name: &str, all_known: bool) -> &str {
    let mut s = strip_ext(name.trim(), all_known);
    for _ in 0..3 {
        let next = strip_inner(s);
        if next.len() == s.len() {
            break;
        }
        s = next;
    }
    s.trim_end_matches([' ', '.', '_', '-'])
}

/// Largest Archive/Video file (ties: lowest index) that has a filename.
fn largest_data_file(files: &[FileInfo]) -> Option<&FileInfo> {
    files
        .iter()
        .filter(|f| matches!(f.kind, FileKind::Archive | FileKind::Video) && f.filename.is_some())
        .fold(None, |best: Option<&FileInfo>, f| match best {
            Some(b) if b.bytes >= f.bytes => Some(b),
            _ => Some(f),
        })
}

/// Title from file names (`PARSER_SPEC`): largest archive/video stem, else the longest common
/// prefix of all filenames, else the most common non-par2 stem.
fn derive_title(files: &[FileInfo]) -> Option<String> {
    let clean = |s: &str| sanitize_text(s, TITLE_BYTES);
    if let Some(name) = largest_data_file(files).and_then(|f| f.filename.as_deref()) {
        let t = clean(strip_release_suffix(name, true));
        if !t.is_empty() {
            return Some(t);
        }
    }
    let stems: Vec<&str> = files
        .iter()
        .filter(|f| f.kind != FileKind::Par2)
        .filter_map(|f| f.filename.as_deref())
        .map(|n| strip_release_suffix(n, true))
        .collect();
    if stems.len() >= 2
        && let Some(prefix) = common_prefix(&stems)
    {
        let t = clean(prefix.trim_end_matches([' ', '.', '_', '-']));
        if t.len() >= MIN_PREFIX_BYTES {
            return Some(t);
        }
    }
    // Most common stem; ties go to the one seen first.
    let mut counts: BTreeMap<&str, (u32, usize)> = BTreeMap::new();
    for (i, s) in stems.iter().enumerate() {
        let e = counts.entry(s).or_insert((0, i));
        e.0 = e.0.saturating_add(1);
    }
    counts
        .into_iter()
        .filter(|(s, _)| !s.is_empty())
        .max_by(|(_, (ca, ia)), (_, (cb, ib))| ca.cmp(cb).then(ib.cmp(ia)))
        .map(|(s, _)| clean(s))
        .filter(|t| !t.is_empty())
}

/// Longest common prefix (char-aligned) of all strings.
fn common_prefix<'a>(items: &[&'a str]) -> Option<&'a str> {
    let first = *items.first()?;
    let mut end = first.len();
    for other in items.iter().skip(1) {
        let mut n = 0usize;
        for (a, b) in first.chars().zip(other.chars()) {
            if a != b {
                break;
            }
            n = n.saturating_add(a.len_utf8());
        }
        end = end.min(n);
    }
    first.get(..end)
}

// --- poster ------------------------------------------------------------------------------------

fn most_frequent_poster(files: &[FileInfo]) -> Option<String> {
    let mut counts: BTreeMap<&str, (u32, usize)> = BTreeMap::new();
    for (i, f) in files.iter().enumerate() {
        if let Some(p) = f.poster.as_deref() {
            let e = counts.entry(p).or_insert((0, i));
            e.0 = e.0.saturating_add(1);
        }
    }
    counts
        .into_iter()
        .max_by(|(_, (ca, ia)), (_, (cb, ib))| ca.cmp(cb).then(ib.cmp(ia)))
        .map(|(p, _)| p.to_owned())
}

// --- flags -------------------------------------------------------------------------------------

/// `OBFUSCATED`: at least 50% of the non-par2 files look obfuscated.
fn is_obfuscated_release(files: &[FileInfo]) -> bool {
    let (mut total, mut obf) = (0usize, 0usize);
    for f in files.iter().filter(|f| f.kind != FileKind::Par2) {
        total = total.saturating_add(1);
        if looks_obfuscated(f.filename.as_deref()) {
            obf = obf.saturating_add(1);
        }
    }
    total > 0 && obf.saturating_mul(2) >= total
}

pub(crate) fn title_hints_password(title: &str) -> bool {
    let lower = title.to_ascii_lowercase();
    lower.contains("password")
        || lower.find("{{").is_some_and(|i| {
            lower
                .get(i.saturating_add(2)..)
                .is_some_and(|r| r.contains("}}"))
        })
}

/// Split-archive naming families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum VolumeStyle {
    /// `name.partNN.rar`
    Part,
    /// `name.rar`, `name.r00`, `name.r01`, ... (`.rar` is volume 0)
    OldRar,
    /// `name.z01`, `name.z02`, ... (final `.zip` carries no number)
    Zip,
    /// `name.7z.001`, `name.001`, ...
    Numeric,
}

fn volume_number(d: &str) -> Option<u32> {
    if d.len() <= MAX_VOLUME_DIGITS && is_digits(d) {
        d.parse::<u32>().ok()
    } else {
        None
    }
}

/// `.rNN` covers volumes 1..=100 (`.r00`..`.r99`), `.sNN` continues at 101.
const S_SERIES_BASE: u32 = 101;

/// `(set key, style, volume number)` for split-archive filenames. Names with a volume number of
/// more than [`MAX_VOLUME_DIGITS`] digits are not volumes at all.
fn volume_of(filename: &str) -> Option<(String, VolumeStyle, u32)> {
    let lower = filename.trim().to_ascii_lowercase();
    if let Some(base) = lower.strip_suffix(".rar") {
        if let Some((head, p)) = base.rsplit_once(".part")
            && is_digits(p)
        {
            return Some((head.to_owned(), VolumeStyle::Part, volume_number(p)?));
        }
        return Some((base.to_owned(), VolumeStyle::OldRar, 0));
    }
    let (stem, ext) = lower.rsplit_once('.')?;
    if let Some(d) = ext.strip_prefix('r')
        && (2..=3).contains(&d.len())
        && let Some(n) = volume_number(d)
    {
        return Some((stem.to_owned(), VolumeStyle::OldRar, n.checked_add(1)?));
    }
    if let Some(d) = ext.strip_prefix('s')
        && d.len() == 2
        && let Some(n) = volume_number(d)
    {
        return Some((
            stem.to_owned(),
            VolumeStyle::OldRar,
            n.checked_add(S_SERIES_BASE)?,
        ));
    }
    if let Some(d) = ext.strip_prefix('z')
        && d.len() == 2
        && let Some(n) = volume_number(d)
    {
        return Some((stem.to_owned(), VolumeStyle::Zip, n));
    }
    // `.001` sets only count behind a real archive extension, so `video.264` is not a set.
    if ext.len() == 3
        && let Some(n) = volume_number(ext)
        && [".7z", ".rar", ".zip"].iter().any(|e| stem.ends_with(e))
    {
        return Some((stem.to_owned(), VolumeStyle::Numeric, n));
    }
    None
}

/// True if any split-archive set lacks a volume number between its first expected and last seen.
fn has_volume_gap(files: &[FileInfo]) -> bool {
    let mut sets: BTreeMap<(String, VolumeStyle), BTreeSet<u32>> = BTreeMap::new();
    let mut s_series: Vec<(String, u32)> = Vec::new();
    for f in files
        .iter()
        .filter(|f| matches!(f.kind, FileKind::Archive | FileKind::Other))
    {
        let Some(name) = f.filename.as_deref() else {
            continue;
        };
        let Some((key, style, n)) = volume_of(name) else {
            continue;
        };
        // `.sNN` is not an Archive per `classify_kind`; it only counts as a continuation of an
        // existing `.rar`/`.rNN` set, so unrelated `.s01` files cannot start a set.
        if f.kind == FileKind::Other {
            if n >= S_SERIES_BASE && style == VolumeStyle::OldRar {
                s_series.push((key, n));
            }
            continue;
        }
        sets.entry((key, style)).or_default().insert(n);
    }
    for (key, n) in s_series {
        if let Some(set) = sets.get_mut(&(key, VolumeStyle::OldRar)) {
            set.insert(n);
        }
    }
    sets.into_iter().any(|((_, style), nums)| {
        let (Some(&first), Some(&last)) = (nums.first(), nums.last()) else {
            return false;
        };
        let start = match style {
            VolumeStyle::OldRar => 0,
            VolumeStyle::Part if first == 0 => 0,
            VolumeStyle::Part | VolumeStyle::Zip | VolumeStyle::Numeric => 1,
        };
        let span = last.saturating_sub(first).saturating_add(1);
        first != start || usize::try_from(span).ok() != Some(nums.len())
    })
}

// --- repairability -----------------------------------------------------------------------------

/// Fallback average segment size when the data files carry no segments (typical Usenet size).
const DEFAULT_SEGMENT_BYTES: u64 = 768_000;

/// Kinds whose loss does not stop an archive/video from being usable.
fn is_non_essential(kind: FileKind) -> bool {
    matches!(
        kind,
        FileKind::Nfo
            | FileKind::Sfv
            | FileKind::Image
            | FileKind::Subtitle
            | FileKind::Par2
            | FileKind::Nzb
    )
}

/// Recovery blocks we are willing to credit. Block counts come from attacker-chosen filenames,
/// so a par2 file counts only if it is itself complete, and never for more blocks than its real
/// size can hold when one block is about one data segment.
fn credited_par2_blocks(files: &[FileInfo], avg_segment_bytes: u64) -> u64 {
    files
        .iter()
        .filter(|f| f.kind == FileKind::Par2 && f.missing_ranges.is_empty() && !f.missing_truncated)
        .filter_map(|f| {
            let by_size = f.bytes.checked_div(avg_segment_bytes.max(1))?;
            Some(u64::from(f.par2_blocks?).min(by_size))
        })
        .fold(0u64, u64::saturating_add)
}

/// Informational *estimate* ("may be repairable"): a heuristic, not a verdict. One missing
/// segment is assumed to cost one recovery block, which is only roughly true. Every kind except
/// the non-essential ones counts as data, including unnamed and obfuscated files. `None` when
/// nothing is missing.
fn repairable(files: &[FileInfo]) -> Option<bool> {
    if files.iter().all(|f| f.missing_ranges.is_empty()) {
        return None;
    }
    let mut missing = 0u64;
    let (mut data_bytes, mut data_segments) = (0u64, 0u64);
    for f in files.iter().filter(|f| !is_non_essential(f.kind)) {
        data_bytes = data_bytes.saturating_add(f.bytes);
        data_segments = data_segments.saturating_add(u64::from(f.segment_count));
        if f.missing_truncated {
            return Some(false);
        }
        for &(a, b) in &f.missing_ranges {
            let len = u64::from(b).saturating_sub(u64::from(a)).saturating_add(1);
            missing = missing.saturating_add(len);
        }
    }
    let avg = data_bytes
        .checked_div(data_segments)
        .filter(|a| *a > 0)
        .unwrap_or(DEFAULT_SEGMENT_BYTES);
    Some(missing <= credited_par2_blocks(files, avg))
}

#[cfg(test)]
mod tests;

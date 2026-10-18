//! Tokenizer and family rules. See the module docs of [`super`] for the safety argument.
//!
//! Every loop is bounded by the (capped) token count; every phrase lookup builds a key of at most
//! three tokens. Slicing is done with `get`, never with indexing.

#![allow(clippy::many_single_char_names, clippy::similar_names)]

use super::rules::{Kind, MAX_PHRASE_WORDS, SceneRules};
use super::{Family, MAX_SCENE_NAME_BYTES, Resolution, SceneFlags, SceneInfo, Source};
use crate::sanitize_text;

/// Raw input is cut here before sanitizing so allocation never scales with hostile input.
const PRE_CAP: usize = MAX_SCENE_NAME_BYTES * 4;
const MAX_EPISODES: usize = 64;
/// Widest accepted `E01-E99` range. `episode_range` is a pair and must never be expanded.
const MAX_RANGE_SPAN: u32 = 1000;
const MAX_TITLE_PARTS: usize = 8;

/// Entry point behind [`super::parse_scene`].
pub(super) fn parse(name: &str, rules: &SceneRules) -> SceneInfo {
    let clean = sanitize_text(cap_bytes(name, PRE_CAP), MAX_SCENE_NAME_BYTES);
    let prep = Prep::new(&clean, rules);
    prep.music()
        .or_else(|| prep.anime())
        .or_else(|| prep.tv())
        .or_else(|| prep.movie())
        // Inconclusive family (PC games, books, ...): the trailing `-GROUP` is still display data.
        // Only that one: a `[tag]` prefix of an unrecognised name is not a release group.
        .unwrap_or_else(|| SceneInfo {
            release_group: prep.group.clone(),
            ..SceneInfo::default()
        })
}

fn cap_bytes(s: &str, cap: usize) -> &str {
    let mut end = cap.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("")
}

// ---------------------------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------------------------

fn is_sep(c: char) -> bool {
    matches!(
        c,
        '.' | '_' | ' ' | '-' | '[' | ']' | '(' | ')' | '{' | '}' | ','
    )
}

#[derive(Debug, Clone)]
struct Tok {
    text: String,
    lower: String,
    /// A `-` occurred in the separator run directly before this token.
    dash: bool,
}

fn tokenize(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut dash = false;
    let mut pending_dash = false;
    for c in s.chars() {
        if is_sep(c) {
            if !cur.is_empty() {
                out.push(Tok {
                    lower: cur.to_ascii_lowercase(),
                    text: std::mem::take(&mut cur),
                    dash,
                });
                pending_dash = false;
            }
            if c == '-' {
                pending_dash = true;
            }
        } else {
            if cur.is_empty() {
                dash = pending_dash;
            }
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(Tok {
            lower: cur.to_ascii_lowercase(),
            text: cur,
            dash,
        });
    }
    out
}

fn join_title(toks: &[Tok]) -> Option<String> {
    let mut out = String::new();
    for t in toks {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&t.text);
    }
    (!out.is_empty()).then_some(out)
}

// ---------------------------------------------------------------------------------------------
// Small shape parsers
// ---------------------------------------------------------------------------------------------

fn parse_digits(s: &str, min: usize, max: usize) -> Option<u32> {
    if s.len() < min || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn prefixed_digits(t: &str, prefix: &str, min: usize, max: usize) -> Option<u32> {
    parse_digits(t.strip_prefix(prefix)?, min, max)
}

/// `S\d{1,3}(E\d{1,4})+` as one token.
fn parse_sxe(t: &str) -> Option<(u32, Vec<u32>)> {
    let rest = t.strip_prefix('s')?;
    let epos = rest.find('e')?;
    let (sd, after) = rest.split_at_checked(epos)?;
    let season = parse_digits(sd, 1, 3)?;
    let mut eps = Vec::new();
    for part in after.split('e').skip(1) {
        eps.push(parse_digits(part, 1, 4)?);
        if eps.len() >= MAX_EPISODES {
            break;
        }
    }
    (!eps.is_empty()).then_some((season, eps))
}

/// `\d{1,2}x\d{2,3}`.
fn parse_nxn(t: &str) -> Option<(u32, u32)> {
    let (a, b) = t.split_once('x')?;
    Some((parse_digits(a, 1, 2)?, parse_digits(b, 2, 3)?))
}

fn is_year(t: &str, max_year: u16) -> Option<u16> {
    let y = parse_digits(t, 4, 4)?;
    let y = u16::try_from(y).ok()?;
    ((1900..=max_year).contains(&y) && (t.starts_with("19") || t.starts_with("20"))).then_some(y)
}

/// Three consecutive numeric tokens forming a plausible date; returns `YYYY-MM-DD` and its year.
fn parse_date(toks: &[Tok], i: usize, max_year: u16) -> Option<(String, u16)> {
    let a = toks.get(i)?.lower.as_str();
    let b = toks.get(i.checked_add(1)?)?.lower.as_str();
    let c = toks.get(i.checked_add(2)?)?.lower.as_str();
    let (y, m, d) = if a.len() == 4 {
        (a, parse_digits(b, 2, 2)?, parse_digits(c, 2, 2)?)
    } else {
        let (x, z) = (parse_digits(a, 2, 2)?, parse_digits(b, 2, 2)?);
        // dd.mm.yyyy when the first number cannot be a month, mm.dd.yyyy otherwise.
        let (m, d) = if x > 12 { (z, x) } else { (x, z) };
        (c, m, d)
    };
    let year = is_year(y, max_year)?;
    (1..=days_in_month(year, m)?)
        .contains(&d)
        .then(|| (format!("{year:04}-{m:02}-{d:02}"), year))
}

/// Calendar month length (Gregorian leap rule); `None` for a month outside 1..=12.
fn days_in_month(year: u16, month: u32) -> Option<u32> {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    })
}

/// `[xxxxxxxx]` with 8 hex digits containing at least one digit and one letter.
fn find_crc(s: &str) -> Option<String> {
    for (i, _) in s.match_indices('[') {
        let Some(win) = s.get(i + 1..i + 10) else {
            continue;
        };
        let Some(hex) = win.strip_suffix(']') else {
            continue;
        };
        if hex.bytes().all(|b| b.is_ascii_hexdigit())
            && hex.bytes().any(|b| b.is_ascii_digit())
            && hex.bytes().any(|b| b.is_ascii_alphabetic())
        {
            return Some(hex.to_ascii_lowercase());
        }
    }
    None
}

/// Known container/archive extensions that are removed before parsing. Returns the stem plus
/// whether `.m4b` / `.iso` were seen.
fn strip_ext(mut s: &str) -> (&str, bool, bool) {
    let (mut m4b, mut iso) = (false, false);
    for _ in 0..4 {
        s = s.trim_end();
        let Some(dot) = s.rfind('.') else { break };
        let (Some(head), Some(ext)) = (s.get(..dot), s.get(dot + 1..)) else {
            break;
        };
        let ext = ext.to_ascii_lowercase();
        let known = matches!(
            ext.as_str(),
            "nzb"
                | "par2"
                | "rar"
                | "zip"
                | "7z"
                | "mkv"
                | "avi"
                | "mp4"
                | "m4v"
                | "mp3"
                | "flac"
                | "m4b"
                | "iso"
                | "nfo"
                | "sfv"
                | "srt"
                | "m2ts"
        ) || prefixed_digits(&ext, "part", 1, 4).is_some()
            || prefixed_digits(&ext, "r", 2, 2).is_some();
        if !known {
            break;
        }
        m4b |= ext == "m4b";
        iso |= ext == "iso";
        s = head;
    }
    (s, m4b, iso)
}

/// Leading `[Group]` (2..=40 bytes inside). Returns the group and the remainder.
fn split_lead_group(s: &str) -> (Option<String>, &str) {
    let t = s.trim_start();
    let Some(inner_and_rest) = t.strip_prefix('[') else {
        return (None, s);
    };
    let Some(close) = inner_and_rest.find(']') else {
        return (None, s);
    };
    let (Some(inner), Some(rest)) = (inner_and_rest.get(..close), inner_and_rest.get(close + 1..))
    else {
        return (None, s);
    };
    let inner = inner.trim();
    let rest = rest.trim_start_matches([' ', '_']);
    if inner.len() < 2 || inner.len() > 40 || inner.contains('[') || rest.is_empty() {
        return (None, s);
    }
    (Some(inner.to_owned()), rest)
}

/// Trailing `-GROUP` (2..=20 alphanumerics or `_`, optionally `.iNTERNAL`). Returns the byte length of
/// the body in front of it, the group and the INTERNAL marker.
fn split_group(s: &str, rules: &SceneRules) -> (usize, Option<(String, bool)>) {
    let none = (s.len(), None);
    let Some(pos) = s.rfind('-') else {
        return none;
    };
    let (Some(head), Some(after)) = (s.get(..pos), s.get(pos + 1..)) else {
        return none;
    };
    let after = after.trim_end();
    let (name, internal) = match after
        .len()
        .checked_sub(9)
        .and_then(|cut| after.split_at_checked(cut))
    {
        Some((n, tail)) if tail.eq_ignore_ascii_case(".internal") => (n, true),
        _ => (after, false),
    };
    if !(2..=20).contains(&name.len())
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || name.bytes().all(|b| b.is_ascii_digit())
        || head.trim().is_empty()
    {
        return none;
    }
    // "WEB-DL", "Blu-ray", "Dual-Audio", "DTS-HD": the dash belongs to a known phrase.
    let prev = head
        .rsplit(is_sep)
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let key = format!("{prev} {}", name.to_ascii_lowercase());
    if rules.phrases.contains_key(&key) {
        return none;
    }
    (pos, Some((name.to_owned(), internal)))
}

/// Fansub tail: `Title - NN(vN)? [..]`. Returns the title and episode number of the last
/// ` - ` that satisfies the pattern (`PARSER_SPEC` §Anime). Four-digit numbers that look like a
/// year are rejected so `[Pub] Book - 2019` stays a non-anime.
fn fansub_tail(core: &str) -> Option<(String, u32)> {
    let mut best = None;
    for (pos, _) in core.match_indices(" - ") {
        let (Some(title), Some(rest)) = (core.get(..pos), core.get(pos + 3..)) else {
            continue;
        };
        let title = title.trim();
        if title.is_empty() {
            continue;
        }
        if let Some(n) = episode_after_dash(rest) {
            best = Some((title.to_owned(), n));
        }
    }
    best
}

fn episode_after_dash(rest: &str) -> Option<u32> {
    let nd = rest.bytes().take_while(u8::is_ascii_digit).count();
    if nd == 0 || nd > 4 {
        return None;
    }
    let (digits, mut after) = rest.split_at_checked(nd)?;
    let n: u32 = digits.parse().ok()?;
    if nd == 4 && (1900..=2099).contains(&n) {
        return None;
    }
    if let Some(v) = after.strip_prefix('v') {
        let mut it = v.chars();
        if it.next().is_some_and(|c| c.is_ascii_digit()) {
            after = it.as_str();
        } else {
            return None;
        }
    }
    let t = after.trim_start();
    (t.is_empty() || t.starts_with('[') || t.starts_with('(')).then_some(n)
}

// ---------------------------------------------------------------------------------------------
// Prepared name
// ---------------------------------------------------------------------------------------------

struct Hit<'a> {
    idx: usize,
    kind: &'a Kind,
}

struct Marker {
    idx: usize,
    season: Option<u32>,
    episodes: Vec<u32>,
    range: Option<(u32, u32)>,
    air_date: Option<(String, u16)>,
    pack: bool,
}

struct Prep<'a> {
    rules: &'a SceneRules,
    m4b: bool,
    iso: bool,
    lead_group: Option<String>,
    group: Option<String>,
    internal: bool,
    /// Name without extension, lead group and `-GROUP`, `_` turned into spaces.
    spaced: String,
    crc: Option<String>,
    toks: Vec<Tok>,
    hits: Vec<Hit<'a>>,
    /// Token index of the last source/resolution/codec hit.
    last_quality: Option<usize>,
}

impl<'a> Prep<'a> {
    fn new(clean: &str, rules: &'a SceneRules) -> Self {
        let (stem, m4b, iso) = strip_ext(clean);
        let crc = find_crc(stem);
        let (lead_group, after_lead) = split_lead_group(stem);
        let (body_end, grp) = split_group(after_lead, rules);
        let body = after_lead.get(..body_end).unwrap_or(after_lead);
        let (group, internal) = grp.map_or((None, false), |(g, i)| (Some(g), i));
        let toks = tokenize(body);
        let hits = scan_hits(&toks, rules);
        let last_quality = hits
            .iter()
            .filter(|h| Self::is_quality(h.kind))
            .map(|h| h.idx)
            .max();
        Self {
            rules,
            m4b,
            iso,
            lead_group,
            group,
            internal,
            spaced: body.replace('_', " "),
            crc,
            toks,
            hits,
            last_quality,
        }
    }

    fn release_group(&self) -> Option<String> {
        self.group.clone().or_else(|| self.lead_group.clone())
    }

    fn tok(&self, i: usize) -> Option<&Tok> {
        self.toks.get(i)
    }

    fn is_quality(kind: &Kind) -> bool {
        matches!(kind, Kind::Source(_) | Kind::Resolution(_) | Kind::Codec(_))
    }

    /// O(1): the last quality index is computed once in `Prep::new`, so the per-token callers
    /// (`marker_at`, `movie`) are O(tokens) overall rather than O(tokens x hits) (SEC-037).
    fn quality_after(&self, i: usize) -> bool {
        self.last_quality.is_some_and(|last| last > i)
    }

    fn first_hit(&self, pred: impl Fn(&Kind) -> bool) -> Option<usize> {
        self.hits.iter().find(|h| pred(h.kind)).map(|h| h.idx)
    }

    fn base(&self, family: Family, category: u16) -> SceneInfo {
        SceneInfo {
            family,
            category: Some(category),
            release_group: self.release_group(),
            ..SceneInfo::default()
        }
    }

    /// Copies resolution/source/codec/... found at or after token `start` into `info`.
    fn fill_common(&self, info: &mut SceneInfo, start: usize) {
        for h in self.hits.iter().filter(|h| h.idx >= start) {
            match h.kind {
                Kind::Source(s) if s.rank() > info.source.rank() => info.source = *s,
                Kind::Resolution(r) if info.resolution == Resolution::Unknown => {
                    info.resolution = *r;
                }
                Kind::Codec(c) if info.video_codec.is_none() => info.video_codec = Some(c.clone()),
                Kind::Audio(a) if info.audio.is_none() => info.audio = Some(a.clone()),
                Kind::Hdr(x) if !info.hdr.contains(x) => info.hdr.push(x.clone()),
                Kind::Language(l) if !info.languages.contains(l) => info.languages.push(l.clone()),
                Kind::Flag(f) => info.flags.insert(*f),
                Kind::ThreeD => info.flags.insert(SceneFlags::THREE_D),
                _ => {}
            }
        }
        if self.internal {
            info.flags.insert(SceneFlags::INTERNAL);
        }
        if info.source == Source::UHDBluRay && info.resolution == Resolution::Unknown {
            info.resolution = Resolution::R2160p;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Episode markers (shared by TV, anime and the movie guard)
    // -----------------------------------------------------------------------------------------

    fn range_after(&self, next_idx: usize, first: u32, last: u32) -> Option<(u32, u32)> {
        let t = self.tok(next_idx)?;
        if !t.dash {
            return None;
        }
        let n = prefixed_digits(&t.lower, "e", 1, 4).or_else(|| parse_digits(&t.lower, 1, 4))?;
        // A wider span is implausible and would be an amplifier for consumers; treat as no range.
        // checked_sub: `first > last` (e.g. `S01E05E03-04`) makes `n - first` negative; that
        // inverted range is implausible too, so it yields no range instead of overflowing.
        let span = n.checked_sub(first)?;
        (n > last && span <= MAX_RANGE_SPAN).then_some((first, n))
    }

    fn sxe_marker(&self, i: usize, season: u32, episodes: Vec<u32>, next: usize) -> Marker {
        let first = episodes.first().copied().unwrap_or_default();
        let last = episodes.last().copied().unwrap_or_default();
        Marker {
            idx: i,
            season: Some(season),
            range: self.range_after(next, first, last),
            episodes,
            air_date: None,
            pack: false,
        }
    }

    /// First TV-style marker at token index >= 1 (an empty title is never conclusive).
    /// `need_quality` demands a source/resolution/codec token for the weak shapes (packs).
    /// `1x02` and dates always need one.
    fn find_marker(&self, need_quality: bool) -> Option<Marker> {
        for (i, t) in self.toks.iter().enumerate().skip(1) {
            if let Some(m) = self.marker_at(i, t, need_quality) {
                return Some(m);
            }
        }
        None
    }

    fn pack(idx: usize, season: Option<u32>) -> Marker {
        Marker {
            idx,
            season,
            episodes: Vec::new(),
            range: None,
            air_date: None,
            pack: true,
        }
    }

    fn marker_at(&self, i: usize, t: &Tok, need_quality: bool) -> Option<Marker> {
        let lower = t.lower.as_str();
        let next = i.checked_add(1)?;
        let q_weak = !need_quality || self.quality_after(i);
        if let Some((season, eps)) = parse_sxe(lower) {
            return Some(self.sxe_marker(i, season, eps, next));
        }
        if let Some(season) = prefixed_digits(lower, "s", 1, 3) {
            // "S01.E05" (split form) is weaker than "S01E05": it needs a quality token.
            if let Some(ep) = self
                .tok(next)
                .and_then(|n| prefixed_digits(&n.lower, "e", 1, 4))
                .filter(|_| q_weak)
            {
                return Some(self.sxe_marker(i, season, vec![ep], next.checked_add(1)?));
            }
            return q_weak.then(|| Self::pack(i, Some(season)));
        }
        if lower == "season" {
            let n = self.tok(next).and_then(|n| parse_digits(&n.lower, 1, 3));
            return n.filter(|_| q_weak).map(|s| Self::pack(i, Some(s)));
        }
        if let Some(s) = prefixed_digits(lower, "season", 1, 3) {
            return q_weak.then(|| Self::pack(i, Some(s)));
        }
        if lower == "complete" && self.tok(next).is_some_and(|n| n.lower == "series") {
            return q_weak.then(|| Self::pack(i, None));
        }
        let q_strict = self.quality_after(i);
        if let Some((s, e)) = parse_nxn(lower) {
            return q_strict.then(|| Marker {
                idx: i,
                season: Some(s),
                episodes: vec![e],
                range: None,
                air_date: None,
                pack: false,
            });
        }
        if q_strict && let Some(d) = parse_date(&self.toks, i, self.rules.max_year) {
            return Some(Marker {
                idx: i,
                season: None,
                episodes: Vec::new(),
                range: None,
                air_date: Some(d),
                pack: false,
            });
        }
        None
    }

    // -----------------------------------------------------------------------------------------
    // TV / sport / documentary
    // -----------------------------------------------------------------------------------------

    fn tv(&self) -> Option<SceneInfo> {
        if let Some(info) = self.sport() {
            return Some(info);
        }
        let m = self.find_marker(true)?;
        let mut title_toks = self.toks.get(..m.idx)?;
        let mut year = m.air_date.as_ref().map(|d| d.1);
        if year.is_none()
            && title_toks.len() >= 2
            && let Some((last, head)) = title_toks.split_last()
            && let Some(y) = is_year(&last.lower, self.rules.max_year)
        {
            year = Some(y);
            title_toks = head;
        }
        let mut info = self.base(Family::Tv, 5000);
        info.title = join_title(title_toks);
        info.year = year;
        info.season = m.season;
        info.episodes = m.episodes;
        info.episode_range = m.range;
        info.season_pack = m.pack;
        info.air_date = m.air_date.map(|d| d.0);
        self.fill_common(&mut info, m.idx);
        let doc = self
            .hits
            .iter()
            .any(|h| h.idx >= m.idx && matches!(h.kind, Kind::Documentary));
        info.category = Some(if doc {
            5080
        } else {
            match info.resolution {
                Resolution::R2160p => 5045,
                Resolution::R720p | Resolution::R1080p => 5040,
                Resolution::Unknown
                    if info.source == Source::Unknown && info.video_codec.is_none() =>
                {
                    5000
                }
                _ => 5030,
            }
        });
        Some(info)
    }

    /// Sports token + (date or `Round\d+`) + a quality token -> 5060.
    fn sport(&self) -> Option<SceneInfo> {
        let sport_idx = self.first_hit(|k| matches!(k, Kind::Sport))?;
        if !self.quality_after(sport_idx) {
            return None;
        }
        let (idx, date) = self.event_marker()?;
        let title_toks = self.toks.get(..idx)?;
        let mut info = self.base(Family::Tv, 5060);
        info.title = join_title(title_toks);
        info.year = date.as_ref().map(|d| d.1);
        info.air_date = date.map(|d| d.0);
        self.fill_common(&mut info, idx);
        Some(info)
    }

    #[allow(clippy::type_complexity)]
    fn event_marker(&self) -> Option<(usize, Option<(String, u16)>)> {
        for (i, t) in self.toks.iter().enumerate().skip(1) {
            if let Some(d) = parse_date(&self.toks, i, self.rules.max_year) {
                return Some((i, Some(d)));
            }
            let round = t.lower == "round"
                && self
                    .tok(i.checked_add(1)?)
                    .is_some_and(|n| parse_digits(&n.lower, 1, 3).is_some());
            if round || prefixed_digits(&t.lower, "round", 1, 3).is_some() {
                return Some((i, None));
            }
        }
        None
    }

    // -----------------------------------------------------------------------------------------
    // Anime
    // -----------------------------------------------------------------------------------------

    fn anime(&self) -> Option<SceneInfo> {
        if let Some(info) = self.anime_fansub() {
            return Some(info);
        }
        let marker_idx = self.first_hit(|k| matches!(k, Kind::AnimeMarker));
        let crc_idx = self.crc.as_ref().map(|c| {
            self.toks
                .iter()
                .position(|t| t.lower == *c)
                .unwrap_or(usize::MAX)
        });
        let ep = self.anime_episode();
        let complete_series = self
            .toks
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.lower == "complete" && b.lower == "series"));
        if crc_idx.is_none() && !(marker_idx.is_some() && (ep.is_some() || complete_series)) {
            return None;
        }
        let first_quality = self
            .hits
            .iter()
            .find(|h| h.idx > 0 && Self::is_quality(h.kind))
            .map(|h| h.idx);
        let title_end = [
            ep.as_ref().map(|m| m.idx),
            marker_idx,
            crc_idx,
            first_quality,
        ]
        .into_iter()
        .flatten()
        .filter(|&i| i > 0)
        .min()
        .unwrap_or(self.toks.len())
        .min(self.toks.len());
        let title = join_title(self.toks.get(..title_end)?)?;
        let mut info = self.base(Family::Anime, 5070);
        info.title = Some(title);
        if let Some(m) = ep {
            info.season = m.season;
            info.episodes = m.episodes;
            info.episode_range = m.range;
            info.season_pack = m.pack;
        } else if complete_series {
            info.season_pack = true;
        }
        self.fill_common(&mut info, title_end);
        Some(info)
    }

    fn anime_fansub(&self) -> Option<SceneInfo> {
        self.lead_group.as_ref()?;
        let (title, ep) = fansub_tail(&self.spaced)?;
        let title_toks = tokenize(&title);
        let mut info = self.base(Family::Anime, 5070);
        info.title = join_title(&title_toks);
        info.episodes = vec![ep];
        self.fill_common(&mut info, title_toks.len());
        Some(info)
    }

    /// Episode evidence for anime: TV markers, `E05`, `Episode05` and ` - 05`.
    fn anime_episode(&self) -> Option<Marker> {
        if let Some(m) = self.find_marker(false) {
            return Some(m);
        }
        for (i, t) in self.toks.iter().enumerate().skip(1) {
            let ep = prefixed_digits(&t.lower, "e", 2, 4)
                .or_else(|| prefixed_digits(&t.lower, "episode", 1, 4))
                .or_else(|| {
                    (t.lower == "episode")
                        .then(|| self.tok(i + 1).and_then(|n| parse_digits(&n.lower, 1, 4)))
                        .flatten()
                });
            if let Some(ep) = ep {
                return Some(Marker {
                    idx: i,
                    season: None,
                    episodes: vec![ep],
                    range: None,
                    air_date: None,
                    pack: false,
                });
            }
        }
        for (pos, _) in self.spaced.match_indices(" - ") {
            let (Some(head), Some(rest)) = (self.spaced.get(..pos), self.spaced.get(pos + 3..))
            else {
                continue;
            };
            let nd = rest.bytes().take_while(u8::is_ascii_digit).count();
            let boundary = rest
                .get(nd..)
                .and_then(|r| r.chars().next())
                .is_none_or(|c| !c.is_alphanumeric());
            if (2..=4).contains(&nd) && boundary {
                let n = rest.get(..nd).and_then(|d| d.parse::<u32>().ok())?;
                if nd == 4 && (1900..=2099).contains(&n) {
                    continue;
                }
                let idx = tokenize(head).len();
                if idx > 0 {
                    return Some(Marker {
                        idx,
                        season: None,
                        episodes: vec![n],
                        range: None,
                        air_date: None,
                        pack: false,
                    });
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------------------------
    // Movies
    // -----------------------------------------------------------------------------------------

    fn movie(&self) -> Option<SceneInfo> {
        if self.find_marker(true).is_some() {
            return None;
        }
        let max_year = self.rules.max_year;
        let mut chosen = None;
        for (j, t) in self.toks.iter().enumerate().rev() {
            if let Some(y) = is_year(&t.lower, max_year)
                && self.quality_after(j)
            {
                chosen = Some((j, y));
                break;
            }
        }
        let (j, year) = chosen?;
        // A year in first position is only the release year if it *is* the title.
        if j == 0 && !self.hits.iter().any(|h| h.idx == 1) {
            return None;
        }
        let tail = j + 1;
        let has = |f: fn(&Kind) -> bool| self.hits.iter().any(|h| h.idx >= tail && f(h.kind));
        let categories = [
            has(|k| matches!(k, Kind::Resolution(_))),
            has(|k| matches!(k, Kind::Source(_))),
            has(|k| matches!(k, Kind::Codec(_))),
        ];
        let present = categories.iter().filter(|b| **b).count();
        if present == 0 || (self.release_group().is_none() && present < 2) {
            return None;
        }
        let mut info = self.base(Family::Movie, 2000);
        info.year = Some(year);
        info.title = if j == 0 {
            self.tok(0).map(|t| t.text.clone())
        } else {
            join_title(self.toks.get(..j)?)
        };
        self.fill_common(&mut info, tail);
        let disc_bluray = has(|k| matches!(k, Kind::DiscBluray))
            || (self.iso
                && matches!(
                    info.source,
                    Source::BluRay | Source::UHDBluRay | Source::Remux | Source::CompleteBluray
                ));
        let disc_dvd = has(|k| matches!(k, Kind::DiscDvd));
        info.category = Some(if info.flags.contains(SceneFlags::THREE_D) {
            2060
        } else if disc_bluray {
            2050
        } else if disc_dvd {
            2070
        } else {
            Self::movie_category(&info)
        });
        Some(info)
    }

    fn movie_category(info: &SceneInfo) -> u16 {
        match info.resolution {
            Resolution::R2160p => 2045,
            Resolution::R720p | Resolution::R1080p => 2040,
            Resolution::R480p | Resolution::R576p => 2030,
            Resolution::Unknown => match info.source {
                Source::UHDBluRay => 2045,
                Source::CAM
                | Source::TS
                | Source::TC
                | Source::SCR
                | Source::R5
                | Source::DVDRip
                | Source::DVD
                | Source::PDTV
                | Source::SDTV => 2030,
                Source::Unknown if matches!(info.video_codec.as_deref(), Some("XviD" | "DivX")) => {
                    2030
                }
                _ => 2000,
            },
        }
    }

    // -----------------------------------------------------------------------------------------
    // Music
    // -----------------------------------------------------------------------------------------

    fn music(&self) -> Option<SceneInfo> {
        self.group.as_ref()?;
        // Video evidence rules music out ("Artist-Show-720p-WEB-2019-GRP").
        if self
            .hits
            .iter()
            .any(|h| matches!(h.kind, Kind::Resolution(_) | Kind::Codec(_)))
            || self.find_marker(true).is_some()
        {
            return None;
        }
        let rules = self.rules;
        let parts: Vec<&str> = self.spaced_body_parts();
        if parts.len() < 2 {
            return None;
        }
        let mut st = MusicState::default();
        for (k, part) in parts.iter().enumerate() {
            Self::music_part(k, part, &mut st, rules);
        }
        if self.m4b {
            st.audiobook = true;
            st.medium.get_or_insert_with(|| "AUDIOBOOK".to_owned());
        }
        let (medium, year) = (st.medium?, st.year?);
        let category = if st.audiobook {
            3030
        } else if st.lossless {
            3040
        } else if st.lossy {
            3010
        } else {
            3000
        };
        let mut info = self.base(Family::Music, category);
        info.title = match (&st.artist, &st.album) {
            (Some(a), Some(b)) => Some(format!("{a} - {b}")),
            (a, b) => a.clone().or_else(|| b.clone()),
        };
        info.artist = st.artist;
        info.album = st.album;
        info.medium = Some(medium);
        info.catalog = st.catalog;
        info.year = Some(year);
        info.lossless = st.lossless;
        info.music_markers = st.markers;
        if self.internal {
            info.flags.insert(SceneFlags::INTERNAL);
        }
        Some(info)
    }

    fn spaced_body_parts(&self) -> Vec<&str> {
        self.spaced.split('-').collect()
    }

    fn music_part(k: usize, raw: &str, st: &mut MusicState, rules: &SceneRules) {
        let raw = raw.trim();
        let wrapped = raw.starts_with(['(', '[']) && raw.ends_with([')', ']']);
        let inner = raw.trim_matches(['(', ')', '[', ']']).trim();
        let lower = inner.to_ascii_lowercase();
        let ptoks = tokenize(inner);
        for t in &ptoks {
            if rules.music_markers.contains(&t.lower) {
                let up = t.lower.to_ascii_uppercase();
                if !st.markers.contains(&up) {
                    st.markers.push(up);
                }
            }
            if rules.audiobook.contains(&t.lower) {
                st.audiobook = true;
            }
        }
        if k == 0 {
            st.artist = join_title(&ptoks);
            return;
        }
        if let Some(y) = parse_digits(&lower, 4, 4)
            .and_then(|y| u16::try_from(y).ok())
            .filter(|y| (rules.music_min_year..=rules.max_year).contains(y))
        {
            st.year = Some(y);
        } else if rules.mediums.contains(&lower) {
            st.medium.get_or_insert_with(|| lower.to_ascii_uppercase());
            if lower == "sacd" {
                st.lossless = true;
            }
        } else if rules.audiobook.contains(&lower) {
            st.medium.get_or_insert_with(|| "AUDIOBOOK".to_owned());
        } else if let Some(lossless) = rules.formats.get(&lower) {
            if *lossless {
                st.lossless = true;
            } else {
                st.lossy = true;
            }
        } else if wrapped {
            if st.catalog.is_none() && !inner.is_empty() {
                st.catalog = Some(inner.to_owned());
            }
        } else if st.album_parts < MAX_TITLE_PARTS {
            st.album_parts += 1;
            if let Some(t) = join_title(&ptoks) {
                st.album = Some(match st.album.take() {
                    Some(prev) => format!("{prev} {t}"),
                    None => t,
                });
            }
        }
    }
}

#[derive(Default)]
struct MusicState {
    artist: Option<String>,
    album: Option<String>,
    album_parts: usize,
    medium: Option<String>,
    catalog: Option<String>,
    year: Option<u16>,
    lossless: bool,
    lossy: bool,
    audiobook: bool,
    markers: Vec<String>,
}

fn scan_hits<'a>(toks: &[Tok], rules: &'a SceneRules) -> Vec<Hit<'a>> {
    let mut hits = Vec::new();
    let mut key = String::new();
    let mut i = 0usize;
    while i < toks.len() {
        let mut consumed = 1;
        for len in (1..=MAX_PHRASE_WORDS).rev() {
            let Some(win) = toks.get(i..i.saturating_add(len)) else {
                continue;
            };
            key.clear();
            for (k, t) in win.iter().enumerate() {
                if k > 0 {
                    key.push(' ');
                }
                key.push_str(&t.lower);
            }
            if let Some(kinds) = rules.phrases.get(key.as_str()) {
                hits.extend(kinds.iter().map(|kind| Hit { idx: i, kind }));
                consumed = len;
                break;
            }
        }
        i = i.saturating_add(consumed);
    }
    hits
}

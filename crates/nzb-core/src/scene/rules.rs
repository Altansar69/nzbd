//! Data-driven token tables (`config/scene_rules.toml`), validated at load.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Deserialize;

use crate::sanitize_text;

use super::{Resolution, SceneFlags, Source};

/// The embedded default rules (same file the operator can inspect in `config/`).
const BUILTIN: &str = include_str!("../../../../config/scene_rules.toml");

/// Longest accepted phrase, in words.
pub(super) const MAX_PHRASE_WORDS: usize = 3;
const MAX_KEY_BYTES: usize = 40;
/// Largest accepted rules file.
pub const MAX_RULES_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSTIC_CHARS: usize = 300;
const MAX_ENTRIES: usize = 4096;

/// Error loading or validating a rules file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SceneRulesError {
    /// The TOML did not parse into the expected shape.
    #[error("scene rules syntax: {0}")]
    Syntax(String),
    /// The TOML parsed but a value is not acceptable.
    #[error("scene rules invalid: {0}")]
    Invalid(String),
}

/// What a phrase means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Kind {
    Source(Source),
    Resolution(Resolution),
    Codec(String),
    Audio(String),
    Hdr(String),
    Language(String),
    Flag(SceneFlags),
    Sport,
    Documentary,
    ThreeD,
    DiscBluray,
    DiscDvd,
    AnimeMarker,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tokens {
    tokens: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Disc {
    bluray: Vec<String>,
    dvd: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnimeRaw {
    markers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MusicRaw {
    mediums: Vec<String>,
    audiobook: Vec<String>,
    markers: Vec<String>,
    min_year: u16,
    formats: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    max_year: u16,
    sources: BTreeMap<String, Source>,
    disc: Disc,
    three_d: Tokens,
    resolutions: BTreeMap<String, Resolution>,
    codecs: BTreeMap<String, String>,
    audio: BTreeMap<String, String>,
    hdr: BTreeMap<String, String>,
    languages: BTreeMap<String, String>,
    flags: BTreeMap<String, String>,
    sports: Tokens,
    documentary: Tokens,
    anime: AnimeRaw,
    music: MusicRaw,
}

/// Compiled rules. Cheap to share by reference; build once at startup.
#[derive(Debug, Clone)]
pub struct SceneRules {
    pub(super) phrases: HashMap<String, Vec<Kind>>,
    pub(super) mediums: HashSet<String>,
    pub(super) audiobook: HashSet<String>,
    pub(super) music_markers: HashSet<String>,
    /// format token -> lossless?
    pub(super) formats: HashMap<String, bool>,
    pub(super) music_min_year: u16,
    pub(super) max_year: u16,
}

impl SceneRules {
    /// Loads the rules embedded in the binary.
    ///
    /// # Errors
    /// Only if the embedded file is broken (covered by a unit test).
    pub fn builtin() -> Result<Self, SceneRulesError> {
        Self::from_toml_str(BUILTIN)
    }

    /// Parses and validates a rules file.
    ///
    /// # Errors
    /// [`SceneRulesError`] on syntax errors, unknown enum values or flag names, malformed phrase
    /// keys (must be 1..=3 lowercase words), or an implausible year bound.
    pub fn from_toml_str(src: &str) -> Result<Self, SceneRulesError> {
        if src.len() > MAX_RULES_BYTES {
            return Err(invalid("rules file too large"));
        }
        let raw: Raw = toml::from_str(src).map_err(|e| {
            // The diagnostic quotes source lines; keep errors short.
            SceneRulesError::Syntax(e.to_string().chars().take(MAX_DIAGNOSTIC_CHARS).collect())
        })?;
        Self::compile(&raw)
    }

    /// Overrides the latest accepted year (callers pass `current_year + 1`; clocks stay outside
    /// this crate so tests are deterministic).
    #[must_use]
    pub fn with_max_year(mut self, max_year: u16) -> Self {
        self.max_year = max_year.clamp(1900, 2200);
        self
    }

    fn compile(raw: &Raw) -> Result<Self, SceneRulesError> {
        if !(1950..=2200).contains(&raw.max_year) || !(1900..=2100).contains(&raw.music.min_year) {
            return Err(invalid("year bounds out of range"));
        }
        let mut phrases: HashMap<String, Vec<Kind>> = HashMap::new();
        let mut add = |key: &str, kind: Kind| -> Result<(), SceneRulesError> {
            check_phrase(key)?;
            let slot = phrases.entry(key.to_owned()).or_default();
            if !slot.contains(&kind) {
                slot.push(kind);
            }
            Ok(())
        };

        for (k, v) in &raw.sources {
            add(k, Kind::Source(*v))?;
        }
        for k in &raw.disc.bluray {
            add(k, Kind::DiscBluray)?;
        }
        for k in &raw.disc.dvd {
            add(k, Kind::DiscDvd)?;
        }
        for k in &raw.three_d.tokens {
            add(k, Kind::ThreeD)?;
        }
        for (k, v) in &raw.resolutions {
            add(k, Kind::Resolution(*v))?;
        }
        for (k, v) in &raw.codecs {
            add(k, Kind::Codec(label(v)?))?;
        }
        for (k, v) in &raw.audio {
            add(k, Kind::Audio(label(v)?))?;
        }
        for (k, v) in &raw.hdr {
            add(k, Kind::Hdr(label(v)?))?;
        }
        for (k, v) in &raw.languages {
            add(k, Kind::Language(label(v)?))?;
        }
        for (k, v) in &raw.flags {
            let f = SceneFlags::from_name(v)
                .ok_or_else(|| invalid(&format!("unknown flag name {v:?}")))?;
            add(k, Kind::Flag(f))?;
        }
        for k in &raw.sports.tokens {
            add(k, Kind::Sport)?;
        }
        for k in &raw.documentary.tokens {
            add(k, Kind::Documentary)?;
        }
        for k in &raw.anime.markers {
            add(k, Kind::AnimeMarker)?;
        }
        if phrases.len() > MAX_ENTRIES {
            return Err(invalid("too many entries"));
        }

        let single_words = |list: &[String]| -> Result<HashSet<String>, SceneRulesError> {
            list.iter()
                .map(|k| {
                    check_phrase(k)?;
                    if k.contains(' ') {
                        return Err(invalid("music tokens must be single words"));
                    }
                    Ok(k.clone())
                })
                .collect()
        };
        let mediums = single_words(&raw.music.mediums)?;
        let audiobook = single_words(&raw.music.audiobook)?;
        let music_markers = single_words(&raw.music.markers)?;
        let mut formats = HashMap::new();
        for (k, v) in &raw.music.formats {
            check_phrase(k)?;
            let lossless = match v.as_str() {
                "lossless" => true,
                "lossy" => false,
                _ => return Err(invalid("music format must be lossless or lossy")),
            };
            formats.insert(k.clone(), lossless);
        }

        Ok(Self {
            phrases,
            mediums,
            audiobook,
            music_markers,
            formats,
            music_min_year: raw.music.min_year,
            max_year: raw.max_year,
        })
    }
}

fn invalid(msg: &str) -> SceneRulesError {
    SceneRulesError::Invalid(msg.to_owned())
}

/// Labels end up in the database and the UI: keep them short and printable.
fn label(v: &str) -> Result<String, SceneRulesError> {
    // sanitize_text strips controls and bidi/invisible (Cf-like) characters and collapses
    // whitespace; a label it would change is rejected (SEC-004).
    if v.is_empty() || v.len() > 32 || sanitize_text(v, 32) != v {
        return Err(invalid(
            "label empty, too long or contains control/format characters",
        ));
    }
    Ok(v.to_owned())
}

/// Keys must be exactly what the tokenizer can produce: 1..=3 non-empty words of lowercase ASCII
/// letters, digits or `+`, separated by single spaces.
fn check_phrase(key: &str) -> Result<(), SceneRulesError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(invalid("phrase empty or too long"));
    }
    let mut words = 0usize;
    for w in key.split(' ') {
        words = words.saturating_add(1);
        if w.is_empty()
            || !w
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'+')
        {
            return Err(invalid(&format!("bad phrase {key:?}")));
        }
    }
    if words > MAX_PHRASE_WORDS {
        return Err(invalid(&format!("phrase {key:?} has too many words")));
    }
    Ok(())
}

//! Scene release-name parser (T015, `PARSER_SPEC` §Categorization, SEC-037).
//!
//! [`parse_scene`] is pure, panic-free and linear-time: the input is capped at 512 bytes before
//! any work happens (longer names are truncated, never rejected), tokenization is a single pass,
//! phrase lookup tries at most three words per position against a hash table, and no regex with
//! backtracking is involved. Allocation is proportional to the capped length only.
//!
//! Families are tried from the strictest to the loosest: music, anime, TV (incl. sport and
//! documentary), movies. Anything else yields [`SceneInfo::default()`] (family `Unknown`), which
//! callers treat as "inconclusive". All strings in the result originate from the (sanitized)
//! input or from the rules file and are display data only.

mod engine;
mod rules;
#[cfg(test)]
mod tests;

use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

pub use rules::{SceneRules, SceneRulesError};

/// Maximum number of bytes of a release name that are examined (SEC-037).
pub const MAX_SCENE_NAME_BYTES: usize = 512;

/// Release family (`release.scene_family`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    /// TV episodes, packs, daily shows, sport and documentaries.
    Tv,
    /// Anime (fansub or scene style).
    Anime,
    /// Movies (incl. discs and 3D).
    Movie,
    /// Music and audiobooks.
    Music,
    /// Inconclusive.
    #[default]
    Unknown,
}

impl Family {
    /// Value stored in `scene_family`; `None` when inconclusive.
    #[must_use]
    pub const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Tv => Some("tv"),
            Self::Anime => Some("anime"),
            Self::Movie => Some("movie"),
            Self::Music => Some("music"),
            Self::Unknown => None,
        }
    }
}

/// Video resolution token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resolution {
    /// 480p / 480i.
    #[serde(rename = "480p")]
    R480p,
    /// 576p / 576i.
    #[serde(rename = "576p")]
    R576p,
    /// 720p.
    #[serde(rename = "720p")]
    R720p,
    /// 1080p / 1080i.
    #[serde(rename = "1080p")]
    R1080p,
    /// 2160p / 4K / UHD.
    #[serde(rename = "2160p")]
    R2160p,
    /// Not stated.
    #[default]
    Unknown,
}

impl Resolution {
    /// Label as stored in `scene_resolution`; `None` for `Unknown`.
    #[must_use]
    pub const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::R480p => Some("480p"),
            Self::R576p => Some("576p"),
            Self::R720p => Some("720p"),
            Self::R1080p => Some("1080p"),
            Self::R2160p => Some("2160p"),
            Self::Unknown => None,
        }
    }
}

/// Release source token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Source {
    /// Camera recording.
    CAM,
    /// Telesync.
    TS,
    /// Telecine.
    TC,
    /// Screener.
    SCR,
    /// Region 5 DVD.
    R5,
    /// HDTV capture.
    HDTV,
    /// PDTV capture.
    PDTV,
    /// SDTV capture.
    SDTV,
    /// DVD rip.
    DVDRip,
    /// DVD (incl. full discs).
    DVD,
    /// WEB rip.
    WEBRip,
    /// WEB download.
    WEBDL,
    /// `BluRay` rip.
    BDRip,
    /// `BluRay` encode.
    BluRay,
    /// `BluRay` remux.
    Remux,
    /// UHD `BluRay`.
    UHDBluRay,
    /// Complete `BluRay` disc.
    CompleteBluray,
    /// Not stated.
    #[default]
    Unknown,
}

impl Source {
    /// Label as stored in `scene_source`; `None` for `Unknown`.
    #[must_use]
    pub const fn as_str(self) -> Option<&'static str> {
        Some(match self {
            Self::CAM => "CAM",
            Self::TS => "TS",
            Self::TC => "TC",
            Self::SCR => "SCR",
            Self::R5 => "R5",
            Self::HDTV => "HDTV",
            Self::PDTV => "PDTV",
            Self::SDTV => "SDTV",
            Self::DVDRip => "DVDRip",
            Self::DVD => "DVD",
            Self::WEBRip => "WEBRip",
            Self::WEBDL => "WEBDL",
            Self::BDRip => "BDRip",
            Self::BluRay => "BluRay",
            Self::Remux => "Remux",
            Self::UHDBluRay => "UHDBluRay",
            Self::CompleteBluray => "CompleteBluray",
            Self::Unknown => return None,
        })
    }

    /// Precedence when several source tokens occur (higher wins).
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::CAM | Self::TS | Self::TC | Self::SCR | Self::R5 => 1,
            Self::SDTV | Self::PDTV => 2,
            Self::HDTV | Self::DVD | Self::DVDRip => 3,
            Self::WEBRip | Self::WEBDL => 4,
            Self::BDRip => 5,
            Self::BluRay => 6,
            Self::UHDBluRay => 7,
            Self::Remux => 8,
            Self::CompleteBluray => 9,
        }
    }
}

/// Bitmask of release flags found in the name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SceneFlags(u32);

impl SceneFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// `PROPER`.
    pub const PROPER: Self = Self(1 << 0);
    /// `REPACK` / `RERIP`.
    pub const REPACK: Self = Self(1 << 1);
    /// `REAL`.
    pub const REAL: Self = Self(1 << 2);
    /// `INTERNAL`.
    pub const INTERNAL: Self = Self(1 << 3);
    /// `READNFO`.
    pub const READNFO: Self = Self(1 << 4);
    /// `DIRFIX`.
    pub const DIRFIX: Self = Self(1 << 5);
    /// `NFOFIX`.
    pub const NFOFIX: Self = Self(1 << 6);
    /// `COMPLETE`.
    pub const COMPLETE: Self = Self(1 << 7);
    /// `EXTENDED`.
    pub const EXTENDED: Self = Self(1 << 8);
    /// `UNRATED`.
    pub const UNRATED: Self = Self(1 << 9);
    /// `3D`.
    pub const THREE_D: Self = Self(1 << 10);
    /// `DUBBED`.
    pub const DUBBED: Self = Self(1 << 11);
    /// `SUBBED`.
    pub const SUBBED: Self = Self(1 << 12);

    const NAMES: [(&'static str, Self); 13] = [
        ("PROPER", Self::PROPER),
        ("REPACK", Self::REPACK),
        ("REAL", Self::REAL),
        ("INTERNAL", Self::INTERNAL),
        ("READNFO", Self::READNFO),
        ("DIRFIX", Self::DIRFIX),
        ("NFOFIX", Self::NFOFIX),
        ("COMPLETE", Self::COMPLETE),
        ("EXTENDED", Self::EXTENDED),
        ("UNRATED", Self::UNRATED),
        ("3D", Self::THREE_D),
        ("DUBBED", Self::DUBBED),
        ("SUBBED", Self::SUBBED),
    ];

    /// Raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True if all flags in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Sets the flags in `other`.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Looks a flag up by its canonical name (`"PROPER"`, `"3D"`, ...).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, f)| *f)
    }

    /// Canonical names of the set flags, in a fixed order.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMES
            .iter()
            .filter(|(_, f)| self.contains(*f))
            .map(|(n, _)| *n)
            .collect()
    }
}

impl Serialize for SceneFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let names = self.names();
        let mut seq = serializer.serialize_seq(Some(names.len()))?;
        for n in names {
            seq.serialize_element(n)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SceneFlags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = SceneFlags;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of scene flag names")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SceneFlags, A::Error> {
                let mut out = SceneFlags::EMPTY;
                while let Some(name) = seq.next_element::<String>()? {
                    let f = SceneFlags::from_name(&name)
                        .ok_or_else(|| de::Error::custom("unknown scene flag"))?;
                    out.insert(f);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_seq(V)
    }
}

/// Parsed release name. `family == Unknown` means inconclusive and every other field is empty.
///
/// Field names map onto the `scene_*` columns of `release` (`DATA_MODEL`); the whole struct is
/// serialised into `scene_json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SceneInfo {
    /// Release family.
    pub family: Family,
    /// Taxonomy id this result maps to (`PARSER_SPEC` §Taxonomy); `None` iff inconclusive.
    pub category: Option<u16>,
    /// Cleaned title (separators turned into spaces).
    pub title: Option<String>,
    /// Release year.
    pub year: Option<u16>,
    /// Season number.
    pub season: Option<u32>,
    /// Explicit episode numbers (at most 64).
    pub episodes: Vec<u32>,
    /// Inclusive episode range written as `E01-E03`.
    pub episode_range: Option<(u32, u32)>,
    /// Air date `YYYY-MM-DD` of daily shows and sport events.
    pub air_date: Option<String>,
    /// Whole-season or complete-series pack.
    pub season_pack: bool,
    /// Resolution.
    pub resolution: Resolution,
    /// Source.
    pub source: Source,
    /// Video codec label.
    pub video_codec: Option<String>,
    /// Audio label.
    pub audio: Option<String>,
    /// HDR labels.
    pub hdr: Vec<String>,
    /// Language labels in order of appearance.
    pub languages: Vec<String>,
    /// Release group (`-GROUP` suffix, or the leading `[Group]` of fansub names).
    pub release_group: Option<String>,
    /// Release flags.
    pub flags: SceneFlags,
    /// Music: artist.
    pub artist: Option<String>,
    /// Music: album.
    pub album: Option<String>,
    /// Music: medium (`CD`, `WEB`, `VINYL`, ...), upper-cased.
    pub medium: Option<String>,
    /// Music: catalogue number.
    pub catalog: Option<String>,
    /// Music: lossless audio.
    pub lossless: bool,
    /// Music: markers such as `EP`, `VA`, `LIVE`, upper-cased.
    pub music_markers: Vec<String>,
}

impl SceneInfo {
    /// True when a family was recognised.
    #[must_use]
    pub const fn is_conclusive(&self) -> bool {
        !matches!(self.family, Family::Unknown)
    }
}

/// Parses a release-name candidate. Pure, panic-free, linear in the (capped) input length.
#[must_use]
pub fn parse_scene(name: &str, rules: &SceneRules) -> SceneInfo {
    engine::parse(name, rules)
}

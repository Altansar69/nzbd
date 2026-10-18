//! Analysis result types.

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use std::ops::{BitOr, BitOrAssign};

/// SHA-256 digest (content address of a stored NZB). Serialized as 64 lowercase hex chars.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256(pub [u8; 32]);

/// Invalid hex form of a [`Sha256`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid sha256 hex string")]
pub struct Sha256ParseError;

impl Sha256 {
    /// Lowercase hex form (64 chars). Safe to use in paths (charset `[0-9a-f]`).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.extend(char::from_digit(u32::from(b >> 4), 16));
            s.extend(char::from_digit(u32::from(b & 0x0f), 16));
        }
        s
    }

    /// First 8 hex chars, used for `untitled-<sha8>`.
    #[must_use]
    pub fn short(&self) -> String {
        self.to_hex().chars().take(8).collect()
    }

    /// Parses exactly 64 lowercase hex characters.
    ///
    /// # Errors
    /// Fails on wrong length, uppercase, or non-hex characters.
    pub fn from_hex(s: &str) -> Result<Self, Sha256ParseError> {
        fn nibble(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
                b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
                _ => None,
            }
        }
        if s.len() != 64 {
            return Err(Sha256ParseError);
        }
        let mut out = [0u8; 32];
        let (pairs, _) = s.as_bytes().as_chunks::<2>();
        for (slot, [hi, lo]) in out.iter_mut().zip(pairs) {
            let hi = nibble(*hi).ok_or(Sha256ParseError)?;
            let lo = nibble(*lo).ok_or(Sha256ParseError)?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({})", self.to_hex())
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(de::Error::custom)
    }
}

/// Kind of a file inside an NZB, derived from the filename extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// mkv mp4 avi ...
    Video,
    /// mp3 flac ...
    Audio,
    /// rar, 7z, zip and split volumes.
    Archive,
    /// par2 recovery files.
    Par2,
    /// nfo, diz.
    Nfo,
    /// sfv checksums.
    Sfv,
    /// srt sub idx ass.
    Subtitle,
    /// jpg png ...
    Image,
    /// nested nzb.
    Nzb,
    /// exe scr bat ... (dangerous when executed).
    Executable,
    /// Anything else, or no filename.
    Other,
}

impl FileKind {
    /// Stable lowercase name (matches the serde form).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Archive => "archive",
            Self::Par2 => "par2",
            Self::Nfo => "nfo",
            Self::Sfv => "sfv",
            Self::Subtitle => "subtitle",
            Self::Image => "image",
            Self::Nzb => "nzb",
            Self::Executable => "executable",
            Self::Other => "other",
        }
    }
}

/// Bitmask of release-level observations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReleaseFlags(u32);

impl ReleaseFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// Most non-par2 files look obfuscated.
    pub const OBFUSCATED: Self = Self(1 << 0);
    /// At least one par2 file.
    pub const HAS_PAR2: Self = Self(1 << 1);
    /// Par2 block count was determined (sum stored in `Analysis::par2_blocks`).
    pub const PAR2_BLOCKS: Self = Self(1 << 2);
    /// Some segments are missing.
    pub const INCOMPLETE: Self = Self(1 << 3);
    /// Duplicate segment numbers seen.
    pub const DUPLICATE_SEGMENTS: Self = Self(1 << 4);
    /// Contains an executable file.
    pub const HAS_EXECUTABLE: Self = Self(1 << 5);
    /// Archive volume sequence has a gap.
    pub const MULTIVOLUME_GAP: Self = Self(1 << 6);
    /// Password meta or hint in title.
    pub const PASSWORD_HINT: Self = Self(1 << 7);
    /// Neither archive nor video present.
    pub const NO_ARCHIVE_OR_VIDEO: Self = Self(1 << 8);
    /// Categorizer fell back to Other/Misc.
    pub const UNCATEGORIZED: Self = Self(1 << 9);

    const ALL: u32 = (1 << 10) - 1;

    /// Raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Builds from raw bits, dropping unknown ones.
    #[must_use]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::ALL)
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
}

impl BitOr for ReleaseFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ReleaseFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Per-file analysis. All strings are sanitized (SEC-004) and display-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    /// Zero-based index in document order.
    pub idx: u32,
    /// Sanitized subject.
    pub subject: String,
    /// Extracted filename, if any (display-only; never a path).
    pub filename: Option<String>,
    /// Kind from extension.
    pub kind: FileKind,
    /// Sanitized poster.
    pub poster: Option<String>,
    /// Post time, Unix seconds; `None` if absent or out of the valid range.
    pub posted_at: Option<i64>,
    /// Sum of segment bytes.
    pub bytes: u64,
    /// Distinct segments seen.
    pub segment_count: u32,
    /// Total declared in the subject (`m` of `(n/m)`).
    pub declared_segments: Option<u32>,
    /// Missing segment number ranges, inclusive, at most 256 entries.
    pub missing_ranges: Vec<(u32, u32)>,
    /// True if more missing ranges existed than were recorded.
    pub missing_truncated: bool,
    /// Par2 recovery blocks (`volNN+MM.par2` gives MM).
    pub par2_blocks: Option<u32>,
    /// Sanitized newsgroup names.
    pub groups: Vec<String>,
}

/// Result of analysing one NZB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    /// SHA-256 of the raw NZB bytes.
    pub sha256: Sha256,
    /// Release-name candidates in categorizer order.
    pub name_candidates: Vec<String>,
    /// How many leading `name_candidates` come from NZB meta (`name`, `title`). The categorizer
    /// inserts the source file stem (candidate 3) right after them.
    #[serde(default)]
    pub meta_name_candidates: u8,
    /// Display title.
    pub title: String,
    /// Most frequent poster.
    pub poster: Option<String>,
    /// Newest valid file date, Unix seconds.
    pub posted_at: Option<i64>,
    /// Sum of all segment bytes.
    pub total_bytes: u64,
    /// Number of files.
    pub file_count: u32,
    /// Number of distinct segments.
    pub segment_count: u64,
    /// Number of duplicate segments dropped.
    pub duplicate_segments: u64,
    /// Sum of the par2 block counts *declared in file names* (unverified, attacker-chosen).
    pub par2_blocks: u64,
    /// Release flags.
    pub flags: ReleaseFlags,
    /// Sanitized `<meta type="category">`, if any.
    pub meta_category: Option<String>,
    /// Heuristic "may be repairable" estimate (label as estimate in UI): `None` if nothing is
    /// missing. Not a verdict; par2 block counts come from untrusted filenames.
    pub repairable_estimate: Option<bool>,
    /// Per-file details.
    pub files: Vec<FileInfo>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_roundtrip() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = u8::try_from(i * 8).unwrap_or(0);
        }
        let s = Sha256(raw);
        let hex = s.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Sha256::from_hex(&hex), Ok(s));
        assert_eq!(s.short(), hex[..8]);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Sha256>(&json).unwrap(), s);
    }

    #[test]
    fn sha256_rejects_bad_hex() {
        assert!(Sha256::from_hex("").is_err());
        assert!(Sha256::from_hex(&"A".repeat(64)).is_err());
        assert!(Sha256::from_hex(&"g".repeat(64)).is_err());
        assert!(Sha256::from_hex(&"0".repeat(63)).is_err());
        assert!(Sha256::from_hex(&format!("../{}", "0".repeat(61))).is_err());
        assert!(Sha256::from_hex(&"é".repeat(32)).is_err());
    }

    #[test]
    fn flags_ops() {
        let mut f = ReleaseFlags::HAS_PAR2 | ReleaseFlags::INCOMPLETE;
        assert!(f.contains(ReleaseFlags::HAS_PAR2));
        assert!(!f.contains(ReleaseFlags::OBFUSCATED));
        f.insert(ReleaseFlags::OBFUSCATED);
        assert!(f.contains(ReleaseFlags::OBFUSCATED | ReleaseFlags::INCOMPLETE));
        assert!(ReleaseFlags::EMPTY.is_empty());
        assert_eq!(
            ReleaseFlags::from_bits_truncate(u32::MAX).bits(),
            (1 << 10) - 1
        );
    }

    #[test]
    fn kind_serde_matches_as_str() {
        let json = serde_json::to_string(&FileKind::Par2).unwrap();
        assert_eq!(json, format!("\"{}\"", FileKind::Par2.as_str()));
    }
}

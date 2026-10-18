//! Parser limits (`PARSER_SPEC` §Limits).

use crate::error::LimitName;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The wall-clock deadline is checked every this many XML events.
pub const DEADLINE_CHECK_INTERVAL: u32 = 1024;

const MIB: u64 = 1024 * 1024;
const TIB: u64 = 1024 * 1024 * 1024 * 1024;

/// Every bound enforced while parsing a hostile NZB.
///
/// Defaults are the spec values. Configuration may only lower them
/// ([`Limits::validate_lowered_only`]); [`Limits::hard_ceilings`] (2x default) is the absolute
/// code-level backstop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum raw NZB size in bytes.
    pub max_file_bytes: u64,
    /// Maximum XML element nesting depth.
    pub max_xml_depth: u32,
    /// Maximum `<file>` elements.
    pub max_files: u32,
    /// Maximum segments in one file (also the maximum segment `number`).
    pub max_segments_per_file: u32,
    /// Maximum segments in the whole NZB.
    pub max_total_segments: u32,
    /// Maximum value of a single `bytes=` attribute.
    pub max_segment_bytes: u64,
    /// Maximum sum of all segment bytes.
    pub max_total_bytes: u64,
    /// Maximum raw subject length in bytes.
    pub max_subject_bytes: u32,
    /// Maximum raw poster length in bytes.
    pub max_poster_bytes: u32,
    /// Maximum length of one group name in bytes.
    pub max_group_bytes: u32,
    /// Maximum groups per file.
    pub max_groups_per_file: u32,
    /// Maximum message-id length in bytes.
    pub max_message_id_bytes: u32,
    /// Maximum `<meta>` entries.
    pub max_meta_entries: u32,
    /// Maximum length of one meta value in bytes.
    pub max_meta_value_bytes: u32,
    /// Wall-clock parse deadline.
    pub parse_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * MIB,
            max_xml_depth: 8,
            max_files: 10_000,
            max_segments_per_file: 100_000,
            max_total_segments: 2_000_000,
            max_segment_bytes: 16 * MIB,
            max_total_bytes: 16 * TIB,
            max_subject_bytes: 2_048,
            max_poster_bytes: 512,
            max_group_bytes: 256,
            max_groups_per_file: 64,
            max_message_id_bytes: 512,
            max_meta_entries: 64,
            max_meta_value_bytes: 4_096,
            parse_deadline: Duration::from_secs(20),
        }
    }
}

/// A configured limit set was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    /// A limit is zero (would reject every input or disable a check).
    #[error("limit {} must be greater than zero", .0.code())]
    Zero(LimitName),
    /// A limit is above the allowed maximum.
    #[error("limit {} is above its allowed maximum", .0.code())]
    TooHigh(LimitName),
    /// The deadline is zero or above the allowed maximum.
    #[error("parse_deadline is out of range")]
    Deadline,
}

impl Limits {
    /// Absolute maximums: 2x the default of every limit. Code never exceeds these.
    #[must_use]
    pub fn hard_ceilings() -> Self {
        let d = Self::default();
        Self {
            max_file_bytes: d.max_file_bytes.saturating_mul(2),
            max_xml_depth: d.max_xml_depth.saturating_mul(2),
            max_files: d.max_files.saturating_mul(2),
            max_segments_per_file: d.max_segments_per_file.saturating_mul(2),
            max_total_segments: d.max_total_segments.saturating_mul(2),
            max_segment_bytes: d.max_segment_bytes.saturating_mul(2),
            max_total_bytes: d.max_total_bytes.saturating_mul(2),
            max_subject_bytes: d.max_subject_bytes.saturating_mul(2),
            max_poster_bytes: d.max_poster_bytes.saturating_mul(2),
            max_group_bytes: d.max_group_bytes.saturating_mul(2),
            max_groups_per_file: d.max_groups_per_file.saturating_mul(2),
            max_message_id_bytes: d.max_message_id_bytes.saturating_mul(2),
            max_meta_entries: d.max_meta_entries.saturating_mul(2),
            max_meta_value_bytes: d.max_meta_value_bytes.saturating_mul(2),
            parse_deadline: d.parse_deadline.saturating_mul(2),
        }
    }

    /// Every limit lowered to at most its [`Limits::hard_ceilings`] value. The parser applies
    /// this to whatever it is handed, so a mis-built `Limits` cannot disable a bound (SEC-002).
    #[must_use]
    pub fn clamped_to_ceilings(&self) -> Self {
        let c = Self::hard_ceilings();
        Self {
            max_file_bytes: self.max_file_bytes.min(c.max_file_bytes),
            max_xml_depth: self.max_xml_depth.min(c.max_xml_depth),
            max_files: self.max_files.min(c.max_files),
            max_segments_per_file: self.max_segments_per_file.min(c.max_segments_per_file),
            max_total_segments: self.max_total_segments.min(c.max_total_segments),
            max_segment_bytes: self.max_segment_bytes.min(c.max_segment_bytes),
            max_total_bytes: self.max_total_bytes.min(c.max_total_bytes),
            max_subject_bytes: self.max_subject_bytes.min(c.max_subject_bytes),
            max_poster_bytes: self.max_poster_bytes.min(c.max_poster_bytes),
            max_group_bytes: self.max_group_bytes.min(c.max_group_bytes),
            max_groups_per_file: self.max_groups_per_file.min(c.max_groups_per_file),
            max_message_id_bytes: self.max_message_id_bytes.min(c.max_message_id_bytes),
            max_meta_entries: self.max_meta_entries.min(c.max_meta_entries),
            max_meta_value_bytes: self.max_meta_value_bytes.min(c.max_meta_value_bytes),
            parse_deadline: self.parse_deadline.min(c.parse_deadline),
        }
    }

    fn numeric(&self) -> [(LimitName, u64); 14] {
        [
            (LimitName::FileBytes, self.max_file_bytes),
            (LimitName::XmlDepth, u64::from(self.max_xml_depth)),
            (LimitName::Files, u64::from(self.max_files)),
            (
                LimitName::SegmentsPerFile,
                u64::from(self.max_segments_per_file),
            ),
            (LimitName::TotalSegments, u64::from(self.max_total_segments)),
            (LimitName::SegmentBytes, self.max_segment_bytes),
            (LimitName::TotalBytes, self.max_total_bytes),
            (LimitName::SubjectBytes, u64::from(self.max_subject_bytes)),
            (LimitName::PosterBytes, u64::from(self.max_poster_bytes)),
            (LimitName::GroupBytes, u64::from(self.max_group_bytes)),
            (
                LimitName::GroupsPerFile,
                u64::from(self.max_groups_per_file),
            ),
            (
                LimitName::MessageIdBytes,
                u64::from(self.max_message_id_bytes),
            ),
            (LimitName::MetaEntries, u64::from(self.max_meta_entries)),
            (
                LimitName::MetaValueBytes,
                u64::from(self.max_meta_value_bytes),
            ),
        ]
    }

    fn validate_against(&self, max: &Self) -> Result<(), LimitsError> {
        for ((name, value), (_, bound)) in self.numeric().into_iter().zip(max.numeric()) {
            if value == 0 {
                return Err(LimitsError::Zero(name));
            }
            if value > bound {
                return Err(LimitsError::TooHigh(name));
            }
        }
        if self.parse_deadline.is_zero() || self.parse_deadline > max.parse_deadline {
            return Err(LimitsError::Deadline);
        }
        Ok(())
    }

    /// Checks that a configured set only *lowers* the defaults: every value is non-zero and
    /// at most the default (which is itself below the hard ceiling).
    ///
    /// # Errors
    /// Returns the first offending limit.
    pub fn validate_lowered_only(&self) -> Result<(), LimitsError> {
        self.validate_against(&Self::default())
    }

    /// Checks non-zero and within [`Limits::hard_ceilings`]. Used for programmatic callers
    /// (tests, tools) that legitimately need more than the default.
    ///
    /// # Errors
    /// Returns the first offending limit.
    pub fn validate_within_ceilings(&self) -> Result<(), LimitsError> {
        self.validate_against(&Self::hard_ceilings())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let d = Limits::default();
        assert_eq!(d.max_file_bytes, 67_108_864);
        assert_eq!(d.max_xml_depth, 8);
        assert_eq!(d.max_files, 10_000);
        assert_eq!(d.max_segments_per_file, 100_000);
        assert_eq!(d.max_total_segments, 2_000_000);
        assert_eq!(d.max_segment_bytes, 16_777_216);
        assert_eq!(d.max_total_bytes, 16 * 1024_u64.pow(4));
        assert_eq!(d.max_subject_bytes, 2_048);
        assert_eq!(d.max_poster_bytes, 512);
        assert_eq!((d.max_group_bytes, d.max_groups_per_file), (256, 64));
        assert_eq!(d.max_message_id_bytes, 512);
        assert_eq!((d.max_meta_entries, d.max_meta_value_bytes), (64, 4_096));
        assert_eq!(d.parse_deadline, Duration::from_secs(20));
        assert_eq!(DEADLINE_CHECK_INTERVAL, 1_024);
    }

    #[test]
    fn ceilings_are_double_defaults() {
        let (d, c) = (Limits::default(), Limits::hard_ceilings());
        assert_eq!(c.max_xml_depth, 16);
        assert_eq!(c.parse_deadline, Duration::from_secs(40));
        for ((_, v), (_, dv)) in c.numeric().into_iter().zip(d.numeric()) {
            assert_eq!(v, dv * 2);
        }
    }

    #[test]
    fn default_is_valid_and_lowering_ok() {
        assert_eq!(Limits::default().validate_lowered_only(), Ok(()));
        let l = Limits {
            max_files: 5,
            parse_deadline: Duration::from_secs(1),
            ..Limits::default()
        };
        assert_eq!(l.validate_lowered_only(), Ok(()));
    }

    #[test]
    fn raising_is_rejected_by_lowered_only() {
        let l = Limits {
            max_files: 10_001,
            ..Limits::default()
        };
        assert_eq!(
            l.validate_lowered_only(),
            Err(LimitsError::TooHigh(LimitName::Files))
        );
        let l = Limits {
            parse_deadline: Duration::from_secs(21),
            ..Limits::default()
        };
        assert_eq!(l.validate_lowered_only(), Err(LimitsError::Deadline));
        let l = Limits {
            max_total_bytes: u64::MAX,
            ..Limits::default()
        };
        assert_eq!(
            l.validate_lowered_only(),
            Err(LimitsError::TooHigh(LimitName::TotalBytes))
        );
    }

    #[test]
    fn zero_is_rejected() {
        let l = Limits {
            max_xml_depth: 0,
            ..Limits::default()
        };
        assert_eq!(
            l.validate_lowered_only(),
            Err(LimitsError::Zero(LimitName::XmlDepth))
        );
        let l = Limits {
            parse_deadline: Duration::ZERO,
            ..Limits::default()
        };
        assert_eq!(l.validate_lowered_only(), Err(LimitsError::Deadline));
    }

    #[test]
    fn ceilings_validation() {
        let up = Limits {
            max_files: 20_000,
            ..Limits::default()
        };
        assert_eq!(up.validate_within_ceilings(), Ok(()));
        let over = Limits {
            max_files: 20_001,
            ..Limits::default()
        };
        assert_eq!(
            over.validate_within_ceilings(),
            Err(LimitsError::TooHigh(LimitName::Files))
        );
        assert_eq!(Limits::hard_ceilings().validate_within_ceilings(), Ok(()));
    }

    #[test]
    fn serde_defaults_and_unknown_fields() {
        let l: Limits = serde_json::from_str(r#"{"max_files": 7}"#).unwrap();
        assert_eq!(l.max_files, 7);
        assert_eq!(l.max_xml_depth, 8);
        assert!(serde_json::from_str::<Limits>(r#"{"bogus": 1}"#).is_err());
    }
}

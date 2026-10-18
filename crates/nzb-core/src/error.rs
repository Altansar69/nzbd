//! Typed parser errors with stable, client-facing codes.

use serde::{Deserialize, Serialize};

/// Identifies which [`crate::Limits`] field was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LimitName {
    /// `max_file_bytes`
    FileBytes,
    /// `max_xml_depth`
    XmlDepth,
    /// `max_files`
    Files,
    /// `max_segments_per_file`
    SegmentsPerFile,
    /// `max_total_segments`
    TotalSegments,
    /// `max_segment_bytes`
    SegmentBytes,
    /// `max_total_bytes`
    TotalBytes,
    /// `max_subject_bytes`
    SubjectBytes,
    /// `max_poster_bytes`
    PosterBytes,
    /// `max_group_bytes`
    GroupBytes,
    /// `max_groups_per_file`
    GroupsPerFile,
    /// `max_message_id_bytes`
    MessageIdBytes,
    /// `max_meta_entries`
    MetaEntries,
    /// `max_meta_value_bytes`
    MetaValueBytes,
}

impl LimitName {
    /// Stable error code, `NZB_LIMIT_<NAME>`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FileBytes => "NZB_LIMIT_FILE_BYTES",
            Self::XmlDepth => "NZB_LIMIT_XML_DEPTH",
            Self::Files => "NZB_LIMIT_FILES",
            Self::SegmentsPerFile => "NZB_LIMIT_SEGMENTS_PER_FILE",
            Self::TotalSegments => "NZB_LIMIT_TOTAL_SEGMENTS",
            Self::SegmentBytes => "NZB_LIMIT_SEGMENT_BYTES",
            Self::TotalBytes => "NZB_LIMIT_TOTAL_BYTES",
            Self::SubjectBytes => "NZB_LIMIT_SUBJECT_BYTES",
            Self::PosterBytes => "NZB_LIMIT_POSTER_BYTES",
            Self::GroupBytes => "NZB_LIMIT_GROUP_BYTES",
            Self::GroupsPerFile => "NZB_LIMIT_GROUPS_PER_FILE",
            Self::MessageIdBytes => "NZB_LIMIT_MESSAGE_ID_BYTES",
            Self::MetaEntries => "NZB_LIMIT_META_ENTRIES",
            Self::MetaValueBytes => "NZB_LIMIT_META_VALUE_BYTES",
        }
    }
}

/// Errors produced while parsing or analysing an NZB.
///
/// Display text never embeds input data (it may be hostile); clients receive [`NzbError::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NzbError {
    /// The document contains a DOCTYPE (XXE / entity expansion defence, SEC-001).
    #[error("DOCTYPE is forbidden")]
    DoctypeForbidden,
    /// The input is not valid UTF-8.
    #[error("input is not valid UTF-8")]
    NotUtf8,
    /// Empty document, missing `<nzb>` root, or no `<file>` elements.
    #[error("NZB is empty")]
    Empty,
    /// A configured limit was exceeded.
    #[error("limit exceeded: {}", which.code())]
    LimitExceeded {
        /// The limit that was hit.
        which: LimitName,
    },
    /// The parse deadline elapsed.
    #[error("parse deadline exceeded")]
    Timeout,
    /// Structurally invalid XML or forbidden construct (e.g. unknown entity).
    #[error("malformed NZB: {reason}")]
    Malformed {
        /// Static, input-independent description.
        reason: &'static str,
    },
}

impl NzbError {
    /// Stable machine-readable code for logs, `reason.json` and API clients.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DoctypeForbidden => "NZB_DOCTYPE_FORBIDDEN",
            Self::NotUtf8 => "NZB_NOT_UTF8",
            Self::Empty => "NZB_EMPTY",
            Self::LimitExceeded { which } => which.code(),
            Self::Timeout => "NZB_TIMEOUT",
            Self::Malformed { .. } => "NZB_MALFORMED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(NzbError::DoctypeForbidden.code(), "NZB_DOCTYPE_FORBIDDEN");
        assert_eq!(NzbError::NotUtf8.code(), "NZB_NOT_UTF8");
        assert_eq!(NzbError::Empty.code(), "NZB_EMPTY");
        assert_eq!(NzbError::Timeout.code(), "NZB_TIMEOUT");
        assert_eq!(NzbError::Malformed { reason: "x" }.code(), "NZB_MALFORMED");
        let e = NzbError::LimitExceeded {
            which: LimitName::Files,
        };
        assert_eq!(e.code(), "NZB_LIMIT_FILES");
        assert_eq!(e.to_string(), "limit exceeded: NZB_LIMIT_FILES");
    }
}

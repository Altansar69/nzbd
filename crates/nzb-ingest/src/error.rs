//! Typed pipeline errors with stable codes (`ingest_log.error_code`, `reason.json`, API).

use nzb_core::NzbError;
use nzb_store::StoreError;

use crate::scanner::OpenError;

/// What the pipeline does with the source of a failed submission. This is the seam for T032
/// (`failed/` + `reason.json`): `Reject` sources are quarantined, `Retry` sources stay put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The content is unacceptable: quarantine it in `failed/`.
    Reject,
    /// The failure may be transient or not about the content: leave the source, back off.
    Retry,
}

/// Why a submission was not ingested. Display text never contains NZB-derived data.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// More than `max_file_bytes` bytes.
    #[error("file too large")]
    FileTooLarge,
    /// The file changed while it was being read, or differs from what the scanner observed.
    #[error("source changed while reading")]
    SourceChanged,
    /// Not a regular file, hard-linked, outside the root, or unreadable.
    #[error("source not readable")]
    SourceUnreadable,
    /// The parser rejected the document.
    #[error("invalid NZB: {0}")]
    Parse(#[from] NzbError),
    /// The submitted category hint is not in the taxonomy.
    #[error("invalid category")]
    InvalidCategory,
    /// Database or blob store failure.
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),
    /// Unexpected internal failure (worker panic, hash inconsistency).
    #[error("internal error")]
    Internal,
    /// The API key (or the account) that submitted the file is no longer usable (T101b, N9):
    /// revoked, or its owner disabled/demoted, while the body streamed. Nothing was written.
    #[error("uploader not permitted")]
    UploaderRefused,
    /// The bounded queue is full (HTTP 503).
    #[error("ingest queue full")]
    QueueFull,
    /// The pipeline is shutting down.
    #[error("ingest is shutting down")]
    ShuttingDown,
    /// `nzbd import` only: the digest belongs to a release deleted from the library (it is in the
    /// trash); it is not brought back unless `--include-deleted` (review 38 L1). Nothing is written.
    #[error("deleted from the library")]
    Trashed,
}

impl IngestError {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FileTooLarge => "FILE_TOO_LARGE",
            Self::SourceChanged => "SOURCE_CHANGED",
            Self::SourceUnreadable => "SOURCE_UNREADABLE",
            Self::Parse(e) => e.code(),
            Self::InvalidCategory => "INVALID_CATEGORY",
            Self::Storage(_) => "STORAGE_ERROR",
            Self::Internal => "INTERNAL",
            Self::UploaderRefused => "UNAUTHORIZED",
            Self::QueueFull => "QUEUE_FULL",
            Self::ShuttingDown => "SHUTTING_DOWN",
            Self::Trashed => "TRASHED",
        }
    }

    /// See [`Disposition`].
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::FileTooLarge | Self::Parse(_) | Self::InvalidCategory => Disposition::Reject,
            _ => Disposition::Retry,
        }
    }

    /// Whether the submission reached a worker (queue errors did not).
    #[must_use]
    pub(crate) const fn reached_worker(&self) -> bool {
        !matches!(self, Self::QueueFull | Self::ShuttingDown)
    }
}

impl From<OpenError> for IngestError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::TooLarge { .. } => Self::FileTooLarge,
            OpenError::Changed => Self::SourceChanged,
            OpenError::NotRegular
            | OpenError::HardLinked
            | OpenError::OutsideRoot
            | OpenError::Io(_) => Self::SourceUnreadable,
        }
    }
}

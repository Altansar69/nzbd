//! The retention policy shared by both backends (D35 d, review 30 M3, SEC-081/103).

use crate::StoreError;

/// The retention policy (`nzbd db set-retention`, review 30 M3): owner-only on Postgres, the `retention_policy` row on
/// SQLite; floors are CHECKs on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Audit class 0 (everything but account-lifecycle events), days; floor 90.
    pub log_days: u32,
    /// Audit class 1 (account lifecycle, `ACCOUNT_AUDIT_EVENTS`), days; floor 365.
    pub account_days: u32,
    /// `ingest_log`, days; floor 1.
    pub ingest_days: u32,
    /// Nothing is purged (2.x `log_retention_days = 0`).
    pub keep_all: bool,
    /// Account-lifecycle rows are never purged (2.x `account_audit_retention_days = 0`).
    pub account_keep_all: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            log_days: 90,
            account_days: 365,
            ingest_days: 90,
            keep_all: false,
            account_keep_all: false,
        }
    }
}

/// Floors of the policy (the CHECKs of `retention_policy` say the same; checked here first for a clear error).
pub const RETENTION_FLOORS: (u32, u32, u32) = (90, 365, 1);

impl RetentionPolicy {
    /// Refuses values below the floors (the table CHECKs say the same; this gives a clear error first).
    ///
    /// # Errors
    /// [`StoreError::OutOfRange`] naming the field below its floor.
    pub fn validate(&self) -> Result<(), StoreError> {
        let (log_floor, account_floor, ingest_floor) = RETENTION_FLOORS;
        if self.log_days < log_floor {
            return Err(StoreError::OutOfRange("log_days below 90"));
        }
        if self.account_days < account_floor {
            return Err(StoreError::OutOfRange("account_days below 365"));
        }
        if self.ingest_days < ingest_floor {
            return Err(StoreError::OutOfRange("ingest_days below 1"));
        }
        Ok(())
    }
}

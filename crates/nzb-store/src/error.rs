//! Store error type. Messages never contain NZB-derived data or secrets.

/// Errors returned by `nzb-store`.
///
/// `Debug` and `Display` never print a Postgres error's message, `DETAIL`, `HINT` or values, only its SQLSTATE and
/// the names of the constraint and table (SEC-097): a unique violation's `DETAIL` names the conflicting value and a
/// CHECK violation's prints the whole failing row (password hashes, sealed TOTP secrets, emails).
#[derive(thiserror::Error)]
pub enum StoreError {
    /// The database failed its startup integrity checks (corrupt or not a database).
    #[error("database integrity check failed: {0}")]
    Integrity(String),
    /// A migration could not be applied.
    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A release with the same SHA-256 already exists.
    #[error("release already exists")]
    Duplicate,
    /// The referenced row does not exist.
    #[error("not found")]
    NotFound,
    /// A user already exists (v1 is single-user, D2).
    #[error("a user already exists")]
    UserExists,
    /// Username is empty, too long, or has characters outside `[A-Za-z0-9._-]`.
    #[error("invalid username")]
    InvalidUsername,
    /// An API key label is empty, too long, or has characters outside the allowed set.
    #[error("invalid label")]
    InvalidLabel,
    /// The category id is not in the taxonomy.
    #[error("unknown category")]
    UnknownCategory,
    /// A value does not fit the database integer range.
    #[error("value out of range: {0}")]
    OutOfRange(&'static str),
    /// A multi-user account rule refused the operation (stable code: [`crate::AccountError::code`]).
    #[error("account rule: {0}")]
    Account(#[from] crate::AccountError),
    /// A saved-search rule refused the operation (stable code: [`crate::SavedSearchError::code`], T127).
    #[error("saved search rule: {0}")]
    SavedSearch(crate::SavedSearchError),
    /// The audit hash chain could not be extended or read (T105); the message is a fixed string.
    #[error("audit chain: {0}")]
    AuditChain(&'static str),
    /// Any other database error (rendered without data, see the type docs).
    #[error("database error: {}", DbRedacted(.0))]
    Db(#[from] sqlx::Error),
    /// Filesystem error (permissions on the database file).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The database is in a state this release refuses to open or serve (stable code, e.g. `LEGACY_DATABASE`,
    /// `LIBRARY_MISMATCH`, `RESTORE_PENDING`). Carries no data.
    #[error("{0}")]
    Refused(&'static str),
    /// Bytes handed to the blob store do not hash to the claimed SHA-256.
    #[error("content does not match its sha256")]
    HashMismatch,
    /// A stored blob does not hash to its address (corruption or tampering).
    #[error("stored blob does not match its sha256")]
    Corrupt,
    /// Test-only simulated crash (fault injection); never produced in production builds.
    #[cfg(test)]
    #[error("injected crash")]
    Injected,
}

/// A database error reduced to what may be logged: SQLSTATE, constraint and table names for server errors; the
/// sqlx error otherwise (pool, I/O, protocol and decode errors carry no row data).
pub(crate) struct DbRedacted<'a>(pub(crate) &'a sqlx::Error);

impl std::fmt::Display for DbRedacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            sqlx::Error::Database(d)
                if d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                    .is_some() =>
            {
                write!(f, "SQLSTATE {}", d.code().as_deref().unwrap_or("?"))?;
                if let Some(c) = d.constraint() {
                    write!(f, " constraint {c}")?;
                }
                if let Some(t) = d.table() {
                    write!(f, " table {t}")?;
                }
                Ok(())
            }
            other => write!(f, "{other}"),
        }
    }
}

impl std::fmt::Debug for DbRedacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            sqlx::Error::Database(d)
                if d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                    .is_some() =>
            {
                f.debug_struct("Database")
                    .field("code", &d.code())
                    .field("constraint", &d.constraint())
                    .field("table", &d.table())
                    .finish_non_exhaustive()
            }
            other => write!(f, "{other:?}"),
        }
    }
}

/// A migration error without database row data (`SECURITY_REVIEW` 31 I1): the database error inside it is reduced like
/// [`DbRedacted`].
struct MigrateRedacted<'a>(&'a sqlx::migrate::MigrateError);

impl std::fmt::Debug for MigrateRedacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sqlx::migrate::MigrateError as M;
        match self.0 {
            M::Execute(e) => f.debug_tuple("Execute").field(&DbRedacted(e)).finish(),
            M::ExecuteMigration(e, v) => f
                .debug_tuple("ExecuteMigration")
                .field(&DbRedacted(e))
                .field(v)
                .finish(),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::fmt::Debug for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integrity(s) => f.debug_tuple("Integrity").field(s).finish(),
            Self::Migrate(e) => f.debug_tuple("Migrate").field(&MigrateRedacted(e)).finish(),
            Self::Duplicate => f.write_str("Duplicate"),
            Self::NotFound => f.write_str("NotFound"),
            Self::UserExists => f.write_str("UserExists"),
            Self::InvalidUsername => f.write_str("InvalidUsername"),
            Self::InvalidLabel => f.write_str("InvalidLabel"),
            Self::UnknownCategory => f.write_str("UnknownCategory"),
            Self::OutOfRange(s) => f.debug_tuple("OutOfRange").field(s).finish(),
            Self::Account(e) => f.debug_tuple("Account").field(e).finish(),
            Self::SavedSearch(e) => f.debug_tuple("SavedSearch").field(e).finish(),
            Self::AuditChain(s) => f.debug_tuple("AuditChain").field(s).finish(),
            Self::Db(e) => f.debug_tuple("Db").field(&DbRedacted(e)).finish(),
            Self::Io(e) => f.debug_tuple("Io").field(e).finish(),
            Self::Refused(code) => f.debug_tuple("Refused").field(code).finish(),
            Self::HashMismatch => f.write_str("HashMismatch"),
            Self::Corrupt => f.write_str("Corrupt"),
            #[cfg(test)]
            Self::Injected => f.write_str("Injected"),
        }
    }
}

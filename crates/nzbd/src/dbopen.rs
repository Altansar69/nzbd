//! Opening the configured backend (`db.backend`, ARCHITECTURE v3 13.1/13.5). The only place in `nzbd` that names
//! both backends' constructors; everything else holds a [`Store`].
//!
//! * SQLite: `paths.db`, created and migrated on open (fresh 3.x library) or refused (`LEGACY_DATABASE` for a 2.x
//!   file, never modified).
//! * Postgres: the app role over the configured socket or internal address, password from `db.password_file`
//!   (SEC-042 rules); never migrates (`serve` refuses `MIGRATIONS_PENDING` and every other readiness code: migrations
//!   are applied with the owner role by `nzbd db migrate` in the one-shot `setup` service, review 30 M4).

use nzb_store::pg::PgDb;
use nzb_store::pg::config::read_password_file;
use nzb_store::{DbBackend, DbConfig, OpenEvent, SqliteDb, StartupCheck, Store, StoreError};

use crate::config::Config;

/// Why an open failed: a stable code for the operator plus the store error when there is one.
#[derive(Debug)]
pub enum OpenError {
    /// A store error (SQLite open/migration, Postgres connection).
    Store(StoreError),
    /// A refusal with a stable code (`MIGRATIONS_PENDING`, `DB_PASSWORD_FILE`, ...).
    Refused(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Refused(s) => f.write_str(s),
        }
    }
}

impl From<StoreError> for OpenError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

async fn connect_pg(cfg: &Config) -> Result<PgDb, OpenError> {
    crate::config::check_process_environment().map_err(|e| OpenError::Refused(e.to_string()))?;
    let s = cfg
        .db
        .pg_settings()
        .map_err(|e| OpenError::Refused(e.to_string()))?;
    let password = read_password_file(&s.password_file)
        .map_err(|e| OpenError::Refused(format!("{}: {e}", e.code())))?;
    Ok(PgDb::connect(&s, &password).await?)
}

async fn ready(db: PgDb) -> Result<Store, OpenError> {
    let r = db.readiness().await?;
    match r.code() {
        None => Ok(Store::Postgres(db)),
        Some(code) => {
            db.close().await;
            Err(OpenError::Refused(format!(
                "{code}: the PostgreSQL database is not ready for this release"
            )))
        }
    }
}

/// Opens the library read-write (operator commands): SQLite creates and migrates a new file; Postgres must be ready.
/// A library marked `restore_pending` is refused with `RESTORE_PENDING` on both backends (review 35 L6): only the
/// commands of the gate list (`db restore-finish`, `db check`, `audit verify`, `backup`, `search status`) run then,
/// through [`open_allow_restore_pending`] or [`open_read_only`].
///
/// # Errors
/// See [`OpenError`].
pub async fn open(cfg: &Config) -> Result<Store, OpenError> {
    open_with(cfg, cfg.db.startup_check.into(), &operator_progress).await
}

/// Operator commands stay quiet about the routine open steps; a fixed file mode (SEC-102) is always a warning.
#[allow(clippy::needless_pass_by_value)] // the progress callback type (`dyn Fn(OpenEvent)`) passes it by value
fn operator_progress(ev: OpenEvent) {
    if matches!(ev, OpenEvent::FileModeFixed { .. }) {
        crate::dbcheck::log_open_event(&ev);
    }
}

/// [`open`] with the SQLite startup check mode and progress events (`serve`).
///
/// # Errors
/// See [`OpenError`].
pub async fn open_with(
    cfg: &Config,
    check: StartupCheck,
    progress: &(dyn Fn(OpenEvent) + Send + Sync),
) -> Result<Store, OpenError> {
    match cfg.db.backend {
        DbBackend::Sqlite => {
            let db = open_sqlite(cfg, check, progress).await?;
            if db.restore_pending().await? {
                db.close().await;
                return Err(OpenError::Refused(
                    "RESTORE_PENDING: this database was restored; run `nzbd db restore-finish` first".to_owned(),
                ));
            }
            Ok(Store::Sqlite(db))
        }
        DbBackend::Postgres => ready(connect_pg(cfg).await?).await,
    }
}

async fn open_sqlite(
    cfg: &Config,
    check: StartupCheck,
    progress: &(dyn Fn(OpenEvent) + Send + Sync),
) -> Result<SqliteDb, OpenError> {
    Ok(SqliteDb::open_with(
        &DbConfig {
            path: cfg.paths.db.clone(),
        },
        check,
        progress,
    )
    .await?)
}

/// Opens the library for `nzbd db restore-finish` and `nzbd backup`: like [`open`], but a database that is only
/// pending a restore (the state restore-finish ends) is accepted on both backends.
///
/// # Errors
/// See [`OpenError`].
pub async fn open_allow_restore_pending(cfg: &Config) -> Result<Store, OpenError> {
    match cfg.db.backend {
        DbBackend::Sqlite => Ok(Store::Sqlite(
            open_sqlite(cfg, cfg.db.startup_check.into(), &operator_progress).await?,
        )),
        DbBackend::Postgres => {
            let db = connect_pg(cfg).await?;
            match db.readiness().await? {
                nzb_store::pg::Readiness::Ready | nzb_store::pg::Readiness::RestorePending => {
                    Ok(Store::Postgres(db))
                }
                other => {
                    db.close().await;
                    Err(OpenError::Refused(format!(
                        "{}: the PostgreSQL database is not ready for this release",
                        other.code().unwrap_or("NOT_READY")
                    )))
                }
            }
        }
    }
}

/// Opens the library without creating, migrating or writing anything (diagnostics, dry runs).
///
/// # Errors
/// See [`OpenError`].
pub async fn open_read_only(cfg: &Config) -> Result<Store, OpenError> {
    match cfg.db.backend {
        DbBackend::Sqlite => Ok(SqliteDb::open_read_only(&cfg.paths.db)
            .await
            .map(Store::Sqlite)?),
        DbBackend::Postgres => Ok(Store::Postgres(connect_pg(cfg).await?)),
    }
}

/// Whether the configured library exists at all (SQLite: the file; Postgres: always, the server holds it).
#[must_use]
pub fn exists(cfg: &Config) -> bool {
    match cfg.db.backend {
        DbBackend::Sqlite => cfg.paths.db.is_file(),
        DbBackend::Postgres => true,
    }
}

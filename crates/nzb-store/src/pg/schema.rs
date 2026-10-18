//! v3 schema version, owner-only migration, and the startup readiness gate (review M4, L7; SEC-087, SEC-094).
//!
//! `serve` never migrates: it connects with the app role and calls [`PgDb::readiness`], which refuses pending
//! migrations (`MIGRATIONS_PENDING`), a database written by a newer binary (`SCHEMA_NEWER`), a restore that has not
//! been finished (`RESTORE_PENDING`) and a database whose locale is not `C` (`DB_LOCALE_NOT_C`). Migrations run only
//! through [`migrate_as_owner`] from the one-shot `setup` service, with the owner role's own connection.

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection as _, PgConnection};

use super::PgDb;
use crate::StoreError;
use crate::taxonomy::seed_rows;

/// The compiled-in v3 migrations (`migrations/v3`; the superuser bootstrap in `migrations/v3/superuser` is not part
/// of it).
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations/v3");

/// Oldest supported Postgres server (`server_version_num`): 18 is pinned in compose, 17 is the minimum (D35 d, owner
/// answer Q6).
pub const MIN_SERVER_VERSION_NUM: i32 = 170_000;

/// Why the database cannot be served yet (stable codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Everything is in place.
    Ready,
    /// Migrations of this binary are not applied (run `nzbd db migrate` in the setup service).
    MigrationsPending(Vec<i64>),
    /// The ledger holds a migration this binary does not know (a newer release wrote the database).
    SchemaNewer(i64),
    /// `db restore` ran and `db restore-finish` did not (SEC-094).
    RestorePending,
    /// The database was not created with `LC_COLLATE`/`LC_CTYPE` = `C` (`DATA_MODEL` v3 section 1).
    LocaleNotC,
    /// The database encoding is not UTF-8 (`SECURITY_REVIEW` 31 L6): the audit hash, the byte-length CHECKs and every
    /// NZB string assume it.
    EncodingNotUtf8,
    /// The server is older than [`MIN_SERVER_VERSION_NUM`] (`IS JSON`, `uuid_send(gen_random_uuid())` need 16+).
    ServerTooOld(i32),
}

impl Readiness {
    /// Stable code, `None` when ready.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::MigrationsPending(_) => Some("MIGRATIONS_PENDING"),
            Self::SchemaNewer(_) => Some("SCHEMA_NEWER"),
            Self::RestorePending => Some("RESTORE_PENDING"),
            Self::LocaleNotC => Some("DB_LOCALE_NOT_C"),
            Self::EncodingNotUtf8 => Some("DB_ENCODING_NOT_UTF8"),
            Self::ServerTooOld(_) => Some("DB_VERSION_UNSUPPORTED"),
        }
    }
}

/// Versions of [`MIGRATOR`] not recorded in the ledger; `Err(SchemaNewer)`-style information is returned through
/// [`Readiness`] by [`PgDb::readiness`]. Read-only; works with the app role (it may `SELECT` the ledger).
///
/// # Errors
/// Database errors.
pub async fn pending_migrations(
    conn: &mut PgConnection,
) -> Result<(Vec<i64>, Option<i64>), StoreError> {
    let has_ledger: bool =
        sqlx::query_scalar("SELECT to_regclass('nzbd._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    let applied: Vec<i64> = if has_ledger {
        sqlx::query_scalar(
            "SELECT version FROM nzbd._sqlx_migrations WHERE success ORDER BY version",
        )
        .fetch_all(&mut *conn)
        .await?
    } else {
        Vec::new()
    };
    let unknown = applied
        .iter()
        .copied()
        .find(|v| !MIGRATOR.iter().any(|m| m.version == *v));
    let pending = MIGRATOR
        .iter()
        .filter(|m| m.migration_type.is_up_migration() && !applied.contains(&m.version))
        .map(|m| m.version)
        .collect();
    Ok((pending, unknown))
}

impl PgDb {
    /// The startup gate of `serve` and of every CLI command (except the documented gate list). Read-only.
    ///
    /// A database marked `restore_pending` is refused until `nzbd db restore-finish` (stricter than 2.x SEC-068; D35 d,
    /// owner answer Q4).
    ///
    /// # Errors
    /// Database errors.
    pub async fn readiness(&self) -> Result<Readiness, StoreError> {
        let mut conn = self.background().acquire().await?;
        let version: i32 =
            sqlx::query_scalar("SELECT current_setting('server_version_num')::integer")
                .fetch_one(&mut *conn)
                .await?;
        if version < MIN_SERVER_VERSION_NUM {
            return Ok(Readiness::ServerTooOld(version));
        }
        let (collate, ctype, encoding): (String, String, String) = sqlx::query_as(
            "SELECT datcollate, datctype, pg_catalog.pg_encoding_to_char(encoding)::text \
             FROM pg_catalog.pg_database WHERE datname = current_database()",
        )
        .fetch_one(&mut *conn)
        .await?;
        if collate != "C" || ctype != "C" {
            return Ok(Readiness::LocaleNotC);
        }
        if encoding != "UTF8" {
            return Ok(Readiness::EncodingNotUtf8);
        }
        let (pending, unknown) = pending_migrations(&mut conn).await?;
        if let Some(v) = unknown {
            return Ok(Readiness::SchemaNewer(v));
        }
        if !pending.is_empty() {
            return Ok(Readiness::MigrationsPending(pending));
        }
        let restore_pending: bool =
            sqlx::query_scalar("SELECT restore_pending FROM db_state WHERE id = 1")
                .fetch_one(&mut *conn)
                .await?;
        if restore_pending {
            return Ok(Readiness::RestorePending);
        }
        Ok(Readiness::Ready)
    }
}

/// The migration plan as the OWNER role sees it (`nzbd db migrate` without `--yes`): pending versions and a ledger
/// version this binary does not know (a newer schema). Read-only.
///
/// # Errors
/// Connection or database errors.
pub async fn pending_as_owner(
    owner: PgConnectOptions,
) -> Result<(Vec<i64>, Option<i64>), StoreError> {
    let mut conn = PgConnection::connect_with(&owner).await?;
    let plan = pending_migrations(&mut conn).await;
    let _ = conn.close().await;
    plan
}

/// Sessions of the APP role on this database (`pg_stat_activity`; the owner sees other roles' rows, not their query
/// text). `nzbd db migrate` / `db restore` refuse while one exists: a running `serve` would keep writing with the old
/// semantics after a migration commits (review 36 M1). Read-only.
///
/// # Errors
/// Connection or database errors.
pub async fn app_sessions_as_owner(owner: PgConnectOptions) -> Result<i64, StoreError> {
    let mut conn = PgConnection::connect_with(&owner).await?;
    let n: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = 'nzbd_app' AND datname = current_database()",
    )
    .fetch_one(&mut conn)
    .await;
    let _ = conn.close().await;
    Ok(n?)
}

/// Applies the pending v3 migrations and synchronizes the taxonomy, connected as the OWNER role (`nzbd db migrate`
/// in the `setup` service; never `serve`, review M4). Each migration file runs in its own transaction (Postgres DDL is
/// transactional, so a failed migration leaves nothing behind). The taxonomy upsert and the matching
/// `category_stats` rows are one transaction.
///
/// # Errors
/// Connection, migration or database errors.
pub async fn migrate_as_owner(owner: PgConnectOptions) -> Result<Vec<i64>, StoreError> {
    migrate_as_owner_with(owner, &MIGRATOR).await
}

/// Test-only: [`migrate_as_owner`] as an older release ran it, with only the compiled-in migrations up to and
/// including `last` (the 3.1 -> 3.2 upgrade-path test builds a 3.1-shaped database this way; the migration files of a
/// released version are never edited, which `upgrade_tests` pins by checksum).
///
/// # Errors
/// As [`migrate_as_owner`].
#[cfg(test)]
pub(crate) async fn migrate_as_owner_upto(
    owner: PgConnectOptions,
    last: i64,
) -> Result<Vec<i64>, StoreError> {
    let migrator = Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= last)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    migrate_as_owner_with(owner, &migrator).await
}

/// [`migrate_as_owner`] with an explicit migration set; returns the versions of that set that were pending.
async fn migrate_as_owner_with(
    owner: PgConnectOptions,
    migrator: &Migrator,
) -> Result<Vec<i64>, StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(owner)
        .await?;
    let before = {
        let mut conn = pool.acquire().await?;
        pending_migrations(&mut conn)
            .await?
            .0
            .into_iter()
            .filter(|v| migrator.iter().any(|m| m.version == *v))
            .collect()
    };
    migrator.run(&pool).await?;
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    for (id, parent, name) in &seed_rows()? {
        sqlx::query(
            "INSERT INTO category (id, parent_id, name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET parent_id = excluded.parent_id, name = excluded.name",
        )
        .bind(i32::try_from(*id).map_err(|_| StoreError::OutOfRange("category id"))?)
        .bind(
            parent
                .map(i32::try_from)
                .transpose()
                .map_err(|_| StoreError::OutOfRange("category parent"))?,
        )
        .bind(name)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO category_stats (category_id) SELECT id FROM category ON CONFLICT (category_id) DO NOTHING",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    drop(conn);
    pool.close().await;
    Ok(before)
}

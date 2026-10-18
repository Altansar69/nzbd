//! T088: startup check modes, migration escalation and progress events of `SqliteDb::open_with`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::borrow::Cow;
use std::path::Path;
use std::sync::Mutex;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{ConnectOptions, Connection};

use crate::{CRITICAL_TABLES, DbConfig, OpenEvent, SqliteDb, StartupCheck, StoreError};

const PAGE: usize = 4096;

fn cfg(dir: &tempfile::TempDir) -> DbConfig {
    DbConfig {
        path: dir.path().join("nzbd.sqlite"),
    }
}

/// Opens with `check` and returns the db (or error) plus every event emitted.
async fn open_events(
    c: &DbConfig,
    check: StartupCheck,
) -> (Result<SqliteDb, StoreError>, Vec<OpenEvent>) {
    let events = Mutex::new(Vec::new());
    let r = SqliteDb::open_with(c, check, &|e| events.lock().unwrap().push(e)).await;
    (r, events.into_inner().unwrap())
}

/// A database that has only the migrations up to `last` (an "older release" file).
async fn seed_up_to(path: &Path, last: i64) {
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .connect()
        .await
        .unwrap();
    let mut m = sqlx::migrate!("../../migrations/v3-sqlite");
    m.migrations = Cow::Owned(
        m.migrations
            .iter()
            .filter(|x| x.version <= last)
            .cloned()
            .collect(),
    );
    m.run(&mut conn).await.unwrap();
    conn.close().await.unwrap();
    // As nzbd itself creates it (0600, SEC-102): the open must not report a mode fix for this test's file.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
}

async fn newest_applied(path: &Path) -> i64 {
    let db = SqliteDb::open_read_only(path).await.unwrap();
    let v: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(db.readers())
        .await
        .unwrap();
    db.close().await;
    v
}

/// Overwrites the b-tree root page of `table` (WAL must be checkpointed: close the db first).
async fn smash_root_page(path: &Path, table: &str) {
    let db = SqliteDb::open_read_only(path).await.unwrap();
    let root: i64 = sqlx::query_scalar("SELECT rootpage FROM sqlite_master WHERE name = ?1")
        .bind(table)
        .fetch_one(db.readers())
        .await
        .unwrap();
    db.close().await;
    let mut bytes = std::fs::read(path).unwrap();
    let start = (usize::try_from(root).unwrap() - 1) * PAGE;
    for b in &mut bytes[start..start + PAGE] {
        *b = 0xFF;
    }
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test]
async fn t088_fast_is_the_default_and_runs_no_migration_on_a_current_database() {
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    SqliteDb::open(&c).await.unwrap().close().await;
    assert_eq!(StartupCheck::default(), StartupCheck::Fast);

    let (db, events) = open_events(&c, StartupCheck::Fast).await;
    db.unwrap().close().await;
    assert!(matches!(
        events.as_slice(),
        [
            OpenEvent::CheckStarted {
                mode: StartupCheck::Fast,
                escalated: false
            },
            OpenEvent::CheckFinished {
                mode: StartupCheck::Fast,
                ..
            }
        ]
    ));
}

#[tokio::test]
async fn t088_the_critical_tables_exist_in_the_schema() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&cfg(&dir)).await.unwrap();
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
            .fetch_all(db.readers())
            .await
            .unwrap();
    for t in CRITICAL_TABLES {
        assert!(names.iter().any(|n| n == t), "{t}");
    }
}

#[tokio::test]
async fn t088_pending_migrations_force_the_full_check_and_report_progress() {
    // A new library: every embedded migration is pending (v3 starts from its baseline, D37), so the requested fast
    // check is escalated to the full one before the first migration runs.
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    let newest = sqlx::migrate!("../../migrations/v3-sqlite")
        .iter()
        .map(|m| m.version)
        .max()
        .unwrap();

    let (db, events) = open_events(&c, StartupCheck::Fast).await;
    db.unwrap().close().await;
    assert!(
        matches!(
            events[0],
            OpenEvent::CheckStarted {
                mode: StartupCheck::Full,
                escalated: true
            }
        ),
        "{events:?}"
    );
    assert!(matches!(
        events[1],
        OpenEvent::CheckFinished {
            mode: StartupCheck::Full,
            ..
        }
    ));
    let OpenEvent::MigrationsPending { total, first, last } = events[2] else {
        panic!("{events:?}");
    };
    assert_eq!((first, last), (1, newest));
    // Versions may have gaps while parallel tasks hold reserved numbers: count what is embedded.
    let embedded: Vec<i64> = sqlx::migrate!("../../migrations/v3-sqlite")
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(total, embedded.len());
    let started: Vec<i64> = events
        .iter()
        .filter_map(|e| match e {
            OpenEvent::MigrationStarted { version, .. } => Some(*version),
            _ => None,
        })
        .collect();
    let finished = events
        .iter()
        .filter(|e| matches!(e, OpenEvent::MigrationFinished { .. }))
        .count();
    assert_eq!(started, embedded);
    assert_eq!(finished, started.len());
    assert_eq!(newest_applied(&c.path).await, newest);
}

#[tokio::test]
async fn t088_a_damaged_database_is_rejected_before_it_is_modified() {
    // (2.x tested this with migrations pending; v3 has one baseline, so the requested full check stands in until the
    // first post-baseline migration exists.)
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    seed_up_to(&c.path, 1).await;
    // A foreign-key violation only the full check sees (quick_check does not look at FKs).
    let mut conn = SqliteConnectOptions::new()
        .filename(&c.path)
        .foreign_keys(false)
        .connect()
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO nzb_file (release_id, idx, subject, kind, bytes, segment_count) VALUES (42, 0, 's', 'other', 0, 0)",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();

    let before = std::fs::read(&c.path).unwrap();
    let (r, events) = open_events(&c, StartupCheck::Full).await;
    assert!(matches!(r, Err(StoreError::Integrity(_))), "{r:?}");
    assert_eq!(std::fs::read(&c.path).unwrap(), before, "file untouched");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, OpenEvent::MigrationStarted { .. })),
        "no migration may start on a database that failed its check"
    );
    assert_eq!(newest_applied(&c.path).await, 1, "ledger untouched");
}

#[tokio::test]
async fn t088_fast_skips_bulk_tables_quick_and_full_read_them() {
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    let db = SqliteDb::open(&c).await.unwrap();
    let mut conn = db.writer().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    // Enough rows that the root page of the bulk table is an interior page.
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000) \
         INSERT INTO nzb_file (release_id, idx, subject, kind, bytes, segment_count) \
         SELECT 1, i, printf('%0120d', i), 'other', 0, 0 FROM n",
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    // Move the rows into the main file (the smash below edits the file, not the WAL).
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    db.close().await;
    smash_root_page(&c.path, "nzb_file").await;

    // Opens: no migration pending, the bulk table is not read.
    let (r, events) = open_events(&c, StartupCheck::Fast).await;
    let db = r.unwrap();
    assert!(matches!(
        events[0],
        OpenEvent::CheckStarted {
            mode: StartupCheck::Fast,
            escalated: false
        }
    ));
    // The explicit checks find it.
    assert!(matches!(
        db.check(StartupCheck::Quick).await,
        Err(StoreError::Integrity(_))
    ));
    assert!(matches!(
        db.check(StartupCheck::Full).await,
        Err(StoreError::Integrity(_))
    ));
    db.close().await;
    let (r, _) = open_events(&c, StartupCheck::Quick).await;
    assert!(matches!(r, Err(StoreError::Integrity(_))));
    let (r, _) = open_events(&c, StartupCheck::Full).await;
    assert!(matches!(r, Err(StoreError::Integrity(_))));
}

#[tokio::test]
async fn t088_fast_catches_damage_to_authentication_tables() {
    for table in ["account", "session", "api_key", "category"] {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(&dir);
        SqliteDb::open(&c).await.unwrap().close().await;
        smash_root_page(&c.path, table).await;
        let (r, _) = open_events(&c, StartupCheck::Fast).await;
        assert!(
            matches!(r, Err(StoreError::Integrity(_))),
            "{table}: damage must fail the fast check"
        );
    }
}

/// A database ledger entry this binary does not know (a newer release wrote it) is rejected
/// before any check or migration runs, and nothing is modified (T088 review L5). The per-step
/// migrators use `ignore_missing: true`, which is only safe because of this early rejection.
#[tokio::test]
async fn t090_an_unknown_ledger_entry_is_rejected_before_any_check_or_migration() {
    let dir = tempfile::tempdir().unwrap();
    let c = cfg(&dir);
    SqliteDb::open(&c).await.unwrap().close().await;
    let mut conn = SqliteConnectOptions::new()
        .filename(&c.path)
        .journal_mode(SqliteJournalMode::Wal)
        .connect()
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (9999, 'from the future', 1, x'00', 0)",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    let before = std::fs::read(&c.path).unwrap();

    for mode in [StartupCheck::Fast, StartupCheck::Full] {
        let (r, events) = open_events(&c, mode).await;
        assert!(
            matches!(
                r,
                Err(StoreError::Migrate(
                    sqlx::migrate::MigrateError::VersionMissing(9999)
                ))
            ),
            "{mode:?}"
        );
        // Neither the check nor a migration started.
        assert!(events.is_empty(), "{events:?}");
    }
    assert_eq!(std::fs::read(&c.path).unwrap(), before);
}

#[derive(Debug)]
struct FakeSqliteError(&'static str);

impl std::fmt::Display for FakeSqliteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fake sqlite error {}", self.0)
    }
}

impl std::error::Error for FakeSqliteError {}

impl sqlx::error::DatabaseError for FakeSqliteError {
    #[allow(clippy::unnecessary_literal_bound)]
    fn message(&self) -> &str {
        "fake"
    }
    fn code(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.0))
    }
    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }
    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::Other
    }
}

/// Only `SQLITE_CORRUPT` (11) and `SQLITE_NOTADB` (26) mean "damaged"; transient errors (BUSY 5,
/// LOCKED 6, IOERR 10, FULL 13, CANTOPEN 14) and extended codes of those must not (T088 L4).
#[test]
fn t090_only_corrupt_and_notadb_are_classified_as_damaged() {
    use crate::db::open_err;
    let err = |code: &'static str| open_err(sqlx::Error::Database(Box::new(FakeSqliteError(code))));
    // 11 = CORRUPT, 779 = CORRUPT_INDEX (11 | 3 << 8), 26 = NOTADB.
    for code in ["11", "779", "26"] {
        assert!(
            matches!(err(code), StoreError::Integrity(_)),
            "{code} is damage"
        );
    }
    // 5 BUSY, 6 LOCKED, 10 IOERR, 13 FULL, 14 CANTOPEN, 8 READONLY, 3338 IOERR_SHORT_READ.
    for code in ["5", "6", "10", "13", "14", "8", "3338"] {
        assert!(
            matches!(err(code), StoreError::Db(_)),
            "{code} is not damage"
        );
    }
    assert!(matches!(
        open_err(sqlx::Error::PoolTimedOut),
        StoreError::Db(_)
    ));
}

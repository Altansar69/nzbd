//! The 3.1 -> 3.2 upgrade path on both backends (3.2 adds the first 3.x migration: Postgres `v3/0008_saved_search`,
//! SQLite `v3-sqlite/0002_saved_search`). Fresh-database tests cannot show that a real 3.1 library opens under 3.2,
//! so each test builds a 3.1-shaped library with the 3.1 migration set, fills it through the store API, upgrades it
//! through the normal 3.2 open (SQLite) / setup-migrate + readiness (Postgres) path and checks that nothing was lost.
//!
//! The 3.1 schema is the compiled-in migrator filtered to the versions present at tag `v3.1.0` (not SQL files copied
//! into fixtures): one source of truth for the migration text. What the filter alone could not catch, an edit of a
//! released migration file (a real 3.1 database would then fail the sqlx checksum check), is pinned by
//! [`released_3_1_migrations_are_unchanged`] with the SHA-384 checksums of the files at `v3.1.0`.
//!
//! A 3.1 binary refusing the 3.2 schema is covered elsewhere: `startup_tests::
//! t090_an_unknown_ledger_entry_is_rejected_before_any_check_or_migration` (SQLite `VersionMissing`) and
//! `pg_tests::readiness_refuses_pending_migrations_newer_schema_and_pending_restore` (Postgres `SCHEMA_NEWER`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use std::sync::{Arc, Mutex};

use crate::acct_testkit::{PHC, POLICY, T0, analysis, sess};
use crate::pg::testing::TestDb;
use crate::pg::{MIGRATOR, Readiness};
use crate::repo::{AccountRepo as _, AuditRepo as _, LibraryRepo as _, OpsRepo as _};
use crate::{
    AnchorVerdict, AuditAnchor, CategorySource, DbAnchor, DbConfig, NewAccount, NewRelease,
    OpenEvent, Role, SceneColumns, SessionStage, SqliteDb, StartupCheck, Store, Theme, Uploader,
    UserPrefs, read_anchor, write_anchor,
};

/// Last SQLite migration of 3.1 (`v3-sqlite/0001_v3_baseline`).
const SQLITE_3_1_LAST: i64 = 1;
/// Last Postgres migration of 3.1 (`v3/0007_library_identity`).
const PG_3_1_LAST: i64 = 7;
/// The migration 3.2 adds on SQLite.
const SQLITE_3_2_SAVED_SEARCH: i64 = 2;
/// The migration 3.2 adds on Postgres.
const PG_3_2_SAVED_SEARCH: i64 = 8;
/// The newest migration of this build on SQLite (T133 adds `0003_page_size` after 3.3.0: fresh data, no upgrade test of its
/// own; the 3.1 library still opens through every later migration).
const SQLITE_NEWEST: i64 = 3;
/// The newest migration of this build on Postgres (T133 adds `0009_page_size` after 3.3.0).
const PG_NEWEST: i64 = 9;

/// SHA-384 (the sqlx checksum) of each migration file at tag `v3.1.0`.
const SQLITE_3_1_CHECKSUMS: [(i64, &str); 1] = [(
    1,
    "8780b893d4fec42d2a15f561f38199640aa2cb802b1825c4e7a375ad04cfe9aa996bcb0e9bf12709e8de593bb6b2dc2c",
)];
const PG_3_1_CHECKSUMS: [(i64, &str); 6] = [
    (
        2,
        "7155bb1a3d8c329a46d68833e02699c7c3d149cc5711b7e54d65b556c8bc509065050625b2561d1facb6cb65d8db1c18",
    ),
    (
        3,
        "95d3b0595a84502c09b04e3dbfe407c9dff851c72f8ce689f9820e0af83cb96e14f0f505b7eff60efd56cdf519199242",
    ),
    (
        4,
        "be242fbc674e7a1359f7e93625b60114d089e2cc0928ce44e1965dee9b93deea5eab027d6589833c30be4a28096ca29a",
    ),
    (
        5,
        "647b887867b37f34a4b660230d2830894bcb3385e0b2499efce8ab6c09cc19a0514e008beeeb1ec3d4bcccbf56274bdc",
    ),
    (
        6,
        "b27d32fd960fe7157e487dfc7373e1c58c1a52c2b78e3befbe2843ec791e3fa44f67da3da1c3c619f95164cd1265ecee",
    ),
    (
        7,
        "41bbe9ff0de3296aa8318607494dc24ee75ab61191f79f7c700c1b9a225ef25327a7b980b29a2afb3b7a60b7d035f0e0",
    ),
];

/// Releases of the fixture: `(n, category)`.
const RELEASES: [(u8, u32); 3] = [(1, 2040), (2, 5040), (3, 8010)];
/// Session id hash byte of the member's session.
const SESSION: u8 = 7;
const LATER: i64 = T0 + 3_000;

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// A released migration file is never edited: a 3.1 database records these checksums, and sqlx refuses to run
/// against a ledger whose checksums differ from the compiled-in files (the filtered 3.1 migrator of the upgrade tests
/// shares the compiled text, so it could not notice such an edit by itself).
#[test]
fn released_3_1_migrations_are_unchanged() {
    let sqlite = sqlx::migrate!("../../migrations/v3-sqlite");
    for (set, pinned, last) in [
        (&sqlite, &SQLITE_3_1_CHECKSUMS[..], SQLITE_3_1_LAST),
        (&MIGRATOR, &PG_3_1_CHECKSUMS[..], PG_3_1_LAST),
    ] {
        let released: Vec<(i64, String)> = set
            .iter()
            .filter(|m| m.version <= last)
            .map(|m| (m.version, hex(&m.checksum)))
            .collect();
        let expected: Vec<(i64, String)> =
            pinned.iter().map(|(v, h)| (*v, (*h).to_owned())).collect();
        assert_eq!(released, expected);
    }
}

/// What the 3.1 library held before the upgrade.
#[derive(Debug)]
struct Before {
    admin: i64,
    member: i64,
    releases: Vec<i64>,
    audit: AuditAnchor,
    anchor: DbAnchor,
    counts: Vec<(&'static str, i64)>,
}

/// Tables whose row counts must survive the upgrade unchanged.
const TABLES: [&str; 7] = [
    "account",
    "user_pref",
    "release",
    "session",
    "audit_log",
    "category",
    "search_outbox",
];

async fn count(store: &Store, table: &str) -> i64 {
    // Test-only: `table` is one of the literals above.
    let sql = format!("SELECT count(*) FROM {table}");
    match store {
        Store::Sqlite(db) => sqlx::query_scalar(&sql)
            .fetch_one(db.readers())
            .await
            .unwrap(),
        Store::Postgres(db) => sqlx::query_scalar(&sql).fetch_one(db.web()).await.unwrap(),
    }
}

async fn counts(store: &Store) -> Vec<(&'static str, i64)> {
    let mut v = Vec::new();
    for t in TABLES {
        v.push((t, count(store, t).await));
    }
    v
}

/// Fills a 3.1 library the way 3.1 would have: an admin and a member, the member's preferences, three releases in
/// three categories (one uploaded by the member), an audit row of each class and an active session.
async fn fill_3_1(store: &Store) -> Before {
    let admin = store
        .create_account_operator(
            &NewAccount {
                username: "alice",
                password_hash: PHC,
                role: Some(Role::Admin),
            },
            POLICY,
            T0,
        )
        .await
        .unwrap();
    let member = store
        .create_account_operator(
            &NewAccount {
                username: "bob",
                password_hash: PHC,
                role: Some(Role::Uploader),
            },
            POLICY,
            T0 + 1,
        )
        .await
        .unwrap();
    // The 3.1-shaped preference row, written as 3.1 stored it: this binary's `set_user_prefs` also writes the T133 page
    // size columns (T133), which a 3.1 schema does not have yet.
    let sql = format!(
        "INSERT INTO user_pref (account_id, hide_xxx, theme, updated_at) VALUES ({member}, true, 'dark', {})",
        T0 + 2
    );
    match store {
        Store::Sqlite(db) => {
            sqlx::query(&sql).execute(db.writer()).await.unwrap();
        }
        Store::Postgres(db) => {
            sqlx::query(&sql).execute(db.web()).await.unwrap();
        }
    }
    let mut releases = Vec::new();
    for (n, category) in RELEASES {
        let a = analysis(n);
        let uploader = if n == 1 {
            Uploader::Account(member)
        } else {
            Uploader::Unattributed
        };
        let id = store
            .insert_release_as(
                &NewRelease {
                    analysis: &a,
                    nzb_size_bytes: 1,
                    source_name: None,
                    source_label: Some("orig"),
                    category_id: category,
                    category_source: CategorySource::Fallback,
                    meta_json: None,
                    scene: SceneColumns::default(),
                    ingested_at: T0 + i64::from(n),
                },
                None,
                &uploader,
            )
            .await
            .unwrap();
        releases.push(id);
    }
    store
        .audit_event(
            T0 + 10,
            Some("user:2"),
            "download",
            Some("release=1"),
            Some("192.0.2.1"),
        )
        .await
        .unwrap();
    store
        .insert_session(&sess(member, SESSION, SessionStage::Active, T0 + 20), 5)
        .await
        .unwrap();

    // The 3.1 chain is whole before anything changes.
    let report = store.audit_walk(None, &mut |_| {}).await.unwrap();
    assert!(report.is_ok(), "{report:?}");
    let audit = store.audit_anchor().await.unwrap();
    // Two account creations and the two audit rows above (the raw 3.1 preference row writes none).
    assert!(audit.rows >= 3, "{audit:?}");
    Before {
        admin,
        member,
        releases,
        audit,
        // What a 3.1 `serve` wrote to paths.state/db-anchor.json.
        anchor: store.capture_anchor().await.unwrap(),
        counts: counts(store).await,
    }
}

/// Everything of [`fill_3_1`] is still there after the upgrade, the identity and restore checks pass, and saved
/// searches work.
async fn verify_3_2(store: &Store, before: &Before, state_dir: &std::path::Path) {
    // Row counts and field values.
    assert_eq!(counts(store).await, before.counts);
    let admin = store.get_account(before.admin).await.unwrap().unwrap();
    assert_eq!(
        (admin.username.as_str(), admin.role),
        ("alice", Role::Admin)
    );
    let member = store.get_account(before.member).await.unwrap().unwrap();
    assert_eq!(
        (member.username.as_str(), member.role, member.created_at),
        ("bob", Role::Uploader, T0 + 1)
    );
    for (id, (n, category)) in before.releases.iter().zip(RELEASES) {
        let r = store.get_release(*id).await.unwrap().unwrap();
        assert_eq!(r.title, format!("release {n}"));
        assert_eq!(r.category_id, category);
        assert_eq!(r.sha256, analysis(n).sha256);
    }
    let first = store
        .release_attribution(before.releases[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.added_by, Some(before.member));
    // The session still signs the member in, with the stored preferences.
    let actor = store
        .session_actor(&[SESSION; 32], T0 + 30)
        .await
        .unwrap()
        .expect("the 3.1 session survives the upgrade");
    assert_eq!(actor.user_id, before.member);
    assert_eq!(
        actor.prefs,
        UserPrefs {
            hide_xxx: true,
            theme: Theme::Dark,
            ..UserPrefs::default()
        }
    );

    // The audit chain verifies and is the same chain (the migration writes no audit row).
    let report = store.audit_walk(None, &mut |_| {}).await.unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(store.audit_anchor().await.unwrap(), before.audit);
    assert!(store.audit_chain_quick().await.unwrap().consistent);

    // Library identity and restore detection: the anchor 3.1 wrote (also through the file) still matches, nothing
    // asks for a restore-finish, and a restore-finish would find exactly the 3.1 state.
    let file = state_dir.join("db-anchor.json");
    write_anchor(&file, &before.anchor).unwrap();
    let anchored = read_anchor(&file).unwrap().unwrap();
    assert_eq!(
        store.check_anchor(&anchored).await.unwrap(),
        AnchorVerdict::Consistent
    );
    let now = store.capture_anchor().await.unwrap();
    assert_eq!(
        (&now.backend, &now.instance_id, &now.system_identifier),
        (
            &before.anchor.backend,
            &before.anchor.instance_id,
            &before.anchor.system_identifier
        )
    );
    assert!(!store.restore_pending().await.unwrap());
    assert!(!store.library_is_empty().await.unwrap());
    let dry = store.restore_finish(LATER, true).await.unwrap();
    assert_eq!(dry.sessions, 1);

    // Saved searches on the upgraded library: create, list, open; private to the account.
    let filters = r#"{"q":"release","cat":"2040"}"#;
    let id = store
        .create_saved_search(before.member, "Movies", filters, LATER)
        .await
        .unwrap();
    let listed = store.saved_searches(before.member).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].id,
            listed[0].name.as_str(),
            listed[0].filters.as_str()
        ),
        (id, "Movies", filters)
    );
    let opened = store
        .open_saved_search(before.member, id, LATER + 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((opened.id, opened.last_seen_at), (id, LATER));
    assert_eq!(
        store.saved_searches(before.member).await.unwrap()[0].last_seen_at,
        LATER + 60
    );
    assert_eq!(store.saved_searches(before.admin).await.unwrap(), []);
    assert!(
        store
            .open_saved_search(before.admin, id, LATER)
            .await
            .unwrap()
            .is_none()
    );
    // Not audited (private display state): the chain is unchanged and still consistent.
    assert_eq!(store.audit_anchor().await.unwrap(), before.audit);
    assert_eq!(
        store.check_anchor(&anchored).await.unwrap(),
        AnchorVerdict::Consistent
    );
}

async fn sqlite_ledger(db: &SqliteDb, version: i64) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE version = ?1 AND success")
        .bind(version)
        .fetch_one(db.readers())
        .await
        .unwrap()
}

async fn sqlite_has_table(db: &SqliteDb, name: &str) -> bool {
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1")
            .bind(name)
            .fetch_one(db.readers())
            .await
            .unwrap();
    n > 0
}

/// SQLite: a 3.1 library (`0001` only) opened by the 3.2 `SqliteDb::open_with` path gets `0002_saved_search` once,
/// after the full startup check, and keeps every row, the audit chain and its identity.
#[tokio::test]
#[ignore = "T134 (D40): fresh data, no upgrade past 3.4 (no uploader role in 3.1; owner decides on this file)"]
async fn upgrade_3_1_to_3_2_keeps_data_and_adds_saved_search() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = DbConfig {
        path: dir.path().join("nzbd.sqlite"),
    };

    // 3.1: the library as the 3.1 binary created and used it.
    let old = SqliteDb::open_at_version(&cfg, SQLITE_3_1_LAST)
        .await
        .unwrap();
    assert_eq!(sqlite_ledger(&old, SQLITE_3_1_LAST).await, 1);
    assert_eq!(sqlite_ledger(&old, SQLITE_3_2_SAVED_SEARCH).await, 0);
    assert!(!sqlite_has_table(&old, "saved_search").await);
    let store = Store::Sqlite(old);
    let before = fill_3_1(&store).await;
    store.close().await;

    // 3.2: the normal open (what `serve` and every CLI command run).
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let db = SqliteDb::open_with(&cfg, StartupCheck::Fast, &move |e| {
        sink.lock().unwrap().push(e);
    })
    .await
    .unwrap();
    {
        let events = events.lock().unwrap();
        // Pending migrations force the full check before anything is migrated.
        assert!(
            matches!(
                events.first(),
                Some(OpenEvent::CheckStarted {
                    mode: StartupCheck::Full,
                    escalated: true
                })
            ),
            "{events:?}"
        );
        let pending: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                OpenEvent::MigrationsPending { total, first, last } => {
                    Some((*total, *first, *last))
                }
                _ => None,
            })
            .collect();
        assert_eq!(pending, [(2, SQLITE_3_2_SAVED_SEARCH, SQLITE_NEWEST)]);
    }
    assert_eq!(sqlite_ledger(&db, SQLITE_3_1_LAST).await, 1);
    assert_eq!(sqlite_ledger(&db, SQLITE_3_2_SAVED_SEARCH).await, 1);
    let store = Store::Sqlite(db);
    let schema = store.schema_info().await.unwrap();
    assert_eq!((schema.latest_applied, schema.applied), (SQLITE_NEWEST, 3));
    verify_3_2(&store, &before, dir.path()).await;
    store.close().await;

    // A second start applies nothing (the migration ran exactly once) and still validates the ledger checksums.
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let db = SqliteDb::open_with(&cfg, StartupCheck::Fast, &move |e| {
        sink.lock().unwrap().push(e);
    })
    .await
    .unwrap();
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, OpenEvent::MigrationStarted { .. })),
    );
    assert_eq!(sqlite_ledger(&db, SQLITE_3_2_SAVED_SEARCH).await, 1);
    db.close().await;
}

async fn pg_ledger(t: &TestDb, version: i64) -> i64 {
    let mut su = t.superuser_conn().await;
    let n = sqlx::query_scalar(
        "SELECT count(*) FROM nzbd._sqlx_migrations WHERE version = $1 AND success",
    )
    .bind(version)
    .fetch_one(&mut su)
    .await
    .unwrap();
    sqlx::Connection::close(su).await.unwrap();
    n
}

/// Postgres: a 3.1 database (`0002`..`0007`) is refused by the 3.2 `serve` gate until `nzbd db migrate` (the
/// owner-only setup path) applies `0008_saved_search` once; then it is ready and keeps every row, the audit chain and
/// its identity, and the app role may use the new table (grants).
#[tokio::test]
#[ignore = "T134 (D40): fresh data, no upgrade past 3.4 (no uploader role in 3.1; owner decides on this file)"]
async fn pg_upgrade_3_1_to_3_2_keeps_data_and_adds_saved_search() {
    let dir = tempfile::tempdir().unwrap();
    let t = TestDb::new_upto(PG_3_1_LAST).await;
    assert_eq!(pg_ledger(&t, PG_3_1_LAST).await, 1);
    assert_eq!(pg_ledger(&t, PG_3_2_SAVED_SEARCH).await, 0);
    let store = Store::Postgres(t.db.clone());
    let before = fill_3_1(&store).await;

    // 3.2 `serve` refuses the 3.1 schema until the setup service migrates.
    assert_eq!(
        t.db.readiness().await.unwrap(),
        Readiness::MigrationsPending(vec![PG_3_2_SAVED_SEARCH, PG_NEWEST])
    );
    let migrated = crate::pg::migrate_as_owner(t.owner_options())
        .await
        .unwrap();
    assert_eq!(migrated, [PG_3_2_SAVED_SEARCH, PG_NEWEST]);
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::Ready);
    assert_eq!(pg_ledger(&t, PG_3_2_SAVED_SEARCH).await, 1);

    // A restarted process (new app-role pools) sees the upgraded library.
    let store = Store::Postgres(
        crate::pg::PgDb::connect(&t.settings(), crate::pg::testing::TEST_APP_PASSWORD)
            .await
            .unwrap(),
    );
    let schema = store.schema_info().await.unwrap();
    assert_eq!(schema.latest_applied, PG_NEWEST);
    verify_3_2(&store, &before, dir.path()).await;

    // Migrating again applies nothing: the migration ran exactly once.
    let again = crate::pg::migrate_as_owner(t.owner_options())
        .await
        .unwrap();
    assert!(again.is_empty(), "{again:?}");
    assert_eq!(pg_ledger(&t, PG_3_2_SAVED_SEARCH).await, 1);
    assert_eq!(t.db.readiness().await.unwrap(), Readiness::Ready);
    store.close().await;
}

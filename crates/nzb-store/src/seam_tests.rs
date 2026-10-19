//! Conformance of the storage seam (ARCHITECTURE 13.1/13.2, review 34 I2 c): the same calls through
//! [`Store`] on both backends give the same results and the **same** [`StoreError`] variant, so the web layer maps
//! each condition to one uniform answer whatever the backend. Every test body is generic over the repository traits
//! and instantiated twice (`sqlite::<name>`, `postgres::<name>`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use nzb_core::Sha256;

use crate::acct_testkit::{PHC, POLICY, T0, analysis};
use crate::{
    AccountActor, AccountRepo, AuditRepo, CategorySource, DbConfig, LibraryRepo, NewAccount,
    NewRelease, OpsRepo, Role, SceneColumns, SqliteDb, Store, StoreError, Uploader,
};

/// Every repository trait (what production code needs from a backend).
pub(crate) trait Repo: AccountRepo + LibraryRepo + AuditRepo + OpsRepo {}
impl<T: AccountRepo + LibraryRepo + AuditRepo + OpsRepo> Repo for T {}

/// A backend under test and whatever keeps it alive (temp dir or test database).
pub(crate) struct Opened {
    pub(crate) store: Store,
    _keep: Box<dyn std::any::Any + Send>,
}

pub(crate) async fn open_sqlite() -> Opened {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    Opened {
        store: Store::Sqlite(db),
        _keep: Box::new(dir),
    }
}

pub(crate) async fn open_postgres() -> Opened {
    let t = crate::pg::testing::TestDb::new().await;
    Opened {
        store: Store::Postgres(t.db.clone()),
        _keep: Box::new(t),
    }
}

/// The variant of an error as a stable string (`Account(LastAdmin)`, `Duplicate`, ...): what the conformance
/// tests compare. Database errors are deliberately one opaque bucket.
fn variant(e: &StoreError) -> String {
    match e {
        StoreError::Account(a) => format!("Account({a:?})"),
        StoreError::Db(_) => "Db".to_owned(),
        StoreError::Integrity(_) => "Integrity".to_owned(),
        StoreError::Migrate(_) => "Migrate".to_owned(),
        StoreError::Io(_) => "Io".to_owned(),
        StoreError::OutOfRange(what) => format!("OutOfRange({what})"),
        StoreError::AuditChain(what) => format!("AuditChain({what})"),
        other => format!("{other:?}"),
    }
}

async fn account<S: Repo>(s: &S, name: &str, role: Role) -> i64 {
    s.create_account_operator(
        &NewAccount {
            username: name,
            password_hash: PHC,
            role: Some(role),
        },
        POLICY,
        T0,
    )
    .await
    .unwrap()
}

async fn actor<S: Repo>(s: &S, id: i64) -> AccountActor {
    // A session is the only production way to an actor; the operator-made account needs none for these rules.
    let sess = crate::acct_testkit::sess(
        id,
        u8::try_from(id % 200).unwrap(),
        crate::SessionStage::Active,
        T0,
    );
    s.insert_session(&sess, 5).await.unwrap();
    s.session_actor(&sess.id_hash, T0).await.unwrap().unwrap()
}

async fn release<S: Repo>(s: &S, n: u8, by: &Uploader) -> Result<i64, StoreError> {
    let a = analysis(n);
    s.insert_release_as(
        &NewRelease {
            analysis: &a,
            nzb_size_bytes: 1,
            source_name: None,
            source_label: None,
            category_id: 8010,
            category_source: CategorySource::Fallback,
            meta_json: None,
            scene: SceneColumns::default(),
            ingested_at: T0,
        },
        None,
        by,
    )
    .await
}

pub(crate) async fn last_admin_is_refused_with_one_variant<S: Repo>(s: &S) {
    let a = account(s, "root", Role::Admin).await;
    let e = s.disable_account_operator(a, T0).await.unwrap_err();
    assert_eq!(variant(&e), "Account(LastAdmin)");
    let e = s
        .set_role_operator(a, Role::Uploader, T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(LastAdmin)");
}

pub(crate) async fn unknown_target_is_target_not_found<S: Repo>(s: &S) {
    account(s, "root", Role::Admin).await;
    let e = s
        .set_role_operator(9_999, Role::Uploader, T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(TargetNotFound)");
    let e = s.disable_account_operator(9_999, T0).await.unwrap_err();
    assert_eq!(variant(&e), "Account(TargetNotFound)");
}

pub(crate) async fn reserved_and_invalid_login_names<S: Repo>(s: &S) {
    for (name, want) in [
        ("system", "Account(ReservedName)"),
        ("user-12", "Account(ReservedName)"),
        ("a b", "InvalidUsername"),
        ("", "InvalidUsername"),
    ] {
        let e = s
            .create_account_operator(
                &NewAccount {
                    username: name,
                    password_hash: PHC,
                    role: Some(Role::Uploader),
                },
                POLICY,
                T0,
            )
            .await
            .unwrap_err();
        assert_eq!(variant(&e), want, "{name:?}");
    }
    account(s, "root", Role::Admin).await;
    let e = s
        .create_account_operator(
            &NewAccount {
                username: "ROOT",
                password_hash: PHC,
                role: Some(Role::Uploader),
            },
            POLICY,
            T0,
        )
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(UsernameUnavailable)");
}

pub(crate) async fn duplicate_release_is_duplicate<S: Repo>(s: &S) {
    let id = release(s, 1, &Uploader::Unattributed).await.unwrap();
    assert!(id > 0);
    let e = release(s, 1, &Uploader::Unattributed).await.unwrap_err();
    assert_eq!(variant(&e), "Duplicate");
    assert_eq!(s.get_release(id).await.unwrap().unwrap().id, id);
    assert!(s.get_release(id + 1_000).await.unwrap().is_none());
}

pub(crate) async fn edits_of_missing_releases_are_not_found<S: Repo>(s: &S) {
    let m = account(s, "root", Role::Admin).await;
    let who = actor(s, m).await;
    let e = s
        .set_category_as(&who, 4_242, 8010, None, T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "NotFound");
    let e = s
        .set_source_label_as(&who, 4_242, Some("x"), None, T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "NotFound");
    let e = s
        .trash_release_checked_as(&who, 4_242, &Sha256([1; 32]), T0, None)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "NotFound");
}

pub(crate) async fn unknown_category_is_unknown_category<S: Repo>(s: &S) {
    let m = account(s, "root", Role::Admin).await;
    let who = actor(s, m).await;
    let id = release(s, 2, &Uploader::Unattributed).await.unwrap();
    let e = s.set_category_as(&who, id, 1, None, T0).await.unwrap_err();
    assert_eq!(variant(&e), "UnknownCategory");
}

pub(crate) async fn trash_is_bound_to_the_confirmed_digest<S: Repo>(s: &S) {
    let m = account(s, "root", Role::Admin).await;
    let who = actor(s, m).await;
    let id = release(s, 3, &Uploader::Unattributed).await.unwrap();
    let e = s
        .trash_release_checked_as(&who, id, &Sha256([4; 32]), T0, None)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "NotFound");
    assert!(s.get_release(id).await.unwrap().is_some());
    let t = s
        .trash_release_checked_as(&who, id, &Sha256([3; 32]), T0, None)
        .await
        .unwrap();
    assert_eq!(t.original_id, id);
    assert!(s.get_release(id).await.unwrap().is_none());
}

pub(crate) async fn viewer_cannot_edit<S: Repo>(s: &S) {
    account(s, "root", Role::Admin).await;
    let v = account(s, "watcher", Role::Viewer).await;
    let who = actor(s, v).await;
    let id = release(s, 5, &Uploader::Unattributed).await.unwrap();
    let e = s
        .set_category_as(&who, id, 8010, None, T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(Forbidden)");
    let e = s
        .bulk_set_category_as(&who, &[id], 8010, &[], None, T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(Forbidden)");
}

/// Review 30.3 (a) on both backends: the password verdict re-reads the credentials inside its transaction, so a
/// password verified against a hash that changed in between is refused (and not counted as a guess).
pub(crate) async fn login_verdict_rereads_credentials<S: Repo>(s: &S) {
    account(s, "root", Role::Admin).await;
    let m = account(s, "uploader1", Role::Uploader).await;
    let seen = s.get_login_user_by_id(m).await.unwrap().unwrap();
    s.reset_password_for(m, "$argon2id$v=19$m=65536,t=3,p=1$bmV3$bmV3", T0)
        .await
        .unwrap();
    let ctx = crate::AttemptContext {
        ip_key: "192.0.2.7",
        session: None,
        bucket_refused: false,
    };
    let ok = s
        .login_password_step_v2(Some(&seen), true, "bad_password", &ctx, None, T0 + 1)
        .await
        .unwrap();
    assert!(!ok, "a stale verification must not be accepted");
    let fresh = s.get_login_user_by_id(m).await.unwrap().unwrap();
    let ok = s
        .login_password_step_v2(Some(&fresh), true, "bad_password", &ctx, None, T0 + 2)
        .await
        .unwrap();
    assert!(ok);
}

/// A password change must close the gap after its predecessor's accepted verdict. Use the
/// same second for every operation so this cannot pass through a timestamp-only comparison.
pub(crate) async fn login_session_issuance_rereads_credentials<S: Repo>(s: &S) {
    use crate::SessionStage::{Active, PendingMfa};
    use crate::acct_testkit::sess;

    let uid = account(s, "root", Role::Admin).await;
    let seen = s.get_login_user_by_id(uid).await.unwrap().unwrap();
    let ctx = crate::AttemptContext {
        ip_key: "192.0.2.7",
        session: None,
        bucket_refused: false,
    };
    let owner = sess(uid, 201, Active, T0);
    let pending = sess(uid, 202, PendingMfa, T0);
    s.insert_session(&owner, 5).await.unwrap();
    s.insert_login_session(&seen, &pending, None, 5)
        .await
        .unwrap();
    assert!(
        s.login_password_step_v2(Some(&seen), true, "bad_password", &ctx, None, T0)
            .await
            .unwrap()
    );

    let replacement = sess(uid, 203, Active, T0);
    s.change_password(
        uid,
        &owner.id_hash,
        "replacement-hash",
        &replacement,
        None,
        T0,
    )
    .await
    .unwrap();
    assert!(s.get_session(&owner.id_hash).await.unwrap().is_none());
    assert!(s.get_session(&pending.id_hash).await.unwrap().is_none());
    let late = sess(uid, 204, PendingMfa, T0);
    for replacing in [None, Some(&replacement.id_hash)] {
        assert!(matches!(
            s.insert_login_session(&seen, &late, replacing, 5).await,
            Err(StoreError::NotFound)
        ));
        assert!(s.get_session(&late.id_hash).await.unwrap().is_none());
        // A refused stale login must not remove the cookie it was asked to replace.
        assert!(s.get_session(&replacement.id_hash).await.unwrap().is_some());
    }
    assert!(matches!(
        s.rotate_session_strict(&pending.id_hash, &sess(uid, 205, Active, T0), 5)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        !s.login_password_step_v2(Some(&seen), true, "bad_password", &ctx, None, T0)
            .await
            .unwrap()
    );
    let fresh = s.get_login_user_by_id(uid).await.unwrap().unwrap();
    assert!(
        s.login_password_step_v2(Some(&fresh), true, "bad_password", &ctx, None, T0)
            .await
            .unwrap()
    );
    s.insert_login_session(&fresh, &late, None, 5)
        .await
        .unwrap();
    assert_eq!(
        s.get_session(&late.id_hash).await.unwrap().unwrap().stage,
        PendingMfa
    );
}

pub(crate) async fn login_session_issuance_preserves_rotation_and_caps<S: Repo>(s: &S) {
    use crate::SessionStage::{Active, PendingMfa};
    use crate::acct_testkit::sess;

    let uid = account(s, "root", Role::Admin).await;
    let seen = s.get_login_user_by_id(uid).await.unwrap().unwrap();
    let active = sess(uid, 210, Active, T0);
    s.insert_session(&active, 1).await.unwrap();
    let first = sess(uid, 211, PendingMfa, T0);
    s.insert_login_session(&seen, &first, None, 1)
        .await
        .unwrap();
    let second = sess(uid, 212, PendingMfa, T0 + 1);
    s.insert_login_session(&seen, &second, Some(&first.id_hash), 1)
        .await
        .unwrap();
    assert!(s.get_session(&first.id_hash).await.unwrap().is_none());
    assert!(s.get_session(&second.id_hash).await.unwrap().is_some());
    let third = sess(uid, 213, PendingMfa, T0 + 2);
    // A missing presented cookie remains harmless, as it was for normal login rotation.
    s.insert_login_session(&seen, &third, Some(&[214; 32]), 1)
        .await
        .unwrap();
    assert!(s.get_session(&second.id_hash).await.unwrap().is_none());
    let row = s.get_session(&third.id_hash).await.unwrap().unwrap();
    assert_eq!(row.stage, PendingMfa);
    assert!(!row.enroll_proven);
    assert!(s.get_session(&active.id_hash).await.unwrap().is_some());
}

pub(crate) async fn login_session_issuance_rejects_invalid_state<S: Repo>(s: &S) {
    use crate::SessionStage::{Active, PendingMfa};
    use crate::acct_testkit::sess;

    account(s, "root", Role::Admin).await;
    let uid = account(s, "member", Role::Uploader).await;
    let seen = s.get_login_user_by_id(uid).await.unwrap().unwrap();
    for invalid in [
        sess(uid, 220, Active, T0),
        sess(uid + 1, 220, PendingMfa, T0),
    ] {
        assert!(matches!(
            s.insert_login_session(&seen, &invalid, None, 5).await,
            Err(StoreError::OutOfRange("login session"))
        ));
    }
    let pending = sess(uid, 220, PendingMfa, T0);
    let mut wrong_role = seen.clone();
    wrong_role.role = Role::Viewer;
    let mut wrong_enrollment = seen.clone();
    wrong_enrollment.totp_enabled = !seen.totp_enabled;
    let mut disabled_observation = seen.clone();
    disabled_observation.disabled = true;
    for stale in [wrong_role, wrong_enrollment, disabled_observation] {
        assert!(matches!(
            s.insert_login_session(&stale, &pending, None, 5).await,
            Err(StoreError::NotFound)
        ));
    }
    s.disable_account_operator(uid, T0).await.unwrap();
    assert!(matches!(
        s.insert_login_session(&seen, &pending, None, 5).await,
        Err(StoreError::NotFound)
    ));
    s.enable_account_operator(uid, T0).await.unwrap();
    s.insert_login_session(&seen, &pending, None, 5)
        .await
        .unwrap();
    // Account deletion requires an explicit disable first, even for the operator.
    s.disable_account_operator(uid, T0).await.unwrap();
    s.delete_account_operator(uid, T0).await.unwrap();
    assert!(matches!(
        s.insert_login_session(&seen, &pending, None, 5).await,
        Err(StoreError::NotFound)
    ));
    assert!(s.get_session(&pending.id_hash).await.unwrap().is_none());
}

pub(crate) async fn audit_append_and_walk_agree<S: Repo>(s: &S) {
    s.audit_event(T0, Some("cli"), "probe", Some("n=1"), None)
        .await
        .unwrap();
    s.audit_event(T0 + 1, Some("cli"), "probe", Some("n=2"), None)
        .await
        .unwrap();
    let mut seen = 0_u32;
    let report = s
        .audit_walk(None, &mut |_row| {
            seen += 1;
        })
        .await
        .unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert!(seen >= 2);
    let quick = s.audit_chain_quick().await.unwrap();
    assert!(quick.consistent, "{quick:?}");
}

/// The reads of the admin Users page, on both backends (with sessions, an invite and a lock present).
pub(crate) async fn users_page_reads_work<S: Repo>(s: &S) {
    let a = account(s, "root", Role::Admin).await;
    let m = account(s, "uploader1", Role::Uploader).await;
    let _ = actor(s, a).await;
    let _ = actor(s, m).await;
    assert_eq!(s.list_accounts(true).await.unwrap().len(), 2);
    let _ = s.list_open_invites(T0).await.unwrap();
    let _ = s.locked_account_ids(T0).await.unwrap();
    let _ = s.online_account_ids(T0, T0 - 300).await.unwrap();
    let counts = s.active_session_counts(T0).await.unwrap();
    assert_eq!(counts.len(), 2, "{counts:?}");
    let _ = s.reserved_login_accounts().await.unwrap();
    let _ = s.security_facts(T0, 0).await.unwrap();
}

/// Keyset pages of 2 walk `all` (newest first) once without overlap; limits clamp to `1..=200`.
async fn audit_paging_and_clamping<S: Repo>(s: &S, all: &[crate::AuditRow]) {
    use crate::AuditFilter;
    // Keyset paging: pages of 2 walk every row once, newest first, without overlap.
    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = s
            .audit_page(&AuditFilter {
                before_id: before,
                limit: 2,
                ..AuditFilter::default()
            })
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2);
        before = page.last().map(|r| r.id);
        seen.extend(page.into_iter().map(|r| r.id));
    }
    let all_ids: Vec<i64> = all.iter().map(|r| r.id).collect();
    assert_eq!(seen, all_ids);
    assert!(all_ids.windows(2).all(|w| w[0] > w[1]));
    // Clamping: 0 behaves as 1, a huge limit as 200.
    let one = s
        .audit_page(&AuditFilter {
            limit: 0,
            ..AuditFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    assert!(
        s.audit_page(&AuditFilter {
            limit: u32::MAX,
            ..AuditFilter::default()
        })
        .await
        .unwrap()
        .len()
            <= 200
    );
}

/// T138: the three upload events are attributed from `user:<id>`, the paged query filters, keysets and clamps, reads
/// without writing, and the audit chain still verifies.
pub(crate) async fn audit_page_filters_and_attributes_uploads<S: Repo>(s: &S) {
    use crate::AuditFilter;
    let a = account(s, "root", Role::Admin).await;
    let m = account(s, "uploader1", Role::Uploader).await;
    let (ua, um) = (format!("user:{a}"), format!("user:{m}"));
    for (i, (who, ev)) in [
        (&um, "nzb_upload"),
        (&um, "nzb_upload_dup"),
        (&ua, "nzb_upload"),
        (&um, "nzb_upload_reject"),
        (&ua, "release_delete"),
    ]
    .into_iter()
    .enumerate()
    {
        let ts = T0 + i64::try_from(i).unwrap();
        s.audit_event(ts, Some(who), ev, Some("size=1"), None)
            .await
            .unwrap();
    }
    let f = |f: AuditFilter| AuditFilter { limit: 50, ..f };
    let by_m = s
        .audit_page(&f(AuditFilter {
            actor_id: Some(m),
            ..AuditFilter::default()
        }))
        .await
        .unwrap();
    let evs: Vec<&str> = by_m.iter().map(|r| r.event.as_str()).collect();
    assert_eq!(evs, ["nzb_upload_reject", "nzb_upload_dup", "nzb_upload"]);
    for r in &by_m {
        assert_eq!(r.actor_id, Some(m));
        assert_eq!(r.actor_kind.as_deref(), Some("user"));
        assert_eq!(r.actor_role.as_deref(), Some("uploader"));
    }
    let up = s
        .audit_page(&f(AuditFilter {
            event: Some("nzb_upload".into()),
            ..AuditFilter::default()
        }))
        .await
        .unwrap();
    assert_eq!(up.len(), 2);
    assert_eq!(up[0].actor_role.as_deref(), Some("admin"));
    let window = s
        .audit_page(&f(AuditFilter {
            from: Some(T0 + 1),
            to: Some(T0 + 2),
            ..AuditFilter::default()
        }))
        .await
        .unwrap();
    assert_eq!(window.len(), 2);
    let all = s.audit_page(&f(AuditFilter::default())).await.unwrap();
    audit_paging_and_clamping(s, &all).await;
    // Pure read: nothing was appended, and the chain verifies.
    assert_eq!(
        s.audit_page(&f(AuditFilter::default()))
            .await
            .unwrap()
            .len(),
        all.len()
    );
    let report = s.audit_walk(None, &mut |_| {}).await.unwrap();
    assert!(report.is_ok(), "{report:?}");
    assert!(s.audit_chain_quick().await.unwrap().consistent);
}

/// Every read the web pages use, on both backends, over a library with data in it (a release with a file, sessions,
/// keys, audit rows, an ingest log row): no backend may fail a read the other answers.
pub(crate) async fn every_page_read_works<S: Repo>(s: &S) {
    let a = account(s, "root", Role::Admin).await;
    let m = account(s, "uploader1", Role::Uploader).await;
    let _ = actor(s, m).await;
    let id = release(s, 7, &Uploader::Account(m)).await.unwrap();
    s.set_category_as(&actor(s, a).await, id, 5040, None, T0)
        .await
        .unwrap();
    s.audit_event(T0, Some("cli"), "probe", Some("n=1"), None)
        .await
        .unwrap();
    let sess = crate::acct_testkit::sess(a, 3, crate::SessionStage::PendingMfa, T0);
    s.insert_session(&sess, 5).await.unwrap();
    let r = s.get_release(id).await.unwrap().unwrap();
    let hex = r.sha256.to_hex();
    macro_rules! ok {
        ($e:expr) => {
            if let Err(e) = $e.await {
                panic!("{}: {e:?}", stringify!($e));
            }
        };
    }
    ok!(s.get_session(&sess.id_hash));
    ok!(s.session_actor(&sess.id_hash, T0));
    ok!(s.get_login_user("root"));
    ok!(s.get_login_user_by_id(a));
    ok!(s.get_mfa_state(a));
    ok!(s.list_active_sessions(a, T0));
    ok!(s.count_unused_recovery_codes(a));
    ok!(s.staged_swap(a, &sess.id_hash, T0));
    ok!(s.throttle_state(a, "192.0.2.1", T0));
    ok!(s.count_throttled_accounts(T0));
    ok!(s.schema_info());
    ok!(s.log_counts());
    ok!(s.security_facts(T0, 0));
    ok!(s.deep_db_check());
    ok!(s.ping());
    ok!(s.ping_writer());
    ok!(s.release_totals_excluding(&[6000]));
    ok!(s.list_ingest_log_excluding(10, &[6000]));
    ok!(s.ingest_log_page(10, 0));
    ok!(s.last_ok_ingest_ts());
    ok!(s.newest_ingested_at());
    ok!(s.list_shas());
    ok!(s.trash_shas());
    ok!(s.list_trash(10));
    ok!(s.list_api_keys());
    ok!(s.list_api_keys_recent(Some(m), 5));
    ok!(s.count_active_api_keys());
    ok!(s.audit_anchor());
    ok!(s.audit_chain_quick());
    ok!(s.recent_audit(50));
    ok!(s.restore_finish_accounts());
    ok!(s.release_attribution(id));
    ok!(s.bulk_items(&[id], &[]));
    ok!(s.list_files(id));
    ok!(s.list_files_page(id, 0, 10));
    ok!(s.get_file(id, 0));
    ok!(s.list_release_groups(id, 10));
    ok!(s.get_release_by_sha(&hex));
    ok!(s.release_ids_in_categories(&[id], &[5040]));
    ok!(s.count_failed_for_sha(&r.sha256));
    ok!(s.list_open_invites(T0));
    ok!(s.get_account_by_username("uploader1"));
}

fn group_item(a: &nzb_core::Analysis, category_id: u32, by: Uploader) -> crate::GroupItem<'_> {
    crate::GroupItem {
        new: NewRelease {
            analysis: a,
            nzb_size_bytes: 1,
            source_name: Some("a.nzb"),
            source_label: None,
            category_id,
            category_source: CategorySource::Fallback,
            meta_json: None,
            scene: SceneColumns::default(),
            ingested_at: T0,
        },
        log: crate::IngestLogEntry {
            ts: T0,
            source: crate::LogSource::Watch,
            api_key_id: None,
            source_name: Some("a.nzb"),
            sha256: Some(a.sha256),
            outcome: crate::LogOutcome::Ok,
            error_code: None,
            detail: None,
        },
        uploader: by,
    }
}

fn group_outcome(o: &crate::GroupOutcome) -> String {
    match o {
        crate::GroupOutcome::Inserted(_) => "Inserted".to_owned(),
        crate::GroupOutcome::Duplicate => "Duplicate".to_owned(),
        crate::GroupOutcome::Deferred => "Deferred".to_owned(),
        crate::GroupOutcome::Failed(e) => format!("Failed({})", variant(e)),
    }
}

/// T114: one commit group answers per job, identically on both backends: new digests are inserted with their files,
/// `ingest_log(ok)` and outbox rows; a digest already indexed or repeated inside the group is a duplicate; a refused
/// uploader and an unknown category fail just their job; nothing of a failed job is written.
pub(crate) async fn commit_group_outcomes_are_per_job<S: Repo>(s: &S) {
    let pre = release(s, 40, &Uploader::Unattributed).await.unwrap();
    let mut with_files = analysis(41);
    with_files.file_count = 2;
    with_files.files = (0..2)
        .map(|i| nzb_core::FileInfo {
            idx: i,
            subject: format!("\"f{i}.rar\" yEnc (1/1)"),
            filename: Some(format!("f{i}.rar")),
            kind: nzb_core::FileKind::Archive,
            poster: None,
            posted_at: None,
            bytes: 10,
            segment_count: 1,
            declared_segments: Some(1),
            missing_ranges: Vec::new(),
            missing_truncated: false,
            par2_blocks: None,
            groups: vec!["alt.binaries.test".to_owned()],
        })
        .collect();
    let (a42, a40, a43, a44) = (analysis(42), analysis(40), analysis(43), analysis(44));
    let items = [
        group_item(&with_files, 8010, Uploader::Unattributed),
        group_item(&a42, 8010, Uploader::Unattributed),
        group_item(&a42, 8010, Uploader::Unattributed),
        group_item(&a40, 8010, Uploader::Unattributed),
        group_item(&a43, 8010, Uploader::ApiKey(9_999)),
        group_item(&a44, 1, Uploader::Unattributed),
    ];
    let before = s.release_totals().await.unwrap().releases;
    let out = s
        .insert_release_group(&items, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    let shown: Vec<String> = out.iter().map(group_outcome).collect();
    assert_eq!(
        shown,
        [
            "Inserted",
            "Inserted",
            "Duplicate",
            "Duplicate",
            "Failed(Account(KeyRefused))",
            "Failed(UnknownCategory)"
        ]
    );
    assert_eq!(s.release_totals().await.unwrap().releases, before + 2);
    let crate::GroupOutcome::Inserted(id) = out[0] else {
        panic!("first job not inserted");
    };
    assert!(id > pre);
    let files = s.list_files(id).await.unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[1].filename.as_deref(), Some("f1.rar"));
    let log = s.list_ingest_log(10).await.unwrap();
    assert_eq!(
        log.len(),
        2,
        "one ok row per inserted job, none for the others"
    );
    assert!(log.iter().all(|l| l.outcome == crate::LogOutcome::Ok));
    for sha in [a43.sha256, a44.sha256] {
        assert!(s.get_release_by_sha(&sha.to_hex()).await.unwrap().is_none());
    }
    // One outbox row per release written (the pre-inserted one and the two of the group).
    assert_eq!(s.search_outbox_read(100).await.unwrap().len(), 3);
    assert_eq!(
        s.insert_release_group(&[], std::time::Duration::ZERO)
            .await
            .unwrap()
            .len(),
        0
    );
}

/// T114: the index lag facts read the outbox: its span and the age of its oldest row; empty after consumption.
pub(crate) async fn outbox_lag_reports_depth_and_age<S: Repo>(s: &S) {
    assert_eq!(
        s.search_outbox_lag().await.unwrap(),
        crate::OutboxLag::default()
    );
    for n in 50..53 {
        release(s, n, &Uploader::Unattributed).await.unwrap();
    }
    let lag = s.search_outbox_lag().await.unwrap();
    assert_eq!(lag.depth, 3);
    assert!(lag.lag_secs < 3_600, "age by the database clock: {lag:?}");
    let rows = s.search_outbox_read(100).await.unwrap();
    let seqs: Vec<i64> = rows.iter().map(|r| r.seq).collect();
    let ids: Vec<i64> = rows.iter().map(|r| r.release_id).collect();
    s.search_outbox_consume(&seqs, &ids).await.unwrap();
    assert_eq!(
        s.search_outbox_lag().await.unwrap(),
        crate::OutboxLag::default()
    );
}

/// T120: preferences are read with the session actor (one statement), written for the actor itself only, audited by
/// key name only, and refused for a disabled actor, with the same results on both backends.
pub(crate) async fn user_prefs_round_trip_with_the_session_actor<S: Repo>(s: &S) {
    use crate::{Theme, UserPrefs};
    let _admin = account(s, "root", Role::Admin).await;
    let v = account(s, "viewer1", Role::Viewer).await;
    assert_eq!(actor(s, v).await.prefs, UserPrefs::default());
    assert_eq!(s.user_prefs(v).await.unwrap(), UserPrefs::default());
    let want = UserPrefs {
        hide_xxx: true,
        theme: Theme::Dark,
        ..UserPrefs::default()
    };
    assert!(
        s.set_user_prefs(v, want, Some("192.0.2.1"), T0 + 1)
            .await
            .unwrap()
    );
    // Unchanged values: no write, no audit row.
    assert!(!s.set_user_prefs(v, want, None, T0 + 2).await.unwrap());
    assert_eq!(s.user_prefs(v).await.unwrap(), want);
    let sess = crate::acct_testkit::sess(v, 77, crate::SessionStage::Active, T0);
    s.insert_session(&sess, 5).await.unwrap();
    assert_eq!(
        s.session_actor(&sess.id_hash, T0)
            .await
            .unwrap()
            .unwrap()
            .prefs,
        want
    );
    let light = UserPrefs {
        theme: Theme::Light,
        ..want
    };
    assert!(s.set_user_prefs(v, light, None, T0 + 3).await.unwrap());
    let rows: Vec<_> = s
        .recent_audit(50)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.event == crate::PREF_CHANGE_EVENT)
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let mut details: Vec<_> = rows
        .iter()
        .map(|r| r.detail.clone().unwrap_or_default())
        .collect();
    details.sort();
    assert_eq!(details, ["keys=hide_xxx,theme", "keys=theme"]);
    for r in &rows {
        assert_eq!((r.actor_id, r.target_id), (Some(v), Some(v)));
        let d = r.detail.as_deref().unwrap_or_default();
        assert!(
            !d.contains("dark") && !d.contains("light") && !d.contains("true"),
            "{d}"
        );
    }
    s.disable_account_operator(v, T0 + 4).await.unwrap();
    let e = s
        .set_user_prefs(v, UserPrefs::default(), None, T0 + 5)
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(Forbidden)");
    assert_eq!(s.user_prefs(v).await.unwrap(), light);
}

/// T133: the two page sizes are stored per account (two accounts are independent), read with the session actor,
/// audited by key name only and keep the other preferences, with the same results on both backends (the CHECKs are
/// exercised by `nzb-web/tests/page_size.rs`; the type cannot build a value outside the allowlist).
pub(crate) async fn t133_page_sizes_are_per_account<S: Repo>(s: &S) {
    use crate::{FilePageSize, ReleasePageSize, Theme, UserPrefs};
    let _admin = account(s, "root", Role::Admin).await;
    let a = account(s, "pager1", Role::Viewer).await;
    let b = account(s, "pager2", Role::Uploader).await;
    let dark = UserPrefs {
        theme: Theme::Dark,
        ..UserPrefs::default()
    };
    assert!(s.set_user_prefs(a, dark, None, T0 + 1).await.unwrap());
    let sized = UserPrefs {
        page_size_releases: ReleasePageSize::new(100).unwrap(),
        page_size_files: FilePageSize::new(500).unwrap(),
        ..dark
    };
    assert!(s.set_user_prefs(a, sized, None, T0 + 2).await.unwrap());
    assert_eq!(s.user_prefs(a).await.unwrap(), sized);
    // The other account still has the defaults (absent row).
    assert_eq!(s.user_prefs(b).await.unwrap(), UserPrefs::default());
    let small = UserPrefs {
        page_size_releases: ReleasePageSize::new(25).unwrap(),
        ..UserPrefs::default()
    };
    assert!(s.set_user_prefs(b, small, None, T0 + 3).await.unwrap());
    assert_eq!(s.user_prefs(a).await.unwrap(), sized);
    assert_eq!(s.user_prefs(b).await.unwrap(), small);
    let sess = crate::acct_testkit::sess(a, 78, crate::SessionStage::Active, T0);
    s.insert_session(&sess, 5).await.unwrap();
    assert_eq!(
        s.session_actor(&sess.id_hash, T0)
            .await
            .unwrap()
            .unwrap()
            .prefs,
        sized
    );
    let mut details: Vec<String> = s
        .recent_audit(50)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.event == crate::PREF_CHANGE_EVENT)
        .map(|r| r.detail.unwrap_or_default())
        .collect();
    details.sort();
    assert_eq!(
        details,
        [
            "keys=page_size_releases",
            "keys=page_size_releases,page_size_files",
            "keys=theme"
        ]
    );
    for d in &details {
        assert!(
            !d.contains("100") && !d.contains("500") && !d.contains("25"),
            "{d}"
        );
    }
}

/// T133 review 48 L1: two saves of different preference fields made from stale snapshots never revert each other:
/// `set_page_size` writes one column, and `patch_user_prefs` applies only its fields to the row as it is inside the
/// write transaction. Unchanged values write nothing and audit nothing. Same results on both backends.
pub(crate) async fn t133_concurrent_preference_saves_do_not_revert_each_other<S: Repo>(s: &S) {
    use crate::{FilePageSize, PageSize, PrefsPatch, ReleasePageSize, Theme, UserPrefs};
    let _admin = account(s, "root", Role::Admin).await;
    let a = account(s, "racer", Role::Viewer).await;
    // Both requests read the same snapshot (the defaults) with their sessions.
    let snapshot = s.user_prefs(a).await.unwrap();
    // The Account form changes the theme ...
    let account_form = UserPrefs {
        theme: Theme::Dark,
        ..snapshot
    };
    // ... while "Per page" stores 100 releases per page first.
    assert!(
        s.set_page_size(
            a,
            PageSize::Releases(ReleasePageSize::new(100).unwrap()),
            None,
            T0 + 1
        )
        .await
        .unwrap()
    );
    assert!(
        s.patch_user_prefs(a, PrefsPatch::between(snapshot, account_form), None, T0 + 2)
            .await
            .unwrap()
    );
    let both = UserPrefs {
        theme: Theme::Dark,
        page_size_releases: ReleasePageSize::new(100).unwrap(),
        ..UserPrefs::default()
    };
    assert_eq!(s.user_prefs(a).await.unwrap(), both);
    // The other order: a stale "Per page" for the files table after a theme change keeps the theme and the other size.
    assert!(
        s.patch_user_prefs(
            a,
            PrefsPatch {
                theme: Some(Theme::Light),
                ..PrefsPatch::default()
            },
            None,
            T0 + 3
        )
        .await
        .unwrap()
    );
    assert!(
        s.set_page_size(
            a,
            PageSize::Files(FilePageSize::new(250).unwrap()),
            None,
            T0 + 4
        )
        .await
        .unwrap()
    );
    let all = UserPrefs {
        theme: Theme::Light,
        page_size_releases: ReleasePageSize::new(100).unwrap(),
        page_size_files: FilePageSize::new(250).unwrap(),
        ..UserPrefs::default()
    };
    assert_eq!(s.user_prefs(a).await.unwrap(), all);
    // Unchanged: no write, no audit row; an empty patch neither.
    let audits = |rows: Vec<crate::AuditRow>| {
        rows.into_iter()
            .filter(|r| r.event == crate::PREF_CHANGE_EVENT)
            .count()
    };
    let before = audits(s.recent_audit(100).await.unwrap());
    assert!(
        !s.set_page_size(
            a,
            PageSize::Files(FilePageSize::new(250).unwrap()),
            None,
            T0 + 5
        )
        .await
        .unwrap()
    );
    assert!(
        !s.patch_user_prefs(a, PrefsPatch::default(), None, T0 + 6)
            .await
            .unwrap()
    );
    assert_eq!(audits(s.recent_audit(100).await.unwrap()), before);
    assert_eq!(before, 4);
    // A disabled actor is refused like every preference write.
    s.disable_account_operator(a, T0 + 7).await.unwrap();
    let e = s
        .set_page_size(
            a,
            PageSize::Releases(ReleasePageSize::new(25).unwrap()),
            None,
            T0 + 8,
        )
        .await
        .unwrap_err();
    assert_eq!(variant(&e), "Account(Forbidden)");
    assert_eq!(s.user_prefs(a).await.unwrap(), all);
}

/// T127: saved searches are private per account (another account's id is `NotFound`, never its data), limited to
/// `MAX_SAVED_SEARCHES`, unique by name per account, refused for a disabled actor, opened with a monotonic
/// `last_seen_at`, and deleted with the account, with the same results and variants on both backends.
#[allow(clippy::too_many_lines)] // one scenario: create, isolate, refuse, rename, open, limit, delete, tombstone
pub(crate) async fn saved_searches_are_private_limited_and_unique<S: Repo>(s: &S) {
    use crate::MAX_SAVED_SEARCHES;
    let _admin = account(s, "root", Role::Admin).await;
    let alice = account(s, "alice1", Role::Viewer).await;
    let bob = account(s, "bobby1", Role::Uploader).await;
    let filters = r#"{"q":"show","cat":"tv"}"#;
    let id = s
        .create_saved_search(alice, "Shows", filters, T0)
        .await
        .unwrap();
    let list = s.saved_searches(alice).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (list[0].id, list[0].name.as_str(), list[0].filters.as_str()),
        (id, "Shows", filters)
    );
    assert_eq!((list[0].created_at, list[0].last_seen_at), (T0, T0));
    // Another account sees nothing and can touch nothing; the same name is free for it.
    assert_eq!(s.saved_searches(bob).await.unwrap().len(), 0);
    assert_eq!(s.open_saved_search(bob, id, T0 + 1).await.unwrap(), None);
    let err = s.rename_saved_search(bob, id, "Mine").await.unwrap_err();
    assert_eq!(variant(&err), "NotFound");
    let err = s.delete_saved_search(bob, id).await.unwrap_err();
    assert_eq!(variant(&err), "NotFound");
    s.create_saved_search(bob, "Shows", "{}", T0).await.unwrap();
    // Duplicate names, bad names and bad filters.
    let err = s
        .create_saved_search(alice, "Shows", "{}", T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&err), "SavedSearch(Duplicate)");
    let long = "y".repeat(61);
    for bad in ["", " padded", "x\u{202e}y", long.as_str()] {
        let err = s
            .create_saved_search(alice, bad, "{}", T0)
            .await
            .unwrap_err();
        assert_eq!(variant(&err), "SavedSearch(InvalidName)", "{bad:?}");
    }
    for bad in ["[]", "{\"q\":1}", "nope"] {
        let err = s
            .create_saved_search(alice, "Other", bad, T0)
            .await
            .unwrap_err();
        assert_eq!(variant(&err), "SavedSearch(InvalidFilters)", "{bad}");
    }
    // Rename: the same name is a no-op, a taken name is a duplicate.
    let id2 = s
        .create_saved_search(alice, "Films", "{}", T0)
        .await
        .unwrap();
    s.rename_saved_search(alice, id2, "Films").await.unwrap();
    let err = s
        .rename_saved_search(alice, id2, "Shows")
        .await
        .unwrap_err();
    assert_eq!(variant(&err), "SavedSearch(Duplicate)");
    s.rename_saved_search(alice, id2, "Movies").await.unwrap();
    let names: Vec<String> = s
        .saved_searches(alice)
        .await
        .unwrap()
        .into_iter()
        .map(|x| x.name)
        .collect();
    assert_eq!(names, ["Movies", "Shows"]);
    // Opening returns the previous visit and moves it forward, never backwards.
    let opened = s
        .open_saved_search(alice, id, T0 + 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.last_seen_at, T0);
    let again = s
        .open_saved_search(alice, id, T0 + 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.last_seen_at, T0 + 50);
    let now = s
        .open_saved_search(alice, id, T0 + 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(now.last_seen_at, T0 + 50);
    // The limit.
    for i in 2..MAX_SAVED_SEARCHES {
        s.create_saved_search(alice, &format!("Search {i:02}"), "{}", T0)
            .await
            .unwrap();
    }
    assert_eq!(
        i64::try_from(s.saved_searches(alice).await.unwrap().len()).unwrap(),
        MAX_SAVED_SEARCHES
    );
    let err = s
        .create_saved_search(alice, "One more", "{}", T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&err), "SavedSearch(Limit)");
    // Deleting frees a slot.
    s.delete_saved_search(alice, id2).await.unwrap();
    let err = s.delete_saved_search(alice, id2).await.unwrap_err();
    assert_eq!(variant(&err), "NotFound");
    s.create_saved_search(alice, "One more", "{}", T0)
        .await
        .unwrap();
    // A disabled actor cannot write.
    s.disable_account_operator(bob, T0 + 1).await.unwrap();
    let err = s
        .create_saved_search(bob, "Later", "{}", T0)
        .await
        .unwrap_err();
    assert_eq!(variant(&err), "Account(Forbidden)");
    // Deleted with the account (the tombstone); the other account keeps its own.
    s.disable_account_operator(alice, T0 + 2).await.unwrap();
    s.delete_account_operator(alice, T0 + 3).await.unwrap();
    assert_eq!(s.saved_searches(alice).await.unwrap().len(), 0);
    assert_eq!(s.saved_searches(bob).await.unwrap().len(), 1);
}

/// A request admitted before its body arrives cannot mutate display state after its session stops
/// authorizing it. The same transaction must reject every mutation before touching state or audit.
#[allow(clippy::too_many_lines)]
pub(crate) async fn sec_036_display_writes_recheck_session<S: Repo>(s: &S) {
    use crate::{
        FilePageSize, PageSize, PrefsPatch, ReleasePageSize, SessionStage, Theme, UserPrefs,
    };

    account(s, "root", Role::Admin).await;
    let uid = account(s, "display1", Role::Viewer).await;
    let other = account(s, "display2", Role::Viewer).await;
    let id = s
        .create_saved_search(uid, "Original", "{}", T0)
        .await
        .unwrap();
    let original = s.saved_searches(uid).await.unwrap();
    let template = actor(s, uid).await;
    let before_audit = s.recent_audit(100).await.unwrap().len();
    for (n, kind) in ["revoked", "expired", "foreign", "pending"]
        .into_iter()
        .enumerate()
    {
        let mut session = crate::acct_testkit::sess(
            if kind == "foreign" { other } else { uid },
            100 + u8::try_from(n).unwrap(),
            if kind == "pending" {
                SessionStage::PendingMfa
            } else {
                SessionStage::Active
            },
            T0,
        );
        if kind == "expired" {
            session.expires_at = T0 + 10;
        }
        s.insert_session(&session, 10).await.unwrap();
        if kind == "revoked" {
            assert!(s.delete_session(&session.id_hash).await.unwrap());
        }
        let stale = AccountActor {
            session: Some(session.id_hash),
            ..template.clone()
        };
        // Stage, role and owner claims in the struct do not replace checking the stored session.
        let attempts = [
            s.create_saved_search_as(&stale, "Unauthorized", "{}", T0 + 10)
                .await
                .map(|_| ()),
            s.rename_saved_search_as(&stale, id, "Unauthorized", T0 + 10)
                .await,
            s.delete_saved_search_as(&stale, id, T0 + 10).await,
            s.open_saved_search_as(&stale, id, T0 + 10)
                .await
                .map(|_| ()),
            s.patch_user_prefs_as(
                &stale,
                PrefsPatch {
                    theme: Some(Theme::Dark),
                    ..PrefsPatch::default()
                },
                None,
                T0 + 10,
            )
            .await
            .map(|_| ()),
            s.set_page_size_as(
                &stale,
                PageSize::Releases(ReleasePageSize::new(100).unwrap()),
                None,
                T0 + 10,
            )
            .await
            .map(|_| ()),
            s.set_page_size_as(
                &stale,
                PageSize::Files(FilePageSize::new(500).unwrap()),
                None,
                T0 + 10,
            )
            .await
            .map(|_| ()),
        ];
        for (operation, result) in attempts.into_iter().enumerate() {
            assert_eq!(
                variant(&result.unwrap_err()),
                "Account(Forbidden)",
                "{kind}, operation {operation}"
            );
        }
        assert_eq!(s.saved_searches(uid).await.unwrap(), original, "{kind}");
        assert_eq!(
            s.user_prefs(uid).await.unwrap(),
            UserPrefs::default(),
            "{kind}"
        );
        assert_eq!(
            s.user_prefs(other).await.unwrap(),
            UserPrefs::default(),
            "{kind}"
        );
        assert_eq!(
            s.recent_audit(100).await.unwrap().len(),
            before_audit,
            "{kind}"
        );
    }
    // Positive control: all operations still work for a live viewer, with the same audit semantics.
    let live = template;
    let fresh = s
        .create_saved_search_as(&live, "Fresh", "{}", T0 + 11)
        .await
        .unwrap();
    s.rename_saved_search_as(&live, fresh, "Renamed", T0 + 12)
        .await
        .unwrap();
    let opened = s
        .open_saved_search_as(&live, fresh, T0 + 13)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (opened.name.as_str(), opened.last_seen_at),
        ("Renamed", T0 + 11)
    );
    assert_eq!(
        s.open_saved_search_as(&live, fresh, T0 + 12)
            .await
            .unwrap()
            .unwrap()
            .last_seen_at,
        T0 + 13
    );
    s.delete_saved_search_as(&live, fresh, T0 + 14)
        .await
        .unwrap();
    assert_eq!(s.saved_searches(uid).await.unwrap(), original);
    assert!(
        s.patch_user_prefs_as(
            &live,
            PrefsPatch {
                theme: Some(Theme::Dark),
                ..PrefsPatch::default()
            },
            None,
            T0 + 15
        )
        .await
        .unwrap()
    );
    assert!(
        s.set_page_size_as(
            &live,
            PageSize::Releases(ReleasePageSize::new(100).unwrap()),
            None,
            T0 + 16
        )
        .await
        .unwrap()
    );
    assert!(
        s.set_page_size_as(
            &live,
            PageSize::Files(FilePageSize::new(500).unwrap()),
            None,
            T0 + 17
        )
        .await
        .unwrap()
    );
    let prefs = s.user_prefs(uid).await.unwrap();
    assert_eq!(prefs.theme, Theme::Dark);
    assert_eq!(prefs.page_size_releases.get(), 100);
    assert_eq!(prefs.page_size_files.get(), 500);
    assert_eq!(
        s.recent_audit(100)
            .await
            .unwrap()
            .iter()
            .filter(|r| r.event == crate::PREF_CHANGE_EVENT)
            .count(),
        3
    );
}

macro_rules! seam_suite {
    ($open:path; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread")]
            async fn $name() {
                let o = $open().await;
                super::$name(&o.store).await;
            }
        )*
    };
}

macro_rules! both {
    ($($name:ident),* $(,)?) => {
        mod sqlite {
            seam_suite!(super::open_sqlite; $($name),*);
        }
        mod postgres {
            seam_suite!(super::open_postgres; $($name),*);
        }
    };
}

both!(
    last_admin_is_refused_with_one_variant,
    unknown_target_is_target_not_found,
    reserved_and_invalid_login_names,
    duplicate_release_is_duplicate,
    edits_of_missing_releases_are_not_found,
    unknown_category_is_unknown_category,
    trash_is_bound_to_the_confirmed_digest,
    viewer_cannot_edit,
    login_verdict_rereads_credentials,
    login_session_issuance_rereads_credentials,
    login_session_issuance_preserves_rotation_and_caps,
    login_session_issuance_rejects_invalid_state,
    audit_append_and_walk_agree,
    users_page_reads_work,
    audit_page_filters_and_attributes_uploads,
    every_page_read_works,
    commit_group_outcomes_are_per_job,
    outbox_lag_reports_depth_and_age,
    user_prefs_round_trip_with_the_session_actor,
    t133_page_sizes_are_per_account,
    t133_concurrent_preference_saves_do_not_revert_each_other,
    saved_searches_are_private_limited_and_unique,
    sec_036_display_writes_recheck_session,
);

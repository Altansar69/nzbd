//! User repository tests (one-user rule, resets).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::{DbConfig, SqliteDb, StoreError};

async fn open() -> (tempfile::TempDir, SqliteDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteDb::open(&DbConfig {
        path: dir.path().join("t.sqlite"),
    })
    .await
    .unwrap();
    (dir, db)
}

#[tokio::test]
async fn sec_027_one_user_rule() {
    let (_d, db) = open().await;
    db.create_user("alice", "hash1", 10).await.unwrap();
    assert!(matches!(
        db.create_user("bob", "hash2", 11).await,
        Err(StoreError::UserExists)
    ));
    // Case-insensitive duplicate also refused.
    assert!(matches!(
        db.create_user("ALICE", "hash3", 12).await,
        Err(StoreError::UserExists)
    ));
    let u = db.get_user_by_username("Alice").await.unwrap().unwrap();
    assert_eq!(u.username, "alice");
    assert!(!u.totp_enabled);
    assert!(!format!("{u:?}").contains("hash1"));
}

#[tokio::test]
async fn sec_027_concurrent_creates_yield_one_user() {
    let (_d, db) = open().await;
    let mut hs = Vec::new();
    for i in 0..8 {
        let db = db.clone();
        hs.push(tokio::spawn(async move {
            db.create_user(&format!("u{i}"), "h", 1).await.is_ok()
        }));
    }
    let mut ok = 0;
    for h in hs {
        ok += usize::from(h.await.unwrap());
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn invalid_usernames_rejected() {
    let (_d, db) = open().await;
    for bad in ["", "a b", "a/b", "é", &"x".repeat(65), "a\0b"] {
        assert!(matches!(
            db.create_user(bad, "h", 1).await,
            Err(StoreError::InvalidUsername)
        ));
    }
    assert!(db.get_only_user().await.unwrap().is_none());
}

#[tokio::test]
async fn sec_027_reset_password_revokes_sessions_and_unlocks() {
    let (_d, db) = open().await;
    let id = db.create_user("alice", "old", 1).await.unwrap();
    sqlx::query("UPDATE account SET failed_logins = 7, locked_until = 999")
        .execute(db.writer())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO session (id_hash, account_id, stage, csrf_token, created_at, last_seen_at, expires_at) \
         VALUES (zeroblob(32), ?1, 'active', zeroblob(32), 1, 1, 2)",
    )
    .bind(id)
    .execute(db.writer())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO api_key (name, prefix, key_hash, created_at) VALUES \
         ('a','aaaaaa',zeroblob(32),1), ('b','bbbbbb',x'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',1)",
    )
    .execute(db.writer())
    .await
    .unwrap();
    sqlx::query("UPDATE api_key SET revoked_at = 2 WHERE name = 'b'")
        .execute(db.writer())
        .await
        .unwrap();
    db.reset_password("new", 5).await.unwrap();
    let revoked: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT name, revoked_at FROM api_key ORDER BY name")
            .fetch_all(db.writer())
            .await
            .unwrap();
    // 'a' revoked now; already-revoked 'b' keeps its original timestamp.
    assert_eq!(
        revoked,
        vec![("a".to_owned(), Some(5)), ("b".to_owned(), Some(2))]
    );
    let detail: String =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE event = 'user.reset_password'")
            .fetch_one(db.writer())
            .await
            .unwrap();
    assert_eq!(detail, "sessions_revoked=1 api_keys_revoked=1");
    let u = db.get_only_user().await.unwrap().unwrap();
    assert_eq!(u.password_hash, "new");
    let (n, f): (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM session), failed_logins FROM account")
            .fetch_one(db.writer())
            .await
            .unwrap();
    assert_eq!((n, f), (0, 0));
    let ev: String = sqlx::query_scalar("SELECT event FROM audit_log ORDER BY id DESC LIMIT 1")
        .fetch_one(db.writer())
        .await
        .unwrap();
    assert_eq!(ev, "user.reset_password");
}

#[tokio::test]
async fn sec_023_reset_mfa_clears_everything() {
    let (_d, db) = open().await;
    let id = db.create_user("alice", "h", 1).await.unwrap();
    sqlx::query(
        "UPDATE account SET totp_secret_enc = x'0102', totp_enabled = 1, totp_last_step = 5",
    )
    .execute(db.writer())
    .await
    .unwrap();
    sqlx::query("INSERT INTO recovery_code (account_id, code_hash) VALUES (?1, randomblob(32))")
        .bind(id)
        .execute(db.writer())
        .await
        .unwrap();
    db.reset_mfa(9).await.unwrap();
    let (enc_null, en, step_null, codes): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT totp_secret_enc IS NULL, totp_enabled, totp_last_step IS NULL, \
         (SELECT count(*) FROM recovery_code) FROM account",
    )
    .fetch_one(db.writer())
    .await
    .unwrap();
    assert_eq!((enc_null, en, step_null, codes), (1, 0, 1, 0));
}

#[tokio::test]
async fn resets_without_user_report_not_found() {
    let (_d, db) = open().await;
    assert!(matches!(db.reset_mfa(1).await, Err(StoreError::NotFound)));
    assert!(matches!(
        db.reset_password("h", 1).await,
        Err(StoreError::NotFound)
    ));
}

//! T081 store tests on the v3 Postgres store (T112): the `release_trash` move. The `TrashStore` (filesystem) tests
//! are unchanged and run in the 2.x suite; the `db` blob backend does not exist in v3 (D33 c).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty
)]

use crate::StoreError;
use crate::pg_release_tests::{analysis, count, new, open, sha};

#[tokio::test]
async fn sec_050_trash_release_moves_every_row_and_frees_the_sha() {
    let (_d, db) = open().await;
    let a = analysis(1, "Gone.1080p", 100, Some(5));
    let id = db.insert_release(&new(&a)).await.unwrap();
    sqlx::query(
        "INSERT INTO ingest_log (ts, source, outcome, release_id) VALUES (1,'watch','ok',$1)",
    )
    .bind(id)
    .execute(db.web())
    .await
    .unwrap();

    let row = db
        .trash_release(id, 1_800_000_000, "user:1", Some("192.0.2.1"))
        .await
        .unwrap();
    assert_eq!(row.sha256, sha(1));
    assert_eq!(row.title, a.title);
    assert_eq!(row.original_id, id);
    assert_eq!(row.deleted_at, 1_800_000_000);

    // Gone from every table the UI reads.
    assert_eq!(count(&db, "release").await, 0);
    assert_eq!(count(&db, "nzb_file").await, 0);
    assert_eq!(db.get_release(id).await.unwrap(), None);
    assert!(db.hydrate(&[id], &[]).await.unwrap().is_empty());
    assert!(db.list_shas().await.unwrap().is_empty());
    assert_eq!(db.release_totals().await.unwrap().releases, 0);
    // The index learns it through the outbox (insert + trash).
    assert_eq!(count(&db, "search_outbox").await, 2);
    // The log keeps its row, unlinked; the audit row has no title and only a sha prefix.
    assert_eq!(count(&db, "ingest_log").await, 1);
    assert_eq!(db.list_ingest_log(5).await.unwrap()[0].release_id, None);
    let audit = db.recent_audit(5).await.unwrap();
    let ev = audit.iter().find(|r| r.event == "release_delete").unwrap();
    assert_eq!(ev.actor.as_deref(), Some("user:1"));
    assert_eq!(
        ev.detail.as_deref(),
        Some(&*format!(
            "release={id} sha8=01010101 added_by=none title=Gone.1080p"
        ))
    );
    // T138: the title is kept in the row so the delete stays explainable.
    assert!(ev.detail.as_deref().unwrap().contains("Gone"));

    // Trash listing and lookups.
    assert_eq!(db.list_trash(10).await.unwrap(), vec![row.clone()]);
    assert_eq!(db.get_trash(row.id).await.unwrap(), Some(row.clone()));
    assert_eq!(db.trash_shas().await.unwrap(), [sha(1)].into());

    // The same bytes can be ingested again (fresh release), and trashed again: one trash row
    // per digest, refreshed.
    let id2 = db.insert_release(&new(&a)).await.unwrap();
    // v3: ids are never reused (identity sequence).
    assert!(id2 > id);
    let again = db
        .trash_release(id2, 1_800_000_500, "user:1", None)
        .await
        .unwrap();
    assert_eq!(again.id, row.id);
    assert_eq!(again.deleted_at, 1_800_000_500);
    assert_eq!(count(&db, "release_trash").await, 1);

    // Unknown id: typed error, nothing written.
    let audits = count(&db, "audit_log").await;
    assert!(matches!(
        db.trash_release(999, 1, "user:1", None).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(count(&db, "audit_log").await, audits);

    assert!(db.forget_trash(row.id).await.unwrap());
    assert!(!db.forget_trash(row.id).await.unwrap());
}

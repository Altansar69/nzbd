//! The release change counter (T102). (The 2.x concurrent-reader tests of the FTS5 listing went with the engine;
//! listing under concurrent writes is the search index's, the `nzb-search` `store_source` tests.)
//!
//! Deterministic: no wall-clock assertions. Every task has to finish (a generous `timeout` only turns
//! a hang into a failure), and every result is checked against invariants that hold for *any*
//! interleaving, not against one particular schedule.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use crate::release_tests::{analysis, new, open};

#[tokio::test]
async fn release_epoch_moves_on_release_writes_and_not_on_reads() {
    let (_d, db) = open().await;
    let e0 = db.release_epoch();
    let a = analysis(1, "Epoch one", 10, None);
    let id = db.insert_release(&new(&a)).await.unwrap();
    let e1 = db.release_epoch();
    assert!(e1 > e0, "insert");

    // Reads and failed writes leave it alone.
    let _ = db.get_release(id).await.unwrap();
    assert!(db.delete_release(id + 999).await.is_err());
    assert!(db.set_category(id + 999, 8010).await.is_err());
    assert_eq!(db.release_epoch(), e1);

    db.set_category(id, 5040).await.unwrap();
    let e2 = db.release_epoch();
    assert!(e2 > e1, "category change");
    db.trash_release(id, 1, "t", None).await.unwrap();
    let e3 = db.release_epoch();
    assert!(e3 > e2, "trash");
    let b = analysis(2, "Epoch two", 10, None);
    let id2 = db.insert_release(&new(&b)).await.unwrap();
    db.delete_release(id2).await.unwrap();
    assert!(db.release_epoch() > e3, "delete");
}

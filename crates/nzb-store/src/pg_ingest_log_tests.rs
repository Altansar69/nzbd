#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use nzb_core::{Analysis, ReleaseFlags, Sha256};

use crate::pg::PgDb;
#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::{
    CategorySource, IngestLogEntry, LogOutcome, LogSource, NewRelease, SceneColumns, StoreError,
};

async fn open() -> (TestDb, PgDb) {
    let t = TestDb::new().await;
    let db = t.db.clone();
    (t, db)
}

fn analysis() -> Analysis {
    Analysis {
        sha256: Sha256([7; 32]),
        name_candidates: vec![],
        meta_name_candidates: 0,
        title: "t".into(),
        poster: None,
        posted_at: None,
        total_bytes: 1,
        file_count: 0,
        segment_count: 0,
        duplicate_segments: 0,
        par2_blocks: 0,
        flags: ReleaseFlags::EMPTY,
        meta_category: None,
        repairable_estimate: None,
        files: vec![],
    }
}

fn entry(a: &Analysis) -> IngestLogEntry<'static> {
    IngestLogEntry {
        ts: 10,
        source: LogSource::Watch,
        api_key_id: None,
        source_name: Some("x\n.nzb"),
        sha256: Some(a.sha256),
        outcome: LogOutcome::Duplicate, // forced to ok by insert_release_logged
        error_code: None,
        detail: None,
    }
}

#[tokio::test]
async fn release_and_log_row_commit_together() {
    let (_d, db) = open().await;
    let a = analysis();
    let new = NewRelease {
        analysis: &a,
        nzb_size_bytes: 1,
        source_name: None,
        source_label: None,
        category_id: 8010,
        category_source: CategorySource::Fallback,
        meta_json: None,
        scene: SceneColumns::default(),
        ingested_at: 5,
    };
    let id = db.insert_release_logged(&new, &entry(&a)).await.unwrap();
    let rows = db.list_ingest_log(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, LogOutcome::Ok);
    assert_eq!(rows[0].release_id, Some(id));
    assert_eq!(rows[0].source_name.as_deref(), Some("x .nzb"));
    // A duplicate insert writes neither a release nor a log row.
    let err = db
        .insert_release_logged(&new, &entry(&a))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Duplicate));
    assert_eq!(db.list_ingest_log(10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn log_page_offsets_and_totals() {
    let (_d, db) = open().await;
    assert_eq!(db.release_totals().await.unwrap().releases, 0);
    assert_eq!(db.last_ok_ingest_ts().await.unwrap(), None);
    db.ping().await.unwrap();
    for ts in 0..5_i64 {
        let e = IngestLogEntry {
            ts,
            source: LogSource::UploadUi,
            api_key_id: None,
            source_name: Some("f.nzb"),
            sha256: None,
            outcome: LogOutcome::Failed,
            error_code: Some("NZB_EMPTY"),
            detail: None,
        };
        db.log_ingest(&e, None).await.unwrap();
    }
    let p1 = db.ingest_log_page(2, 0).await.unwrap();
    let p2 = db.ingest_log_page(2, 2).await.unwrap();
    assert_eq!(p1.iter().map(|r| r.ts).collect::<Vec<_>>(), [4, 3]);
    assert_eq!(p2.iter().map(|r| r.ts).collect::<Vec<_>>(), [2, 1]);
    assert_eq!(db.ingest_log_page(2, 10).await.unwrap().len(), 0);
    assert_eq!(db.last_ok_ingest_ts().await.unwrap(), None);
}

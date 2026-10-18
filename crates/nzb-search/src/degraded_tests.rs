//! Degraded browse bounds (review L5, SEC-095). The source models T112's `PgDb::degraded_browse`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    clippy::assert_is_empty,
    clippy::panic
)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use nzb_core::Taxonomy;
use nzb_store::ReleaseRow;

use crate::degraded::{
    CATEGORY_FACTOR, DegradedPage, DegradedRequest, DegradedSource, ROW_BUDGET, WalkPage, browse,
};
use crate::error::SearchError;
use crate::testkit::{doc, row_of};

/// Current rows newest first; every primary-key entry read is counted.
struct PkWalk {
    rows: Mutex<Vec<ReleaseRow>>,
    read: AtomicU64,
}

impl DegradedSource for PkWalk {
    async fn browse(
        &self,
        before: Option<i64>,
        categories: &[u32],
        exclude: &[u32],
        limit: u32,
    ) -> Result<WalkPage, SearchError> {
        let rows = self.rows.lock().unwrap();
        let mut items = Vec::new();
        let mut scanned = 0u64;
        let mut low = None;
        for r in rows.iter().filter(|r| before.is_none_or(|b| r.id < b)) {
            if scanned >= ROW_BUDGET || items.len() >= limit as usize {
                break;
            }
            scanned += 1;
            low = Some(r.id);
            if (categories.is_empty() || categories.contains(&r.category_id))
                && !exclude.contains(&r.category_id)
            {
                items.push(r.clone());
            }
        }
        self.read.fetch_add(scanned, Ordering::SeqCst);
        let exhausted = scanned >= ROW_BUDGET && items.len() < limit as usize;
        Ok(WalkPage {
            next_before: if exhausted {
                low
            } else {
                items.last().map(|r| r.id)
            },
            items,
            budget_exhausted: exhausted,
        })
    }

    async fn category_totals(&self) -> Result<Vec<(u32, u64)>, SearchError> {
        let mut m = std::collections::BTreeMap::new();
        for r in self.rows.lock().unwrap().iter() {
            *m.entry(r.category_id).or_insert(0u64) += 1;
        }
        Ok(m.into_iter().collect())
    }
}

fn library(n: i64, cat_of: impl Fn(i64) -> u32) -> PkWalk {
    let rows = (1..=n)
        .rev()
        .map(|id| {
            let mut d = doc(id, "x");
            d.category_id = cat_of(id);
            row_of(&d)
        })
        .collect();
    PkWalk {
        rows: Mutex::new(rows),
        read: AtomicU64::new(0),
    }
}

fn ids(p: &DegradedPage) -> Vec<i64> {
    match p {
        DegradedPage::Page { items, .. } => items.iter().map(|r| r.id).collect(),
        DegradedPage::CategoryUnavailable => vec![],
    }
}

#[tokio::test]
async fn sec_095_degraded_browse_is_bounded() {
    let tax = Taxonomy::builtin().unwrap();
    // 300k releases; only the oldest 50 are not XXX and XXX is hidden for this caller.
    let src = library(300_000, |id| if id <= 50 { 5040 } else { 6000 });
    let req = DegradedRequest {
        exclude_categories: vec![6000],
        limit: 25,
        ..DegradedRequest::default()
    };
    let p = browse(&src, &tax, &req).await.unwrap();
    // The walk stops at the row budget; nothing hidden is shown or becomes a cursor (the source's own
    // continuation id is a hidden row's here, and is not used).
    assert_eq!(src.read.load(Ordering::SeqCst), ROW_BUDGET);
    match &p {
        DegradedPage::Page {
            items,
            total,
            next_before,
            budget_exhausted,
        } => {
            assert!(items.is_empty());
            assert_eq!(*total, 50);
            assert_eq!(*next_before, None);
            assert!(*budget_exhausted);
        }
        DegradedPage::CategoryUnavailable => panic!("browse without category is always served"),
    }

    // A category page whose allowed set is smaller than limit x 1000 is not walked at all.
    src.read.store(0, Ordering::SeqCst);
    let small = DegradedRequest {
        categories: vec![5000],
        limit: 25,
        ..DegradedRequest::default()
    };
    assert_eq!(
        browse(&src, &tax, &small).await.unwrap(),
        DegradedPage::CategoryUnavailable
    );
    assert_eq!(src.read.load(Ordering::SeqCst), 0);
    // The threshold counts the allowed set only (hidden categories never make a page "large"); a parent
    // is sent to the source with its children.
    let src2 = library(60_000, |id| if id % 2 == 0 { 5040 } else { 6000 });
    let tv = DegradedRequest {
        categories: vec![5000],
        exclude_categories: vec![6000],
        limit: 25,
        ..DegradedRequest::default()
    };
    let p = browse(&src2, &tax, &tv).await.unwrap();
    assert_eq!(ids(&p)[..3], [60_000, 59_998, 59_996]);
    let DegradedPage::Page { total, .. } = p else {
        panic!("served")
    };
    assert!(total >= 25 * CATEGORY_FACTOR);
}

#[tokio::test]
async fn degraded_pages_continue_from_the_last_displayed_row() {
    let tax = Taxonomy::builtin().unwrap();
    let src = library(100, |id| if id % 3 == 0 { 6000 } else { 5040 });
    let mut req = DegradedRequest {
        exclude_categories: vec![6000],
        limit: 10,
        ..DegradedRequest::default()
    };
    let mut seen = Vec::new();
    loop {
        let p = browse(&src, &tax, &req).await.unwrap();
        let DegradedPage::Page {
            items,
            total,
            next_before,
            budget_exhausted,
        } = p
        else {
            panic!("served")
        };
        assert_eq!(total, 67);
        assert!(!budget_exhausted);
        if let Some(n) = next_before {
            assert_eq!(Some(n), items.last().map(|r| r.id));
        }
        seen.extend(items.iter().map(|r| r.id));
        match next_before {
            Some(b) => req.before = Some(b),
            None => break,
        }
    }
    let want: Vec<i64> = (1..=100).rev().filter(|i| i % 3 != 0).collect();
    assert_eq!(seen, want);
}

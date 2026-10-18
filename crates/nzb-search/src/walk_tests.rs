//! Sorted walk vs collect pass (same rows, order, totals), the planner's choices, and the sidecar
//! lifecycle (review L6 b: validated, rebuilt when invalid, garbage-collected).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::sync::Arc;

use nzb_core::ReleaseFlags;
use nzb_store::{PageCursor, SearchQuery, SeekDir, SortKey};
use proptest::prelude::*;

use crate::clock::{Deadline, SystemClock};
use crate::config::SearchConfig;
use crate::conformance_tests::SORTS;
use crate::doc::IndexDoc;
use crate::engine::{Engine, Payload, WriterSettings};
use crate::index::{EngineResult, PathChoice, engine_search};
use crate::request::SearchRequest;
use crate::testkit::{EPOCH, doc, row_of};

fn far() -> Deadline {
    Deadline::after(Arc::new(SystemClock::new()), 60_000)
}

fn run(
    e: &Engine,
    req: &SearchRequest,
    at: Option<(SeekDir, &PageCursor)>,
    force: Option<PathChoice>,
) -> EngineResult {
    engine_search(e, req, at, &SearchConfig::default(), &far(), force).unwrap()
}

fn both(
    e: &Engine,
    req: &SearchRequest,
    at: Option<(SeekDir, &PageCursor)>,
) -> (EngineResult, EngineResult) {
    let c = run(e, req, at, Some(PathChoice::Collect));
    let w = run(e, req, at, Some(PathChoice::Walk));
    assert!(!c.walked);
    (c, w)
}

#[derive(Debug, Clone)]
struct RawDoc {
    title: String,
    size: u64,
    posted: Option<i64>,
    cat: usize,
    year: Option<u32>,
    family: Option<usize>,
    group: Option<usize>,
    label: bool,
    by: i64,
}

const CATS: [(u32, u32); 5] = [
    (5040, 5000),
    (5030, 5000),
    (2040, 2000),
    (2000, 2000),
    (6000, 6000),
];
const FAMILIES: [&str; 2] = ["tv", "movie"];
const GROUPS: [&str; 3] = ["GRP", "grp", "Other"];

fn raw_doc() -> impl Strategy<Value = RawDoc> {
    (
        "[aAbB][a-c ]{0,3}",
        0u64..4,
        prop::option::of(0i64..5),
        0usize..5,
        prop::option::of(2000u32..2003),
        prop::option::of(0usize..2),
        prop::option::of(0usize..3),
        any::<bool>(),
        0i64..3,
    )
        .prop_map(
            |(title, size, posted, cat, year, family, group, label, by)| RawDoc {
                title,
                size,
                posted,
                cat,
                year,
                family,
                group,
                label,
                by,
            },
        )
}

fn to_doc(i: usize, r: &RawDoc) -> IndexDoc {
    let mut d = doc(i as i64 + 1, &r.title);
    d.total_bytes = r.size * 100;
    d.posted_at = r.posted;
    d.category_id = CATS[r.cat].0;
    d.category_parent = CATS[r.cat].1;
    d.year = r.year;
    d.family = r.family.map(|f| FAMILIES[f].to_owned());
    d.group = r.group.map(|g| GROUPS[g].to_owned());
    d.source_label = r.label.then(|| "Torrent".to_owned());
    d.added_by = Some(r.by);
    d
}

#[derive(Debug, Clone)]
struct RawFilter {
    cats: Vec<u32>,
    exclude: bool,
    range: Option<(i64, i64)>,
    size: Option<(u64, u64)>,
    year: Option<u32>,
    family: Option<usize>,
    group: Option<usize>,
    label: bool,
    by: Option<i64>,
}

fn raw_filter() -> impl Strategy<Value = RawFilter> {
    (
        prop::collection::vec(
            prop::sample::select(vec![5000u32, 5040, 2000, 2040, 6000]),
            0..2,
        ),
        any::<bool>(),
        prop::option::of((0i64..3, 2i64..5)),
        prop::option::of((0u64..200, 100u64..400)),
        prop::option::of(2000u32..2003),
        prop::option::of(0usize..2),
        prop::option::of(0usize..3),
        any::<bool>(),
        prop::option::of(-1i64..3),
    )
        .prop_map(
            |(cats, exclude, range, size, year, family, group, label, by)| RawFilter {
                cats,
                exclude,
                range,
                size,
                year,
                family,
                group,
                label,
                by,
            },
        )
}

fn request(f: &RawFilter, sort: SortKey, limit: u32) -> SearchRequest {
    SearchRequest {
        query: SearchQuery {
            categories: f.cats.clone(),
            exclude_categories: if f.exclude { vec![6000] } else { vec![] },
            since: f.range.map(|r| r.0),
            until: f.range.map(|r| r.1),
            min_bytes: f.size.map(|s| s.0),
            max_bytes: f.size.map(|s| s.1),
            year: f.year,
            family: f.family.map(|x| FAMILIES[x].to_owned()),
            group: f.group.map(|x| GROUPS[x].to_owned()),
            sort,
            limit,
            ..SearchQuery::default()
        },
        source_label: f.label.then(|| "torrent".to_owned()),
        added_by: f.by,
        want_facets: true,
        ..SearchRequest::default()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    /// Walk and collect agree on every page, cursor position, total and facet, across segments with
    /// deleted and replaced documents.
    #[test]
    fn walk_equals_collect(
        raw in prop::collection::vec(raw_doc(), 1..36),
        split in 1usize..4,
        deletes in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
        filter in raw_filter(),
    ) {
        let docs: Vec<IndexDoc> = raw.iter().enumerate().map(|(i, r)| to_doc(i, r)).collect();
        let e = Engine::in_ram(Payload::new(EPOCH)).unwrap();
        for chunk in docs.chunks(docs.len().div_ceil(split)) {
            e.apply(chunk, &[]).unwrap();
            e.commit(&e.payload()).unwrap();
        }
        // Deletes and replacements after the fact (alive bitsets, two copies of one id).
        let mut live: Vec<IndexDoc> = docs.clone();
        let mut gone = Vec::new();
        let mut replaced = Vec::new();
        for (n, ix) in deletes.iter().enumerate() {
            let d = ix.get(&docs).clone();
            if n % 2 == 0 {
                gone.push(d.id);
                live.retain(|x| x.id != d.id);
            } else if live.iter().any(|x| x.id == d.id) {
                let mut r = d.clone();
                r.title = format!("{} again", d.title);
                r.total_bytes += 100;
                live.retain(|x| x.id != d.id);
                live.push(r.clone());
                replaced.push(r);
            }
        }
        e.apply(&replaced, &gone).unwrap();
        e.commit(&e.payload()).unwrap();
        e.warm_sidecars().unwrap();

        for sort in SORTS {
            let req = request(&filter, sort, 4);
            let (c, w) = both(&e, &req, None);
            prop_assert_eq!(&w.ids, &c.ids);
            prop_assert_eq!(w.total, c.total);
            prop_assert_eq!(w.has_more, c.has_more);
            // Every offset page.
            let mut all = Vec::new();
            for off in (0..c.total.max(1)).step_by(4) {
                let mut r = req.clone();
                r.query.offset = off as u32;
                let (c, w) = both(&e, &r, None);
                prop_assert_eq!(&w.ids, &c.ids);
                all.extend(c.ids);
            }
            // Keyset from every live document (matching or not, hidden or not), both directions.
            for d in &live {
                let at = PageCursor::for_row(sort, &row_of(d));
                for dir in [SeekDir::After, SeekDir::Before] {
                    let (c, w) = both(&e, &req, Some((dir, &at)));
                    prop_assert_eq!(&w.ids, &c.ids, "{:?} {:?} {}", sort, dir, d.id);
                    prop_assert_eq!(w.has_more, c.has_more);
                    prop_assert_eq!(w.total, c.total);
                }
            }
            prop_assert_eq!(all.len() as u64, c.total);
        }
    }
}

#[test]
fn planner_walks_broad_listings_and_collects_selective_ones() {
    let mut docs = Vec::new();
    for i in 1..=2000i64 {
        let mut d = doc(
            i,
            if i % 2 == 0 {
                "common even"
            } else {
                "common odd"
            },
        );
        d.category_id = if i % 10 == 0 { 6000 } else { 5040 };
        d.category_parent = if i % 10 == 0 { 6000 } else { 5000 };
        d.year = (i == 77).then_some(2001);
        d.flags = if i % 3 == 0 {
            ReleaseFlags::HAS_PAR2
        } else {
            ReleaseFlags::EMPTY
        };
        docs.push(d);
    }
    let e = Engine::in_ram(Payload::new(EPOCH)).unwrap();
    e.apply(&docs, &[]).unwrap();
    e.commit(&e.payload()).unwrap();
    e.warm_sidecars().unwrap();
    let plan = |q: SearchQuery| {
        run(
            &e,
            &SearchRequest::from(SearchQuery { limit: 50, ..q }),
            None,
            None,
        )
    };
    // Browse, hidden XXX, a big category: walked, totals from the histograms.
    let r = plan(SearchQuery::default());
    assert!(r.walked);
    assert_eq!(r.total, 2000);
    let r = plan(SearchQuery {
        exclude_categories: vec![6000],
        ..SearchQuery::default()
    });
    assert!(r.walked);
    assert_eq!(r.total, 1800);
    assert!(
        plan(SearchQuery {
            categories: vec![5000],
            ..SearchQuery::default()
        })
        .walked
    );
    // Text and flags are posting lists: collect. A rare year: collect.
    assert!(
        !plan(SearchQuery {
            q: Some("common".into()),
            ..SearchQuery::default()
        })
        .walked
    );
    assert!(
        !plan(SearchQuery {
            flags: ReleaseFlags::HAS_PAR2,
            ..SearchQuery::default()
        })
        .walked
    );
    let r = plan(SearchQuery {
        year: Some(2001),
        ..SearchQuery::default()
    });
    assert!(!r.walked);
    assert_eq!(r.ids, [77]);
}

fn disk_engine(dir: &std::path::Path, batches: usize) -> Engine {
    let w = WriterSettings {
        heap_bytes: 32 << 20,
        threads: 1,
    };
    let e = Engine::create(dir, Payload::new(EPOCH), w).unwrap();
    for b in 0..batches {
        let docs: Vec<IndexDoc> = (0..20)
            .map(|i| {
                let id = (b * 20 + i + 1) as i64;
                let mut d = doc(id, &format!("t{}", (id * 7) % 13));
                d.total_bytes = (id % 5) as u64;
                d.posted_at = (id % 4 != 0).then_some(id % 6);
                d
            })
            .collect();
        e.apply(&docs, &[]).unwrap();
        e.commit(&e.payload()).unwrap();
    }
    e.warm_sidecars().unwrap();
    e
}

fn sortperm_files(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.contains(".sortperm"))
        .collect();
    v.sort();
    v
}

fn walk_all(e: &Engine, sort: SortKey) -> Vec<i64> {
    let req = SearchRequest::from(SearchQuery {
        sort,
        limit: 100,
        ..SearchQuery::default()
    });
    run(e, &req, None, Some(PathChoice::Walk)).ids
}

#[test]
fn sec_091_invalid_sidecar_is_rebuilt_not_trusted() {
    let d = tempfile::tempdir().unwrap();
    let want: Vec<Vec<i64>>;
    {
        let e = disk_engine(d.path(), 4);
        want = SORTS.iter().map(|s| walk_all(&e, *s)).collect();
        // One file per segment and family, read back on the next open.
        assert_eq!(sortperm_files(d.path()).len(), 4 * 3);
        // The walk agrees with the collect pass.
        for (s, w) in SORTS.iter().zip(&want) {
            let req = SearchRequest::from(SearchQuery {
                sort: *s,
                limit: 100,
                ..SearchQuery::default()
            });
            assert_eq!(&run(&e, &req, None, Some(PathChoice::Collect)).ids, w);
        }
        e.close().unwrap();
    }
    // Corrupt every sidecar in a different way: wrong length, entry >= max_doc, duplicate entry,
    // wrong order, garbage.
    let files = sortperm_files(d.path());
    for (n, name) in files.iter().enumerate() {
        let p = d.path().join(name);
        let mut b = std::fs::read(&p).unwrap();
        match n % 5 {
            0 => b.truncate(b.len() - 4),
            1 => b[..4].copy_from_slice(&999_999u32.to_le_bytes()),
            2 => {
                let first: [u8; 4] = b[..4].try_into().unwrap();
                b[4..8].copy_from_slice(&first);
            }
            3 => b.swap(0, 4),
            _ => b.iter_mut().for_each(|x| *x = 0xff),
        }
        std::fs::write(&p, b).unwrap();
    }
    let e = Engine::open(
        d.path(),
        WriterSettings {
            heap_bytes: 32 << 20,
            threads: 1,
        },
    )
    .unwrap();
    // The indexer warms before install: corrupt files are discarded and rebuilt there.
    e.warm_sidecars().unwrap();
    // Same results as before (the corrupt files were not used) and valid files on disk again.
    let got: Vec<Vec<i64>> = SORTS.iter().map(|s| walk_all(&e, *s)).collect();
    assert_eq!(got, want);
    // Every corrupt file was replaced by a valid one: 4 x max_doc bytes, a permutation of 0..20.
    for f in &files {
        let b = std::fs::read(d.path().join(f)).unwrap();
        assert_eq!(b.len(), 4 * 20, "{f}");
        let mut ids: Vec<u32> = b
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, (0..20).collect::<Vec<u32>>(), "{f}");
    }
    drop(e);
}

#[test]
fn sidecars_follow_their_segments() {
    let d = tempfile::tempdir().unwrap();
    let e = disk_engine(d.path(), 3);
    let want = walk_all(&e, SortKey::TitleAsc);
    assert_eq!(sortperm_files(d.path()).len(), 3 * 3);
    // Leftovers and foreign files: temporary sidecars and orphans go, other files stay.
    let orphan = "0123456789abcdef0123456789abcdef.size.sortperm";
    let temp = format!(".{}.7.tmp", sortperm_files(d.path())[0]);
    for f in [
        orphan,
        temp.as_str(),
        "notes.txt",
        "0123.size.sortperm",
        "x.sortperm",
    ] {
        std::fs::write(d.path().join(f), b"x").unwrap();
    }
    e.commit(&e.payload()).unwrap();
    let left = sortperm_files(d.path());
    assert!(!left.iter().any(|f| f == orphan || *f == temp), "{left:?}");
    assert!(
        left.iter().any(|f| f == "0123.size.sortperm"),
        "not our pattern: untouched"
    );
    assert!(left.iter().any(|f| f == "x.sortperm"));
    assert!(d.path().join("notes.txt").exists());
    // A merge replaces the three segments by one: their sidecars are deleted at the next commit; a
    // search does not build the new segment's (it collects), the indexer's warm-up does.
    e.merge_all().unwrap();
    let ours = |v: &[String]| v.iter().filter(|f| f.len() > 40).count();
    assert_eq!(ours(&sortperm_files(d.path())), 0);
    assert_eq!(walk_all(&e, SortKey::TitleAsc), want);
    assert_eq!(ours(&sortperm_files(d.path())), 0);
    e.warm_sidecars().unwrap();
    assert_eq!(ours(&sortperm_files(d.path())), 3);
}

#[test]
fn sec_095_sidecar_is_never_built_on_the_request_path() {
    let d = tempfile::tempdir().unwrap();
    let ws = WriterSettings {
        heap_bytes: 32 << 20,
        threads: 1,
    };
    let want: Vec<Vec<i64>>;
    {
        let e = disk_engine(d.path(), 3);
        want = SORTS.iter().map(|s| walk_all(&e, *s)).collect();
        // The merged segment (the largest one after a rebuild) has no sidecar yet.
        e.merge_all().unwrap();
        e.close().unwrap();
    }
    let e = Engine::open(d.path(), ws).unwrap();
    let browse = |sort| {
        SearchRequest::from(SearchQuery {
            sort,
            limit: 10,
            ..SearchQuery::default()
        })
    };
    // Every sort, planner and forced walk alike: the page is served by the collect pass, nothing is
    // built or written.
    for (s, w) in SORTS.iter().zip(&want) {
        for force in [None, Some(PathChoice::Walk)] {
            let r = run(&e, &browse(*s), None, force);
            assert!(!r.walked, "{s:?} {force:?}");
            assert_eq!(&r.ids[..], &w[..10]);
        }
    }
    assert_eq!(e.sidecar_loads(), 0);
    assert_eq!(sortperm_files(d.path()).len(), 0);
    // After the warm-up (indexer, before install) the planner walks again.
    e.warm_sidecars().unwrap();
    assert_eq!(e.sidecar_loads(), 3);
    for (s, w) in SORTS.iter().zip(&want) {
        let r = run(&e, &browse(*s), None, None);
        assert!(r.walked, "{s:?}");
        assert_eq!(&r.ids[..], &w[..10]);
    }
    assert_eq!(e.sidecar_loads(), 3);
}

//! T115 `nzbd import <dir>` (MIGRATION v3 1, SEC-096): copy only, no-follow walk, regular files only, bounded,
//! hostile names as display data, idempotent and resumable by digest. On the backend of the CI leg.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::AtomicBool;

use super::*;
use crate::import::{ImportGuard, ImportLimits, ImportReport, SkipReason, import_dir};

fn limits() -> ImportLimits {
    ImportLimits {
        max_depth: 8,
        max_entries: 10_000,
        max_file_bytes: 64 * 1024,
        max_in_flight: 32,
        include_deleted: false,
    }
}

async fn run(e: &Env, root: &Path, l: ImportLimits) -> ImportReport {
    run_guarded(e, root, l, &ImportGuard::default())
        .await
        .unwrap()
}

async fn run_guarded(
    e: &Env,
    root: &Path,
    l: ImportLimits,
    guard: &ImportGuard,
) -> Result<ImportReport, crate::import::ImportError> {
    let (handle, workers) = e.pipeline.spawn(IngestSettings {
        workers: 4,
        queue_cap: 64,
        ..IngestSettings::default()
    });
    let report = import_dir(
        root,
        l,
        &handle,
        Arc::new(AtomicBool::new(false)),
        guard,
        Duration::from_secs(3600),
        &|_| {},
    )
    .await;
    drop(handle);
    for w in workers {
        w.await.unwrap();
    }
    report
}

/// Every entry below `dir` (symlinks not followed): relative path -> (type, size, mode, inode, links, mtime, bytes).
fn snapshot(dir: &Path) -> BTreeMap<Vec<u8>, String> {
    fn walk(root: &Path, d: &Path, out: &mut BTreeMap<Vec<u8>, String>) {
        for e in fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            let rel = p
                .strip_prefix(root)
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec();
            let content = if m.file_type().is_file() {
                format!("{:?}", sha_of(&fs::read(&p).unwrap()))
            } else if m.file_type().is_symlink() {
                format!("-> {:?}", fs::read_link(&p).unwrap())
            } else {
                String::new()
            };
            out.insert(
                rel,
                format!(
                    "{:?} {} {:o} {} {} {:?} {content}",
                    m.file_type(),
                    m.len(),
                    m.mode(),
                    m.ino(),
                    m.nlink(),
                    m.modified().ok()
                ),
            );
            if m.file_type().is_dir() {
                walk(root, &p, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn mkfifo(path: &Path) {
    let st = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

fn source(e: &Env) -> PathBuf {
    let p = e.tmpdir.path().join("import-src");
    fs::create_dir(&p).unwrap();
    p
}

/// A 2.x data directory's store layout plus a flat collection, hidden 2.x store folders and a non-NZB file: every
/// `.nzb` is copied into the library, the source tree is byte-, inode-, mode- and mtime-identical afterwards, and
/// nothing lands in the watch, failed or duplicates folders.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_copies_and_never_modifies_the_source() {
    let e = env(OPTS).await;
    let src = source(&e);
    let mut expected = Vec::new();
    for i in 0..5 {
        let b = nzb(&format!("{SHOW}.flat{i}"));
        let name = if i == 0 {
            "UPPER.NZB".to_owned()
        } else {
            format!("flat{i}.nzb")
        };
        fs::write(src.join(name), &b).unwrap();
        expected.push(sha_of(&b));
    }
    // 2.x store layout: data/store/aa/bb/<sha256>.nzb (level 2).
    for i in 0..4 {
        let b = nzb(&format!("{SHOW}.store{i}"));
        let hex = sha_of(&b).to_hex();
        let d = src.join("store").join(&hex[..2]).join(&hex[2..4]);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join(format!("{hex}.nzb")), &b).unwrap();
        expected.push(sha_of(&b));
    }
    // Hidden 2.x store folders (deleted releases, temp files) and other files are not imported.
    for hidden in [".trash", ".tmp", ".gc-trash"] {
        let d = src.join("store").join(hidden);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("x.nzb"), nzb(&format!("{SHOW}.{hidden}"))).unwrap();
    }
    fs::write(src.join(".hidden.nzb"), nzb("hidden.mkv")).unwrap();
    fs::write(src.join("notes.txt"), b"not an nzb").unwrap();
    // A second name of one file (a hard-linked backup tree): read only, so it is fine.
    fs::hard_link(src.join("flat1.nzb"), src.join("flat1-link.nzb")).unwrap();
    // A broken NZB fails alone and stays where it is.
    fs::write(src.join("broken.nzb"), b"<nzb>").unwrap();
    let before = snapshot(&src);

    let r = run(&e, &src, limits()).await;
    assert_eq!(
        snapshot(&src),
        before,
        "the source must not change in any way"
    );
    assert_eq!(r.imported, 9, "{r:?}");
    assert_eq!(r.duplicates, 1, "the hard link is the same content");
    assert_eq!(r.failed_total(), 1);
    assert!(r.failed.keys().all(|c| c.starts_with("NZB_")), "{r:?}");
    assert_eq!(r.skipped_total(), 0);
    assert_eq!(
        r.ignored, 5,
        "three hidden folders, one hidden file, one text file"
    );
    assert!(r.has_problems());
    assert_eq!(e.release_count().await, 9);
    for sha in &expected {
        assert!(
            e.db.get_release_by_sha(&sha.to_hex())
                .await
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(e.blobs().len(), 9);
    assert!(names(&e.watch).is_empty());
    assert!(
        names(&e.failed).is_empty(),
        "rejected imports are not moved"
    );
    assert!(names(&e.dups).is_empty());
    // Recorded like a watch-folder file, with the file name as display data (flat2 has no second name, so no race
    // decides which name is recorded).
    let row =
        e.db.get_release_by_sha(&expected[2].to_hex())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.source_name.as_deref(), Some("flat2.nzb"));
    // D39 (T131): an import takes its title from the file name too.
    assert_eq!(row.title, "flat2");
    // Review 38 I1: every log row of an import (ok and failed) says so.
    let log = e.db.list_ingest_log(100).await.unwrap();
    assert_eq!(log.len(), 10, "nine ok rows and the broken file");
    assert!(
        log.iter().all(|l| l.detail.as_deref() == Some("import")),
        "{log:?}"
    );
}

/// No symbolic link is followed (to a file or a directory, inside or outside the root, also a symlinked root) and
/// FIFOs, sockets and oversized files are skipped and reported; the walk never blocks on a FIFO.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_skips_symlinks_and_special_files() {
    let e = env(OPTS).await;
    let src = source(&e);
    let outside = e.tmpdir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.nzb"), nzb("outside.mkv")).unwrap();
    std::os::unix::fs::symlink(outside.join("secret.nzb"), src.join("file-link.nzb")).unwrap();
    std::os::unix::fs::symlink(&outside, src.join("dir-link")).unwrap();
    fs::write(src.join("real.nzb"), nzb("real.mkv")).unwrap();
    std::os::unix::fs::symlink(src.join("real.nzb"), src.join("inner-link.nzb")).unwrap();
    mkfifo(&src.join("fifo.nzb"));
    let _sock = std::os::unix::net::UnixListener::bind(src.join("sock.nzb")).unwrap();
    fs::write(src.join("huge.nzb"), vec![b' '; 64 * 1024 + 1]).unwrap();

    let r = run(&e, &src, limits()).await;
    assert_eq!(r.imported, 1, "{r:?}");
    assert_eq!(r.skipped.get(&SkipReason::Symlink), Some(&3));
    assert_eq!(r.skipped.get(&SkipReason::Special), Some(&2));
    assert_eq!(r.skipped.get(&SkipReason::TooLarge), Some(&1));
    assert!(
        e.db.get_release_by_sha(&sha_of(&nzb("outside.mkv")).to_hex())
            .await
            .unwrap()
            .is_none()
    );
    let codes: Vec<&str> = r.problems.iter().map(|(_, c)| *c).collect();
    assert!(codes.contains(&"SYMLINK_SKIPPED") && codes.contains(&"SPECIAL_FILE_SKIPPED"));

    // A symlinked root and a file as root are refused before anything is read.
    let link_root = e.tmpdir.path().join("root-link");
    std::os::unix::fs::symlink(&src, &link_root).unwrap();
    let (handle, workers) = e.pipeline.spawn(IngestSettings::default());
    for bad in [link_root.as_path(), src.join("real.nzb").as_path()] {
        let err = import_dir(
            bad,
            limits(),
            &handle,
            Arc::new(AtomicBool::new(false)),
            &ImportGuard::default(),
            Duration::from_secs(60),
            &|_| {},
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("IMPORT_DIR_UNUSABLE"));
    }
    drop(handle);
    for w in workers {
        w.await.unwrap();
    }
}

/// Names are display data only: control characters, bidi overrides, newlines, shell syntax, `..` and non-UTF-8
/// bytes in file and directory names reach neither a path nor the terminal unescaped; stored files are named by
/// their SHA-256 only and the stored display name is sanitized.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_hostile_names_are_display_only() {
    let e = env(OPTS).await;
    let src = source(&e);
    let names_raw: Vec<Vec<u8>> = vec![
        b"up..%2f..%2fetc%2fpasswd..nzb".to_vec(),
        b"line\nbreak\r.nzb".to_vec(),
        b"\x1b[31mred\x07.nzb".to_vec(),
        "bidi\u{202e}gpj.nzb".as_bytes().to_vec(),
        b"$(touch pwned);`id`.nzb".to_vec(),
        b"latin1-\xe9\xff.nzb".to_vec(),
        [&b"x"[..]; 251]
            .concat()
            .into_iter()
            .chain(*b".nzb")
            .collect(),
    ];
    let hostile_dir = src.join(std::ffi::OsStr::from_bytes(b"dir\n\x1b..\xfe"));
    fs::create_dir(&hostile_dir).unwrap();
    for (i, n) in names_raw.iter().enumerate() {
        let dir = if i % 2 == 0 { &src } else { &hostile_dir };
        fs::write(
            dir.join(std::ffi::OsStr::from_bytes(n)),
            nzb(&format!("../../{SHOW}.{i}")),
        )
        .unwrap();
    }
    // One broken file inside the hostile directory puts a problem line with a hostile name into the report.
    fs::write(
        hostile_dir.join(std::ffi::OsStr::from_bytes(b"bad\n\x1b.nzb")),
        b"<x/>",
    )
    .unwrap();
    let r = run(&e, &src, limits()).await;
    assert_eq!(r.imported, 7, "{r:?}");
    assert_eq!(r.failed_total(), 1);
    for (line, _) in &r.problems {
        assert!(
            line.chars().all(|c| !c.is_control() && c != '\u{202e}'),
            "{line:?}"
        );
    }
    // Store files are `<sha256>.nzb` only, under the store; nothing was created anywhere else.
    for b in e.blobs() {
        let n = b.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(n.len(), 68, "{n}");
        assert!(n[..64].bytes().all(|c| c.is_ascii_hexdigit()) && &n[64..] == ".nzb");
    }
    assert!(!Path::new("pwned").exists());
    assert!(!e.tmpdir.path().join("etc").exists());
    for row in e.db.list_ingest_log(50).await.unwrap() {
        let n = row.source_name.unwrap_or_default();
        assert!(
            n.chars().all(|c| !c.is_control() && c != '\u{202e}'),
            "{n:?}"
        );
    }
}

/// The walk is bounded: directories below `max_depth` are skipped and reported, and the walk stops after
/// `max_entries` entries; a second run with room imports the rest and nothing twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_limits_depth_and_entries() {
    let e = env(OPTS).await;
    let src = source(&e);
    let mut d = src.clone();
    for level in 0..5 {
        fs::write(
            d.join(format!("l{level}.nzb")),
            nzb(&format!("{SHOW}.deep{level}")),
        )
        .unwrap();
        d = d.join(format!("d{level}"));
        fs::create_dir(&d).unwrap();
    }
    let r = run(
        &e,
        &src,
        ImportLimits {
            max_depth: 2,
            ..limits()
        },
    )
    .await;
    assert_eq!(r.imported, 3, "levels 0..=2 only: {r:?}");
    assert_eq!(r.skipped.get(&SkipReason::TooDeep), Some(&1));

    let flat = e.tmpdir.path().join("flat");
    fs::create_dir(&flat).unwrap();
    for i in 0..10 {
        fs::write(
            flat.join(format!("f{i}.nzb")),
            nzb(&format!("{SHOW}.flat{i}")),
        )
        .unwrap();
    }
    let r = run(
        &e,
        &flat,
        ImportLimits {
            max_entries: 4,
            ..limits()
        },
    )
    .await;
    assert!(r.entry_limit_hit && r.has_problems());
    assert_eq!(r.imported, 4);
    let r = run(&e, &flat, limits()).await;
    assert!(!r.entry_limit_hit);
    assert_eq!((r.imported, r.duplicates), (6, 4));
    assert_eq!(e.release_count().await, 13);
}

/// Idempotent and resumable by digest: a run that died before its commits (every blob durable, nothing committed)
/// left the source as it was; the next run imports everything once, and a further run imports nothing, writes no log
/// row and changes no release.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_is_idempotent_and_resumable() {
    let mut e = env(OPTS).await;
    let src = source(&e);
    for i in 0..20 {
        fs::write(
            src.join(format!("f{i:02}.nzb")),
            nzb(&format!("{SHOW}.r{i}")),
        )
        .unwrap();
    }
    let before = snapshot(&src);
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::BeforeGroupCommit)));
    let r = run(&e, &src, limits()).await;
    assert_eq!(r.imported, 0);
    assert_eq!(r.failed.get("INTERNAL"), Some(&20));
    assert_eq!(e.release_count().await, 0);
    assert_eq!(snapshot(&src), before);

    e.restart(OPTS);
    let r = run(&e, &src, limits()).await;
    assert_eq!((r.imported, r.duplicates, r.failed_total()), (20, 0, 0));
    assert!(!r.has_problems());
    let log = e.db.list_ingest_log(100).await.unwrap().len();
    assert_eq!(log, 20);

    let r = run(&e, &src, limits()).await;
    assert_eq!((r.imported, r.duplicates), (0, 20));
    assert_eq!(e.release_count().await, 20);
    assert_eq!(
        e.db.list_ingest_log(100).await.unwrap().len(),
        log,
        "a re-run logs nothing"
    );
    assert_eq!(snapshot(&src), before);

    // An interrupted run stops early and says so; nothing it did is lost or doubled.
    let (handle, workers) = e.pipeline.spawn(IngestSettings::default());
    let r = import_dir(
        &src,
        limits(),
        &handle,
        Arc::new(AtomicBool::new(true)),
        &ImportGuard::default(),
        Duration::from_secs(60),
        &|_| {},
    )
    .await
    .unwrap();
    assert!(r.interrupted);
    drop(handle);
    for w in workers {
        w.await.unwrap();
    }
    assert_eq!(e.release_count().await, 20);
}

/// Review 38 L1: a re-run never brings back a release that was deleted from the library (its digest is in the trash);
/// it is counted as `trashed`, writes nothing and makes the run report a problem. `--include-deleted` restores it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_does_not_bring_back_deleted_releases() {
    let e = env(OPTS).await;
    let src = source(&e);
    for i in 0..4 {
        fs::write(src.join(format!("f{i}.nzb")), nzb(&format!("{SHOW}.t{i}"))).unwrap();
    }
    let r = run(&e, &src, limits()).await;
    assert_eq!(r.imported, 4);
    let gone = sha_of(&nzb(&format!("{SHOW}.t2")));
    let row =
        e.db.get_release_by_sha(&gone.to_hex())
            .await
            .unwrap()
            .unwrap();
    e.db.trash_release(row.id, 1_700_000_100, "admin", None)
        .await
        .unwrap();
    assert!(e.db.release_is_trashed(&gone).await.unwrap());
    let log = e.db.list_ingest_log(100).await.unwrap().len();

    let r = run(&e, &src, limits()).await;
    assert_eq!((r.imported, r.duplicates, r.trashed), (0, 3, 1), "{r:?}");
    assert!(r.has_problems());
    assert_eq!(r.problems, vec![("\"f2.nzb\"".to_owned(), "TRASHED")]);
    assert!(
        e.db.get_release_by_sha(&gone.to_hex())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        e.db.list_ingest_log(100).await.unwrap().len(),
        log,
        "no row for a skipped file"
    );

    let r = run(
        &e,
        &src,
        ImportLimits {
            include_deleted: true,
            ..limits()
        },
    )
    .await;
    assert_eq!((r.imported, r.trashed), (1, 0));
    assert!(
        e.db.get_release_by_sha(&gone.to_hex())
            .await
            .unwrap()
            .is_some()
    );
}

/// Review 38 L2: overlap with a managed directory is decided on device and inode of the opened root and its
/// ancestors, so a symlink, a `..` spelling, a path through a symlinked ancestor (what a bind mount looks like to a
/// path comparison), a sub-directory and a parent directory are all refused; an unrelated directory is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_096_import_overlap_is_decided_by_identity() {
    let e = env(OPTS).await;
    fs::write(e.watch.join("w.nzb"), nzb("watched.mkv")).unwrap();
    let guard = ImportGuard {
        managed: vec![
            e.watch.clone(),
            e.store_root.clone(),
            e.failed.clone(),
            e.dups.clone(),
            e.staging.clone(),
        ],
        ..ImportGuard::default()
    };
    let top = e.tmpdir.path();
    std::os::unix::fs::symlink(&e.store_root, top.join("store-link")).unwrap();
    std::os::unix::fs::symlink(top, top.join("alias")).unwrap();
    fs::create_dir(e.store_root.join("aa")).unwrap();
    let spelled = e.store_root.join("..").join("watch");
    for bad in [
        e.store_root.clone(),
        spelled,
        top.join("alias").join("tmp"),
        e.store_root.join("aa"),
        top.to_path_buf(),
    ] {
        let err = run_guarded(&e, &bad, limits(), &guard).await.unwrap_err();
        assert!(
            matches!(err, crate::import::ImportError::Overlap),
            "{bad:?}: {err}"
        );
        assert!(crate::import::check_root(&bad, &guard).is_err());
    }
    // A symlinked root is refused as unusable before identity is even asked.
    let err = run_guarded(&e, &top.join("store-link"), limits(), &guard)
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("IMPORT_DIR_UNUSABLE"));
    assert_eq!(e.release_count().await, 0);
    assert!(e.watch.join("w.nzb").exists());
    // A separate directory passes.
    let src = source(&e);
    fs::write(src.join("a.nzb"), nzb("separate.mkv")).unwrap();
    assert!(crate::import::check_root(&src, &guard).is_ok());
    assert_eq!(
        run_guarded(&e, &src, limits(), &guard)
            .await
            .unwrap()
            .imported,
        1
    );
}

/// Review 38 L4 / SEC-092: next to a running server the import waits while the server's lag gate is paused and goes
/// on once the index has caught up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sec_092_import_waits_for_the_index_lag_gate() {
    let e = env(OPTS).await;
    let src = source(&e);
    for i in 0..5 {
        fs::write(src.join(format!("g{i}.nzb")), nzb(&format!("{SHOW}.g{i}"))).unwrap();
    }
    let asked = Arc::new(AtomicU64::new(0));
    let a2 = Arc::clone(&asked);
    // Far behind for the first three asks, then caught up.
    let gate = crate::LagGate::new(
        100,
        Arc::new(move || {
            let n = a2.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Some(if n < 3 { 500 } else { 0 }) })
        }),
    );
    let guard = ImportGuard {
        lag_gate: Some(gate),
        gate_every: Some(Duration::from_millis(20)),
        ..ImportGuard::default()
    };
    let r = run_guarded(&e, &src, limits(), &guard).await.unwrap();
    assert_eq!(r.imported, 5);
    assert_eq!(r.index_waits, 3, "{r:?}");
    assert!(!r.waiting_for_index);
    assert!(asked.load(Ordering::SeqCst) >= 4);
}

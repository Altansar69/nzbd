//! T032 tests: `reason.json`, retry, retention, startup recovery and the SEC-008 crash points of
//! the failure path. A child module of `pipeline_tests` so it reuses its fake-clock harness.

#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::*;
use crate::failure::{self, RetryTarget, apply_retention, is_failed_name, list_failed};
use crate::recovery::{RecoveryConfig, gc_orphans, recover, recover_with};

const BAD: &[u8] = b"<nzb><not closed";
const STAMP: &str = "20231114T221320Z";

fn rcfg(e: &Env) -> RecoveryConfig {
    RecoveryConfig {
        watch_dir: e.watch.clone(),
        failed_dir: e.failed.clone(),
        duplicates_dir: e.dups.clone(),
        tmp_dir: Some(e.staging.clone()),
        recursive: false,
        max_file_bytes: 64 * 1024,
    }
}

/// Pushes `bytes` through the pipeline as a watch file; returns the error code.
async fn fail_one(e: &mut Env, name: &str, bytes: &[u8]) -> String {
    e.put_watch(name, bytes);
    let mut c = e.candidates();
    let c = c.remove(0);
    e.pipeline
        .process(Job::watch(c))
        .await
        .unwrap_err()
        .code()
        .to_owned()
}

fn failed_nzbs(e: &Env) -> Vec<String> {
    names(&e.failed)
        .into_iter()
        .filter(|n| n.ends_with(".nzb"))
        .collect()
}

fn snapshot(e: &Env) -> Vec<Vec<String>> {
    vec![names(&e.watch), names(&e.failed), names(&e.dups)]
}

fn side(e: &Env, name: &str) -> PathBuf {
    e.failed.join(format!("{name}.reason.json"))
}

// ---------------------------------------------------------------- reason.json

#[tokio::test(flavor = "multi_thread")]
async fn reason_json_has_sanitized_fields_0600_and_no_paths() {
    let mut e = env(OPTS).await;
    let hostile = "ev\u{202e}il\n\"x\".nzb";
    let code = fail_one(&mut e, hostile, BAD).await;
    let files = failed_nzbs(&e);
    assert_eq!(files.len(), 1);
    let name = &files[0];
    assert!(is_failed_name(name), "{name}");
    assert_eq!(name, &format!("{STAMP}-{}.nzb", sha_of(BAD).short()));

    let meta = fs::symlink_metadata(side(&e, name)).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let raw = fs::read_to_string(side(&e, name)).unwrap();
    // No filesystem paths of this installation, no hostile characters.
    assert!(!raw.contains(e.tmpdir.path().to_str().unwrap()));
    assert!(!raw.contains('\u{202e}'));
    let r = failure::read_reason(&e.failed, name).unwrap();
    assert_eq!(r.error_code, code);
    assert_eq!(r.source, "watch");
    assert_eq!(r.sha256.as_deref(), Some(sha_of(BAD).to_hex().as_str()));
    assert_eq!(r.size, u64::try_from(BAD.len()).unwrap());
    assert_eq!(r.at, T0);
    assert_eq!(r.retry_count, 0);
    let sn = r.source_name.unwrap();
    assert!(!sn.contains('\n') && !sn.contains('\u{202e}'));
    assert!(r.message.len() <= 200);
    // ingest_log has the matching row.
    let log = e.db.list_ingest_log(10).await.unwrap();
    assert_eq!(log[0].error_code.as_deref(), Some(code.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_upload_gets_up_marker_and_reason_with_its_source() {
    let e = env(OPTS).await;
    let staged = e.staging.join("s1");
    fs::write(&staged, BAD).unwrap();
    let _ = e
        .pipeline
        .process(Job::upload(
            nzb_store::LogSource::UploadUi,
            Payload::Staged(staged),
        ))
        .await
        .unwrap_err();
    let files = failed_nzbs(&e);
    assert_eq!(files.len(), 1);
    assert!(files[0].contains("-up"), "{}", files[0]);
    assert!(is_failed_name(&files[0]));
    let r = failure::read_reason(&e.failed, &files[0]).unwrap();
    assert_eq!(r.source, "upload_ui");
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_rotation_removes_the_sidecar_of_the_rotated_file_only() {
    let e = env(OPTS).await;
    for i in 0..3u8 {
        e.wall.0.fetch_add(1, Ordering::SeqCst);
        let staged = e.staging.join(format!("s{i}"));
        fs::write(&staged, [b'x', i]).unwrap();
        let _ = e
            .pipeline
            .process(Job::upload(
                nzb_store::LogSource::UploadApi,
                Payload::Staged(staged),
            ))
            .await;
    }
    assert_eq!(failed_nzbs(&e).len(), 3);
    // A watch-origin failure and its sidecar must survive rotation.
    let keep = format!("{STAMP}-aaaaaaaa.nzb");
    fs::write(e.failed.join(&keep), b"w").unwrap();
    let removed = crate::fsops::rotate_upload_rejects(&e.failed, 1, 0);
    assert_eq!(removed, 2);
    let left = names(&e.failed);
    assert!(left.contains(&keep));
    let nzbs = failed_nzbs(&e);
    assert_eq!(nzbs.len(), 2); // 1 kept upload + the watch file
    for n in names(&e.failed) {
        if let Some(f) = n.strip_suffix(".reason.json") {
            assert!(nzbs.iter().any(|x| x == f), "orphan sidecar {n}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_count_counts_earlier_failures_of_the_same_content() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    let n1 = failed_nzbs(&e).remove(0);
    assert_eq!(failure::read_reason(&e.failed, &n1).unwrap().retry_count, 0);
    failure::retry(&e.failed, &e.watch, &RetryTarget::Name(n1)).unwrap();
    e.wall.0.fetch_add(10, Ordering::SeqCst);
    let mut c = e.candidates();
    let _ = e
        .pipeline
        .process(Job::watch(c.remove(0)))
        .await
        .unwrap_err();
    let n2 = failed_nzbs(&e).remove(0);
    assert_eq!(failure::read_reason(&e.failed, &n2).unwrap().retry_count, 1);
}

// ---------------------------------------------------- SEC-008: failure crash points

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_after_move_before_reason_keeps_the_file_and_never_retention_deletes_it() {
    let mut e = env(OPTS).await;
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::AfterQuarantineMove)));
    fail_one(&mut e, "a.nzb", BAD).await;
    assert_eq!(failed_nzbs(&e).len(), 1);
    assert_eq!(names(&e.failed).len(), 1, "no sidecar yet");
    assert!(names(&e.watch).is_empty());

    e.restart(OPTS);
    let rep = recover(&rcfg(&e), &e.db, &e.store, T0 + 365 * 86_400).await;
    assert_eq!(rep.failed_without_reason, 1);
    let ret = apply_retention(&e.failed, 1, T0 + 365 * 86_400);
    assert_eq!(
        (ret.expired, ret.skipped),
        (0, 1),
        "unmanaged file must survive"
    );
    assert_eq!(failed_nzbs(&e).len(), 1);
    // Still listed and retryable, with an unknown reason.
    let l = list_failed(&e.failed).unwrap();
    assert!(l[0].reason.is_none());
    let r = failure::retry(&e.failed, &e.watch, &RetryTarget::All).unwrap();
    assert_eq!(r.moved.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_with_reason_tmp_written_is_cleaned_and_file_kept() {
    let mut e = env(OPTS).await;
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::ReasonTmpWritten)));
    fail_one(&mut e, "a.nzb", BAD).await;
    let hidden: Vec<_> = names(&e.failed)
        .into_iter()
        .filter(|n| n.starts_with('.') && n.ends_with(".part"))
        .collect();
    assert_eq!(hidden.len(), 1);
    assert_eq!(failed_nzbs(&e).len(), 1);

    e.restart(OPTS); // Pipeline::new removes stale .part files
    assert_eq!(names(&e.failed).len(), 1);
    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep.failed_without_reason, 1);
    assert_eq!(failed_nzbs(&e).len(), 1);
}

/// T085-L3: a sidecar swapped for a FIFO must neither block nor be followed. The read runs on
/// a helper thread with a deadline so a regression fails instead of hanging the suite.
#[tokio::test(flavor = "multi_thread")]
async fn sec032_a_fifo_sidecar_is_refused_without_blocking() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    let n = failed_nzbs(&e).remove(0);
    assert!(failure::read_reason(&e.failed, &n).is_some());
    let sc = side(&e, &n);
    std::fs::remove_file(&sc).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&sc)
            .status()
            .unwrap()
            .success()
    );
    let (dir, name) = (e.failed.clone(), n.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = failure::read_reason(&dir, &name);
        let l = list_failed(&dir).map(|v| v.len());
        let _ = tx.send((r.is_none(), l.ok()));
    });
    let (refused, listed) = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("read_reason blocked on a FIFO sidecar");
    assert!(refused);
    assert_eq!(listed, Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_after_reason_is_a_complete_state() {
    let mut e = env(OPTS).await;
    e.pipeline
        .set_hook(Some(Arc::new(|p| p == CrashPoint::AfterReason)));
    fail_one(&mut e, "a.nzb", BAD).await;
    let n = failed_nzbs(&e).remove(0);
    assert!(failure::read_reason(&e.failed, &n).is_some());
    let before = snapshot(&e);
    e.restart(OPTS);
    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep, RecoveryReport::default());
    assert_eq!(snapshot(&e), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_after_ingest_log_before_move_reprocesses_the_source() {
    // The log row is written before the move; a kill in between leaves the file in watch
    // (it is simply failed again) and never loses it.
    let mut e = env(OPTS).await;
    let src = e.put_watch("a.nzb", BAD);
    let mut c = e.candidates();
    let c = c.remove(0);
    // Simulate: log row exists, source not moved.
    e.db.log_ingest(
        &nzb_store::IngestLogEntry {
            ts: T0,
            source: nzb_store::LogSource::Watch,
            api_key_id: None,
            source_name: Some("a.nzb"),
            sha256: Some(sha_of(BAD)),
            outcome: LogOutcome::Failed,
            error_code: Some("NZB_MALFORMED"),
            detail: None,
        },
        None,
    )
    .await
    .unwrap();
    drop(c);
    e.restart(OPTS);
    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep, RecoveryReport::default());
    assert!(src.exists());
    let mut c = e.candidates();
    let _ = e
        .pipeline
        .process(Job::watch(c.remove(0)))
        .await
        .unwrap_err();
    let n = failed_nzbs(&e).remove(0);
    // The earlier log row counts as one previous failure.
    assert_eq!(failure::read_reason(&e.failed, &n).unwrap().retry_count, 1);
}

// ------------------------------------------------------------------------- retry

#[tokio::test(flavor = "multi_thread")]
async fn retry_moves_back_to_watch_with_a_collision_free_name_and_drops_the_sidecar() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    let n = failed_nzbs(&e).remove(0);
    // A file already squatting on the first candidate name must not be clobbered.
    let stem = n.strip_suffix(".nzb").unwrap();
    let squat = e.watch.join(format!("retry-{stem}.nzb"));
    fs::write(&squat, b"squatter").unwrap();
    let rep = failure::retry(&e.failed, &e.watch, &RetryTarget::Name(n.clone())).unwrap();
    assert_eq!(rep.moved.len(), 1);
    assert_eq!(fs::read(&squat).unwrap(), b"squatter");
    assert_eq!(rep.moved[0].1, format!("retry-{stem}-1.nzb"));
    assert_eq!(fs::read(e.watch.join(&rep.moved[0].1)).unwrap(), BAD);
    assert!(names(&e.failed).is_empty(), "file and sidecar gone");
    // Not found afterwards.
    let err = failure::retry(&e.failed, &e.watch, &RetryTarget::Name(n)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_all_moves_everything_and_ignores_foreign_names() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    fail_one(&mut e, "b.nzb", b"<nzb><also bad").await;
    fs::write(e.failed.join("notes.txt"), b"mine").unwrap();
    fs::write(e.failed.join("random.nzb"), b"mine too").unwrap();
    let rep = failure::retry(&e.failed, &e.watch, &RetryTarget::All).unwrap();
    assert_eq!(rep.moved.len(), 2);
    assert!(rep.errors.is_empty());
    assert_eq!(names(&e.failed), vec!["notes.txt", "random.nzb"]);
    assert_eq!(names(&e.watch).len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_rejects_hostile_names_and_never_follows_symlinks() {
    let e = env(OPTS).await;
    let outside = e.tmpdir.path().join("outside.txt");
    fs::write(&outside, b"precious").unwrap();
    for bad in [
        "../outside.txt",
        "..",
        ".",
        "",
        "/etc/passwd",
        &outside.to_string_lossy(),
        "a\0b.nzb",
        "20231114T221320Z-abcdef12.nzb/../../outside.txt",
        "20231114T221320Z-ABCDEF12.nzb",
        "20231114T221320Z-abcdef12.nzb ",
        "20231114T221320Z-abcdef12-up-.nzb",
        "20231114T221320Z-abcdef12-0.nzb",
        "20231114T221320Z-abcdef12.NZB",
        "20231114T221320Z-abcdef12.nzb.reason.json",
        "retry-x.nzb",
    ] {
        let err =
            failure::retry(&e.failed, &e.watch, &RetryTarget::Name(bad.to_owned())).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{bad:?}");
    }
    // A symlink with a perfectly valid name is not listed and cannot be retried.
    let link = format!("{STAMP}-abcdef12.nzb");
    std::os::unix::fs::symlink(&outside, e.failed.join(&link)).unwrap();
    assert!(list_failed(&e.failed).unwrap().is_empty());
    let err = failure::retry(&e.failed, &e.watch, &RetryTarget::Name(link.clone())).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    let rep = failure::retry(&e.failed, &e.watch, &RetryTarget::All).unwrap();
    assert!(rep.moved.is_empty());
    assert_eq!(fs::read(&outside).unwrap(), b"precious");
    assert!(names(&e.watch).is_empty());
    assert!(fs::symlink_metadata(e.failed.join(&link)).is_ok());
}

#[test]
fn failed_name_pattern_table() {
    for ok in [
        "20231114T221320Z-abcdef12.nzb",
        "20231114T221320Z-abcdef12-up.nzb",
        "20231114T221320Z-abcdef12-3.nzb",
        "20231114T221320Z-abcdef12-up-12.nzb",
        "20231114T221320Z-unknown.nzb",
    ] {
        assert!(is_failed_name(ok), "{ok}");
    }
    for bad in [
        "",
        ".nzb",
        "20231114T221320Z-abcdef1.nzb",
        "20231114T221320Z-abcdef123.nzb",
        "20231114T221320Z-abcdef12-up-0.nzb",
        "20231114T221320Z-abcdef12-12345.nzb",
        "20231114T221320Z-abcdef12-x.nzb",
        "2023111TT221320Z-abcdef12.nzb",
        "20231114T221320-abcdef12.nzb",
        "20231114T221320Z-abcdeg12.nzb",
        "20231114T221320Z-abcdef12.nzb\n",
    ] {
        assert!(!is_failed_name(bad), "{bad:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_during_retry_after_move_leaves_orphan_sidecar_that_recovery_removes() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    let n = failed_nzbs(&e).remove(0);
    let err = failure::retry_with(&e.failed, &e.watch, &RetryTarget::Name(n.clone()), &|p| {
        p == CrashPoint::RetryAfterMove
    })
    .unwrap_err();
    assert_eq!(err.to_string(), "injected crash");
    assert_eq!(names(&e.watch).len(), 1, "file is in watch");
    assert!(side(&e, &n).exists(), "stale sidecar");
    assert!(!e.failed.join(&n).exists());

    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep.orphan_sidecars_removed, 1);
    assert!(names(&e.failed).is_empty());
    assert_eq!(names(&e.watch).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_crash_during_retry_between_link_and_unlink_is_healed() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    let n = failed_nzbs(&e).remove(0);
    // State after the hard link but before the unlink of the failed name.
    fs::hard_link(e.failed.join(&n), e.watch.join(format!("retry-{n}"))).unwrap();
    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep.split_links_healed, 1);
    assert_eq!(rep.orphan_sidecars_removed, 1);
    assert!(names(&e.failed).is_empty());
    let w = names(&e.watch);
    assert_eq!(w.len(), 1);
    assert_eq!(fs::read(e.watch.join(&w[0])).unwrap(), BAD);
    assert_eq!(fs::metadata(e.watch.join(&w[0])).unwrap().nlink(), 1);
}

// --------------------------------------------------------------------- retention

fn plant_failed(e: &Env, name: &str, bytes: &[u8], at: i64) {
    fs::write(e.failed.join(name), bytes).unwrap();
    let r = failure::Reason::new(
        "NZB_MALFORMED",
        "m",
        "watch",
        None,
        Some(sha_of(bytes).to_hex()),
        u64::try_from(bytes.len()).unwrap(),
        at,
        0,
    );
    failure::write_reason(&e.failed, name, &r, &failure::no_faults).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_only_removes_old_nzbd_written_failed_files() {
    let e = env(OPTS).await;
    let day = 86_400;
    let old = format!("{STAMP}-aaaaaaaa.nzb");
    let fresh = format!("{STAMP}-bbbbbbbb.nzb");
    let tampered = format!("{STAMP}-cccccccc.nzb");
    let foreign = format!("{STAMP}-dddddddd.nzb");
    let forged = format!("{STAMP}-eeeeeeee.nzb");
    plant_failed(&e, &old, b"old", T0 - 40 * day);
    plant_failed(&e, &fresh, b"fresh", T0 - day);
    plant_failed(&e, &tampered, b"orig", T0 - 40 * day);
    fs::write(e.failed.join(&tampered), b"edit").unwrap(); // user replaced the content
    fs::write(e.failed.join(&foreign), b"foreign").unwrap(); // no sidecar
    fs::write(e.failed.join("notes.txt"), b"n").unwrap();
    // A sidecar copied from another file does not authorize deleting this one.
    fs::write(e.failed.join(&forged), b"forged").unwrap();
    fs::copy(side(&e, &old), side(&e, &forged)).unwrap();
    // Old files elsewhere are never touched.
    let in_watch = e.put_watch("old.nzb", b"w");
    let in_dups = e.dups.join(format!("{STAMP}-ffffffff.nzb"));
    fs::write(&in_dups, b"d").unwrap();

    assert_eq!(apply_retention(&e.failed, 0, T0).expired, 0, "0 = forever");
    let rep = apply_retention(&e.failed, 30, T0);
    assert_eq!(rep.expired, 1);
    // Moved, not deleted: file and sidecar sit in failed/expired/, out of `list`/`retry`.
    assert!(!e.failed.join(&old).exists());
    assert!(!side(&e, &old).exists());
    let x = e.failed.join(failure::EXPIRED_DIR);
    assert_eq!(fs::read(x.join(&old)).unwrap(), b"old");
    assert!(x.join(format!("{old}.reason.json")).exists());
    assert!(
        list_failed(&e.failed)
            .unwrap()
            .iter()
            .all(|f| f.name != old)
    );
    // Much later only the still-valid `fresh` file is eligible; `old` in expired/ is never
    // touched again, nor are the tampered/forged/foreign ones.
    assert_eq!(apply_retention(&e.failed, 30, T0 + 999 * day).expired, 1);
    assert!(x.join(&old).exists() && x.join(&fresh).exists());
    assert_eq!(fs::read(e.failed.join(&tampered)).unwrap(), b"edit");
    for keep in [&tampered, &foreign, &forged] {
        assert!(e.failed.join(keep).exists(), "{keep}");
    }
    assert!(e.failed.join("notes.txt").exists());
    assert!(in_watch.exists() && in_dups.exists());
}

// ---------------------------------------------------------------------- recovery

async fn ingest(e: &mut Env, name: &str, bytes: &[u8]) -> Sha256 {
    e.put_watch(name, bytes);
    let mut c = e.candidates();
    e.pipeline
        .process(Job::watch(c.remove(0)))
        .await
        .unwrap()
        .sha256
}

fn trash(e: &Env, tag: &str, bytes: &[u8]) -> PathBuf {
    let p = e.watch.join(format!(".nzbd-trash.{tag}"));
    fs::write(&p, bytes).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_moves_indexed_trash_to_duplicates_and_restores_unindexed_trash() {
    let mut e = env(OPTS).await;
    let good = nzb(SHOW);
    ingest(&mut e, "a.nzb", &good).await;
    let t_indexed = trash(&e, "1", &good);
    let other = nzb("other.bin");
    let t_new = trash(&e, "2", &other);
    let shared = trash(&e, "3", b"shared");
    fs::hard_link(&shared, e.failed.join(format!("{STAMP}-99999999.nzb"))).unwrap();

    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep.trash_to_duplicates, 1);
    assert_eq!(rep.trash_restored, 1);
    assert_eq!(rep.trash_unlinked, 1);
    assert_eq!(rep.errors, 0);
    assert!(!t_indexed.exists() && !t_new.exists() && !shared.exists());
    // Indexed content is kept (moved, not deleted); the blob is intact.
    let d = names(&e.dups);
    assert_eq!(d.len(), 1);
    assert_eq!(fs::read(e.dups.join(&d[0])).unwrap(), good);
    assert!(e.store.exists(&sha_of(&good)).await.unwrap());
    // Unindexed content is back in watch under a visible name and gets ingested normally.
    let w = names(&e.watch);
    assert_eq!(w.len(), 1);
    assert!(w[0].starts_with("restored-"), "{w:?}");
    assert_eq!(fs::read(e.watch.join(&w[0])).unwrap(), other);
    // The shared inode kept its other name.
    assert_eq!(
        fs::read(e.failed.join(format!("{STAMP}-99999999.nzb"))).unwrap(),
        b"shared"
    );
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Ingested);

    // Idempotent.
    let again = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    // Only the informational count of the sidecar-less foreign file remains.
    assert_eq!(
        again,
        RecoveryReport {
            failed_without_reason: 1,
            ..RecoveryReport::default()
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_heals_missing_blob_report_orphans_and_cleans_staging() {
    let mut e = env(OPTS).await;
    let good = nzb(SHOW);
    let sha = ingest(&mut e, "a.nzb", &good).await;
    // Blob lost (disk problem): reported, row untouched.
    let blob = e.blobs().remove(0);
    fs::remove_file(&blob).unwrap();
    // An orphan blob (crash after put).
    let orphan = nzb("orphan.bin");
    e.store.put(sha_of(&orphan), &orphan).await.unwrap();
    // Staging leftovers and a stale part file.
    let staged = e.staging.join(crate::recovery::staging_name());
    fs::write(&staged, b"x").unwrap();
    fs::write(e.staging.join("foreign.nzb"), b"mine").unwrap();
    fs::create_dir(e.staging.join("subdir")).unwrap();
    fs::write(
        e.failed
            .join(format!(".{STAMP}-aaaaaaaa.nzb.reason.1-2-3.part")),
        b"x",
    )
    .unwrap();
    fs::write(e.failed.join(".my-notes.part"), b"mine").unwrap();

    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep.missing_total, 1);
    assert_eq!(rep.missing_blobs, vec![sha]);
    assert_eq!(rep.tmp_removed, 1);
    assert_eq!(rep.stale_parts_removed, 1);
    assert!(!staged.exists());
    assert!(e.staging.join("foreign.nzb").exists(), "foreign files stay");
    assert!(
        e.failed.join(".my-notes.part").exists(),
        "foreign parts stay"
    );
    assert!(e.staging.join("subdir").is_dir());
    // Orphan is only reported (and only after the grace, which has not elapsed on the fake
    // clock vs the real mtime), never removed at startup.
    assert!(e.store.exists(&sha_of(&orphan)).await.unwrap());
    assert_eq!(e.release_count().await, 1);

    // A duplicate of the lost release heals the blob (T031) and recovery then reports clean.
    e.put_watch("again.nzb", &good);
    let mut c = e.candidates();
    let out = e.pipeline.process(Job::watch(c.remove(0))).await.unwrap();
    assert_eq!(out.kind, OutcomeKind::Duplicate);
    let rep = recover(&rcfg(&e), &e.db, &e.store, T0).await;
    assert_eq!(rep.missing_total, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn gc_orphans_respects_grace_dry_run_and_references() {
    let mut e = env(OPTS).await;
    let good = nzb(SHOW);
    ingest(&mut e, "a.nzb", &good).await;
    let orphan = nzb("orphan.bin");
    e.store.put(sha_of(&orphan), &orphan).await.unwrap();
    let real_now = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    // Inside the grace period: nothing is reclaimable.
    let r = gc_orphans(&e.db, &e.store, real_now, 3600, false)
        .await
        .unwrap();
    assert!(r.removed.is_empty());
    assert_eq!(r.too_new, 1);
    // Past it: a dry run reports, a real run removes; the referenced blob stays.
    let later = real_now + 10 * 86_400;
    let r = gc_orphans(&e.db, &e.store, later, 3600, true)
        .await
        .unwrap();
    assert_eq!(r.removed.len(), 1);
    assert!(e.store.exists(&sha_of(&orphan)).await.unwrap());
    let r = gc_orphans(&e.db, &e.store, later, 3600, false)
        .await
        .unwrap();
    assert_eq!(r.removed, vec![sha_of(&orphan)]);
    assert!(!e.store.exists(&sha_of(&orphan)).await.unwrap());
    assert!(e.store.exists(&sha_of(&good)).await.unwrap());
}

/// A messy post-crash state exercising every recovery phase.
async fn messy() -> Env {
    let mut e = env(OPTS).await;
    let good = nzb(SHOW);
    ingest(&mut e, "a.nzb", &good).await;
    trash(&e, "1", &good);
    trash(&e, "2", &nzb("other.bin"));
    fs::write(e.staging.join("up"), b"x").unwrap();
    fs::write(e.failed.join(format!(".{STAMP}-aaaaaaaa.1-2-3.part")), b"x").unwrap();
    plant_failed(
        &e,
        &format!("{STAMP}-aaaaaaaa.nzb"),
        b"old",
        T0 - 90 * 86_400,
    );
    // orphan sidecar: file gone
    plant_failed(&e, &format!("{STAMP}-bbbbbbbb.nzb"), b"gone", T0);
    fs::remove_file(e.failed.join(format!("{STAMP}-bbbbbbbb.nzb"))).unwrap();
    // interrupted retry (both names of one inode)
    let n = format!("{STAMP}-cccccccc.nzb");
    plant_failed(&e, &n, b"both", T0);
    fs::hard_link(e.failed.join(&n), e.watch.join(format!("retry-{n}"))).unwrap();
    e
}

#[tokio::test(flavor = "multi_thread")]
async fn sec008_kill_recovery_after_every_phase_converges_to_the_same_state() {
    let reference = messy().await;
    recover(&rcfg(&reference), &reference.db, &reference.store, T0).await;
    let _ = apply_retention(&reference.failed, 30, T0);
    let want = snapshot(&reference);
    // retention expired the 90-day-old file, trash was resolved, links healed.
    assert!(!want[1].contains(&format!("{STAMP}-aaaaaaaa.nzb")));

    for phase in 0..=4u8 {
        let e = messy().await;
        let cfg = rcfg(&e);
        let partial = recover_with(&cfg, &e.db, &e.store, T0, &|p| {
            p == CrashPoint::RecoveryPhase(phase)
        })
        .await;
        drop(partial);
        // "Restart": a fresh recovery completes the job from whatever state was left.
        recover(&cfg, &e.db, &e.store, T0).await;
        let _ = apply_retention(&e.failed, 30, T0);
        assert_eq!(snapshot(&e), want, "crash after phase {phase}");
        // No user content was lost: both fixtures' bytes still exist somewhere.
        let all: Vec<Vec<u8>> = [&e.watch, &e.failed, &e.dups]
            .iter()
            .flat_map(|d| {
                names(d)
                    .into_iter()
                    .filter_map(|n| fs::read(d.join(n)).ok())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(all.iter().any(|b| b == b"both"));
        assert!(all.iter().any(|b| *b == nzb("other.bin")));
        assert_eq!(recover(&cfg, &e.db, &e.store, T0).await.errors, 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_is_idempotent_on_the_messy_state() {
    let e = messy().await;
    let cfg = rcfg(&e);
    let first = recover(&cfg, &e.db, &e.store, T0).await;
    assert!(first.trash_restored + first.trash_to_duplicates >= 2);
    let snap = snapshot(&e);
    let second = recover(&cfg, &e.db, &e.store, T0).await;
    assert_eq!(second, RecoveryReport::default());
    assert_eq!(snapshot(&e), snap);
}

// ------------------------------------------- T032 review fixes (M1, M2, L4, L6)

fn real_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn m1_staging_cleanup_never_touches_other_files_even_if_tmp_is_a_data_dir() {
    let mut e = env(OPTS).await;
    fail_one(&mut e, "a.nzb", BAD).await;
    let before = names(&e.failed);
    // Misconfiguration: staging dir == failed/. Config::validate refuses it, and recovery is
    // harmless anyway because only generated `nzbd-upload-*` names are removed.
    let mut cfg = rcfg(&e);
    cfg.tmp_dir = Some(e.failed.clone());
    let rep = recover(&cfg, &e.db, &e.store, T0).await;
    assert_eq!(rep.tmp_removed, 0);
    assert_eq!(names(&e.failed), before);
    // Symlinked staging dir pointing at the failed dir: same.
    let link = e.tmpdir.path().join("tmp-link");
    std::os::unix::fs::symlink(&e.failed, &link).unwrap();
    cfg.tmp_dir = Some(link);
    assert_eq!(recover(&cfg, &e.db, &e.store, T0).await.tmp_removed, 0);
    assert_eq!(names(&e.failed), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn m2_gc_plan_flags_a_restored_database_and_clean_plans_pass() {
    let mut e = env(OPTS).await;
    // One release whose row is stamped by the fake clock (2023).
    ingest(&mut e, "a.nzb", &nzb(SHOW)).await;
    let orphan = nzb("orphan.bin");
    e.store.put(sha_of(&orphan), &orphan).await.unwrap(); // mtime: real now
    let later = real_now() + 30 * 86_400;
    // The blob is newer than the newest row: the signature of a database restored from a
    // backup taken before the blob was ingested.
    let plan = crate::recovery::gc_plan(&e.db, &e.store, later, 3600)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.suspicious.len(), 1);
    assert!(plan.suspicious[0].1.contains("newest release row"));
    assert_eq!(plan.newest_row, Some(T0));

    // The blob is not a candidate inside the grace period.
    let inside = crate::recovery::gc_plan(&e.db, &e.store, real_now(), 3600)
        .await
        .unwrap();
    assert!(inside.candidates.is_empty());

    // A release row newer than the blob (database up to date) makes the plan clean.
    e.wall.0.store(real_now() + 20 * 86_400, Ordering::SeqCst);
    ingest(&mut e, "b.nzb", &nzb("other.bin")).await;
    let plan = crate::recovery::gc_plan(&e.db, &e.store, later, 3600)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    assert!(plan.suspicious.is_empty(), "{:?}", plan.suspicious);

    // A blob restored with its old mtime (cp -p / rsync -a): ctime is much newer.
    let (sha, bytes) = (sha_of(b"restored"), b"restored".to_vec());
    e.store.put(sha, &bytes).await.unwrap();
    let path = e
        .blobs()
        .into_iter()
        .find(|p| p.to_string_lossy().contains(&sha.to_hex()))
        .unwrap();
    let f = fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_hours(5 * 24))
        .unwrap();
    drop(f);
    let plan = crate::recovery::gc_plan(&e.db, &e.store, later, 3600)
        .await
        .unwrap();
    let why: Vec<_> = plan.suspicious.iter().filter(|(s, _)| *s == sha).collect();
    assert_eq!(why.len(), 1);
    assert!(why[0].1.contains("restored"));
}

#[tokio::test(flavor = "multi_thread")]
async fn l4_retention_hash_refuses_fifos_and_symlinks_without_blocking() {
    let e = env(OPTS).await;
    let fifo = e.failed.join(format!("{STAMP}-aaaaaaaa.nzb"));
    let st = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(st.success());
    assert!(failure::hash_regular(&fifo, &e.failed).is_none());
    let target = e.tmpdir.path().join("outside");
    fs::write(&target, b"x").unwrap();
    let link = e.failed.join(format!("{STAMP}-bbbbbbbb.nzb"));
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(failure::hash_regular(&link, &e.failed).is_none());
    // A hard-linked file is refused too (nlink > 1: not the only name).
    let one = e.failed.join(format!("{STAMP}-cccccccc.nzb"));
    fs::write(&one, b"x").unwrap();
    assert!(failure::hash_regular(&one, &e.failed).is_some());
    fs::hard_link(&one, e.watch.join("alias.nzb")).unwrap();
    assert!(failure::hash_regular(&one, &e.failed).is_none());
    // And retention over such a directory neither hangs nor touches anything.
    let rep = apply_retention(&e.failed, 1, T0 + 999 * 86_400);
    assert_eq!(rep.expired, 0);
    assert_eq!(fs::read(&target).unwrap(), b"x");
}

#[tokio::test(flavor = "multi_thread")]
async fn l6_trash_handling_is_capped_per_start_and_finishes_next_start() {
    let e = env(OPTS).await;
    let anchor = e.failed.join(format!("{STAMP}-aaaaaaaa.nzb"));
    fs::write(&anchor, b"anchor").unwrap();
    let extra = 3usize;
    for i in 0..crate::recovery::MAX_TRASH_PER_START + extra {
        fs::hard_link(&anchor, e.watch.join(format!(".nzbd-trash.t{i}"))).unwrap();
    }
    let cfg = rcfg(&e);
    let first = recover(&cfg, &e.db, &e.store, T0).await;
    assert_eq!(first.trash_unlinked, crate::recovery::MAX_TRASH_PER_START);
    assert_eq!(names(&e.watch).len(), extra);
    let second = recover(&cfg, &e.db, &e.store, T0).await;
    assert_eq!(second.trash_unlinked, extra);
    assert!(names(&e.watch).is_empty());
    assert_eq!(fs::read(&anchor).unwrap(), b"anchor");
}

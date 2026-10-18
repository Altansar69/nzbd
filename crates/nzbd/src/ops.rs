//! Operator CLI for failure handling and the blob store (T032):
//! `nzbd failed list|retry` and `nzbd store verify|gc`.
//!
//! Exit codes: 0 = ok / nothing wrong, 1 = error (bad input, I/O, refused), 2 = the check ran
//! and found problems (`store verify`; `failed retry` with partial failures). Everything
//! printed that originates from files is Debug-escaped, so a hostile name cannot inject
//! terminal control sequences.

use nzb_store::prelude::*;
use std::fmt::Write as _;
use std::process::ExitCode;

use clap::Subcommand;
use nzb_ingest::{FailedEntry, RetryTarget};

use crate::config::Config;

/// Shown names/codes are capped so a corrupted sidecar cannot flood the terminal.
const MAX_SHOWN: usize = 120;
/// Missing/corrupt digests printed individually.
const MAX_LISTED: usize = 50;

/// `nzbd failed ...`
#[derive(Subcommand)]
pub enum FailedAction {
    /// List quarantined files: name, error code, time, size.
    List,
    /// Move quarantined file(s) back into the watch folder to be ingested again.
    ///
    /// NAME must be a name shown by `failed list`; it is only compared against the directory
    /// listing, never used as a path.
    Retry {
        /// Exact name from `failed list`.
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        name: Option<String>,
        /// Retry every listed file.
        #[arg(long)]
        all: bool,
    },
}

/// `nzbd store ...`
#[derive(Subcommand)]
pub enum StoreAction {
    /// Check the blob store against the database. `--quick` only checks that every release
    /// has its blob; the full check also re-hashes every blob. Read-only.
    Verify {
        /// Skip re-hashing.
        #[arg(long)]
        quick: bool,
    },
    /// Quarantine blobs no release references (orphans left by a crash before the row commit).
    ///
    /// Without `--yes` this only prints what it would do. Blobs are MOVED to the store's
    /// `.gc-trash/` (restore with `store gc-restore`), and quarantined blobs older than 7 days
    /// are deleted for good by a later `--yes` run (never at startup).
    ///
    /// Safety: blobs younger than --grace-hours are never touched (a blob is written before
    /// its row), every blob is re-checked against the database right before it is moved, and
    /// the command refuses (without --force) when the database has no releases, when a
    /// candidate is newer than the newest release row, or when a candidate's timestamps look
    /// restored from a copy. After restoring the database from a backup, run `store verify`
    /// and `store gc` (dry run) first: blobs newer than the backup are unreferenced but are
    /// the only copy of your NZBs.
    Gc {
        /// Print the plan and exit (also the default when --yes is absent).
        #[arg(long)]
        dry_run: bool,
        /// Actually quarantine the reclaimable blobs after seeing the counts.
        #[arg(long)]
        yes: bool,
        /// Proceed although the plan looks like a stale or restored database.
        #[arg(long)]
        force: bool,
        /// Minimum age of a reclaimable blob, in hours (>= 1).
        #[arg(long, default_value_t = 24)]
        grace_hours: u64,
    },
    /// Put every quarantined blob (see `store gc`) back into the store.
    GcRestore,
}

fn debug(s: &str) -> String {
    let shown: String = s.chars().take(MAX_SHOWN).collect();
    format!("{shown:?}")
}

/// Table for `failed list`: `NAME CODE TIME SIZE`, one row per file.
pub fn render_failed(entries: &[FailedEntry]) -> String {
    let mut out = format!(
        "{:<44} {:<28} {:<17} {:>10}\n",
        "NAME", "CODE", "TIME", "SIZE"
    );
    for e in entries {
        let (code, time) = e.reason.as_ref().map_or_else(
            || ("-".to_owned(), "-".to_owned()),
            |r| (r.error_code.clone(), nzb_ingest::utc_stamp(r.at)),
        );
        let _ = writeln!(
            out,
            "{:<44} {:<28} {:<17} {:>10}",
            debug(&e.name),
            debug(&code),
            time,
            e.size
        );
    }
    out
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Runs `nzbd failed ...` (no database needed).
#[allow(clippy::needless_pass_by_value)] // clap value consumed by the match
pub fn run_failed(cfg: &Config, action: FailedAction) -> Result<ExitCode, String> {
    match action {
        FailedAction::List => {
            let list = nzb_ingest::list_failed(&cfg.paths.failed)
                .map_err(|e| format!("failed/: {:?}", e.kind()))?;
            print!("{}", render_failed(&list));
            println!("{} file(s)", list.len());
            Ok(ExitCode::SUCCESS)
        }
        FailedAction::Retry { name, all } => {
            let target = match (name, all) {
                (_, true) => RetryTarget::All,
                (Some(n), false) => RetryTarget::Name(n),
                (None, false) => return Err("give a NAME or --all".into()),
            };
            let rep = nzb_ingest::retry(&cfg.paths.failed, &cfg.paths.watch, &target).map_err(
                |e| match e.kind() {
                    std::io::ErrorKind::InvalidInput => {
                        "not a failed-file name (copy it from `nzbd failed list`)".to_owned()
                    }
                    std::io::ErrorKind::NotFound => "no such failed file".to_owned(),
                    k => format!("retry: {k:?}"),
                },
            )?;
            for (from, to) in &rep.moved {
                println!("retrying {} as {}", debug(from), debug(to));
            }
            for (name, kind) in &rep.errors {
                eprintln!("error: {}: {kind}", debug(name));
            }
            println!("{} moved, {} failed", rep.moved.len(), rep.errors.len());
            Ok(if rep.errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}

pub(crate) async fn open_db(cfg: &Config) -> Result<nzb_store::Store, String> {
    if !crate::dbopen::exists(cfg) {
        return Err(format!(
            "database {} does not exist; check paths.db",
            cfg.paths.db.display()
        ));
    }
    crate::dbopen::open(cfg)
        .await
        .map_err(|e| format!("database: {e}"))
}

/// Runs `nzbd store ...`.
#[allow(clippy::needless_pass_by_value)] // clap value consumed by the match
pub fn run_store(cfg: &Config, action: StoreAction) -> Result<ExitCode, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let db = open_db(cfg).await?;
        // Passive: the CLI must not clean `.tmp/`, which belongs to a running `serve`.
        let fs = nzb_store::FsStore::open_passive(&cfg.paths.store)
            .map_err(|e| format!("store: {e}"))?;
        let blobs = fs_store(cfg, fs);
        let res = match action {
            StoreAction::Verify { quick } => verify(&db, &blobs, quick).await,
            StoreAction::Gc {
                dry_run,
                yes,
                force,
                grace_hours,
            } => {
                let opts = GcOptions {
                    apply: yes && !dry_run,
                    force,
                    grace_hours,
                };
                gc(&db, &blobs, opts).await
            }
            StoreAction::GcRestore => {
                let n = nzb_store::BlobMaintenance::restore_gc_trash(&blobs)
                    .await
                    .map_err(|e| format!("gc-restore: {e}"))?;
                println!("restored {n} blob(s)");
                Ok(ExitCode::SUCCESS)
            }
        };
        db.close().await;
        res
    })
}

/// The NZB file store with the blob size cap of `serve`. v3 keeps NZB files on the filesystem only (D36 a); the 2.x
/// database blob backend and `store migrate` are not part of the v3 runtime.
pub fn fs_store(cfg: &Config, fs: nzb_store::FsStore) -> nzb_store::FsStore {
    fs.set_max_blob_bytes(cfg.limits.max_file_bytes.saturating_mul(2));
    fs
}

async fn verify<S: nzb_store::BlobMaintenance + ?Sized>(
    db: &nzb_store::Store,
    store: &S,
    quick: bool,
) -> Result<ExitCode, String> {
    let c = nzb_ingest::check_store(db, store, quick)
        .await
        .map_err(|e| format!("verify: {e}"))?;
    println!(
        "file store: {} release(s), {} blob(s) missing",
        c.rows,
        c.missing.len()
    );
    for sha in c.missing.iter().take(MAX_LISTED) {
        println!("missing: {}", sha.to_hex());
    }
    let mut bad = !c.missing.is_empty();
    if let Some(f) = &c.full {
        println!(
            "{} blob(s) ok, {} corrupt, {} unexpected entr(y/ies)",
            f.ok,
            f.corrupt.len(),
            f.unexpected
        );
        for sha in f.corrupt.iter().take(MAX_LISTED) {
            println!("corrupt: {}", sha.to_hex());
        }
        bad |= !f.corrupt.is_empty() || f.unexpected > 0 || f.incomplete;
    }
    Ok(if bad {
        ExitCode::from(2)
    } else {
        println!("store ok");
        ExitCode::SUCCESS
    })
}

/// Days a quarantined blob stays restorable before a later `gc --yes` deletes it.
const GC_TRASH_GRACE_DAYS: u64 = 7;

struct GcOptions {
    apply: bool,
    force: bool,
    grace_hours: u64,
}

/// Refuses plans that look like a stale or restored database (`SECURITY_REVIEW` T032 M2).
fn check_plan(plan: &nzb_ingest::GcPlan, rows: usize, force: bool) -> Result<(), String> {
    if plan.candidates.is_empty() || force {
        return Ok(());
    }
    if rows == 0 {
        return Err(
            "refusing: the database has no releases but the store has reclaimable blobs \
             (wrong paths.db, or a restore in progress?); use --force only if you are sure"
                .into(),
        );
    }
    if let Some((sha, why)) = plan.suspicious.first() {
        return Err(format!(
            "refusing: {} reclaimable blob(s) look like the only copy of NZBs the database does \
             not know (first: {}: {why}); verify the database, then use --force",
            plan.suspicious.len(),
            sha.to_hex()
        ));
    }
    Ok(())
}

async fn gc<S: nzb_store::BlobMaintenance + ?Sized>(
    db: &nzb_store::Store,
    store: &S,
    o: GcOptions,
) -> Result<ExitCode, String> {
    if o.grace_hours == 0 {
        return Err("--grace-hours must be at least 1".into());
    }
    let grace = o.grace_hours.saturating_mul(3600);
    let now = now_secs();
    let e = |e: nzb_store::StoreError| format!("gc: {e}");
    let plan = nzb_ingest::gc_plan(db, store, now, grace)
        .await
        .map_err(e)?;
    let rows = db.list_shas().await.map_err(e)?.len();
    println!(
        "{} reclaimable blob(s), {} byte(s); {} look suspicious; {} release(s) in the database",
        plan.candidates.len(),
        plan.bytes,
        plan.suspicious.len(),
        rows
    );
    for c in plan.candidates.iter().take(MAX_LISTED) {
        println!("candidate: {}", c.sha.to_hex());
    }
    if let Err(msg) = check_plan(&plan, rows, o.force) {
        if o.apply {
            return Err(msg);
        }
        println!("note: a real run would be {msg}");
    }
    if !o.apply {
        println!("dry run: nothing changed; re-run with --yes to quarantine these blobs");
        return Ok(ExitCode::SUCCESS);
    }
    let rep = nzb_ingest::gc_orphans(db, store, now, grace, false)
        .await
        .map_err(e)?;
    let place = ".gc-trash/";
    println!(
        "quarantined {} blob(s) in {place} (undo with `nzbd store gc-restore`)",
        rep.removed.len()
    );
    let old = std::time::SystemTime::now()
        - std::time::Duration::from_secs(GC_TRASH_GRACE_DAYS.saturating_mul(86_400));
    let purged = store
        .purge_gc_trash(old)
        .await
        .map_err(|x| format!("gc: {x}"))?;
    if purged > 0 {
        println!("deleted {purged} blob(s) quarantined more than {GC_TRASH_GRACE_DAYS} days ago");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nzb_ingest::Reason;

    fn entry(name: &str, reason: Option<Reason>) -> FailedEntry {
        FailedEntry {
            name: name.to_owned(),
            size: 12,
            reason,
        }
    }

    #[test]
    fn table_has_name_code_time_size_and_escapes_hostile_text() {
        let r = Reason::new(
            "NZB_MALFORMED",
            "m",
            "watch",
            None,
            None,
            12,
            1_700_000_000,
            0,
        );
        let mut hostile = r.clone();
        hostile.error_code = "A\u{1b}[31mB".into();
        let t = render_failed(&[
            entry("20231114T221320Z-abcdef12.nzb", Some(r)),
            entry("20231114T221320Z-abcdef13.nzb", Some(hostile)),
            entry("20231114T221320Z-abcdef14.nzb", None),
        ]);
        let lines: Vec<&str> = t.lines().collect();
        assert!(lines[0].starts_with("NAME") && lines[0].contains("CODE"));
        assert!(lines[1].contains("NZB_MALFORMED") && lines[1].contains("20231114T221320Z"));
        assert!(lines[1].trim_end().ends_with("12"));
        assert!(!t.contains('\u{1b}'), "escape sequence leaked");
        assert!(lines[3].contains(" - "));
    }

    fn config(dir: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.paths.failed = dir.join("failed");
        cfg.paths.watch = dir.join("watch");
        std::fs::create_dir_all(&cfg.paths.failed).unwrap();
        std::fs::create_dir_all(&cfg.paths.watch).unwrap();
        cfg
    }

    #[test]
    fn retry_exit_codes_and_hostile_name_rejection() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let name = "20231114T221320Z-abcdef12.nzb";
        std::fs::write(cfg.paths.failed.join(name), b"x").unwrap();
        for bad in ["../x", "/etc/passwd", "a\0b"] {
            let r = run_failed(
                &cfg,
                FailedAction::Retry {
                    name: Some(bad.into()),
                    all: false,
                },
            );
            assert!(r.is_err(), "{bad:?}");
        }
        assert!(cfg.paths.failed.join(name).exists());
        let missing = run_failed(
            &cfg,
            FailedAction::Retry {
                name: Some("20231114T221320Z-abcdef99.nzb".into()),
                all: false,
            },
        );
        assert_eq!(missing.unwrap_err(), "no such failed file");
        let ok = run_failed(
            &cfg,
            FailedAction::Retry {
                name: Some(name.into()),
                all: false,
            },
        );
        assert!(ok.is_ok());
        assert!(!cfg.paths.failed.join(name).exists());
        assert_eq!(std::fs::read_dir(&cfg.paths.watch).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn gc_grace_protects_fresh_blobs_and_zero_grace_is_refused() {
        use nzb_store::NzbStore;
        let d = tempfile::tempdir().unwrap();
        let ts = nzb_store::test_backend::TestStore::open(d.path()).await;
        let db = ts.store.clone();
        let store = nzb_store::FsStore::open(d.path().join("store")).unwrap();
        // SHA-256 of the empty input.
        let sha = nzb_core::Sha256::from_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        store.put(sha, b"").await.unwrap();
        let opts = |apply, grace_hours| GcOptions {
            apply,
            force: false,
            grace_hours,
        };
        assert!(gc(&db, &store, opts(true, 0)).await.is_err());
        assert!(gc(&db, &store, opts(true, 24)).await.is_ok());
        assert!(
            store.exists(&sha).await.unwrap(),
            "fresh orphan survives the grace"
        );
        // Quick verify of an empty database is clean.
        assert!(verify(&db, &store, true).await.is_ok());
    }

    #[test]
    fn t032_m2_check_plan_refuses_stale_database_signatures_without_force() {
        let sha = nzb_core::Sha256([7; 32]);
        let cand = nzb_store::GcCandidate {
            sha,
            size: 1,
            mtime: 5,
            ctime: 5,
        };
        let clean = nzb_ingest::GcPlan {
            candidates: vec![cand],
            bytes: 1,
            newest_row: Some(10),
            suspicious: vec![],
        };
        assert!(check_plan(&clean, 3, false).is_ok());
        // Nothing to do is always fine, even on an empty database.
        assert!(check_plan(&nzb_ingest::GcPlan::default(), 0, false).is_ok());
        // Empty database next to reclaimable blobs.
        assert!(check_plan(&clean, 0, false).is_err());
        assert!(check_plan(&clean, 0, true).is_ok());
        // Restore signature.
        let stale = nzb_ingest::GcPlan {
            suspicious: vec![(sha, "newer than the newest release row (stale database?)")],
            ..clean
        };
        let e = check_plan(&stale, 3, false).unwrap_err();
        assert!(e.contains("--force") && e.contains(&sha.to_hex()));
        assert!(check_plan(&stale, 3, true).is_ok());
    }
}

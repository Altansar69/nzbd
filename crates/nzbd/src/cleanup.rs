//! `nzbd cleanup status|purge` and `nzbd trash list|restore|purge` (T081): the headless twin of
//! the admin Cleanup panel and of the release delete flow.
//!
//! Purging is a dry run unless `--yes` is given (it prints what it would remove). Every printed
//! number comes from the same engine as the web panel (`nzb_ingest::cleanup`), so counts match.
//! The CLI is operator-trusted (shell access on the host) and does not re-authenticate, but it
//! writes the same audit rows, with the actor `cli`. Exit codes: 0 ok, 1 error, 2 the purge
//! skipped something because a safety check refused it, hit an I/O error, or ran out of time.

use nzb_store::prelude::*;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Subcommand, ValueEnum};
use nzb_ingest::cleanup::{self, Bucket, CleanupEnv, CleanupStatus, RestoreError};
use nzb_store::{FsStore, TrashStore, sha8};

use crate::config::Config;

/// Deadline of a CLI purge (the web purge uses 120 s; a shell user can wait longer).
const CLI_DEADLINE: Duration = Duration::from_mins(30);
/// Names and titles printed are cut so a corrupted record cannot flood the terminal.
const MAX_SHOWN: usize = 120;

/// Buckets as accepted on the command line.
#[derive(Clone, Copy, ValueEnum)]
pub enum BucketArg {
    /// Deleted releases, `.gc-trash` quarantine, leftovers.
    Trash,
    /// failed/ items rejected by policy or hostile-input codes.
    Blocked,
    /// All other failed/ items.
    Failed,
}

impl From<BucketArg> for Bucket {
    fn from(b: BucketArg) -> Self {
        match b {
            BucketArg::Trash => Self::Trash,
            BucketArg::Blocked => Self::Blocked,
            BucketArg::Failed => Self::Failed,
        }
    }
}

/// `nzbd cleanup ...`
#[derive(Subcommand)]
pub enum CleanupAction {
    /// Show items and sizes of the Trash, Blocked and Failed buckets. Read-only.
    Status,
    /// Permanently delete the files of one bucket.
    ///
    /// Without `--yes` this only prints what it would do. Only files nzbd wrote (valid reason
    /// record that still matches the file) are removed from failed/; the watch folder, the
    /// NZB store, duplicates and backups are never touched. Quarantined store blobs younger
    /// than 7 days are kept.
    Purge {
        /// Bucket to purge.
        #[arg(long, value_enum)]
        bucket: BucketArg,
        /// Really delete (default: dry run).
        #[arg(long)]
        yes: bool,
    },
}

/// `nzbd trash ...`
#[derive(Subcommand)]
pub enum TrashAction {
    /// List deleted releases: trash id, deleted time, size, sha prefix, title.
    List,
    /// Put a deleted release back: its NZB is written to the watch folder as
    /// `restored-<sha8>.nzb` and re-ingested (new release id; a manual category is not kept).
    Restore {
        /// Trash id from `trash list`.
        id: i64,
    },
    /// Same as `cleanup purge --bucket trash`.
    Purge {
        /// Really delete (default: dry run).
        #[arg(long)]
        yes: bool,
    },
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn debug(s: &str) -> String {
    let shown: String = s.chars().take(MAX_SHOWN).collect();
    format!("{shown:?}")
}

/// Plain-text table of the three buckets.
#[must_use]
pub fn render_status(s: &CleanupStatus) -> String {
    let mut out = format!("{:<8} {:>8} {:>14}\n", "BUCKET", "ITEMS", "BYTES");
    let _ = writeln!(
        out,
        "{:<8} {:>8} {:>14}",
        "trash",
        s.trash.items(),
        s.trash.bytes()
    );
    let _ = writeln!(
        out,
        "  deleted releases {:>6} ({} bytes), quarantined blobs {:>6} ({} bytes), leftovers {:>4} ({} bytes)",
        s.trash.releases,
        s.trash.release_bytes,
        s.trash.quarantine,
        s.trash.quarantine_bytes,
        s.trash.leftovers,
        s.trash.leftover_bytes
    );
    let _ = writeln!(
        out,
        "{:<8} {:>8} {:>14}",
        "blocked", s.blocked.items, s.blocked.bytes
    );
    let _ = writeln!(
        out,
        "{:<8} {:>8} {:>14}",
        "failed", s.failed.items, s.failed.bytes
    );
    let unmanaged = s.blocked.unmanaged.saturating_add(s.failed.unmanaged);
    if unmanaged > 0 || s.foreign_files > 0 || s.trash.unrecorded > 0 || s.trash.foreign > 0 {
        let _ = writeln!(
            out,
            "never purged: {unmanaged} without a reason record, {} foreign file(s) in failed/, {} trash file(s) without a record, {} foreign entr(y/ies) in the store's trash folders",
            s.foreign_files, s.trash.unrecorded, s.trash.foreign
        );
    }
    out
}

fn env(cfg: &Config, db: nzb_store::Store) -> Result<CleanupEnv, String> {
    // Passive: the CLI must not clean `.tmp/`, which belongs to a running `serve`.
    let fs = FsStore::open_passive(&cfg.paths.store).map_err(|e| format!("store: {e}"))?;
    let store: Arc<dyn TrashStore> = Arc::new(crate::ops::fs_store(cfg, fs));
    Ok(CleanupEnv {
        db,
        store,
        failed_dir: cfg.paths.failed.clone(),
    })
}

fn bucket_slice(s: &CleanupStatus, b: Bucket) -> (u64, u64, u64) {
    match b {
        Bucket::Trash => (s.trash.items(), s.trash.bytes(), 0),
        Bucket::Blocked => (s.blocked.items, s.blocked.bytes, s.blocked.unmanaged),
        Bucket::Failed => (s.failed.items, s.failed.bytes, s.failed.unmanaged),
    }
}

async fn purge(env: &CleanupEnv, bucket: Bucket, yes: bool) -> Result<ExitCode, String> {
    let status = cleanup::status(env)
        .await
        .map_err(|e| format!("cleanup: {e}"))?;
    let (items, bytes, unmanaged) = bucket_slice(&status, bucket);
    println!(
        "{}: {items} item(s), {bytes} byte(s); {unmanaged} of them have no valid reason record and are never purged",
        bucket.slug()
    );
    if !yes {
        println!(
            "dry run: nothing deleted; re-run with --yes to purge the {} bucket permanently",
            bucket.slug()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let now = now_secs();
    let rep = cleanup::purge(env, bucket, now, Instant::now() + CLI_DEADLINE)
        .await
        .map_err(|e| format!("cleanup: {e}"))?;
    println!(
        "removed {} item(s), {} byte(s); skipped {} not written by nzbd, {} by a safety check, {} too young, {} not processed; {} error(s)",
        rep.removed,
        rep.bytes,
        rep.unmanaged,
        rep.refused,
        rep.kept_recent,
        rep.remaining,
        rep.errors
    );
    let detail = format!(
        "bucket={} count={} bytes={} skipped={}",
        bucket.slug(),
        rep.removed,
        rep.bytes,
        rep.skipped()
    );
    env.db
        .audit_event(now, Some("cli"), "cleanup_purge", Some(&detail), None)
        .await
        .map_err(|e| format!("audit: {e}"))?;
    Ok(if rep.errors > 0 || rep.refused > 0 || rep.remaining > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

/// Runs `nzbd cleanup ...`.
#[allow(clippy::needless_pass_by_value)] // clap value consumed by the match
pub fn run_cleanup(cfg: &Config, action: CleanupAction) -> Result<ExitCode, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let db = crate::ops::open_db(cfg).await?;
        let res = match env(cfg, db.clone()) {
            Ok(env) => match action {
                CleanupAction::Status => cleanup::status(&env)
                    .await
                    .map(|s| {
                        print!("{}", render_status(&s));
                        ExitCode::SUCCESS
                    })
                    .map_err(|e| format!("cleanup: {e}")),
                CleanupAction::Purge { bucket, yes } => purge(&env, bucket.into(), yes).await,
            },
            Err(e) => Err(e),
        };
        db.close().await;
        res
    })
}

/// Runs `nzbd trash ...`.
#[allow(clippy::needless_pass_by_value)] // clap value consumed by the match
pub fn run_trash(cfg: &Config, action: TrashAction) -> Result<ExitCode, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let db = crate::ops::open_db(cfg).await?;
        let res = match env(cfg, db.clone()) {
            Ok(env) => trash(cfg, &env, action).await,
            Err(e) => Err(e),
        };
        db.close().await;
        res
    })
}

async fn trash(cfg: &Config, env: &CleanupEnv, action: TrashAction) -> Result<ExitCode, String> {
    match action {
        TrashAction::List => {
            let rows = env
                .db
                .list_trash(10_000)
                .await
                .map_err(|e| format!("trash: {e}"))?;
            println!(
                "{:>6} {:<17} {:>12} {:<8} TITLE",
                "ID", "DELETED", "SIZE", "SHA"
            );
            for r in &rows {
                println!(
                    "{:>6} {:<17} {:>12} {:<8} {}",
                    r.id,
                    nzb_ingest::utc_stamp(r.deleted_at),
                    r.total_bytes,
                    sha8(&r.sha256),
                    debug(&r.title)
                );
            }
            println!("{} deleted release(s)", rows.len());
            Ok(ExitCode::SUCCESS)
        }
        TrashAction::Restore { id } => {
            let r = cleanup::restore_to_watch(env, &cfg.paths.watch, id)
                .await
                .map_err(|e| match e {
                    RestoreError::NoSuchRelease => {
                        "no such deleted release (see `nzbd trash list`)".to_owned()
                    }
                    RestoreError::BlobMissing => {
                        "the NZB of this release is no longer in the trash (purged?)".to_owned()
                    }
                    RestoreError::AlreadyIndexed => {
                        "this content is already indexed again; purge the trash copy instead"
                            .to_owned()
                    }
                    RestoreError::Cleanup(e) => format!("restore: {e}"),
                })?;
            println!(
                "restored {} into the watch folder as {}; it is re-ingested within a scan interval",
                r.sha8,
                debug(&r.watch_name)
            );
            env.db
                .audit_event(
                    now_secs(),
                    Some("cli"),
                    "release_restore",
                    Some(&format!("trash={id} sha8={}", r.sha8)),
                    None,
                )
                .await
                .map_err(|e| format!("audit: {e}"))?;
            Ok(ExitCode::SUCCESS)
        }
        TrashAction::Purge { yes } => purge(env, Bucket::Trash, yes).await,
    }
}

//! Watch-folder scanner (`INGEST_SPEC` §Discovery; SEC-006, SEC-007).
//!
//! The scanner is a synchronous state machine: [`Scanner::scan`] walks the watch directory once,
//! updates per-path observations and returns the candidates that are *stable* and may be handed
//! to the pipeline. Time comes from a [`Clock`] so tests are deterministic. File names are
//! display data: they are only ever joined onto the scanned directory entry and never
//! interpreted (no parsing into paths, no sub-folder traversal driven by names).
//!
//! Known limitation (L1): only the last path component is protected by `O_NOFOLLOW`. With
//! `recursive = true` an attacker who can write the watch dir could swap a sub-directory for a
//! symlink between scan and open. Mitigations in place: [`open_regular`] re-checks that the
//! canonical parent is still under the canonical watch root, that the opened inode matches the
//! observed [`FileId`] and that `nlink == 1`. Fully closing the race needs `openat2`
//! (`RESOLVE_NO_SYMLINKS`), which is not available without `unsafe`. The default configuration
//! (non-recursive) is unaffected.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// Monotonic seconds source. Only differences matter.
pub trait Clock: Send + Sync {
    /// Seconds elapsed on this clock.
    fn now_secs(&self) -> u64;
}

/// Real monotonic clock.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// Create a clock starting at zero now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        Instant::now().duration_since(self.start).as_secs()
    }
}

/// Scanner settings (mapped from the `ingest.*` config section).
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Directory to scan.
    pub watch_dir: PathBuf,
    /// Descend into sub-directories (depth-limited, never through symlinks).
    pub recursive: bool,
    /// Files larger than this are ignored (and left alone).
    pub max_file_bytes: u64,
    /// Seconds the file identity must stay unchanged before a file is processed.
    pub stable_secs: u64,
    /// Seconds to leave a path alone after [`Scanner::fail_backoff`] (spec: 600).
    pub backoff_secs: u64,
    /// Upper bound on directory entries visited per scan (flood protection).
    pub max_entries_per_scan: usize,
}

/// Default for [`ScannerConfig::max_entries_per_scan`].
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Maximum recursion depth when `recursive` is on.
pub const MAX_DEPTH: usize = 4;

/// Maximum number of ignored paths remembered for log de-duplication.
const IGNORED_LOG_CAP: usize = 1024;

/// Identity of a file as observed by the scanner. `ctime` cannot be set from user space, so a
/// size-preserving rewrite with a restored mtime still changes the identity (SEC-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileId {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time.
    pub mtime: Option<SystemTime>,
    /// Inode change time, seconds.
    pub ctime: i64,
    /// Inode change time, nanoseconds part.
    pub ctime_nsec: i64,
}

impl FileId {
    /// Build from metadata (`lstat` or `fstat`).
    #[must_use]
    pub fn from_meta(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime: meta.modified().ok(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}

type InFlightSet = Arc<Mutex<HashSet<PathBuf>>>;

/// Releases the path from the scanner's in-flight set when dropped, so a candidate that is
/// dropped without an explicit call can never leak (L5). A dropped candidate whose file is
/// still present is offered again by a later scan; use [`Scanner::fail_backoff`] to avoid a
/// hot loop when the file could not be moved away.
#[derive(Debug)]
struct InFlightGuard {
    set: InFlightSet,
    path: PathBuf,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.path);
    }
}

/// A stable file ready for the pipeline. Keep it alive while the file is being processed.
#[derive(Debug)]
pub struct Candidate {
    /// Path of the file (watch dir joined with scanned entries only).
    pub path: PathBuf,
    /// Size observed during the last scan.
    pub size: u64,
    /// Identity observed by the scanner; pass to [`open_regular`].
    pub id: FileId,
    /// Name of the first-level sub-folder, if any and valid UTF-8. Must only be compared
    /// against the category slug allowlist, never used as a path.
    pub subfolder: Option<String>,
    guard: Option<InFlightGuard>,
}

#[derive(Debug)]
struct Observation {
    id: FileId,
    since: u64,
}

/// The discovery state machine.
pub struct Scanner<C: Clock> {
    cfg: ScannerConfig,
    clock: C,
    seen: HashMap<PathBuf, Observation>,
    in_flight: InFlightSet,
    backoff: HashMap<PathBuf, u64>,
    ignored_logged: HashSet<PathBuf>,
    ignored_now: HashSet<PathBuf>,
    last_scan_at: Option<u64>,
}

/// Name-based candidate rules (hidden, temp, extension). Pure function, easy to test.
#[must_use]
pub fn name_is_candidate(name: &str) -> bool {
    if name.starts_with('.') || name.starts_with('~') || name.ends_with('~') {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if [".part", ".tmp", ".crdownload"]
        .iter()
        .any(|s| lower.ends_with(s))
    {
        return false;
    }
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("nzb"))
}

/// What [`walk`] needs to know (a subset of [`ScannerConfig`]).
#[derive(Debug, Clone)]
pub(crate) struct WalkSettings {
    /// Watch root.
    pub(crate) root: PathBuf,
    /// Descend into sub-directories (depth <= [`MAX_DEPTH`], never through symlinks).
    pub(crate) recursive: bool,
    /// Larger files are ignored.
    pub(crate) max_file_bytes: u64,
    /// Entry budget of one walk (flood protection).
    pub(crate) max_entries: usize,
}

/// One entry reported by [`walk`].
pub(crate) enum Seen {
    /// A regular, singly linked, UTF-8 named `.nzb` within the size cap.
    Candidate {
        /// Watch root joined with directory entries only.
        path: PathBuf,
        /// `lstat` of the entry.
        meta: Metadata,
        /// First-level sub-folder name (compare only, never a path).
        subfolder: Option<String>,
    },
    /// Any other entry that is not a directory.
    Ignored {
        /// Path of the entry.
        path: PathBuf,
        /// Static reason, for the debug log.
        why: &'static str,
    },
    /// A directory the walk would have entered (recursive, within the depth limit) but skips
    /// because it is hidden or its name is not UTF-8. The scanner ignores this report (its
    /// behaviour is unchanged); the dry run lists it so nothing disappears silently (review 41 I3).
    SkippedDir {
        /// Path of the directory.
        path: PathBuf,
        /// Static reason.
        why: &'static str,
    },
}

/// The one watch-folder walk, shared by [`Scanner::scan`] and the read-only rule dry run
/// (`crate::rules::dry_run`) so both see exactly the same files (SEC-006: `lstat` only, symlinks
/// never followed, hidden and non-UTF-8 directories skipped, depth <= [`MAX_DEPTH`], at most
/// `max_entries` entries).
pub(crate) fn walk(s: &WalkSettings, mut f: impl FnMut(Seen)) {
    let mut visited: usize = 0;
    let mut stack: Vec<(PathBuf, usize, Option<String>)> = vec![(s.root.clone(), 0, None)];
    'walk: while let Some((dir, depth, sub)) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(error = %e, "cannot read watch directory");
                continue;
            }
        };
        for entry in rd {
            visited = visited.saturating_add(1);
            if visited > s.max_entries {
                tracing::warn!(
                    limit = s.max_entries,
                    "scan entry limit reached; remaining entries skipped"
                );
                break 'walk;
            }
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            // symlink_metadata never follows links (SEC-006).
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            let name_os = entry.file_name();
            let name = name_os.to_str();
            if meta.is_dir() {
                if s.recursive && depth < MAX_DEPTH {
                    match name {
                        Some(n) if !n.starts_with('.') => {
                            let child_sub = if depth == 0 {
                                Some(n.to_owned())
                            } else {
                                sub.clone()
                            };
                            stack.push((path, depth.saturating_add(1), child_sub));
                        }
                        Some(_) => f(Seen::SkippedDir {
                            path,
                            why: "hidden directory",
                        }),
                        None => f(Seen::SkippedDir {
                            path,
                            why: "non-UTF-8 directory name",
                        }),
                    }
                }
                continue;
            }
            let why = match name {
                None => Some("non-UTF-8 name"),
                Some(_) if !meta.file_type().is_file() => Some("not a regular file"),
                Some(_) if meta.nlink() > 1 => Some("multiple hard links"),
                Some(n) if !name_is_candidate(n) => Some("name does not match candidate rules"),
                Some(_) if meta.len() > s.max_file_bytes => Some("larger than max_file_bytes"),
                Some(_) => None,
            };
            match why {
                Some(why) => f(Seen::Ignored { path, why }),
                None => f(Seen::Candidate {
                    path,
                    meta,
                    subfolder: sub.clone(),
                }),
            }
        }
    }
}

impl<C: Clock> Scanner<C> {
    /// Create a scanner.
    pub fn new(cfg: ScannerConfig, clock: C) -> Self {
        Self {
            cfg,
            clock,
            seen: HashMap::new(),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            backoff: HashMap::new(),
            ignored_logged: HashSet::new(),
            ignored_now: HashSet::new(),
            last_scan_at: None,
        }
    }

    /// Clock reading of the last completed scan (scanner heartbeat for `/healthz`).
    #[must_use]
    pub fn last_scan_at(&self) -> Option<u64> {
        self.last_scan_at
    }

    /// Number of paths currently tracked for stability.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }

    /// The pipeline moved `path` away (success or failure). Forget its observation. The
    /// in-flight mark is released when the [`Candidate`] is dropped.
    pub fn finish(&mut self, path: &Path) {
        self.seen.remove(path);
    }

    /// The pipeline could not move `path` away: do not hand it out again for `backoff_secs`.
    pub fn fail_backoff(&mut self, path: &Path) {
        self.seen.remove(path);
        let until = self.clock.now_secs().saturating_add(self.cfg.backoff_secs);
        self.backoff.insert(path.to_path_buf(), until);
    }

    fn is_in_flight(&self, path: &Path) -> bool {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(path)
    }

    /// Walk the watch dir once and return up to `max` stable candidates (sorted by path).
    /// Stable candidates beyond `max` are returned by a later scan (queue backpressure).
    pub fn scan(&mut self, max: usize) -> Vec<Candidate> {
        let now = self.clock.now_secs();
        self.backoff.retain(|_, until| *until > now);
        self.ignored_now.clear();

        let mut present: HashSet<PathBuf> = HashSet::new();
        let mut ready: Vec<Candidate> = Vec::new();
        let settings = WalkSettings {
            root: self.cfg.watch_dir.clone(),
            recursive: self.cfg.recursive,
            max_file_bytes: self.cfg.max_file_bytes,
            max_entries: self.cfg.max_entries_per_scan,
        };
        walk(&settings, |seen| match seen {
            Seen::Ignored { path, why } => self.ignore(&path, why),
            // Unchanged scanner behaviour: skipped directories are not logged or tracked.
            Seen::SkippedDir { .. } => {}
            Seen::Candidate {
                path,
                meta,
                subfolder,
            } => {
                present.insert(path.clone());
                if self.is_in_flight(&path) || self.backoff.contains_key(&path) {
                    return;
                }
                if self.observe(&path, &meta, now) {
                    ready.push(Candidate {
                        path,
                        size: meta.len(),
                        id: FileId::from_meta(&meta),
                        subfolder,
                        guard: None,
                    });
                }
            }
        });

        self.seen.retain(|p, _| present.contains(p));
        std::mem::swap(&mut self.ignored_logged, &mut self.ignored_now);
        ready.sort_by(|a, b| a.path.cmp(&b.path));
        ready.truncate(max);
        {
            let mut set = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for c in &mut ready {
                set.insert(c.path.clone());
                c.guard = Some(InFlightGuard {
                    set: Arc::clone(&self.in_flight),
                    path: c.path.clone(),
                });
            }
        }
        self.last_scan_at = Some(now);
        ready
    }

    /// Record an observation; true when the file identity has been unchanged for
    /// `stable_secs`.
    fn observe(&mut self, path: &Path, meta: &Metadata, now: u64) -> bool {
        let id = FileId::from_meta(meta);
        match self.seen.get_mut(path) {
            Some(obs) if obs.id == id => {
                id.size > 0 && now.saturating_sub(obs.since) >= self.cfg.stable_secs
            }
            Some(obs) => {
                *obs = Observation { id, since: now };
                false
            }
            None => {
                // First sight is never "ready": stability needs two observations.
                self.seen
                    .insert(path.to_path_buf(), Observation { id, since: now });
                false
            }
        }
    }

    /// Log an ignored entry once (debug) while remembering at most `IGNORED_LOG_CAP` paths;
    /// beyond that nothing is logged or stored, so junk floods cost no memory.
    fn ignore(&mut self, path: &Path, why: &str) {
        if self.ignored_now.len() >= IGNORED_LOG_CAP {
            return;
        }
        if !self.ignored_logged.contains(path) {
            tracing::debug!(reason = why, path = ?path, "ignoring watch entry");
        }
        self.ignored_now.insert(path.to_path_buf());
    }
}

/// Why [`open_regular`] refused a path.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// Not a regular file, or it changed identity between check and open.
    #[error("not a regular file")]
    NotRegular,
    /// The file has more than one hard link (refused, see L2).
    #[error("file has multiple hard links")]
    HardLinked,
    /// The parent directory resolves outside the watch root.
    #[error("path escapes the watch root")]
    OutsideRoot,
    /// The file differs from what the scanner observed (rewritten, replaced or growing).
    #[error("file changed since it was observed")]
    Changed,
    /// Larger than the cap (checked before any read).
    #[error("file too large: {size} bytes")]
    TooLarge {
        /// Observed size.
        size: u64,
    },
    /// Underlying I/O error (includes ELOOP when the path became a symlink).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Open `path` for reading with no-follow semantics (SEC-006): `O_NOFOLLOW | O_NONBLOCK |
/// O_NOCTTY`, then verify via the descriptor that it is a regular file with `nlink == 1`,
/// the same device/inode as the `lstat`, within `max_bytes`, and (when given) identical to the
/// `expected` identity observed by the scanner (SEC-007). When `root` is given, the canonical
/// parent directory must lie under the canonical root. Returns the file and its size.
///
/// The caller must still bound reads with `Read::take(max + 1)`: the file can grow after the
/// check.
///
/// # Errors
/// See [`OpenError`].
pub fn open_regular(
    path: &Path,
    max_bytes: u64,
    expected: Option<&FileId>,
    root: Option<&Path>,
) -> Result<(File, u64), OpenError> {
    if let Some(root) = root {
        let parent = path.parent().ok_or(OpenError::OutsideRoot)?;
        let canon_parent = fs::canonicalize(parent)?;
        let canon_root = fs::canonicalize(root)?;
        if !canon_parent.starts_with(&canon_root) {
            return Err(OpenError::OutsideRoot);
        }
    }
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(OpenError::NotRegular);
    }
    if before.nlink() > 1 {
        return Err(OpenError::HardLinked);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() || meta.dev() != before.dev() || meta.ino() != before.ino() {
        return Err(OpenError::NotRegular);
    }
    if meta.nlink() > 1 {
        return Err(OpenError::HardLinked);
    }
    if meta.len() > max_bytes {
        return Err(OpenError::TooLarge { size: meta.len() });
    }
    if expected.is_some_and(|exp| FileId::from_meta(&meta) != *exp) {
        return Err(OpenError::Changed);
    }
    Ok((file, meta.len()))
}

/// Convenience for callers computing heartbeat freshness.
#[must_use]
pub fn heartbeat_fresh(last: Option<u64>, now: u64, scan_interval: Duration) -> bool {
    last.is_some_and(|l| now.saturating_sub(l) < scan_interval.as_secs().saturating_mul(3))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::many_single_char_names,
    clippy::assert_is_empty
)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);
    impl FakeClock {
        fn advance(&self, s: u64) {
            self.0.fetch_add(s, Ordering::SeqCst);
        }
    }
    impl Clock for FakeClock {
        fn now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn setup(recursive: bool) -> (tempfile::TempDir, Scanner<FakeClock>, FakeClock) {
        let dir = tempfile::tempdir().unwrap();
        let clock = FakeClock::default();
        let cfg = ScannerConfig {
            watch_dir: dir.path().to_path_buf(),
            recursive,
            max_file_bytes: 1000,
            stable_secs: 10,
            backoff_secs: 600,
            max_entries_per_scan: DEFAULT_MAX_ENTRIES,
        };
        (dir, Scanner::new(cfg, clock.clone()), clock)
    }

    fn write(p: &Path, data: &[u8]) {
        fs::write(p, data).unwrap();
    }

    /// Two scans 10 s apart.
    fn settle(s: &mut Scanner<FakeClock>, c: &FakeClock) -> Vec<Candidate> {
        assert!(s.scan(100).is_empty());
        c.advance(10);
        s.scan(100)
    }

    fn mkfifo(p: &Path) {
        assert!(
            std::process::Command::new("mkfifo")
                .arg(p)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn name_rules() {
        for ok in ["a.nzb", "A.NZB", "x y.NzB"] {
            assert!(name_is_candidate(ok), "{ok}");
        }
        for bad in [
            ".a.nzb",
            "~a.nzb",
            "a.nzb~",
            "a.nzb.part",
            "a.nzb.tmp",
            "a.nzb.crdownload",
            ".nzb",
            "a.txt",
            "a",
        ] {
            assert!(!name_is_candidate(bad), "{bad}");
        }
    }

    // SEC-007
    #[test]
    fn sec007_stable_only_after_unchanged_for_stable_secs() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"abc");
        assert!(s.scan(10).is_empty(), "first sight is never ready");
        c.advance(9);
        assert!(s.scan(10).is_empty(), "9 s < stable_secs");
        c.advance(1);
        let got = s.scan(10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].size, 3);
        // Not handed out twice while in flight.
        c.advance(100);
        assert!(s.scan(10).is_empty());
    }

    // SEC-007
    #[test]
    fn sec007_growing_file_resets_the_timer() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"abc");
        assert!(s.scan(10).is_empty());
        c.advance(8);
        let mut h = fs::OpenOptions::new().append(true).open(&f).unwrap();
        h.write_all(b"def").unwrap();
        h.sync_all().unwrap();
        assert!(s.scan(10).is_empty(), "changed: timer restarts");
        c.advance(9);
        assert!(s.scan(10).is_empty(), "only 9 s since the change");
        c.advance(1);
        assert_eq!(s.scan(10).len(), 1);
    }

    // SEC-007
    #[test]
    fn sec007_mtime_change_with_same_size_resets_the_timer() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"abc");
        assert!(s.scan(10).is_empty());
        c.advance(10);
        let h = fs::OpenOptions::new().write(true).open(&f).unwrap();
        h.set_modified(SystemTime::now() + Duration::from_secs(5))
            .unwrap();
        assert!(s.scan(10).is_empty());
        c.advance(10);
        assert_eq!(s.scan(10).len(), 1);
    }

    // SEC-007 / M3
    #[test]
    fn sec007_size_preserving_rewrite_with_restored_mtime_is_not_stable() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"abcd");
        let mtime = fs::metadata(&f).unwrap().modified().unwrap();
        assert!(s.scan(10).is_empty());
        c.advance(10);
        // Linux stamps ctime from a coarse clock (a few ms); without waiting for a tick
        // the rewrite can land in the same tick and the ctime looks unchanged.
        assert!(nzb_testkit::wait_for_ctime_tick(&f));
        // Rewrite same size, restore mtime: only ctime betrays it.
        let mut h = fs::OpenOptions::new().write(true).open(&f).unwrap();
        h.write_all(b"wxyz").unwrap();
        h.set_modified(mtime).unwrap();
        drop(h);
        assert!(
            s.scan(10).is_empty(),
            "ctime change must restart the stability timer"
        );
        c.advance(10);
        assert_eq!(s.scan(10).len(), 1);
    }

    // SEC-007 / M3
    #[test]
    fn sec007_open_regular_rejects_replaced_or_modified_file() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"abcd");
        let got = settle(&mut s, &c);
        let cand = &got[0];
        assert!(open_regular(&cand.path, 1000, Some(&cand.id), None).is_ok());
        // Atomic rename-over with same size: inode differs.
        write(&d.path().join("tmp"), b"wxyz");
        fs::rename(d.path().join("tmp"), &f).unwrap();
        assert!(matches!(
            open_regular(&cand.path, 1000, Some(&cand.id), None),
            Err(OpenError::Changed)
        ));
    }

    #[test]
    fn empty_file_is_never_ready_until_it_has_content() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"");
        assert!(settle(&mut s, &c).is_empty());
        c.advance(100);
        assert!(s.scan(10).is_empty());
        write(&f, b"x");
        assert!(s.scan(10).is_empty());
        c.advance(10);
        assert_eq!(s.scan(10).len(), 1);
    }

    // SEC-006
    #[test]
    fn sec006_ignores_symlinks_special_hidden_temp_and_oversize() {
        let (d, mut s, c) = setup(false);
        let p = d.path();
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("real.nzb"), b"secret");
        std::os::unix::fs::symlink(outside.path().join("real.nzb"), p.join("link.nzb")).unwrap();
        std::os::unix::fs::symlink(outside.path(), p.join("dirlink.nzb")).unwrap();
        std::os::unix::fs::symlink(p.join("nonexistent"), p.join("dangling.nzb")).unwrap();
        mkfifo(&p.join("fifo.nzb"));
        let _sock = std::os::unix::net::UnixListener::bind(p.join("sock.nzb")).unwrap();
        fs::create_dir(p.join("dir.nzb")).unwrap();
        write(&p.join("dir.nzb").join("in.nzb"), b"x");
        write(&p.join(".hidden.nzb"), b"x");
        write(&p.join("~tmp.nzb"), b"x");
        write(&p.join("a.nzb.part"), b"x");
        write(&p.join("a.nzb.crdownload"), b"x");
        write(&p.join("notes.txt"), b"x");
        write(&p.join("huge.nzb"), &[b'x'; 1001]);
        write(&p.join("good.NZB"), b"ok");
        let got = settle(&mut s, &c);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].path, p.join("good.NZB"));
        // Everything ignored is left alone on disk.
        assert!(p.join("link.nzb").symlink_metadata().is_ok());
        assert!(p.join("huge.nzb").exists());
        assert_eq!(s.tracked(), 1);
    }

    // SEC-006
    #[test]
    fn sec006_recursion_off_by_default_and_never_follows_symlinks() {
        let (d, mut s, c) = setup(false);
        fs::create_dir(d.path().join("sub")).unwrap();
        write(&d.path().join("sub/a.nzb"), b"x");
        assert!(settle(&mut s, &c).is_empty());

        let (d, mut s, c) = setup(true);
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("o.nzb"), b"x");
        std::os::unix::fs::symlink(outside.path(), d.path().join("escape")).unwrap();
        fs::create_dir(d.path().join("anime")).unwrap();
        write(&d.path().join("anime/a.nzb"), b"x");
        fs::create_dir(d.path().join(".hid")).unwrap();
        write(&d.path().join(".hid/h.nzb"), b"x");
        let got = settle(&mut s, &c);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].subfolder.as_deref(), Some("anime"));
    }

    // SEC-006
    #[test]
    fn sec006_non_utf8_file_and_dir_names_are_skipped() {
        let (d, mut s, c) = setup(true);
        let bad_file = std::ffi::OsStr::from_bytes(b"bad\xff.nzb");
        let bad_dir = std::ffi::OsStr::from_bytes(b"dir\xfe");
        write(&d.path().join(bad_file), b"x");
        fs::create_dir(d.path().join(bad_dir)).unwrap();
        // The directory must be skipped entirely, not descended into.
        write(&d.path().join(bad_dir).join("in.nzb"), b"x");
        write(&d.path().join("ok.nzb"), b"x");
        let got = settle(&mut s, &c);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, d.path().join("ok.nzb"));
        assert_eq!(got[0].subfolder, None);
    }

    // SEC-006 / L2
    #[test]
    fn sec006_hardlinked_files_are_ignored_and_refused() {
        let (d, mut s, c) = setup(false);
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("o.nzb"), b"secret");
        // Same filesystem needed for a hard link: link inside the watch dir.
        write(&d.path().join("orig.nzb"), b"data");
        fs::hard_link(d.path().join("orig.nzb"), d.path().join("link.nzb")).unwrap();
        assert!(settle(&mut s, &c).is_empty());
        assert!(matches!(
            open_regular(&d.path().join("link.nzb"), 1000, None, None),
            Err(OpenError::HardLinked)
        ));
    }

    // SEC-006 / L1
    #[test]
    fn sec006_open_regular_refuses_symlinked_subdirectory_under_root() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("o.nzb"), b"secret");
        std::os::unix::fs::symlink(outside.path(), d.path().join("sub")).unwrap();
        let p = d.path().join("sub").join("o.nzb");
        assert!(matches!(
            open_regular(&p, 1000, None, Some(d.path())),
            Err(OpenError::OutsideRoot)
        ));
        // A real sub-directory is fine.
        fs::create_dir(d.path().join("real")).unwrap();
        write(&d.path().join("real/a.nzb"), b"x");
        assert!(open_regular(&d.path().join("real/a.nzb"), 1000, None, Some(d.path())).is_ok());
    }

    #[test]
    fn recursion_depth_is_limited() {
        let (d, mut s, c) = setup(true);
        let mut p = d.path().to_path_buf();
        for i in 0..6 {
            p = p.join(format!("d{i}"));
            fs::create_dir(&p).unwrap();
            write(&p.join("a.nzb"), b"x");
        }
        // depths 1..=4 are scanned (d0..d3), d4 and d5 are too deep.
        assert_eq!(settle(&mut s, &c).len(), 4);
    }

    // SEC-006
    #[test]
    fn open_regular_refuses_symlink_fifo_and_oversize() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        write(&p.join("a.nzb"), b"hello");
        std::os::unix::fs::symlink(p.join("a.nzb"), p.join("l.nzb")).unwrap();
        mkfifo(&p.join("f.nzb"));
        let (mut f, n) = open_regular(&p.join("a.nzb"), 5, None, None).unwrap();
        assert_eq!(n, 5);
        let mut s = String::new();
        std::io::Read::read_to_string(&mut f, &mut s).unwrap();
        assert_eq!(s, "hello");
        assert!(matches!(
            open_regular(&p.join("a.nzb"), 4, None, None),
            Err(OpenError::TooLarge { size: 5 })
        ));
        assert!(matches!(
            open_regular(&p.join("l.nzb"), 100, None, None),
            Err(OpenError::NotRegular)
        ));
        assert!(matches!(
            open_regular(&p.join("f.nzb"), 100, None, None),
            Err(OpenError::NotRegular)
        ));
        assert!(open_regular(&p.join("missing"), 100, None, None).is_err());
    }

    #[test]
    fn max_limits_batch_and_rest_follow_later() {
        let (d, mut s, c) = setup(false);
        for i in 0..5 {
            write(&d.path().join(format!("{i}.nzb")), b"x");
        }
        assert!(s.scan(2).is_empty());
        c.advance(10);
        // Hold the batches: dropping a candidate releases it for re-offer.
        let b1 = s.scan(2);
        let b2 = s.scan(2);
        let b3 = s.scan(2);
        assert_eq!((b1.len(), b2.len(), b3.len()), (2, 2, 1));
        assert!(s.scan(2).is_empty());
    }

    // L5
    #[test]
    fn dropped_candidate_is_released_and_reoffered() {
        let (d, mut s, c) = setup(false);
        write(&d.path().join("a.nzb"), b"x");
        let held = settle(&mut s, &c);
        assert_eq!(held.len(), 1);
        assert!(s.scan(10).is_empty(), "held: not offered twice");
        drop(held);
        assert_eq!(s.scan(10).len(), 1, "dropped without finish: not leaked");
    }

    #[test]
    fn finish_and_backoff() {
        let (d, mut s, c) = setup(false);
        let f = d.path().join("a.nzb");
        write(&f, b"x");
        let got = settle(&mut s, &c);
        // Pipeline could not move it away: back off 10 minutes, no hot loop.
        s.fail_backoff(&got[0].path);
        drop(got);
        for _ in 0..5 {
            c.advance(100);
            assert!(s.scan(10).is_empty());
        }
        c.advance(100);
        assert!(
            s.scan(10).is_empty(),
            "re-observation starts after backoff expiry"
        );
        c.advance(10);
        let again = s.scan(10);
        assert_eq!(again.len(), 1);
        // Removed file is forgotten.
        s.finish(&f);
        drop(again);
        fs::remove_file(&f).unwrap();
        assert!(s.scan(10).is_empty());
        assert_eq!(s.tracked(), 0);
    }

    // M4
    #[test]
    fn junk_flood_keeps_state_bounded() {
        let (d, mut s, _c) = setup(false);
        for i in 0..(IGNORED_LOG_CAP + 500) {
            write(&d.path().join(format!("junk{i}.txt")), b"x");
        }
        for _ in 0..2 {
            assert!(s.scan(10).is_empty());
            assert!(s.ignored_logged.len() <= IGNORED_LOG_CAP);
        }
    }

    // M4
    #[test]
    fn entry_cap_limits_a_single_scan() {
        let dir = tempfile::tempdir().unwrap();
        let clock = FakeClock::default();
        let cfg = ScannerConfig {
            watch_dir: dir.path().to_path_buf(),
            recursive: false,
            max_file_bytes: 1000,
            stable_secs: 0,
            backoff_secs: 600,
            max_entries_per_scan: 10,
        };
        let mut s = Scanner::new(cfg, clock);
        for i in 0..50 {
            write(&dir.path().join(format!("{i}.nzb")), b"x");
        }
        let _ = s.scan(100);
        assert!(s.tracked() <= 10, "tracked {}", s.tracked());
    }

    #[test]
    fn heartbeat() {
        let (_d, mut s, c) = setup(false);
        assert_eq!(s.last_scan_at(), None);
        c.advance(7);
        let _ = s.scan(1);
        assert_eq!(s.last_scan_at(), Some(7));
        assert!(heartbeat_fresh(Some(7), 20, Duration::from_secs(5)));
        assert!(!heartbeat_fresh(Some(7), 22, Duration::from_secs(5)));
        assert!(!heartbeat_fresh(None, 0, Duration::from_secs(5)));
    }

    /// Dev-only (DEPLOYMENT §Development environment): with the OS watcher disabled the
    /// periodic scan alone discovers files.
    #[test]
    fn ingest_discovery_works_with_inotify_disabled() {
        let (d, mut s, c) = setup(false);
        let w = crate::watcher::WatchHandle::disabled();
        assert!(!w.is_active());
        write(&d.path().join("a.nzb"), b"x");
        assert!(!w.wait(Duration::from_millis(10)));
        let _ = s.scan(10);
        c.advance(10);
        assert!(!w.wait(Duration::from_millis(10)));
        assert_eq!(s.scan(10).len(), 1);
    }

    #[test]
    fn notify_wakes_on_new_file() {
        let d = tempfile::tempdir().unwrap();
        let w = crate::watcher::spawn_watcher(d.path(), false);
        if !w.is_active() {
            return; // platform without a usable watcher; periodic scan covers it
        }
        write(&d.path().join("a.nzb"), b"x");
        assert!(w.wait(Duration::from_secs(5)));
    }

    // M1
    #[test]
    fn idle_scans_do_not_wake_the_watcher() {
        let (d, mut s, _c) = setup(false);
        let w = crate::watcher::spawn_watcher(d.path(), false);
        if !w.is_active() {
            return;
        }
        while w.wait(Duration::from_millis(200)) {}
        let mut wakes = 0;
        for _ in 0..10 {
            let _ = s.scan(10);
            if w.wait(Duration::from_millis(100)) {
                wakes += 1;
            }
        }
        assert_eq!(wakes, 0, "own read_dir must not wake the scanner");
    }

    // M2
    #[test]
    fn recursive_watcher_does_not_follow_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("esc")).unwrap();
        let w = crate::watcher::spawn_watcher(d.path(), true);
        if !w.is_active() {
            return;
        }
        while w.wait(Duration::from_millis(300)) {}
        write(&outside.path().join("x.nzb"), b"x");
        assert!(
            !w.wait(Duration::from_millis(500)),
            "write via planted symlink must not wake the watcher"
        );
    }

    // M4
    #[test]
    fn wake_channel_coalesces() {
        let w = crate::watcher::WatchHandle::disabled();
        for _ in 0..10_000 {
            w.poke();
        }
        assert!(w.wait(Duration::from_millis(10)));
        assert!(!w.wait(Duration::from_millis(10)));
    }

    // M1
    #[test]
    fn event_filter_drops_self_triggered_kinds() {
        use crate::watcher::event_is_relevant as rel;
        use notify::EventKind as K;
        use notify::event::{AccessKind, AccessMode, CreateKind, MetadataKind, ModifyKind};
        assert!(!rel(&K::Access(AccessKind::Open(AccessMode::Any))));
        assert!(!rel(&K::Access(AccessKind::Close(AccessMode::Read))));
        assert!(!rel(&K::Modify(ModifyKind::Metadata(MetadataKind::Any))));
        assert!(rel(&K::Access(AccessKind::Close(AccessMode::Write))));
        assert!(rel(&K::Create(CreateKind::File)));
        assert!(rel(&K::Modify(ModifyKind::Any)));
    }
}

//! Blocking filesystem helpers of the pipeline: bounded read + hash, identity-verified source
//! removal, and no-clobber moves (hard link + verified unlink, or copy → fsync → verify →
//! verified unlink when the destination is on another filesystem). Destination names are built
//! by the caller from a UTC stamp and the SHA-256 only, never from NZB or file names (SEC-005).
//!
//! Removing a user's file is the dangerous operation (BETA: never lose a user's NZB), so every
//! removal goes through [`remove_if_unchanged`]: compare the identity captured *before* the
//! first read, rename the file to a hidden trash name in the same directory, verify the renamed
//! inode once more, and only then unlink it. A file that was swapped in meanwhile is renamed
//! back, never unlinked. Rust's std has no `unlinkat`-by-inode, so this is the closest
//! race-free primitive available without `unsafe`.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nzb_core::Sha256;
use sha2::{Digest, Sha256 as Hasher};

use crate::error::IngestError;
use crate::scanner::{FileId, open_regular};

/// Highest `-N` suffix tried when a destination name is taken.
const MAX_NAME_TRIES: u32 = 1000;
/// Attempts at a unique part-file name.
const MAX_PART_TRIES: u32 = 16;

/// Full identity of a file: inode, size and both timestamps. `ctime` cannot be set from user
/// space, so a same-length rewrite with a restored mtime is still detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceIdent {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: Option<SystemTime>,
    ctime: i64,
    ctime_nsec: i64,
}

impl SourceIdent {
    pub(crate) fn of(meta: &Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime: meta.modified().ok(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }

    /// Size at the time the identity was captured.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// Same inode and content stamps, ignoring `ctime` (which links and renames advance).
    fn same_content(&self, other: &Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.size == other.size
            && self.mtime == other.mtime
    }
}

/// Bytes of a source plus their digest and the identity they were read from.
pub(crate) struct Loaded {
    pub bytes: Vec<u8>,
    pub sha: Sha256,
    /// Identity captured before the first read; `None` for in-memory payloads.
    pub ident: Option<SourceIdent>,
}

/// SHA-256 of `bytes`.
pub(crate) fn digest(bytes: &[u8]) -> Sha256 {
    Sha256(Hasher::digest(bytes).into())
}

/// `INGEST_SPEC` step 1: open without following symlinks, read at most `max + 1` bytes, hash.
pub(crate) fn read_source(
    path: &Path,
    max: u64,
    expected: Option<&FileId>,
    root: Option<&Path>,
) -> Result<Loaded, IngestError> {
    let (file, size) = open_regular(path, max, expected, root)?;
    read_opened(file, size, max, || {})
}

/// Reads an opened regular file. The identity is taken from the descriptor *before* the first
/// read and must be identical after the last one; a torn read (in-place rewrite, even with
/// the same length and a restored mtime) is `SOURCE_CHANGED` and nothing is trusted.
/// `mid_read` runs between the two (fault injection in tests).
pub(crate) fn read_opened(
    mut file: File,
    size: u64,
    max: u64,
    mid_read: impl FnOnce(),
) -> Result<Loaded, IngestError> {
    let before = SourceIdent::of(&file.metadata().map_err(|_| IngestError::SourceChanged)?);
    mid_read();
    let cap = usize::try_from(size.min(max)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(cap);
    (&mut file)
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| IngestError::SourceUnreadable)?;
    let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read > max {
        return Err(IngestError::FileTooLarge);
    }
    let after = SourceIdent::of(&file.metadata().map_err(|_| IngestError::SourceChanged)?);
    if read != size || before.size != size || after != before {
        return Err(IngestError::SourceChanged);
    }
    let sha = digest(&bytes);
    Ok(Loaded {
        bytes,
        sha,
        ident: Some(before),
    })
}

pub(crate) fn lstat_ident(path: &Path) -> io::Result<Option<SourceIdent>> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => Ok(Some(SourceIdent::of(&m))),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Best-effort directory fsync (makes a rename/unlink durable).
pub(crate) fn fsync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A name unique across processes and restarts: pid, nanoseconds and a counter.
pub(crate) fn unique_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        UNIQUE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Unlinks `path` only if it is still the very file that was read (`ident`, taken before the
/// first read). Returns `Ok(false)` and leaves a file at `path` when it changed or vanished.
pub(crate) fn remove_if_unchanged(path: &Path, ident: &SourceIdent) -> io::Result<bool> {
    remove_with_hook(path, ident, || {})
}

/// [`remove_if_unchanged`] with a hook between the precheck and the rename (tests swap the
/// file there to exercise the rename-over race).
pub(crate) fn remove_with_hook(
    path: &Path,
    ident: &SourceIdent,
    between: impl FnOnce(),
) -> io::Result<bool> {
    if lstat_ident(path)?.as_ref() != Some(ident) {
        return Ok(false);
    }
    between();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // Hidden, so the scanner never offers it; unique, so the rename never replaces anything.
    let trash = dir.join(format!(".nzbd-trash.{}", unique_tag()));
    fs::rename(path, &trash)?;
    // The rename advanced the ctime, so compare inode, size and mtime only.
    if lstat_ident(&trash)?.is_some_and(|t| t.same_content(ident)) {
        fs::remove_file(&trash)?;
        fsync_dir(dir);
        return Ok(true);
    }
    // Someone replaced the file between the precheck and the rename: put it back. A hard link
    // fails if yet another file appeared meanwhile; then the file stays under its hidden name
    // (nothing is lost) and the error is reported.
    fs::hard_link(&trash, path)?;
    fs::remove_file(&trash)?;
    Ok(false)
}

fn candidate_name(stem: &str, n: u32) -> String {
    if n == 0 {
        format!("{stem}.nzb")
    } else {
        format!("{stem}-{n}.nzb")
    }
}

/// Moves `src` into `dest_dir` as `<stem>.nzb` (or `<stem>-N.nzb` if taken), never replacing an
/// existing file. Returns the final path. `read` is the identity captured when the file was
/// read: if the file is no longer that file the move is refused (the stem carries the hash of
/// the old content). The source is unlinked only after the destination is durable and verified.
pub(crate) fn move_no_clobber(
    src: &Path,
    dest_dir: &Path,
    stem: &str,
    read: Option<&SourceIdent>,
) -> io::Result<PathBuf> {
    let Some(snapshot) = lstat_ident(src)? else {
        return Err(io::Error::other("source is not a regular file"));
    };
    if read.is_some_and(|r| !r.same_content(&snapshot)) {
        return Err(io::Error::other("source changed since it was read"));
    }
    for n in 0..MAX_NAME_TRIES {
        let dest = dest_dir.join(candidate_name(stem, n));
        match fs::hard_link(src, &dest) {
            Ok(()) => {
                // The link must point at the inode we snapshotted (a rename-over between the
                // snapshot and the link would otherwise move someone else's file).
                let linked = lstat_ident(&dest)?;
                if !linked.as_ref().is_some_and(|l| l.same_content(&snapshot)) {
                    let _ = fs::remove_file(&dest);
                    return Err(io::Error::other("source changed during move"));
                }
                fsync_dir(dest_dir);
                return finish_link_move(src, dest, linked);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            // EXDEV, or a filesystem without hard links (some SMB/FUSE mounts).
            Err(_) => return copy_no_clobber(src, dest_dir, stem, read),
        }
    }
    Err(io::Error::other("no free destination name"))
}

/// After the hard link both names share one inode. Remove the source name with the verified
/// unlink; if the source changed meanwhile (a writer appended), undo the link instead so the
/// kept source never stays at `nlink == 2` (which `open_regular` would refuse forever).
fn finish_link_move(src: &Path, dest: PathBuf, linked: Option<SourceIdent>) -> io::Result<PathBuf> {
    // `linked` was read through the destination name just after linking: it carries the
    // post-link ctime, which is exactly what the source name shows now unless it changed.
    let removed = match linked {
        Some(ident) => remove_if_unchanged(src, &ident)?,
        None => false,
    };
    if removed {
        Ok(dest)
    } else {
        let _ = fs::remove_file(&dest);
        fsync_dir(dest.parent().unwrap_or_else(|| Path::new(".")));
        Err(io::Error::other(
            "source changed during move; left in place",
        ))
    }
}

/// Cross-filesystem move: copy to a hidden part file in `dest_dir`, fsync, verify the digest of
/// what was written, publish under a free name, then unlink the source if it did not change.
pub(crate) fn copy_no_clobber(
    src: &Path,
    dest_dir: &Path,
    stem: &str,
    read: Option<&SourceIdent>,
) -> io::Result<PathBuf> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(src)?;
    let meta = input.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::other("source is not a regular file"));
    }
    let before = SourceIdent::of(&meta);
    if read.is_some_and(|r| !r.same_content(&before)) {
        return Err(io::Error::other("source changed since it was read"));
    }
    let (part, mut out) = create_part(dest_dir, stem)?;
    let result = (|| -> io::Result<PathBuf> {
        let mut hasher = Hasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = buf.get(..n).unwrap_or_default();
            hasher.update(chunk);
            out.write_all(chunk)?;
        }
        out.sync_all()?;
        let copied: [u8; 32] = hasher.finalize().into();
        let reread = hash_file(&part)?;
        if copied != reread || SourceIdent::of(&input.metadata()?) != before {
            return Err(io::Error::other("copy verification failed"));
        }
        publish(&part, dest_dir, stem)
    })();
    let _ = fs::remove_file(&part);
    let dest = result?;
    fsync_dir(dest_dir);
    // The copy is complete and durable: now the source may go (verified, trash-renamed).
    if remove_if_unchanged(src, &before)? {
        Ok(dest)
    } else {
        let _ = fs::remove_file(&dest);
        Err(io::Error::other(
            "source changed during copy; left in place",
        ))
    }
}

fn create_part(dest_dir: &Path, stem: &str) -> io::Result<(PathBuf, File)> {
    for _ in 0..MAX_PART_TRIES {
        let part = dest_dir.join(format!(".{stem}.{}.part", unique_tag()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&part)
        {
            Ok(f) => return Ok((part, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("no free part file name"))
}

fn hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut h = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().into());
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
}

/// Publishes `part` under the first free name without ever replacing a file: hard link, or
/// (filesystems without links) an exclusive-create copy. Never `exists()` + `rename()`.
fn publish(part: &Path, dest_dir: &Path, stem: &str) -> io::Result<PathBuf> {
    for n in 0..MAX_NAME_TRIES {
        let dest = dest_dir.join(candidate_name(stem, n));
        match fs::hard_link(part, &dest) {
            Ok(()) => return Ok(dest),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => match copy_exclusive(part, &dest) {
                Ok(()) => return Ok(dest),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            },
        }
    }
    Err(io::Error::other("no free destination name"))
}

/// `O_EXCL` copy: fails with `AlreadyExists` instead of clobbering. A crash mid-copy leaves a
/// short file in `failed/`/`duplicates/` while the source is still present (it is unlinked only
/// afterwards), so nothing is lost.
fn copy_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let mut src = File::open(from)?;
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    let res = io::copy(&mut src, &mut dst).and_then(|_| dst.sync_all());
    if res.is_err() {
        let _ = fs::remove_file(to);
    }
    res
}

/// True only for the exact names this crate generates for part files: `.<stem>.<tag>.part`
/// with `<stem>` = `<UTC stamp>-<sha8|unknown>[-up]` (cross-filesystem copy) or
/// `<failed name>.reason` (sidecar tmp) and `<tag>` = `<pid>-<nanos>-<counter>`. A user's own
/// hidden `*.part` file never matches (`SECURITY_REVIEW` T032 L2).
pub(crate) fn is_generated_part(name: &str) -> bool {
    let Some(mid) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".part")) else {
        return false;
    };
    let Some((head, tag)) = mid.rsplit_once('.') else {
        return false;
    };
    let tag_ok = {
        let mut it = tag.split('-');
        let nums = [it.next(), it.next(), it.next()];
        it.next().is_none()
            && nums
                .iter()
                .all(|p| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())))
    };
    if !tag_ok {
        return false;
    }
    match head.strip_suffix(".reason") {
        Some(file) => crate::failure::is_failed_name(file),
        None => crate::failure::is_failed_name(&format!("{head}.nzb")),
    }
}

/// Removes leftover hidden part files (see [`is_generated_part`]) of crashed cross-filesystem
/// moves and sidecar writes in a destination directory (startup recovery). A part file is
/// never the only copy: the source is unlinked only after the final name exists. Returns how
/// many were removed.
pub(crate) fn clean_stale_parts(dir: &Path) -> usize {
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    let mut n = 0usize;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_generated_part(name)
            && e.file_type().is_ok_and(|t| t.is_file())
            && fs::remove_file(e.path()).is_ok()
        {
            n = n.saturating_add(1);
        }
    }
    n
}

/// True for names written by [`crate::pipeline`] for a rejected upload:
/// `<16-char UTC stamp>-<8 hex>-up[-N].nzb`.
#[allow(clippy::case_sensitive_file_extension_comparisons)] // our own lowercase names
fn is_upload_reject_name(name: &str) -> bool {
    let b = name.as_bytes();
    let stamp_ok = name.get(..16).is_some_and(|s| {
        s.bytes()
            .all(|c| c.is_ascii_digit() || c == b'T' || c == b'Z')
    });
    let sha_ok = name
        .get(17..25)
        .is_some_and(|s| s.bytes().all(|c| c.is_ascii_hexdigit()));
    stamp_ok
        && sha_ok
        && b.get(16) == Some(&b'-')
        && name.get(25..).is_some_and(|r| r.starts_with("-up"))
        && name.ends_with(".nzb")
}

/// Deletes the oldest rejected *uploads* in `failed/` until at most `max_files` files and
/// `max_bytes` bytes remain (0 = unlimited). Only regular files whose name marks them as an
/// upload reject are candidates: watch-folder files, `reason.json` files and anything else a
/// user put there are never touched (BETA: never delete a user's NZB from the watch folder).
/// Returns the number of files removed.
pub(crate) fn rotate_upload_rejects(dir: &Path, max_files: usize, max_bytes: u64) -> usize {
    if max_files == 0 && max_bytes == 0 {
        return 0;
    }
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    let mut files: Vec<(String, SystemTime, u64, PathBuf)> = Vec::new();
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_upload_reject_name(&name) {
            continue;
        }
        let Ok(m) = fs::symlink_metadata(e.path()) else {
            continue;
        };
        if m.file_type().is_file() {
            let stamp = name.get(..16).unwrap_or_default().to_owned();
            files.push((stamp, m.modified().unwrap_or(UNIX_EPOCH), m.len(), e.path()));
        }
    }
    files.sort();
    let mut count = files.len();
    let mut bytes: u64 = files.iter().map(|f| f.2).sum();
    let mut removed = 0usize;
    for (_, _, len, path) in files {
        let over_files = max_files > 0 && count > max_files;
        let over_bytes = max_bytes > 0 && bytes > max_bytes;
        if !(over_files || over_bytes) {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            // The sidecar is nzbd's own file and has no meaning without its upload.
            let mut side = path.clone().into_os_string();
            side.push(crate::failure::REASON_SUFFIX);
            let _ = fs::remove_file(side);
            removed = removed.saturating_add(1);
            count = count.saturating_sub(1);
            bytes = bytes.saturating_sub(len);
        }
    }
    removed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn pause(path: &Path) {
        // Coarse filesystem timestamps: wait until the kernel's ctime clock has ticked past
        // the file's current ctime, so a rewrite is guaranteed a different ctime (no sleeps).
        assert!(nzb_testkit::wait_for_ctime_tick(path));
    }

    #[test]
    fn move_never_clobbers_and_numbers_names() {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("dest");
        fs::create_dir(&dest).unwrap();
        for i in 0..3u8 {
            let src = d.path().join(format!("s{i}.nzb"));
            fs::write(&src, [i]).unwrap();
            let p = move_no_clobber(&src, &dest, "20240101T000000Z-aaaaaaaa", None).unwrap();
            assert!(!src.exists());
            assert_eq!(fs::read(p).unwrap(), vec![i]);
        }
        let names: std::collections::BTreeSet<_> = fs::read_dir(&dest)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains("20240101T000000Z-aaaaaaaa.nzb"));
        assert!(names.contains("20240101T000000Z-aaaaaaaa-2.nzb"));
    }

    #[test]
    fn copy_fallback_verifies_publishes_and_unlinks() {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("dest");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("x.nzb"), b"existing").unwrap();
        let src = d.path().join("s.nzb");
        fs::write(&src, b"payload").unwrap();
        let p = copy_no_clobber(&src, &dest, "x", None).unwrap();
        assert_eq!(p.file_name().unwrap(), "x-1.nzb");
        assert_eq!(fs::read(dest.join("x.nzb")).unwrap(), b"existing");
        assert_eq!(fs::read(p).unwrap(), b"payload");
        assert!(!src.exists());
        // No part or trash files left behind.
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn t031_l8_exclusive_copy_never_clobbers() {
        let d = tempfile::tempdir().unwrap();
        let part = d.path().join("p");
        fs::write(&part, b"new").unwrap();
        let taken = d.path().join("taken.nzb");
        fs::write(&taken, b"old").unwrap();
        let e = copy_exclusive(&part, &taken).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&taken).unwrap(), b"old");
        // publish() falls through to the next free name when links are unavailable/taken.
        fs::write(d.path().join("x.nzb"), b"old").unwrap();
        let p = publish(&part, d.path(), "x").unwrap();
        assert_eq!(p.file_name().unwrap(), "x-1.nzb");
        assert_eq!(fs::read(d.path().join("x.nzb")).unwrap(), b"old");
    }

    #[test]
    fn remove_if_unchanged_keeps_modified_source() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.nzb");
        fs::write(&p, b"one").unwrap();
        let l = read_source(&p, 100, None, None).unwrap();
        pause(&p);
        fs::write(&p, b"longer content").unwrap();
        assert!(!remove_if_unchanged(&p, l.ident.as_ref().unwrap()).unwrap());
        assert!(p.exists());
        let l = read_source(&p, 100, None, None).unwrap();
        assert!(remove_if_unchanged(&p, l.ident.as_ref().unwrap()).unwrap());
        assert!(!p.exists());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0, "no trash left");
    }

    #[test]
    fn t031_m1_same_length_rewrite_with_restored_mtime_keeps_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.nzb");
        fs::write(&p, b"AAAA").unwrap();
        let l = read_source(&p, 100, None, None).unwrap();
        let mtime = fs::metadata(&p).unwrap().modified().unwrap();
        pause(&p);
        fs::write(&p, b"BBBB").unwrap(); // same length
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(mtime)
            .unwrap(); // `touch -r`
        assert!(!remove_if_unchanged(&p, l.ident.as_ref().unwrap()).unwrap());
        assert_eq!(fs::read(&p).unwrap(), b"BBBB");
    }

    #[test]
    fn t031_m1_torn_read_is_source_changed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.nzb");
        fs::write(&p, b"AAAA").unwrap();
        let (file, size) = open_regular(&p, 100, None, None).unwrap();
        let p2 = p.clone();
        // The rewrite lands after the pre-read identity was taken and before the data is read.
        let res = read_opened(file, size, 100, move || {
            pause(&p2);
            let f = File::options().write(true).open(&p2).unwrap();
            let mtime = f.metadata().unwrap().modified().unwrap();
            (&f).write_all(b"BBBB").unwrap();
            f.set_modified(mtime).unwrap();
        });
        assert!(matches!(res, Err(IngestError::SourceChanged)));
        assert_eq!(fs::read(&p).unwrap(), b"BBBB");
    }

    #[test]
    fn t031_l1_file_swapped_in_before_the_unlink_is_restored() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.nzb");
        fs::write(&p, b"read").unwrap();
        let l = read_source(&p, 100, None, None).unwrap();
        let (p2, other) = (p.clone(), d.path().join("b.nzb"));
        fs::write(&other, b"users-new-file").unwrap();
        // rename-over between the precheck and the unlink
        let done = remove_with_hook(&p, l.ident.as_ref().unwrap(), move || {
            fs::rename(&other, &p2).unwrap();
        })
        .unwrap();
        assert!(!done);
        assert_eq!(fs::read(&p).unwrap(), b"users-new-file");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "no trash left");
    }

    #[test]
    fn t031_l3_kept_source_does_not_stay_hard_linked() {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("dest");
        fs::create_dir(&dest).unwrap();
        let src = d.path().join("s.nzb");
        fs::write(&src, b"abc").unwrap();
        let read = read_source(&src, 100, None, None).unwrap();
        pause(&src);
        // The file was replaced after it was read: the move is refused, nothing is linked.
        fs::write(&src, b"abcdef").unwrap();
        let e = move_no_clobber(&src, &dest, "stem", read.ident.as_ref());
        assert!(e.is_err());
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
        assert_eq!(fs::metadata(&src).unwrap().nlink(), 1);
        // A writer appends right after the link: the link is undone, nlink back to 1.
        let snapshot = lstat_ident(&src).unwrap().unwrap();
        let linked_name = dest.join("x.nzb");
        fs::hard_link(&src, &linked_name).unwrap();
        let linked = lstat_ident(&linked_name);
        pause(&src);
        fs::write(&src, b"abcdefgh").unwrap();
        assert!(finish_link_move(&src, linked_name.clone(), linked.unwrap()).is_err());
        assert!(!linked_name.exists());
        assert_eq!(fs::metadata(&src).unwrap().nlink(), 1);
        assert_eq!(fs::read(&src).unwrap(), b"abcdefgh");
        let _ = snapshot;
    }

    #[test]
    fn t031_l7_part_names_are_unique_and_stale_parts_are_cleaned() {
        let d = tempfile::tempdir().unwrap();
        let (a, _fa) = create_part(d.path(), "20231114T221320Z-abcdef12").unwrap();
        let (b, _fb) = create_part(d.path(), "20231114T221320Z-abcdef12-up").unwrap();
        assert_ne!(a, b);
        fs::write(d.path().join(".20231114T221320Z-abcdef12.1-2-3.part"), b"x").unwrap();
        fs::write(
            d.path()
                .join(".20231114T221320Z-abcdef12.nzb.reason.1-2-3.part"),
            b"x",
        )
        .unwrap();
        fs::write(d.path().join("keep.nzb"), b"x").unwrap();
        fs::write(d.path().join(".hidden.nzb"), b"x").unwrap();
        assert_eq!(clean_stale_parts(d.path()), 4);
        assert!(d.path().join("keep.nzb").exists() && d.path().join(".hidden.nzb").exists());
    }

    #[test]
    fn t032_l2_only_generated_part_names_are_cleaned() {
        let d = tempfile::tempdir().unwrap();
        let foreign = [
            ".my-notes.part",
            ".draft.part",
            ".old.1.part",
            ".20231114T221320Z-abcdef12.1-2.part",
            ".20231114T221320Z-abcdef12.1-2-3-4.part",
            ".20231114T221320Z-abcdef12.a-b-c.part",
            ".20231114T221320Z-ABCDEF12.1-2-3.part",
            "20231114T221320Z-abcdef12.1-2-3.part",
            ".20231114T221320Z-abcdef12.1-2-3.part.bak",
            ".x.nzb.reason.1-2-3.part",
        ];
        for f in foreign {
            fs::write(d.path().join(f), b"mine").unwrap();
        }
        assert_eq!(clean_stale_parts(d.path()), 0);
        for f in foreign {
            assert!(d.path().join(f).exists(), "{f}");
        }
    }

    #[test]
    fn read_is_bounded_and_symlinks_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("big.nzb");
        fs::write(&p, vec![b'x'; 11]).unwrap();
        assert!(matches!(
            read_source(&p, 10, None, None),
            Err(IngestError::FileTooLarge)
        ));
        let l = d.path().join("link.nzb");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(matches!(
            read_source(&l, 100, None, None),
            Err(IngestError::SourceUnreadable)
        ));
    }
}

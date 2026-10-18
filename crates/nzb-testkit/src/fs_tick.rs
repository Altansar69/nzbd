//! Deterministic replacement for "sleep a few ms so the next write gets a different ctime".
//!
//! Linux stamps `ctime`/`mtime` from a coarse kernel clock (one jiffy, 1-10 ms), and `ctime`
//! cannot be set from user space. A test that needs "this rewrite is observable through ctime"
//! used to sleep a fixed time, which is both slow and still racy on a loaded host. Instead we
//! ask the filesystem itself: create a scratch file next to the target until *its* ctime is
//! strictly newer than the target's. Every later write to the target is then stamped with a
//! tick at or after the probe's, hence different from the one recorded before the call.
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static PROBE: AtomicU64 = AtomicU64::new(0);

/// Blocks until the filesystem holding `path`'s parent directory has ticked past the current
/// `ctime` of `path`. Returns `false` only if no tick was observed within 30 s (a stuck
/// clock), so callers can `assert!` on it. A missing `path` counts as ticked.
#[must_use]
pub fn wait_for_ctime_tick(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return true;
    };
    let target = (meta.ctime(), meta.ctime_nsec());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let probe = dir.join(format!(
        ".ctime-probe-{}-{}",
        std::process::id(),
        PROBE.fetch_add(1, Ordering::Relaxed)
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ticked = false;
    while Instant::now() < deadline {
        let seen = fs::File::create(&probe)
            .and_then(|mut f| {
                f.write_all(b"x")?;
                f.metadata()
            })
            .map(|m| (m.ctime(), m.ctime_nsec()));
        if matches!(seen, Ok(t) if t > target) {
            ticked = true;
            break;
        }
        std::thread::yield_now();
    }
    let _ = fs::remove_file(&probe);
    ticked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_after_the_tick_has_a_newer_ctime() {
        let d = std::env::temp_dir().join(format!("nzbd-tick-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        let p = d.join("f");
        for _ in 0..50 {
            fs::write(&p, b"a").unwrap();
            let m = fs::metadata(&p).unwrap();
            let before = (m.ctime(), m.ctime_nsec());
            assert!(wait_for_ctime_tick(&p));
            fs::write(&p, b"b").unwrap();
            let m = fs::metadata(&p).unwrap();
            assert!((m.ctime(), m.ctime_nsec()) > before);
        }
        fs::remove_dir_all(&d).unwrap();
    }
}

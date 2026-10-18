//! `notify` integration. Events are only a *wake-up hint*: they never carry paths into the
//! pipeline, so a forged or missing event cannot change what is ingested. The periodic scan
//! stays authoritative (events are unreliable on Docker bind mounts / NFS / SMB).

use std::path::Path;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use notify::event::{AccessKind, AccessMode, ModifyKind};
use notify::{Config, EventKind, RecursiveMode, Watcher};

/// Whether an event can mean "the directory content changed". `Access(Open)` and
/// `Access(Close(NoWrite))` are produced by our own `read_dir` scans and would make the
/// scanner wake itself in a hot loop; metadata-only changes never make a file ready.
#[must_use]
pub fn event_is_relevant(kind: &EventKind) -> bool {
    match kind {
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
        EventKind::Access(_) | EventKind::Modify(ModifyKind::Metadata(_)) => false,
        EventKind::Any
        | EventKind::Create(_)
        | EventKind::Modify(_)
        | EventKind::Remove(_)
        | EventKind::Other => true,
    }
}

/// Keeps the OS watcher alive and exposes the wake-up channel.
pub struct WatchHandle {
    watcher: Option<notify::RecommendedWatcher>,
    wake_tx: SyncSender<()>,
    // Mutex only to make the handle `Sync` (it is shared with a blocking wait task).
    wake_rx: Mutex<Receiver<()>>,
}

impl WatchHandle {
    /// A handle without an OS watcher (inotify disabled / unavailable): periodic scan only.
    #[must_use]
    pub fn disabled() -> Self {
        // Capacity 1 + try_send: wake-ups coalesce, memory stays bounded under event floods.
        let (wake_tx, wake_rx) = sync_channel(1);
        Self {
            watcher: None,
            wake_tx,
            wake_rx: Mutex::new(wake_rx),
        }
    }

    /// Whether an OS watcher is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.watcher.is_some()
    }

    /// Wait up to `timeout` for an event, then drain any burst. Returns true if woken by an
    /// event, false on timeout (the caller scans in both cases). The caller must still enforce
    /// a minimum gap between scans.
    #[must_use]
    pub fn wait(&self, timeout: Duration) -> bool {
        let rx = self.wake_rx.lock().unwrap_or_else(PoisonError::into_inner);
        let woke = rx.recv_timeout(timeout).is_ok();
        while rx.try_recv().is_ok() {}
        woke
    }

    /// Manually request a scan (used by tests and by upload paths).
    pub fn poke(&self) {
        let _ = self.wake_tx.try_send(());
    }
}

fn notify_wake(tx: &SyncSender<()>) {
    match tx.try_send(()) {
        Ok(()) | Err(TrySendError::Full(()) | TrySendError::Disconnected(())) => {}
    }
}

/// Start watching `dir`. Failure to start is not fatal: the error is logged and the handle
/// degrades to periodic scanning only. Symlinks are never followed by the recursive watch.
#[must_use]
pub fn spawn_watcher(dir: &Path, recursive: bool) -> WatchHandle {
    let (wake_tx, wake_rx) = sync_channel(1);
    let tx = wake_tx.clone();
    let made = notify::RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            if res.is_ok_and(|ev| event_is_relevant(&ev.kind)) {
                notify_wake(&tx);
            }
        },
        Config::default().with_follow_symlinks(false),
    );
    let watch_mode = if recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    let watcher = match made {
        Ok(mut w) => match w.watch(dir, watch_mode) {
            Ok(()) => Some(w),
            Err(e) => {
                tracing::warn!(error = %e, "watch registration failed; periodic scan only");
                None
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "watcher unavailable; periodic scan only");
            None
        }
    };
    WatchHandle {
        watcher,
        wake_tx,
        wake_rx: Mutex::new(wake_rx),
    }
}

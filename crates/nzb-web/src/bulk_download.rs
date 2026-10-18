//! `POST /releases/bulk/download` (T130): the ticked releases of the result list as one `.zip`.
//!
//! The index form posts repeated `id` fields (the T119 bulk form, CSRF token first). The route sits
//! behind the active-session gate (any role that may download: viewer and up), which verified
//! Origin and the synchronizer token and charged the download buckets: the per-IP download class
//! (30/min) in the rate-limit layer and the per-account download bucket after the role check.
//!
//! # Order
//! 1. **Capacity** (review 46 L1/L4): the account must not already run a bulk download, then a permit
//!    of the bulk pool ([`MAX_CONCURRENT_BULK_DOWNLOADS`]) and one of the shared download pool
//!    ([`crate::download::MAX_CONCURRENT_DOWNLOADS`]); otherwise `503 BUSY` with
//!    `Retry-After: 30` ([`BULK_BUSY_RETRY_AFTER_SECS`]). Checked **before** the strict bulk budget is
//!    charged, so a busy answer costs none of it.
//! 2. **Strict budget:** [`BULK_DOWNLOADS_PER_MIN`] per client IP and per account (`429`); from here
//!    every request counts, whatever its outcome.
//! 3. The form: at most [`crate::bulk::MAX_FORM_FIELDS`] fields (else `400 BAD_REQUEST`), 1 to
//!    [`nzb_store::MAX_BULK_IDS`] strict `id` fields (`NO_SELECTION`, `TOO_MANY_IDS`, `INVALID_ID`);
//!    other fields of the shared bulk form (`category`, `source`, `action`) are ignored.
//! 4. Each id is looked up; unknown releases and releases of a category hidden from the caller are
//!    **skipped silently**, exactly as the list hides them: they are never named in the archive or
//!    the response. If none remain, the uniform `404 NOT_FOUND`.
//! 5. The stored NZB sizes are summed; over [`MAX_BULK_DOWNLOAD_BYTES`] the answer is
//!    `413 BULK_DOWNLOAD_TOO_LARGE` before any blob is read.
//! 6. One best-effort audit row `download_bulk count=<n>` (attributed: an `ID_EVENTS` entry).
//! 7. The response starts; a detached producer task owns the permits and the account's running
//!    slot and writes the archive.
//!
//! # Streaming
//! The producer reads one blob at a time from the store (which verifies its SHA-256), writes the
//! local header (CRC-32 computed over the verified bytes), then the bytes in [`FRAME_BYTES`]
//! frames copied out of the blob, so the blob is freed as soon as its last frame is queued: memory
//! is one blob plus [`QUEUE_FRAMES`] frames. Frames go through a small bounded channel to the
//! response body, so a slow reader slows the producer down instead of buffering. After the end of
//! central directory record the producer sends an explicit **end marker**; the body ends cleanly
//! only after it (review 46 L2).
//!
//! The permits are released when the producer ends: archive complete, client gone (the next send
//! fails), store error, too slow a reader, or the deadline. **Deadline:** one `Instant` shared by
//! body and producer, [`BulkLimits::deadline`] of the total stored size: 60 s + 1 s per MiB, at
//! most [`BULK_DEADLINE_MAX`] (4 min 30 s, below the shipped proxy's 5-minute write timeout, review
//! 46 L3). **Minimum throughput** (review 46 L1): after a [`BULK_PROGRESS_GRACE`] of 30 s, every
//! [`BULK_PROGRESS_WINDOW`] of 30 s in which the producer waited for the reader must see at least
//! [`BULK_MIN_PROGRESS_BYTES`] (256 KiB) taken by the body, or the download is aborted.
//!
//! **No partial success that looks complete:** if a blob is corrupt or missing while its release
//! still exists, the reader is too slow, or the deadline passes, the channel closes without the end
//! marker, the body ends with an error, the server aborts the response without the final chunk (the
//! client sees a failed transfer) and the archive never gets its central directory. A release
//! deleted (or hidden, or replaced) while the archive streams is left out instead (review 46 I2),
//! before its header is written, so the archive stays consistent. The response has no
//! `Content-Length` (chunked): the stored sizes decide the cap, but the archive size is never
//! promised from them.
//!
//! # Format
//! A plain ZIP (APPNOTE 6.3.x subset): STORE method only (no compression, so no decompression
//! bomb for the client and nothing to tune), no data descriptors (the CRC is known before the
//! header), no zip64 (the cap keeps every offset far below 4 GiB), no extra fields, no comments.
//! Entry names are [`crate::download::safe_filename`] (plain `[A-Za-z0-9._-]`, never a path, never
//! starting with a dot), de-duplicated case-insensitively by inserting `-<id>` before `.nzb`.
//! Entries are in ascending release id order. Every entry carries the download time (UTC, DOS
//! format, 2-second resolution).

use nzb_store::prelude::*;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body::{Body, Frame};
use nzb_core::Sha256;
use nzb_store::{NzbStore, Store, StoreError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Instant, Sleep};

use crate::auth::{SessionCtx, WallClock};
use crate::csrf;
use crate::ctx::ClientIp;
use crate::download::{audit, content_disposition, safe_filename};
use crate::error::ApiError;
use crate::middleware::SharedLimiter;
use crate::ratelimit::{Class, Decision, KeyedLimiter};
use crate::release::{St, fail, internal, not_found};

pub use crate::ratelimit::BULK_DOWNLOADS_PER_MIN;

/// Audit event of the bulk download (an `ID_EVENTS` entry of the store: attributed by user id).
pub const BULK_DOWNLOAD_EVENT: &str = "download_bulk";
/// Concurrent bulk downloads (on top of one permit of the shared download pool each).
pub const MAX_CONCURRENT_BULK_DOWNLOADS: usize = 1;
/// Largest total of stored NZB bytes one archive may hold (1 GiB). Decided from the stored sizes
/// before streaming and enforced again on the bytes actually read.
pub const MAX_BULK_DOWNLOAD_BYTES: u64 = 1 << 30;
/// Fixed part of the send deadline.
pub const BULK_DEADLINE_BASE: Duration = Duration::from_secs(60);
/// The deadline grows by one second per this many stored bytes (1 MiB).
pub const BULK_DEADLINE_BYTES_PER_SEC: u64 = 1 << 20;
/// Hard maximum of the send deadline: 4 min 30 s, kept below the 5-minute `write` timeout of the
/// shipped Caddy (`deploy/Caddyfile`), which would cut a longer response anyway (review 46 L3).
/// At the 1 GiB cap this needs about 3.8 MiB/s; slower links should select fewer releases.
pub const BULK_DEADLINE_MAX: Duration = Duration::from_secs(270);
/// No throughput rule during the first seconds of a download.
pub const BULK_PROGRESS_GRACE: Duration = Duration::from_secs(30);
/// Length of one throughput window.
pub const BULK_PROGRESS_WINDOW: Duration = Duration::from_secs(30);
/// Bytes the reader must take per [`BULK_PROGRESS_WINDOW`] while the producer waits for it.
pub const BULK_MIN_PROGRESS_BYTES: u64 = 256 * 1024;
/// `Retry-After` of a busy answer: about how long a typical bulk download takes.
pub const BULK_BUSY_RETRY_AFTER_SECS: u64 = 30;
/// Media type of the archive.
pub const ZIP_CONTENT_TYPE: &str = "application/zip";
/// Size of one body frame.
const FRAME_BYTES: usize = 64 * 1024;
/// Frames queued between the producer and the body (backpressure: 256 KiB at most).
const QUEUE_FRAMES: usize = 4;
/// Upper bound of tracked accounts in the per-account bulk bucket.
const MAX_TRACKED_ACCOUNTS: usize = 4096;

/// Tunables of the bulk download. The defaults are the documented constants; tests shrink the
/// times through [`crate::release::routes_with_bulk`].
#[derive(Clone, Copy, Debug)]
pub struct BulkLimits {
    /// Concurrent bulk downloads, instance-wide.
    pub max_concurrent: usize,
    /// Fixed part of the deadline.
    pub deadline_base: Duration,
    /// Stored bytes per extra second of deadline.
    pub deadline_bytes_per_sec: u64,
    /// Hard maximum of the deadline.
    pub deadline_max: Duration,
    /// Time before the throughput rule applies.
    pub progress_grace: Duration,
    /// Throughput window.
    pub progress_window: Duration,
    /// Minimum bytes per window.
    pub min_progress_bytes: u64,
}

impl Default for BulkLimits {
    fn default() -> Self {
        Self {
            max_concurrent: MAX_CONCURRENT_BULK_DOWNLOADS,
            deadline_base: BULK_DEADLINE_BASE,
            deadline_bytes_per_sec: BULK_DEADLINE_BYTES_PER_SEC,
            deadline_max: BULK_DEADLINE_MAX,
            progress_grace: BULK_PROGRESS_GRACE,
            progress_window: BULK_PROGRESS_WINDOW,
            min_progress_bytes: BULK_MIN_PROGRESS_BYTES,
        }
    }
}

impl BulkLimits {
    /// Send deadline for an archive of `total` stored bytes: the base plus one second per
    /// `deadline_bytes_per_sec`, at most `deadline_max`.
    #[must_use]
    pub fn deadline(&self, total: u64) -> Duration {
        let per_sec = self.deadline_bytes_per_sec.max(1);
        self.deadline_base
            .saturating_add(Duration::from_secs(total.div_ceil(per_sec)))
            .min(self.deadline_max)
    }
}

/// [`BulkLimits::deadline`] with the default limits.
#[must_use]
pub fn bulk_deadline(total: u64) -> Duration {
    BulkLimits::default().deadline(total)
}

/// Shared state of the bulk download route (held by the release routes' state).
pub(crate) struct BulkState {
    limits: BulkLimits,
    pool: Arc<Semaphore>,
    /// Accounts with a running bulk download (at most one each, review 46 L1).
    running: Mutex<HashSet<i64>>,
    /// Per-account bulk budget.
    accounts: KeyedLimiter<i64>,
}

impl BulkState {
    pub(crate) fn new(limits: BulkLimits, clock: Arc<dyn WallClock>) -> Self {
        Self {
            pool: Arc::new(Semaphore::new(limits.max_concurrent.max(1))),
            running: Mutex::new(HashSet::new()),
            accounts: KeyedLimiter::new(
                BULK_DOWNLOADS_PER_MIN,
                MAX_TRACKED_ACCOUNTS,
                Arc::new(crate::bulk::WallMs(clock)),
            ),
            limits,
        }
    }
}

/// The account's running slot; freed when dropped (with the producer, or on an early return).
struct Running {
    state: Arc<BulkState>,
    user_id: i64,
}

impl Running {
    fn claim(state: &Arc<BulkState>, user_id: i64) -> Option<Self> {
        let mut set = state.running.lock().unwrap_or_else(PoisonError::into_inner);
        set.insert(user_id).then(|| Self {
            state: Arc::clone(state),
            user_id,
        })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.state
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.user_id);
    }
}

/// `(year, month, day, hour, minute, second)` in UTC of unix seconds (clamped to 1970..=9999).
fn utc_parts(ts: i64) -> (i64, i64, i64, i64, i64, i64) {
    let ts = ts.clamp(0, 253_402_300_799);
    let (y, m, d) = crate::index::civil_from_days(ts.div_euclid(86_400));
    let rem = ts.rem_euclid(86_400);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Archive name: `nzbd-<n>-releases-<yyyymmdd-hhmmss>.zip` (UTC).
#[must_use]
pub fn archive_name(count: usize, now: i64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(now);
    format!("nzbd-{count}-releases-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}.zip")
}

/// MS-DOS `(time, date)` of unix seconds (UTC); dates before 1980 become 1980-01-01 00:00:00 and
/// after 2107 the last representable day.
#[must_use]
pub fn dos_time_date(now: i64) -> (u16, u16) {
    let (y, mo, d, h, mi, s) = utc_parts(now);
    if y < 1980 {
        return (0, (1 << 5) | 1);
    }
    let (y, mo, d, h, mi, s) = if y > 2107 {
        (2107, 12, 31, 23, 59, 58)
    } else {
        (y, mo, d, h, mi, s)
    };
    let pack = |v: i64| u16::try_from(v).unwrap_or(0);
    let time = (pack(h) << 11) | (pack(mi) << 5) | pack(s / 2);
    let date = (pack(y - 1980) << 9) | (pack(mo) << 5) | pack(d);
    (time, date)
}

/// Entry names for `(id, title)` pairs in the given order: [`safe_filename`], and for a name already
/// used (compared case-insensitively, as on common desktop file systems) `-<id>` before `.nzb`,
/// repeated until the name is free.
#[must_use]
pub fn entry_names(items: &[(i64, &str)]) -> Vec<String> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for (id, title) in items {
        let mut name = safe_filename(title, *id);
        while used.contains(&name.to_ascii_lowercase()) {
            let stem = name.strip_suffix(".nzb").unwrap_or(&name);
            name = format!("{stem}-{id}.nzb");
        }
        used.insert(name.to_ascii_lowercase());
        out.push(name);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// ZIP writer

/// The archive would not fit the classic (non-zip64) format.
#[derive(Debug, PartialEq, Eq)]
pub struct ZipTooLarge;

/// Minimal streaming ZIP writer (STORE only, no zip64). The caller sends, in order, for each entry
/// the bytes of [`ZipWriter::entry_header`] then the entry data unchanged, and finally the bytes
/// of [`ZipWriter::finish`] (central directory and end record).
pub struct ZipWriter {
    /// Bytes written so far (offset of the next local header).
    offset: u32,
    central: Vec<u8>,
    entries: u16,
    time: u16,
    date: u16,
}

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const END_SIG: u32 = 0x0605_4b50;
/// Version 2.0 (made by MS-DOS / needed to extract): the baseline every unzip tool reads.
const VERSION: u16 = 20;

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

impl ZipWriter {
    /// A writer whose entries all carry this MS-DOS time and date ([`dos_time_date`]).
    #[must_use]
    pub fn new(time: u16, date: u16) -> Self {
        Self {
            offset: 0,
            central: Vec::new(),
            entries: 0,
            time,
            date,
        }
    }

    /// The local file header of an entry named `name` (ASCII) holding `data`; records its central
    /// directory entry and advances the offset past header and data.
    ///
    /// # Errors
    /// [`ZipTooLarge`] when the name, the entry count or an offset would not fit the format.
    pub fn entry_header(&mut self, name: &str, data: &[u8]) -> Result<Vec<u8>, ZipTooLarge> {
        let name_len = u16::try_from(name.len()).map_err(|_| ZipTooLarge)?;
        let size = u32::try_from(data.len()).map_err(|_| ZipTooLarge)?;
        let entries = self.entries.checked_add(1).ok_or(ZipTooLarge)?;
        let crc = crc32fast::hash(data);
        let mut h = Vec::with_capacity(30_usize.saturating_add(name.len()));
        put32(&mut h, LOCAL_SIG);
        put16(&mut h, VERSION);
        put16(&mut h, 0); // flags: no data descriptor, names are ASCII
        put16(&mut h, 0); // method: stored
        put16(&mut h, self.time);
        put16(&mut h, self.date);
        put32(&mut h, crc);
        put32(&mut h, size); // compressed size
        put32(&mut h, size); // uncompressed size
        put16(&mut h, name_len);
        put16(&mut h, 0); // extra field length
        h.extend_from_slice(name.as_bytes());
        let header_len = u32::try_from(h.len()).map_err(|_| ZipTooLarge)?;
        let next = self
            .offset
            .checked_add(header_len)
            .and_then(|o| o.checked_add(size))
            .ok_or(ZipTooLarge)?;
        let c = &mut self.central;
        put32(c, CENTRAL_SIG);
        put16(c, VERSION); // made by
        put16(c, VERSION); // needed
        put16(c, 0);
        put16(c, 0);
        put16(c, self.time);
        put16(c, self.date);
        put32(c, crc);
        put32(c, size);
        put32(c, size);
        put16(c, name_len);
        put16(c, 0); // extra
        put16(c, 0); // comment
        put16(c, 0); // disk number start
        put16(c, 0); // internal attributes
        put32(c, 0); // external attributes
        put32(c, self.offset);
        c.extend_from_slice(name.as_bytes());
        self.offset = next;
        self.entries = entries;
        Ok(h)
    }

    /// The central directory and the end-of-central-directory record.
    ///
    /// # Errors
    /// [`ZipTooLarge`] when the directory would end beyond 4 GiB.
    pub fn finish(self) -> Result<Vec<u8>, ZipTooLarge> {
        let cd_size = u32::try_from(self.central.len()).map_err(|_| ZipTooLarge)?;
        self.offset.checked_add(cd_size).ok_or(ZipTooLarge)?;
        let mut out = self.central;
        put32(&mut out, END_SIG);
        put16(&mut out, 0); // this disk
        put16(&mut out, 0); // disk with the central directory
        put16(&mut out, self.entries);
        put16(&mut out, self.entries);
        put32(&mut out, cd_size);
        put32(&mut out, self.offset);
        put16(&mut out, 0); // comment length
        Ok(out)
    }
}

// ---------------------------------------------------------------------------------------------
// Response body

/// Why the archive was cut off (the body ends with this error, so the response is aborted).
#[derive(Debug)]
pub struct BulkAbort;

impl std::fmt::Display for BulkAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bulk download aborted")
    }
}

impl std::error::Error for BulkAbort {}

/// One item from the producer.
enum Msg {
    Data(Bytes),
    /// The archive is complete (sent after the end of central directory record).
    Done,
}

/// The streamed archive: frames from the producer, cut off at the deadline; a channel that closes
/// without [`Msg::Done`] is an error.
struct BulkBody {
    rx: Option<mpsc::Receiver<Msg>>,
    deadline: Pin<Box<Sleep>>,
    /// Bytes handed to the server so far (read by the producer's throughput rule).
    taken: Arc<AtomicU64>,
}

impl Body for BulkBody {
    type Data = Bytes;
    type Error = BulkAbort;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BulkAbort>>> {
        let this = &mut *self;
        let Some(rx) = this.rx.as_mut() else {
            return Poll::Ready(None);
        };
        if this.deadline.as_mut().poll(cx).is_ready() {
            // Dropping the receiver stops the producer at its next send.
            this.rx = None;
            return Poll::Ready(Some(Err(BulkAbort)));
        }
        match rx.poll_recv(cx) {
            Poll::Ready(Some(Msg::Data(b))) => {
                this.taken.fetch_add(
                    u64::try_from(b.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                Poll::Ready(Some(Ok(Frame::data(b))))
            }
            Poll::Ready(Some(Msg::Done)) => {
                this.rx = None;
                Poll::Ready(None)
            }
            // Closed without the end marker: the producer failed, timed out or stopped.
            Poll::Ready(None) => {
                this.rx = None;
                Poll::Ready(Some(Err(BulkAbort)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.rx.is_none()
    }
}

// ---------------------------------------------------------------------------------------------
// Producer

/// One archive entry, decided before streaming.
struct Entry {
    id: i64,
    sha: Sha256,
    name: String,
}

/// Why the producer ended without completing the archive.
enum Stop {
    /// The receiver is gone (client disconnected or body deadline).
    Gone,
    /// The reader took too little in a throughput window.
    Slow,
    /// Store or format error (already logged).
    Failed,
}

/// Sends with the throughput rule: while the producer waits for queue space, each window must
/// see at least the minimum taken by the body. Time spent elsewhere (reading the store) restarts
/// the window instead of counting against the reader.
struct Pacer {
    tx: mpsc::Sender<Msg>,
    taken: Arc<AtomicU64>,
    judge_from: Instant,
    next_check: Instant,
    mark: u64,
    window: Duration,
    min: u64,
}

impl Pacer {
    fn new(tx: mpsc::Sender<Msg>, taken: Arc<AtomicU64>, limits: &BulkLimits) -> Self {
        let start = Instant::now() + limits.progress_grace;
        Self {
            tx,
            taken,
            judge_from: start,
            next_check: start,
            mark: 0,
            window: limits.progress_window.max(Duration::from_millis(1)),
            min: limits.min_progress_bytes,
        }
    }

    async fn send(&mut self, msg: Msg) -> Result<(), Stop> {
        let now = Instant::now();
        if now >= self.next_check {
            self.mark = self.taken.load(Ordering::Relaxed);
            self.next_check = now + self.window;
        }
        loop {
            match tokio::time::timeout_at(self.next_check, self.tx.reserve()).await {
                Ok(Ok(permit)) => {
                    permit.send(msg);
                    return Ok(());
                }
                Ok(Err(_)) => return Err(Stop::Gone),
                Err(_) => {
                    let now_taken = self.taken.load(Ordering::Relaxed);
                    if self.next_check > self.judge_from
                        && now_taken.saturating_sub(self.mark) < self.min
                    {
                        return Err(Stop::Slow);
                    }
                    self.mark = now_taken;
                    self.next_check += self.window;
                }
            }
        }
    }

    /// Sends `bytes` as frames copied out of it (so the caller can free the source at once).
    async fn frames(&mut self, bytes: &[u8]) -> Result<(), Stop> {
        for chunk in bytes.chunks(FRAME_BYTES) {
            self.send(Msg::Data(Bytes::copy_from_slice(chunk))).await?;
        }
        Ok(())
    }
}

/// What the producer needs besides the channel.
struct Job {
    store: Arc<dyn NzbStore>,
    db: Store,
    sess: SessionCtx,
    entries: Vec<Entry>,
    dos: (u16, u16),
}

/// Whether a missing blob belongs to a release that is gone (deleted, hidden or replaced since the
/// lookup): such an entry is skipped. `false` when it still exists unchanged (a store problem).
async fn vanished(job: &Job, e: &Entry) -> bool {
    match job.db.get_release(e.id).await {
        Ok(Some(r)) => r.sha256 != e.sha || job.sess.hides_category(r.category_id),
        Ok(None) => true,
        // Cannot tell: treat it as a store problem (abort).
        Err(err) => {
            tracing::error!(error = %err, "release lookup failed during bulk download");
            false
        }
    }
}

/// Writes the archive and the end marker. Any `Err` leaves the archive without its end.
async fn produce(job: Job, pacer: &mut Pacer) -> Result<(), Stop> {
    let (time, date) = job.dos;
    let mut zip = ZipWriter::new(time, date);
    let mut total: u64 = 0;
    for e in &job.entries {
        let bytes = match job.store.get(&e.sha).await {
            Ok(b) => b,
            Err(StoreError::NotFound) if vanished(&job, e).await => {
                // Deleted meanwhile (review 46 I2): left out like the list would, header not written.
                tracing::info!(
                    release_id = e.id,
                    "release gone during bulk download, entry skipped"
                );
                continue;
            }
            Err(err) => {
                let class = match err {
                    StoreError::NotFound => "missing",
                    StoreError::Corrupt => "corrupt",
                    _ => "io",
                };
                // Admin-visible and content-free: release id and error class only.
                tracing::error!(
                    release_id = e.id,
                    class,
                    "stored NZB unavailable, bulk download aborted"
                );
                return Err(Stop::Failed);
            }
        };
        // The stored sizes decided the cap; the bytes actually read are held to it as well.
        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let header = if total > MAX_BULK_DOWNLOAD_BYTES {
            Err(ZipTooLarge)
        } else {
            zip.entry_header(&e.name, &bytes)
        };
        let Ok(header) = header else {
            tracing::error!(
                release_id = e.id,
                "bulk download over its size cap, aborted"
            );
            return Err(Stop::Failed);
        };
        pacer.frames(&header).await?;
        pacer.frames(&bytes).await?;
        // Peak memory: one blob at a time (the queued frames are copies).
        drop(bytes);
    }
    let Ok(end) = zip.finish() else {
        return Err(Stop::Failed);
    };
    pacer.frames(&end).await?;
    pacer.send(Msg::Done).await
}

// ---------------------------------------------------------------------------------------------
// Handler

/// The releases of `ids` the caller may see (unknown and hidden ones dropped).
// The error is a ready-made response that is returned straight to the client.
#[allow(clippy::result_large_err)]
async fn visible_rows(
    st: &St,
    sess: &SessionCtx,
    ids: Vec<i64>,
) -> Result<Vec<nzb_store::ReleaseRow>, Response> {
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        match st.deps.db.get_release(id).await {
            Ok(Some(r)) if !sess.hides_category(r.category_id) => rows.push(r),
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "release lookup failed");
                return Err(internal());
            }
        }
    }
    Ok(rows)
}

fn busy() -> Response {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "BUSY")
        .retry_after(BULK_BUSY_RETRY_AFTER_SECS)
        .into_response()
}

fn limited(retry_after_secs: u64) -> Response {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
        .retry_after(retry_after_secs)
        .into_response()
}

/// `POST /releases/bulk/download` (T130): see the module documentation.
pub(crate) async fn download_bulk(
    State(st): State<St>,
    Extension(sess): Extension<SessionCtx>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    limiter: Option<Extension<SharedLimiter>>,
    body: Bytes,
) -> Response {
    // CSRF (Origin + synchronizer token), role and the download buckets were handled by the gate.
    let state = Arc::clone(&st.bulk);
    // 1. Capacity first, so a busy answer spends none of the strict budget (review 46 L4).
    let Some(running) = Running::claim(&state, sess.user_id) else {
        return busy();
    };
    let Ok(bulk) = Arc::clone(&state.pool).try_acquire_owned() else {
        return busy();
    };
    let Ok(permit) = Arc::clone(&st.downloads).try_acquire_owned() else {
        return busy();
    };
    // 2. The strict budget, per client IP then per account. Fail closed without the limiter: the
    // rate-limit layer always installs it.
    let Some(Extension(SharedLimiter(lim))) = limiter else {
        tracing::error!("shared rate limiter missing for the bulk download");
        return internal();
    };
    if let Decision::Deny { retry_after_secs } = lim.check(Class::BulkDownload, ip) {
        return limited(retry_after_secs);
    }
    if let Decision::Deny { retry_after_secs } = state.accounts.check(sess.user_id) {
        return limited(retry_after_secs);
    }
    // 3. The form.
    let Some(form) = csrf::parse_form_strict(&body, crate::bulk::MAX_FORM_FIELDS) else {
        return fail(StatusCode::BAD_REQUEST, "BAD_REQUEST");
    };
    let ids = match crate::bulk::selection(&form) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // 4. Unknown and hidden releases are skipped like the list hides them; at most 100 lookups.
    let rows = match visible_rows(&st, &sess, ids).await {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return not_found(),
        Err(r) => return r,
    };
    // 5. The cap, from the stored sizes.
    let total = rows
        .iter()
        .fold(0_u64, |a, r| a.saturating_add(r.nzb_size_bytes));
    if total > MAX_BULK_DOWNLOAD_BYTES {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "BULK_DOWNLOAD_TOO_LARGE");
    }
    let titles: Vec<(i64, &str)> = rows.iter().map(|r| (r.id, r.title.as_str())).collect();
    let names = entry_names(&titles);
    let entries: Vec<Entry> = rows
        .iter()
        .zip(names)
        .map(|(r, name)| Entry {
            id: r.id,
            sha: r.sha256,
            name,
        })
        .collect();
    let count = entries.len();
    let now = st.deps.clock.now_secs();
    let name = archive_name(count, now);
    let Ok(cd) = HeaderValue::from_str(&content_disposition(&name)) else {
        return internal();
    };
    // 6. Audit.
    let detail = format!("count={count}");
    audit(&st, &sess, ip, BULK_DOWNLOAD_EVENT, &detail).await;

    // 7. Stream. One deadline for body and producer (review 46 L2).
    let deadline = Instant::now() + state.limits.deadline(total);
    let (tx, rx) = mpsc::channel(QUEUE_FRAMES);
    let taken = Arc::new(AtomicU64::new(0));
    let mut pacer = Pacer::new(tx, Arc::clone(&taken), &state.limits);
    let job = Job {
        store: Arc::clone(&st.deps.store),
        db: st.deps.db.clone(),
        sess,
        entries,
        dos: dos_time_date(now),
    };
    // The detached producer owns both permits and the account's running slot until it ends, so a
    // client disconnect cannot free them while a blob read is still running. Ending without the
    // end marker (dropping the sender) aborts the response.
    tokio::spawn(async move {
        let _held: (OwnedSemaphorePermit, OwnedSemaphorePermit, Running) = (permit, bulk, running);
        match tokio::time::timeout_at(deadline, produce(job, &mut pacer)).await {
            Ok(Ok(()) | Err(Stop::Gone | Stop::Failed)) => {}
            Ok(Err(Stop::Slow)) => {
                tracing::warn!(entries = count, "bulk download reader too slow, aborted");
            }
            Err(_) => {
                // I5: the count helps tell a slow client from a short (understated) deadline.
                tracing::warn!(entries = count, "bulk download deadline exceeded, aborted");
            }
        }
    });
    zip_response(
        BulkBody {
            rx: Some(rx),
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            taken,
        },
        cd,
    )
}

/// The SEC-030 attachment response of the archive.
fn zip_response(body: BulkBody, cd: HeaderValue) -> Response {
    let mut resp = Response::new(axum::body::Body::new(body));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ZIP_CONTENT_TYPE),
    );
    h.insert(header::CONTENT_DISPOSITION, cd);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }
    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }

    #[test]
    fn sec_030_zip_writer_layout_is_stored_and_consistent() {
        let (time, date) = dos_time_date(1_700_000_000);
        let mut z = ZipWriter::new(time, date);
        let a = b"123456789".to_vec();
        let b = b"".to_vec();
        let mut out = Vec::new();
        out.extend(z.entry_header("a.nzb", &a).unwrap());
        out.extend(&a);
        out.extend(z.entry_header("b.nzb", &b).unwrap());
        out.extend(&b);
        out.extend(z.finish().unwrap());
        // Local header of the first entry.
        assert_eq!(u32_at(&out, 0), LOCAL_SIG);
        assert_eq!(u16_at(&out, 8), 0, "stored");
        assert_eq!(u32_at(&out, 14), 0xCBF4_3926, "CRC-32 check value");
        assert_eq!(u32_at(&out, 18), 9);
        assert_eq!(u32_at(&out, 22), 9);
        assert_eq!(&out[30..35], b"a.nzb");
        assert_eq!(&out[35..44], b"123456789");
        // End record.
        let end = out.len() - 22;
        assert_eq!(u32_at(&out, end), END_SIG);
        assert_eq!(u16_at(&out, end + 10), 2);
        let cd_size = usize::try_from(u32_at(&out, end + 12)).unwrap();
        let cd_off = usize::try_from(u32_at(&out, end + 16)).unwrap();
        assert_eq!(cd_off + cd_size, end);
        assert_eq!(u32_at(&out, cd_off), CENTRAL_SIG);
        // Second central entry points at the second local header.
        let second = cd_off + 46 + 5;
        assert_eq!(u32_at(&out, second), CENTRAL_SIG);
        let off2 = usize::try_from(u32_at(&out, second + 42)).unwrap();
        assert_eq!(off2, 44);
        assert_eq!(u32_at(&out, off2), LOCAL_SIG);
    }

    #[test]
    fn sec_030_zip_writer_refuses_what_classic_zip_cannot_hold() {
        let mut z = ZipWriter::new(0, 33);
        let long = "a".repeat(usize::from(u16::MAX) + 1);
        assert_eq!(z.entry_header(&long, b"x"), Err(ZipTooLarge));
        z.offset = u32::MAX - 10;
        assert_eq!(z.entry_header("a.nzb", b"0123456789"), Err(ZipTooLarge));
    }

    #[test]
    fn sec_030_bulk_names_are_allowlisted_and_deduplicated() {
        let names = entry_names(&[
            (3, "Show (2020)"),
            (5, "show_2020"),
            (7, "Show 2020"),
            (8, "../../etc/passwd"),
            (9, "a\r\nb\"; x"),
            (10, ""),
            (11, "Show_2020-7"),
        ]);
        assert_eq!(
            names,
            [
                "Show_2020.nzb",
                "show_2020-5.nzb",
                "Show_2020-7.nzb",
                "etc_passwd.nzb",
                "a_b_x.nzb",
                "release-10.nzb",
                "Show_2020-7-11.nzb",
            ]
        );
        for n in &names {
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "{n}"
            );
            assert!(!n.starts_with('.') && !n.contains(".."), "{n}");
        }
    }

    #[test]
    fn sec_030_archive_name_and_dos_time() {
        // 2023-11-14 22:13:20 UTC.
        assert_eq!(
            archive_name(3, 1_700_000_000),
            "nzbd-3-releases-20231114-221320.zip"
        );
        let (t, d) = dos_time_date(1_700_000_000);
        assert_eq!(d, ((2023 - 1980) << 9) + (11 << 5) + 14);
        assert_eq!(t, (22 << 11) + (13 << 5) + 10);
        assert_eq!(dos_time_date(0), (0, 33));
        assert_eq!(dos_time_date(-5), (0, 33));
    }

    #[test]
    fn sec_030_bulk_deadline_is_proportional_and_capped() {
        assert_eq!(bulk_deadline(0), Duration::from_secs(60));
        assert_eq!(bulk_deadline(1), Duration::from_secs(61));
        assert_eq!(bulk_deadline(10 << 20), Duration::from_secs(70));
        assert_eq!(bulk_deadline(200 << 20), Duration::from_secs(260));
        // Kept below the shipped proxy's 5-minute write timeout (review 46 L3).
        assert_eq!(bulk_deadline(MAX_BULK_DOWNLOAD_BYTES), BULK_DEADLINE_MAX);
        assert_eq!(bulk_deadline(u64::MAX), BULK_DEADLINE_MAX);
        assert!(BULK_DEADLINE_MAX < Duration::from_secs(300));
    }

    fn body_with(rx: mpsc::Receiver<Msg>, deadline: Duration) -> BulkBody {
        BulkBody {
            rx: Some(rx),
            deadline: Box::pin(tokio::time::sleep(deadline)),
            taken: Arc::new(AtomicU64::new(0)),
        }
    }

    #[tokio::test]
    async fn sec_030_bulk_body_ends_cleanly_only_after_the_end_marker() {
        use http_body_util::BodyExt;
        // With the marker: the data, then a clean end; the bytes are counted for the pacer.
        let (tx, rx) = mpsc::channel(4);
        assert!(tx.send(Msg::Data(Bytes::from_static(b"abc"))).await.is_ok());
        assert!(tx.send(Msg::Done).await.is_ok());
        drop(tx);
        let mut b = body_with(rx, Duration::from_secs(30));
        let taken = Arc::clone(&b.taken);
        assert!(b.frame().await.unwrap().is_ok());
        assert!(b.frame().await.is_none());
        assert_eq!(taken.load(Ordering::Relaxed), 3);
        // A producer that stops (error, timeout, panic) without the marker: an error, never a
        // clean end (review 46 L2).
        let (tx, rx) = mpsc::channel(4);
        assert!(tx.send(Msg::Data(Bytes::from_static(b"abc"))).await.is_ok());
        drop(tx);
        let mut b = body_with(rx, Duration::from_secs(30));
        assert!(b.frame().await.unwrap().is_ok());
        assert!(b.frame().await.unwrap().is_err());
        assert!(b.frame().await.is_none());
        // The deadline: an error even while frames are still queued.
        let (tx, rx) = mpsc::channel(4);
        assert!(tx.send(Msg::Data(Bytes::from_static(b"abc"))).await.is_ok());
        let mut b = body_with(rx, Duration::from_millis(20));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(b.frame().await.unwrap().is_err());
        assert!(tx.is_closed(), "the producer sees the receiver gone");
    }

    #[tokio::test]
    async fn sec_030_bulk_pacer_aborts_a_reader_that_takes_too_little() {
        let limits = BulkLimits {
            progress_grace: Duration::from_millis(30),
            progress_window: Duration::from_millis(30),
            min_progress_bytes: 10,
            ..BulkLimits::default()
        };
        let taken = Arc::new(AtomicU64::new(0));
        // The queue holds one item and nobody reads: the grace passes, then the first judged
        // window ends the send with `Slow`.
        let (tx, _rx) = mpsc::channel(1);
        let mut p = Pacer::new(tx, Arc::clone(&taken), &limits);
        assert!(p.send(Msg::Done).await.is_ok());
        let t0 = std::time::Instant::now();
        assert!(matches!(p.send(Msg::Done).await, Err(Stop::Slow)));
        assert!(t0.elapsed() >= Duration::from_millis(50));
        // A reader that keeps taking enough is never cut off.
        let (tx, mut rx) = mpsc::channel(1);
        let mut p = Pacer::new(tx, Arc::clone(&taken), &limits);
        let counter = Arc::clone(&taken);
        let reader = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                counter.fetch_add(100, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        for _ in 0..20 {
            assert!(p.send(Msg::Done).await.is_ok());
        }
        drop(p);
        reader.await.unwrap();
        // A receiver that is gone ends the producer at once.
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let mut p = Pacer::new(tx, taken, &limits);
        assert!(matches!(p.send(Msg::Done).await, Err(Stop::Gone)));
    }
}

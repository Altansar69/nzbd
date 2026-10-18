//! Connection-level hardening (SEC-032).
//!
//! `axum::serve` exposes no hyper builder, so the limits live in a [`Listener`] wrapper:
//!
//! * a global connection cap, plus a small reserved pool for loopback peers so the container
//!   `HEALTHCHECK` is never starved by remote clients (excess connections are closed at once
//!   rather than queued);
//! * a per-peer-IP connection cap (IPv6 per /64);
//! * an idle timeout (no read or write progress);
//! * an absolute request-head deadline and head size cap: from the first byte of a request (or
//!   from accept, for the first request) the head must complete within `header_timeout` and
//!   `max_head_bytes`, however slowly the bytes trickle in. This defeats slowloris drip-feeding
//!   and bounds what hyper buffers before `max_header_bytes` is checked.
//!
//! Head tracking is a byte scan for the blank line that ends the head; it resumes after the
//! server writes a final (non-1xx) response status line.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

/// Connection limits applied by [`LimitedListener`].
#[derive(Clone, Copy, Debug)]
pub struct ListenerLimits {
    /// Concurrent connections from non-loopback peers.
    pub max_connections: usize,
    /// Extra connections reserved for loopback peers (healthcheck, local tooling).
    pub loopback_reserved: usize,
    /// Concurrent connections per peer IP (non-loopback).
    pub max_per_ip: usize,
    /// Close a connection after this long without read/write progress.
    pub idle: Duration,
    /// Absolute time allowed to receive one complete request head.
    pub header_timeout: Duration,
    /// Max bytes of one request head (request line plus headers) before it is aborted.
    pub max_head_bytes: usize,
}

/// Wraps a [`Listener`] and enforces [`ListenerLimits`].
pub struct LimitedListener<L> {
    inner: L,
    general: Arc<Semaphore>,
    loopback: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    limits: ListenerLimits,
}

impl<L> LimitedListener<L> {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(inner: L, limits: ListenerLimits) -> Self {
        Self {
            inner,
            general: Arc::new(Semaphore::new(limits.max_connections.max(1))),
            loopback: Arc::new(Semaphore::new(limits.loopback_reserved.max(1))),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            limits,
        }
    }
}

/// Socket peer address of a connection accepted through [`LimitedListener`]; use as
/// `into_make_service_with_connect_info::<PeerAddr>()`. (axum's built-in `SocketAddr`
/// connect-info only supports a bare `TcpListener`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

impl<L> Connected<IncomingStream<'_, LimitedListener<L>>> for PeerAddr
where
    L: Listener<Addr = SocketAddr>,
    L::Io: Unpin,
{
    fn connect_info(stream: IncomingStream<'_, LimitedListener<L>>) -> Self {
        Self(*stream.remote_addr())
    }
}

/// Per-IP bucket: canonical address, IPv6 reduced to its /64.
fn ip_bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Decrements the per-IP counter when the connection ends.
struct IpGuard {
    map: Arc<Mutex<HashMap<IpAddr, usize>>>,
    key: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = m.get_mut(&self.key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Request-head tracking state.
struct Head {
    /// A head is being received; the deadline and size cap apply.
    active: bool,
    /// The server answered the previous request; the next byte starts a new head.
    awaiting: bool,
    /// Bytes of the current head seen so far.
    read: usize,
    /// Consecutive line feeds (CR ignored) at the end of the scanned bytes.
    nl_run: u8,
    /// A non-newline byte was seen (leading blank lines must not end the head).
    content: bool,
}

impl Head {
    /// A fresh head being received.
    const fn begin() -> Self {
        Self {
            active: true,
            awaiting: false,
            read: 0,
            nl_run: 0,
            content: false,
        }
    }
}

/// I/O wrapper holding the connection permits and the timers.
pub struct LimitedIo<Io> {
    io: Io,
    idle_sleep: Pin<Box<Sleep>>,
    head_sleep: Pin<Box<Sleep>>,
    idle: Duration,
    header_timeout: Duration,
    max_head_bytes: usize,
    head: Head,
    _permit: OwnedSemaphorePermit,
    _ip: Option<IpGuard>,
}

fn timed_out<T>(what: &'static str) -> Poll<io::Result<T>> {
    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, what)))
}

impl<Io> LimitedIo<Io> {
    fn touch(&mut self) {
        self.idle_sleep.as_mut().reset(Instant::now() + self.idle);
    }

    /// Tracks request-head progress over freshly read bytes.
    fn on_read(&mut self, new: &[u8]) -> io::Result<()> {
        if !self.head.active {
            if !self.head.awaiting {
                return Ok(()); // inside a request body
            }
            self.head = Head::begin();
            self.head_sleep
                .as_mut()
                .reset(Instant::now() + self.header_timeout);
        }
        for &b in new {
            self.head.read = self.head.read.saturating_add(1);
            match b {
                b'\n' => self.head.nl_run = self.head.nl_run.saturating_add(1),
                b'\r' => {}
                _ => {
                    self.head.nl_run = 0;
                    self.head.content = true;
                }
            }
            if self.head.content && self.head.nl_run >= 2 {
                self.head.active = false;
                return Ok(());
            }
            if self.head.read > self.max_head_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request head too large",
                ));
            }
        }
        if Instant::now() >= self.head_sleep.deadline() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request head deadline",
            ));
        }
        Ok(())
    }

    /// Notes that the server started writing a final response (`HTTP/1.x NNN`, not 1xx).
    fn on_write(&mut self, buf: &[u8]) {
        let final_status = buf.starts_with(b"HTTP/1.") && buf.get(9).is_some_and(|d| *d != b'1');
        if final_status && !self.head.active {
            self.head.awaiting = true;
        }
    }
}

impl<Io: AsyncRead + Unpin> AsyncRead for LimitedIo<Io> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    return timed_out("connection idle timeout");
                }
                if this.head.active && this.head_sleep.as_mut().poll(cx).is_ready() {
                    return timed_out("request head deadline");
                }
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                let new = buf.filled().get(before..).unwrap_or_default();
                if !new.is_empty() {
                    this.touch();
                    if let Err(e) = this.on_read(new) {
                        return Poll::Ready(Err(e));
                    }
                }
                Poll::Ready(Ok(()))
            }
            other @ Poll::Ready(_) => other,
        }
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for LimitedIo<Io> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write(cx, buf) {
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    timed_out("connection idle timeout")
                } else {
                    Poll::Pending
                }
            }
            ready @ Poll::Ready(_) => {
                this.touch();
                this.on_write(buf);
                ready
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl<L> LimitedListener<L> {
    /// Reserves a per-IP slot for `ip`; `None` when the peer is at its cap.
    fn take_ip_slot(&self, ip: IpAddr) -> Option<IpGuard> {
        let key = ip_bucket(ip);
        let mut m = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
        let cur = m.get(&key).copied().unwrap_or(0);
        if cur >= self.limits.max_per_ip.max(1) {
            return None;
        }
        m.insert(key, cur.saturating_add(1));
        Some(IpGuard {
            map: self.per_ip.clone(),
            key,
        })
    }
}

impl<L> Listener for LimitedListener<L>
where
    L: Listener<Addr = SocketAddr>,
    L::Io: Unpin,
{
    type Io = LimitedIo<L::Io>;
    type Addr = SocketAddr;

    #[allow(clippy::manual_async_fn)] // must match the trait's `impl Future + Send` signature
    fn accept(&mut self) -> impl Future<Output = (Self::Io, Self::Addr)> + Send {
        async move {
            loop {
                let (io, addr) = self.inner.accept().await;
                let loopback = addr.ip().to_canonical().is_loopback();
                // Never wait for a slot: queueing would let remote clients delay the loopback
                // healthcheck behind them. Over-limit connections are closed immediately.
                let sem = if loopback {
                    self.loopback.clone()
                } else {
                    self.general.clone()
                };
                let Ok(permit) = sem.try_acquire_owned() else {
                    tracing::warn!(loopback, "connection limit reached, closing");
                    continue;
                };
                let ip_guard = if loopback {
                    None
                } else if let Some(g) = self.take_ip_slot(addr.ip()) {
                    Some(g)
                } else {
                    tracing::warn!("per-IP connection limit reached, closing");
                    continue;
                };
                let now = Instant::now();
                let io = LimitedIo {
                    io,
                    idle_sleep: Box::pin(tokio::time::sleep_until(now + self.limits.idle)),
                    head_sleep: Box::pin(tokio::time::sleep_until(
                        now + self.limits.header_timeout,
                    )),
                    idle: self.limits.idle,
                    header_timeout: self.limits.header_timeout,
                    max_head_bytes: self.limits.max_head_bytes,
                    // The first request's head clock starts at accept.
                    head: Head::begin(),
                    _permit: permit,
                    _ip: ip_guard,
                };
                return (io, addr);
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc;

    /// Listener fed by the test: each queued item is a connection from a chosen peer.
    struct Fake(mpsc::UnboundedReceiver<(DuplexStream, SocketAddr)>);

    impl Listener for Fake {
        type Io = DuplexStream;
        type Addr = SocketAddr;
        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            match self.0.recv().await {
                Some(v) => v,
                None => std::future::pending().await,
            }
        }
        fn local_addr(&self) -> io::Result<Self::Addr> {
            Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
        }
    }

    fn limits() -> ListenerLimits {
        ListenerLimits {
            max_connections: 4,
            loopback_reserved: 2,
            max_per_ip: 2,
            idle: Duration::from_secs(30),
            header_timeout: Duration::from_millis(300),
            max_head_bytes: 1024,
        }
    }

    fn setup(
        l: ListenerLimits,
    ) -> (
        LimitedListener<Fake>,
        mpsc::UnboundedSender<(DuplexStream, SocketAddr)>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        (LimitedListener::new(Fake(rx), l), tx)
    }

    /// Queues a connection from `peer`; returns the client side.
    fn connect(
        tx: &mpsc::UnboundedSender<(DuplexStream, SocketAddr)>,
        peer: &str,
    ) -> Option<DuplexStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tx.send((server, peer.parse().ok()?)).ok()?;
        Some(client)
    }

    async fn accept_one(l: &mut LimitedListener<Fake>) -> Option<LimitedIo<DuplexStream>> {
        tokio::time::timeout(Duration::from_millis(300), l.accept())
            .await
            .ok()
            .map(|(io, _)| io)
    }

    #[tokio::test]
    async fn sec_032_idle_connection_is_closed() {
        let mut lim = limits();
        lim.idle = Duration::from_millis(100);
        lim.header_timeout = Duration::from_secs(30);
        let (mut l, tx) = setup(lim);
        let _c = connect(&tx, "192.0.2.1:1000");
        let Some(mut io) = accept_one(&mut l).await else {
            panic!("accept");
        };
        let mut buf = [0_u8; 8];
        let r = io.read(&mut buf).await;
        assert_eq!(r.err().map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
    }

    #[tokio::test]
    async fn sec_032_slowloris_drip_feed_hits_absolute_header_deadline() {
        let (mut l, tx) = setup(limits());
        let Some(mut client) = connect(&tx, "192.0.2.1:1000") else {
            panic!("connect");
        };
        let Some(mut io) = accept_one(&mut l).await else {
            panic!("accept");
        };
        // One byte every 80 ms never idles out (30 s) but must die at ~300 ms.
        let feeder = tokio::spawn(async move {
            let _ = client.write_all(b"GET / HTTP/1.1\r\n").await;
            for _ in 0..50 {
                tokio::time::sleep(Duration::from_millis(80)).await;
                if client.write_all(b"X").await.is_err() {
                    break;
                }
            }
        });
        let mut buf = [0_u8; 64];
        let err = loop {
            match io.read(&mut buf).await {
                Ok(0) => panic!("eof"),
                Ok(_) => {}
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // The deadline fired while the drip-feeder (about 4 s of bytes) was still writing: a
        // slow trickle did not extend it. Checked on the feeder's state, not on host wall time.
        assert!(!feeder.is_finished(), "deadline outlived the trickle");
        feeder.abort();
    }

    #[tokio::test]
    async fn sec_032_silent_connection_hits_header_deadline() {
        let (mut l, tx) = setup(limits());
        let _c = connect(&tx, "192.0.2.1:1000");
        let Some(mut io) = accept_one(&mut l).await else {
            panic!("accept");
        };
        let mut buf = [0_u8; 8];
        let r = tokio::time::timeout(Duration::from_secs(2), io.read(&mut buf)).await;
        assert_eq!(
            r.ok().and_then(Result::err).map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
    }

    #[tokio::test]
    async fn sec_032_oversized_head_is_cut_off_before_buffering() {
        let (mut l, tx) = setup(limits());
        let Some(mut client) = connect(&tx, "192.0.2.1:1000") else {
            panic!("connect");
        };
        let Some(mut io) = accept_one(&mut l).await else {
            panic!("accept");
        };
        let _ = client.write_all(&vec![b'A'; 8192]).await;
        let mut buf = [0_u8; 4096];
        let err = loop {
            match io.read(&mut buf).await {
                Ok(0) => panic!("eof"),
                Ok(_) => {}
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn sec_032_body_after_head_is_not_subject_to_header_deadline() {
        let (mut l, tx) = setup(limits());
        let Some(mut client) = connect(&tx, "192.0.2.1:1000") else {
            panic!("connect");
        };
        let Some(mut io) = accept_one(&mut l).await else {
            panic!("accept");
        };
        let _ = client
            .write_all(b"POST /upload HTTP/1.1\r\nContent-Length: 100000\r\n\r\n")
            .await;
        let mut buf = [0_u8; 4096];
        let n = io.read(&mut buf).await.unwrap_or(0);
        assert!(n > 0);
        // Body bytes (even blank lines and more than max_head_bytes in total) dribble in
        // past the 300 ms head deadline without error.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = client.write_all(&vec![b'\n'; 600]).await;
            let r = io.read(&mut buf).await;
            assert!(r.is_ok(), "{r:?}");
        }
        // After the server answers, the next request is head-limited again.
        let _ = io.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let _ = client.write_all(&vec![b'A'; 4096]).await;
        let err = loop {
            match io.read(&mut buf).await {
                Ok(0) => panic!("eof"),
                Ok(_) => {}
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn sec_032_per_ip_cap_closes_extra_connections_and_releases() {
        let (mut l, tx) = setup(limits());
        let c1 = connect(&tx, "192.0.2.1:1");
        let c2 = connect(&tx, "192.0.2.1:2");
        let mut c3 = connect(&tx, "192.0.2.1:3");
        let other = connect(&tx, "192.0.2.2:4");
        let Some(io1) = accept_one(&mut l).await else {
            panic!("1");
        };
        let Some(_io2) = accept_one(&mut l).await else {
            panic!("2");
        };
        // The third is closed (skipped); the next accepted connection is the other host's.
        let Some(_io4) = accept_one(&mut l).await else {
            panic!("other host must still be served");
        };
        if let Some(c) = c3.as_mut() {
            let mut b = [0_u8; 1];
            assert_eq!(
                c.read(&mut b).await.ok(),
                Some(0),
                "over-cap peer is closed"
            );
        }
        drop(io1);
        let _c5 = connect(&tx, "192.0.2.1:5");
        assert!(accept_one(&mut l).await.is_some(), "slot released");
        drop((c1, c2, other));
    }

    #[tokio::test]
    async fn sec_032_global_cap_does_not_starve_loopback_healthcheck() {
        let mut lim = limits();
        lim.max_per_ip = 100;
        let (mut l, tx) = setup(lim);
        let mut held = Vec::new();
        let mut clients = Vec::new();
        for i in 0..4 {
            clients.push(connect(&tx, &format!("192.0.2.{}:1", i + 1)));
            held.push(accept_one(&mut l).await);
        }
        assert!(held.iter().all(Option::is_some));
        // At the cap: a remote connection is dropped, a loopback one is served at once.
        let mut extra = connect(&tx, "192.0.2.50:1");
        let _lo = connect(&tx, "127.0.0.1:9");
        assert!(
            accept_one(&mut l).await.is_some(),
            "loopback must be accepted"
        );
        if let Some(c) = extra.as_mut() {
            let mut b = [0_u8; 1];
            assert_eq!(c.read(&mut b).await.ok(), Some(0));
        }
    }
}

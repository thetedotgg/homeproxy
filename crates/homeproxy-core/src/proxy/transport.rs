//! TCP liveness and cancellable, inactivity-bounded tunnel transport.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{sleep, Instant},
};
use tokio_util::sync::CancellationToken;

/// Enable keepalive without taking ownership of the stream's socket.
/// Unsupported options and OS errors are returned to the caller.
pub(super) fn configure_keepalive(stream: &TcpStream) -> io::Result<()> {
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(60));
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
        target_os = "nuttx",
        all(target_os = "wasi", not(target_env = "p1")),
    ))]
    let keepalive = keepalive
        .with_interval(Duration::from_secs(20))
        .with_retries(3);
    SockRef::from(stream).set_tcp_keepalive(&keepalive)
}

#[derive(Debug)]
pub(super) enum RelayOutcome {
    Finished(io::Result<(u64, u64)>),
    Idle,
    Cancelled,
}

pub(super) struct Activity<F = fn()> {
    last: Mutex<Instant>,
    on_progress: F,
}

impl<F: Fn()> Activity<F> {
    pub(super) fn new(on_progress: F) -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            on_progress,
        }
    }

    fn record(&self) {
        // No callback runs under the lock. Store full monotonic Instants rather
        // than truncating the elapsed time into an integer counter.
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        (self.on_progress)();
    }

    fn elapsed(&self) -> Duration {
        self.last
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
    }
}

pub(super) struct ProgressIo<T, F = fn()> {
    inner: T,
    activity: Arc<Activity<F>>,
}

impl<T, F> ProgressIo<T, F> {
    pub(super) fn new(inner: T, activity: Arc<Activity<F>>) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin, F: Fn()> AsyncRead for ProgressIo<T, F> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.activity.record();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin, F: Fn()> AsyncWrite for ProgressIo<T, F> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.record();
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.record();
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Copy both directions until completion, cancellation, or byte inactivity.
///
/// A zero timeout explicitly returns `Idle` without polling either stream.
/// Positive reads and writes in either direction renew the inactivity window;
/// EOF, pending I/O, flushing, shutdown and TCP probes do not. `on_progress`
/// runs synchronously for each such operation and should be short/nonblocking.
///
/// One copy future retains its buffers across all timer wakes and preserves
/// Tokio's half-close semantics. Cancellation/timeout drops that future and may
/// discard its pending buffered bytes; the caller owns closing the streams.
pub(super) async fn relay<A, B, F>(
    a: &mut A,
    b: &mut B,
    cancellation: &CancellationToken,
    idle_timeout: Duration,
    on_progress: F,
) -> RelayOutcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    F: Fn() + Send + Sync,
{
    if idle_timeout.is_zero() {
        return RelayOutcome::Idle;
    }

    let activity = Arc::new(Activity::new(on_progress));
    let mut a = ProgressIo::new(a, activity.clone());
    let mut b = ProgressIo::new(b, activity.clone());
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    match bounded(copy, cancellation, idle_timeout, &activity).await {
        BoundOutcome::Finished(result) => RelayOutcome::Finished(result),
        BoundOutcome::Idle => RelayOutcome::Idle,
        BoundOutcome::Cancelled => RelayOutcome::Cancelled,
    }
}

pub(super) enum BoundOutcome<T> {
    Finished(T),
    Idle,
    Cancelled,
}

/// Poll one future continuously, preserving its buffers across timer wakes.
/// Only positive I/O recorded in `activity` extends the inactivity window.
/// The timer takes no Stats locks and never polls or recreates the I/O future.
pub(super) async fn bounded<T, F: Fn()>(
    future: impl Future<Output = T>,
    cancellation: &CancellationToken,
    idle_timeout: Duration,
    activity: &Activity<F>,
) -> BoundOutcome<T> {
    if idle_timeout.is_zero() {
        return BoundOutcome::Idle;
    }
    let timer = sleep(idle_timeout);
    tokio::pin!(future, timer);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return BoundOutcome::Cancelled,
            result = &mut future => return BoundOutcome::Finished(result),
            _ = &mut timer => {
                let elapsed = activity.elapsed();
                if elapsed >= idle_timeout {
                    return BoundOutcome::Idle;
                }
                timer.set(sleep(idle_timeout - elapsed));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::{
        io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream},
        net::TcpListener,
        task::{yield_now, JoinHandle},
        time::advance,
    };

    const IDLE: Duration = Duration::from_secs(10);

    fn start_relay(
        mut a: DuplexStream,
        mut b: DuplexStream,
        cancellation: CancellationToken,
        progress: Arc<AtomicUsize>,
    ) -> JoinHandle<RelayOutcome> {
        // Spawning verifies that the relay future is Send.
        tokio::spawn(async move {
            relay(&mut a, &mut b, &cancellation, IDLE, || {
                progress.fetch_add(1, Ordering::SeqCst);
            })
            .await
        })
    }

    #[tokio::test(start_paused = true)]
    async fn idle_expires_after_the_complete_window() {
        let (_client, a) = duplex(64);
        let (_server, b) = duplex(64);
        let progress = Arc::new(AtomicUsize::new(0));
        let task = start_relay(a, b, CancellationToken::new(), progress.clone());
        yield_now().await;
        advance(IDLE - Duration::from_secs(1)).await;
        assert!(!task.is_finished());
        assert_eq!(progress.load(Ordering::SeqCst), 0);
        advance(Duration::from_secs(1)).await;
        assert!(matches!(task.await.unwrap(), RelayOutcome::Idle));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_timeout_is_immediate_without_io_or_callback() {
        let (mut a, _client) = duplex(64);
        let (mut b, _server) = duplex(64);
        let start = Instant::now();
        let result = relay(
            &mut a,
            &mut b,
            &CancellationToken::new(),
            Duration::ZERO,
            || panic!("zero timeout must not observe I/O"),
        )
        .await;
        assert!(matches!(result, RelayOutcome::Idle));
        assert_eq!(start, Instant::now());
    }

    #[tokio::test(start_paused = true)]
    async fn one_way_progress_survives_many_idle_windows() {
        let (mut client, a) = duplex(64);
        let (mut server, b) = duplex(64);
        let progress = Arc::new(AtomicUsize::new(0));
        let task = start_relay(a, b, CancellationToken::new(), progress.clone());
        yield_now().await;
        for byte in 0..12u8 {
            advance(Duration::from_secs(9)).await;
            client.write_all(&[byte]).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), byte);
            assert!(!task.is_finished());
        }
        assert!(progress.load(Ordering::SeqCst) >= 24);
        advance(Duration::from_secs(9)).await;
        assert!(!task.is_finished());
        advance(Duration::from_secs(1)).await;
        assert!(matches!(task.await.unwrap(), RelayOutcome::Idle));
    }

    #[tokio::test(start_paused = true)]
    async fn progress_near_deadline_rearms_from_latest_byte() {
        let (mut client, a) = duplex(64);
        let (mut server, b) = duplex(64);
        let task = start_relay(
            a,
            b,
            CancellationToken::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        yield_now().await;
        advance(Duration::from_millis(9_999)).await;
        client.write_all(b"x").await.unwrap();
        assert_eq!(server.read_u8().await.unwrap(), b'x');
        advance(Duration::from_millis(1)).await;
        yield_now().await;
        assert!(!task.is_finished());
        advance(Duration::from_millis(9_998)).await;
        assert!(!task.is_finished());
        advance(Duration::from_millis(1)).await;
        assert!(matches!(task.await.unwrap(), RelayOutcome::Idle));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_write_expires_despite_buffered_data() {
        let (mut client, a) = duplex(16_384);
        let (_server, b) = duplex(16);
        client.write_all(&vec![7; 16_384]).await.unwrap();
        let progress = Arc::new(AtomicUsize::new(0));
        let task = start_relay(a, b, CancellationToken::new(), progress.clone());
        // Preloaded data fills the copy buffer and the destination on its
        // first poll. The unread destination then keeps writes pending.
        yield_now().await;
        let calls = progress.load(Ordering::SeqCst);
        assert!(calls > 0);
        advance(Duration::from_secs(9)).await;
        assert!(!task.is_finished());
        assert_eq!(progress.load(Ordering::SeqCst), calls);
        advance(Duration::from_secs(1)).await;
        assert!(matches!(task.await.unwrap(), RelayOutcome::Idle));
        assert!(client.write_all(b"closed").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn half_close_drains_buffers_and_preserves_reverse_direction() {
        let (mut client, a) = duplex(32);
        let (mut server, b) = duplex(32);
        let task = start_relay(
            a,
            b,
            CancellationToken::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        let sender = tokio::spawn(async move {
            client.write_all(&vec![5; 4_096]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            reply
        });
        let receiver = tokio::spawn(async move {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            server.write_all(&vec![9; 1_024]).await.unwrap();
            server.shutdown().await.unwrap();
            request
        });
        assert_eq!(receiver.await.unwrap(), vec![5; 4_096]);
        assert_eq!(sender.await.unwrap(), vec![9; 1_024]);
        match task.await.unwrap() {
            RelayOutcome::Finished(Ok(counts)) => assert_eq!(counts, (4_096, 1_024)),
            outcome => panic!("unexpected relay outcome: {outcome:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timer_wake_preserves_pending_forward_buffer_and_half_close() {
        let (mut client, a) = duplex(8_192);
        let (mut server, b) = duplex(32);
        let payload: Vec<_> = (0..4_096).map(|i| (i % 251) as u8).collect();
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let task = start_relay(
            a,
            b,
            CancellationToken::new(),
            Arc::new(AtomicUsize::new(0)),
        );
        yield_now().await;
        // Forward writes are blocked, but reverse progress renews activity.
        advance(Duration::from_secs(9)).await;
        server.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        advance(Duration::from_secs(1)).await;
        yield_now().await;
        assert!(!task.is_finished());
        // The original deadline has fired. All pending forward bytes must
        // still drain, including the FIN following that buffered request.
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        server.shutdown().await.unwrap();
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        match task.await.unwrap() {
            RelayOutcome::Finished(Ok(counts)) => assert_eq!(counts, (4_096, 5)),
            outcome => panic!("unexpected relay outcome: {outcome:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_stops_pending_relay_without_waiting_for_timeout() {
        let (_client, a) = duplex(64);
        let (_server, b) = duplex(64);
        let cancellation = CancellationToken::new();
        let task = start_relay(a, b, cancellation.clone(), Arc::new(AtomicUsize::new(0)));
        yield_now().await;
        let before = Instant::now();
        cancellation.cancel();
        assert!(matches!(task.await.unwrap(), RelayOutcome::Cancelled));
        assert_eq!(Instant::now(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn already_cancelled_wins_over_ready_eof() {
        let (mut a, client) = duplex(64);
        let (mut b, server) = duplex(64);
        drop(client);
        drop(server);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = relay(&mut a, &mut b, &cancellation, IDLE, || {
            panic!("cancelled relay must not poll I/O")
        })
        .await;
        assert!(matches!(result, RelayOutcome::Cancelled));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_wins_when_idle_timer_is_already_ready() {
        let (mut a, _client) = duplex(64);
        let (mut b, _server) = duplex(64);
        let cancellation = CancellationToken::new();
        let future = relay(&mut a, &mut b, &cancellation, IDLE, || {});
        tokio::pin!(future);
        // Poll manually so advance cannot let a spawned relay consume the
        // ready deadline before we make cancellation ready as well.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
            Poll::Ready(())
        })
        .await;
        advance(IDLE).await;
        cancellation.cancel();
        assert!(matches!(future.await, RelayOutcome::Cancelled));
    }

    struct ScriptedIo {
        reads: usize,
        writes: usize,
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let step = self.reads;
            self.reads += 1;
            match step {
                0 => Poll::Pending,
                1 => {
                    buf.put_slice(b"x");
                    Poll::Ready(Ok(()))
                }
                2 => Poll::Ready(Ok(())),
                _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset))),
            }
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let step = self.writes;
            self.writes += 1;
            match step {
                0 => Poll::Pending,
                1 => Poll::Ready(Ok(1)),
                2 => Poll::Ready(Ok(0)),
                _ => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn callback_and_timestamp_change_only_on_positive_successful_io() {
        let count = AtomicUsize::new(0);
        let activity = Arc::new(Activity {
            last: Mutex::new(Instant::now()),
            on_progress: || {
                count.fetch_add(1, Ordering::SeqCst);
            },
        });
        let mut inner = ScriptedIo {
            reads: 0,
            writes: 0,
        };
        let mut io = ProgressIo {
            inner: &mut inner,
            activity: activity.clone(),
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut bytes = [0; 8];
        let mut buf = ReadBuf::new(&mut bytes);
        // The existing filled byte must not be mistaken for new progress.
        buf.put_slice(b"a");
        advance(Duration::from_secs(1)).await;
        assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
        assert_eq!(activity.elapsed(), Duration::from_secs(1));
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(activity.elapsed(), Duration::ZERO);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        advance(Duration::from_secs(1)).await;
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Err(_))
        ));
        assert!(Pin::new(&mut io).poll_write(&mut cx, b"x").is_pending());
        assert_eq!(activity.elapsed(), Duration::from_secs(1));
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"x"),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(activity.elapsed(), Duration::ZERO);
        advance(Duration::from_secs(1)).await;
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"x"),
            Poll::Ready(Ok(0))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"x"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(activity.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn relay_returns_io_error_without_waiting_for_idle() {
        let mut a = ScriptedIo {
            reads: 3,
            writes: 0,
        };
        let (mut b, _server) = duplex(64);
        let start = Instant::now();
        let outcome = relay(&mut a, &mut b, &CancellationToken::new(), IDLE, || {}).await;
        match outcome {
            RelayOutcome::Finished(Err(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset)
            }
            outcome => panic!("unexpected relay outcome: {outcome:?}"),
        }
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test]
    async fn accepted_and_outbound_loopback_sockets_enable_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (outbound, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept(),
        );
        let outbound = outbound.unwrap();
        let (accepted, _) = accepted.unwrap();
        for stream in [&outbound, &accepted] {
            configure_keepalive(stream).unwrap();
            let socket = SockRef::from(stream);
            assert!(socket.keepalive().unwrap());
            #[cfg(target_os = "linux")]
            {
                assert_eq!(
                    socket.tcp_keepalive_time().unwrap(),
                    Duration::from_secs(60)
                );
                assert_eq!(
                    socket.tcp_keepalive_interval().unwrap(),
                    Duration::from_secs(20)
                );
                assert_eq!(socket.tcp_keepalive_retries().unwrap(), 3);
            }
        }
        // The helper borrowed the sockets: both remain usable afterwards.
        outbound.writable().await.unwrap();
        assert_eq!(outbound.try_write(b"x").unwrap(), 1);
        let mut accepted = accepted;
        assert_eq!(accepted.read_u8().await.unwrap(), b'x');
    }
}

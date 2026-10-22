use std::{
    fs::File,
    future::Future,
    io::{Read, Seek, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
};

use super::EntryLease;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio_util::sync::CancellationToken;

use super::{CacheFill, IO_CHUNK_BYTES};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Next<S> =
    Pin<Box<dyn Future<Output = (Option<S>, Option<Result<Frame<Bytes>, BoxError>>)> + Send>>;

struct ReadState {
    file: File,
    remaining: u64,
    _guard: EntryLease,
}

pub struct CacheBody {
    state: Option<ReadState>,
    pending: Option<Next<ReadState>>,
    memory: Option<Bytes>,
    verified_representation: Option<(u64, String)>,
}

impl CacheBody {
    pub fn range(&mut self, start: u64, length: u64) -> std::io::Result<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| std::io::Error::other("body already read"))?;
        if start
            .checked_add(length)
            .is_none_or(|end| end > state.remaining)
        {
            return Err(std::io::Error::other("invalid body range"));
        }
        state.file.seek(SeekFrom::Start(start))?;
        state.remaining = length;
        Ok(())
    }
    pub(super) fn verified_representation(&self) -> Option<(u64, &str)> {
        self.verified_representation
            .as_ref()
            .map(|(length, hash)| (*length, hash.as_str()))
    }

    pub(super) fn file(file: File, length: u64, guard: EntryLease, sha256: String) -> Self {
        Self {
            state: Some(ReadState {
                file,
                remaining: length,
                _guard: guard,
            }),
            pending: None,
            memory: None,
            verified_representation: Some((length, sha256)),
        }
    }
}

#[cfg(test)]
impl From<Bytes> for CacheBody {
    fn from(bytes: Bytes) -> Self {
        Self {
            state: None,
            pending: None,
            memory: Some(bytes),
            verified_representation: None,
        }
    }
}

impl Body for CacheBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Some(bytes) = this.memory.take() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if this.pending.is_none() {
            let Some(mut state) = this.state.take() else {
                return Poll::Ready(None);
            };
            if state.remaining == 0 {
                return Poll::Ready(None);
            }
            this.pending = Some(Box::pin(async move {
                match tokio::task::spawn_blocking(move || {
                    let mut buffer = vec![0; state.remaining.min(IO_CHUNK_BYTES as u64) as usize];
                    // A short/error read is an error, never a successful truncated body.
                    let result = state.file.read_exact(&mut buffer);
                    if result.is_ok() {
                        state.remaining -= buffer.len() as u64;
                    }
                    (state, result.map(|_| Bytes::from(buffer)))
                })
                .await
                {
                    Ok((state, Ok(bytes))) => (Some(state), Some(Ok(Frame::data(bytes)))),
                    Ok((_, Err(error))) => (None, Some(Err(error.into()))),
                    Err(error) => (None, Some(Err(error.into()))),
                }
            }));
        }
        let result = this.pending.as_mut().unwrap().as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready((state, frame)) => {
                this.state = state;
                this.pending = None;
                Poll::Ready(frame)
            }
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct TeeState<B> {
    origin: B,
    queued: Option<Frame<Bytes>>,
    fill: Option<CacheFill>,
    remainder: Bytes,
    received: u64,
    length: u64,
    cancellation: CancellationToken,
    _flight: Option<super::FillGuard>,
}

pub struct TeeBody<B> {
    state: Option<TeeState<B>>,
    pending: Option<Next<TeeState<B>>>,
}

impl<B> TeeBody<B> {
    pub fn with_flight(mut self, guard: Option<super::FillGuard>) -> Self {
        self.state.as_mut().unwrap()._flight = guard;
        self
    }
    pub fn new(origin: B, fill: CacheFill, length: u64, cancellation: CancellationToken) -> Self {
        Self {
            state: Some(TeeState {
                origin,
                queued: None,
                fill: Some(fill.with_cancellation(cancellation.clone())),
                remainder: Bytes::new(),
                received: 0,
                length,
                cancellation,
                _flight: None,
            }),
            pending: None,
        }
    }
}

impl<B> TeeState<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError> + Send,
{
    async fn next(mut self) -> (Option<Self>, Option<Result<Frame<Bytes>, BoxError>>) {
        if self.cancellation.is_cancelled() {
            return (
                None,
                Some(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "proxy stopped",
                )
                .into())),
            );
        }
        if self.remainder.is_empty() {
            match if let Some(frame) = self.queued.take() {
                Some(Ok(frame))
            } else {
                self.origin.frame().await
            } {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => self.remainder = data,
                    Err(frame) => {
                        self.fill = None;
                        return (Some(self), Some(Ok(frame)));
                    }
                },
                Some(Err(error)) => return (None, Some(Err(error.into()))),
                None => {
                    if self.received == self.length {
                        if let Some(fill) = self.fill.take() {
                            fill.commit().await;
                        }
                    }
                    if self.received != self.length {
                        return (
                            None,
                            Some(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "incomplete origin body",
                            )
                            .into())),
                        );
                    }
                    return (None, None);
                }
            }
        }
        let bytes = self
            .remainder
            .split_to(self.remainder.len().min(IO_CHUNK_BYTES));
        self.received = self.received.saturating_add(bytes.len() as u64);
        if let Some(fill) = self.fill.take() {
            self.fill = fill.write(bytes.clone()).await;
        }
        // Hyper may stop polling once Content-Length bytes have been emitted. Keep
        // the final chunk until true upstream EOF and the disk commit are complete.
        if self.received >= self.length && self.remainder.is_empty() {
            match self.origin.frame().await {
                None => {
                    if self.received == self.length && !self.cancellation.is_cancelled() {
                        if let Some(fill) = self.fill.take() {
                            fill.commit().await;
                        }
                    }
                    return (None, Some(Ok(Frame::data(bytes))));
                }
                Some(Err(error)) => return (None, Some(Err(error.into()))),
                Some(Ok(frame)) => {
                    // Preserve trailers for the caller, but never store them.
                    self.fill = None;
                    self.queued = Some(frame);
                }
            }
        }
        (Some(self), Some(Ok(Frame::data(bytes))))
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError> + Send,
{
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            let Some(state) = this.state.take() else {
                return Poll::Ready(None);
            };
            this.pending = Some(Box::pin(state.next()));
        }
        match this.pending.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((state, frame)) => {
                this.state = state;
                this.pending = None;
                Poll::Ready(frame)
            }
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheStore, MAX_CACHE_ITEM_BYTES};
    use http::{HeaderMap, StatusCode};
    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };

    struct Frames(VecDeque<Result<Frame<Bytes>, std::io::Error>>);
    impl Body for Frames {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front())
        }
    }
    fn data(bytes: &'static [u8]) -> Result<Frame<Bytes>, std::io::Error> {
        Ok(Frame::data(Bytes::from_static(bytes)))
    }
    async fn fill(cache: &CacheStore, length: u64) -> CacheFill {
        cache
            .begin_fill(
                cache.epoch(),
                &"a".repeat(64),
                StatusCode::OK,
                &HeaderMap::new(),
                length,
                Duration::from_secs(60),
                Instant::now(),
                MAX_CACHE_ITEM_BYTES + 1024 * 1024,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn tee_binds_cancellation_to_publication_after_true_eof() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let cancellation = CancellationToken::new();
        let body = TeeBody::new(
            Frames(VecDeque::from([data(b"abc")])),
            fill(&cache, 3).await,
            3,
            cancellation.clone(),
        );
        let started = std::sync::Arc::new(std::sync::Barrier::new(2));
        let resume = std::sync::Arc::new(std::sync::Barrier::new(2));
        cache.set_commit_gate(Some((started.clone(), resume.clone())));
        let draining = tokio::spawn(async move { body.collect().await });
        tokio::task::spawn_blocking(move || started.wait())
            .await
            .unwrap();
        cache.cancel_fill(&cancellation);
        cache.set_commit_gate(None);
        tokio::task::spawn_blocking(move || resume.wait())
            .await
            .unwrap();
        let _ = draining.await.unwrap();
        assert!(cache.get(&"a".repeat(64)).await.is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn true_eof_commits_before_the_final_chunk_is_returned() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let mut body = TeeBody::new(
            Frames(VecDeque::from([data(b"abc")])),
            fill(&cache, 3).await,
            3,
            CancellationToken::new(),
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "abc"
        );
        assert!(cache.get(&"a".repeat(64)).await.is_some());
    }

    #[tokio::test]
    async fn partial_error_trailers_and_drop_never_commit() {
        for frames in [
            vec![data(b"a")],
            vec![data(b"a"), Err(std::io::Error::other("upstream failed"))],
            vec![data(b"abc"), Ok(Frame::trailers(HeaderMap::new()))],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            let body = TeeBody::new(
                Frames(frames.into()),
                fill(&cache, 3).await,
                3,
                CancellationToken::new(),
            );
            let _ = body.collect().await;
            assert!(cache.get(&"a".repeat(64)).await.is_none());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let mut body = TeeBody::new(
            Frames(VecDeque::from([data(b"a"), data(b"bc")])),
            fill(&cache, 3).await,
            3,
            CancellationToken::new(),
        );
        body.frame().await.unwrap().unwrap();
        drop(body);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn disk_write_failure_preserves_the_entire_network_body() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let mut writer = fill(&cache, 3).await;
        let read_only = File::open(writer.temporary.path()).unwrap();
        *writer.temporary.as_file_mut() = read_only;
        let body = TeeBody::new(
            Frames(VecDeque::from([data(b"a"), data(b"bc")])),
            writer,
            3,
            CancellationToken::new(),
        );
        assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
        assert!(cache.get(&"a".repeat(64)).await.is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn cancellation_drops_the_partial_cache_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let cancel = CancellationToken::new();
        let mut body = TeeBody::new(
            Frames(VecDeque::from([data(b"a"), data(b"bc")])),
            fill(&cache, 3).await,
            3,
            cancel.clone(),
        );
        body.frame().await.unwrap().unwrap();
        cancel.cancel();
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn cached_file_short_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache
            .put(
                &"a".repeat(64),
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                1024,
            )
            .await
            .unwrap();
        let entry = cache.get(&"a".repeat(64)).await.unwrap();
        // Simulates external truncation after the integrity prepass.
        File::options()
            .write(true)
            .open(dir.path().join(format!("{}.body", "a".repeat(64))))
            .unwrap()
            .set_len(1)
            .unwrap();
        assert!(entry.body.collect().await.is_err());
    }
}

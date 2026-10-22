//! A failed incoming connection must not cancel every healthy tunnel.
use std::{future::Future, io, time::Duration};
use tokio_util::sync::CancellationToken;

fn recoverable(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::OutOfMemory
    ) {
        return true;
    }
    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    ) {
        return true;
    }
    // Linux accept(2) exposes pending network errors from the incoming socket.
    // Its man page recommends retrying these like EAGAIN.
    // https://man7.org/linux/man-pages/man2/accept.2.html
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if matches!(
        error.raw_os_error(),
        Some(
            libc::ENETDOWN
                | libc::EPROTO
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        )
    ) {
        return true;
    }
    // Winsock resource exhaustion and temporarily unavailable network.
    #[cfg(windows)]
    if matches!(
        error.raw_os_error(),
        Some(10024 | 10050 | 10051 | 10052 | 10055 | 10065)
    ) {
        return true;
    }
    false
}

pub(super) async fn next<F, Fut, T>(
    mut accept: F,
    cancellation: &CancellationToken,
    on_error: impl Fn(&io::Error),
) -> io::Result<Option<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut delay = Duration::from_millis(50);
    loop {
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Ok(None),
            result = accept() => result,
        };
        match result {
            Ok(value) => return Ok(Some(value)),
            Err(error) => {
                on_error(&error);
                if !recoverable(&error) {
                    return Err(error);
                }
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Ok(None),
                    _ = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test(start_paused = true)]
    async fn connection_error_retries_in_place_then_returns_success() {
        let calls = Cell::new(0);
        let errors = Cell::new(0);
        let result = next(
            || {
                calls.set(calls.get() + 1);
                std::future::ready(if calls.get() < 4 {
                    Err(io::ErrorKind::ConnectionAborted.into())
                } else {
                    Ok(42)
                })
            },
            &CancellationToken::new(),
            |_| errors.set(errors.get() + 1),
        )
        .await
        .unwrap();
        assert_eq!(result, Some(42));
        assert_eq!(errors.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_backoff_and_fatal_error_is_not_retried() {
        let cancellation = CancellationToken::new();
        let task_token = cancellation.clone();
        let task = tokio::spawn(async move {
            next(
                || std::future::ready::<io::Result<()>>(Err(io::ErrorKind::OutOfMemory.into())),
                &task_token,
                |_| {},
            )
            .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(task.await.unwrap().unwrap(), None);

        let calls = Cell::new(0);
        let result = next(
            || {
                calls.set(calls.get() + 1);
                std::future::ready::<io::Result<()>>(Err(io::ErrorKind::PermissionDenied.into()))
            },
            &CancellationToken::new(),
            |_| {},
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn resource_errors_are_retryable_without_classifying_every_io_error() {
        #[cfg(unix)]
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(recoverable(&io::Error::from_raw_os_error(code)));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        for code in [
            libc::ENETDOWN,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ] {
            assert!(recoverable(&io::Error::from_raw_os_error(code)));
        }
        assert!(!recoverable(&io::ErrorKind::InvalidInput.into()));
    }
}

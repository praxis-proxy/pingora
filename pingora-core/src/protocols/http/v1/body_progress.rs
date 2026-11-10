// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Payload-only progress retained when a body write is cancelled or fails.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

/// Track accepted payload while excluding the chunk header and trailer.
pub(super) struct BodyProgress<'a, S> {
    pub stream: &'a mut S,
    pub sent: &'a mut usize,
    pub skip: usize,
    pub remaining: usize,
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BodyProgress<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut *self.stream).poll_write(cx, data) {
            Poll::Ready(Ok(count)) => {
                let framing = count.min(self.skip);
                self.skip -= framing;
                let payload = count.saturating_sub(framing).min(self.remaining);
                self.remaining -= payload;
                *self.sent = self.sent.saturating_add(payload);
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::body::BodyWriter;
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn cancelled_writes_preserve_payload_progress_without_chunk_framing() {
        for chunked in [false, true] {
            let (mut stream, mut reader) = tokio::io::duplex(8);
            let mut writer = BodyWriter::new();
            if chunked {
                writer.init_chunked();
            } else {
                writer.init_content_length(32);
            }
            let mut sent = 0;
            let mut progress = BodyProgress {
                stream: &mut stream,
                sent: &mut sent,
                skip: if chunked { 4 } else { 0 },
                remaining: 32,
            };
            assert!(tokio::time::timeout(
                Duration::from_millis(5),
                writer.write_body(&mut progress, &[b'x'; 32])
            )
            .await
            .is_err());
            assert_eq!(sent, if chunked { 4 } else { 8 });
            let mut received = [0; 8];
            reader.read_exact(&mut received).await.unwrap();
            assert_eq!(received.iter().filter(|byte| **byte == b'x').count(), sent);
        }
    }

    struct FlushFailure;
    impl AsyncWrite for FlushFailure {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn flush_failure_does_not_erase_accepted_payload() {
        let mut writer = BodyWriter::new();
        writer.init_content_length(4);
        let mut stream = FlushFailure;
        let mut sent = 0;
        let mut progress = BodyProgress {
            stream: &mut stream,
            sent: &mut sent,
            skip: 0,
            remaining: 4,
        };
        assert!(writer.write_body(&mut progress, b"body").await.is_err());
        assert_eq!(sent, 4);
    }
}

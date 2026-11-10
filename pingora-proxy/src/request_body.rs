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

//! Transport-owned admission of filtered request body prefixes.

use async_trait::async_trait;
use pingora_core::protocols::http::HttpTask;
use pingora_error::{Error, ErrorType::InternalError, Result};

/// An owned admission budget for one filtered request body chunk.
///
/// A pending `next` may be cancelled and polled again. Implementations must
/// retain admitted ownership until `written`, and refund unacknowledged bytes
/// on drop. Admission time is distinct from the transport's write timeout.
#[async_trait]
pub trait RequestBodyPacer: Send + Sync {
    /// Wait for a nonempty prefix no larger than `remaining`.
    async fn next(&mut self, remaining: usize) -> Result<usize>;
    /// Acknowledge payload accepted by the upstream body writer.
    fn written(&mut self, bytes: usize);
}

/// A pipe item retains its budget while queued, waiting, and writing.
pub(crate) struct RequestBodyTask {
    task: Option<HttpTask>,
    pacer: Option<Box<dyn RequestBodyPacer>>,
}

impl From<HttpTask> for RequestBodyTask {
    fn from(task: HttpTask) -> Self {
        Self::new(task, None)
    }
}

impl RequestBodyTask {
    pub(crate) fn new(task: HttpTask, pacer: Option<Box<dyn RequestBodyPacer>>) -> Self {
        Self {
            task: Some(task),
            pacer,
        }
    }

    /// Split only after admission. Cancellation leaves the original tail owned.
    pub(crate) async fn next(&mut self) -> Result<(HttpTask, usize)> {
        let (data, end, upgraded) = match self.task.as_ref() {
            Some(HttpTask::Body(Some(data), end)) => (data, *end, false),
            Some(HttpTask::UpgradedBody(Some(data), end)) => (data, *end, true),
            _ => return Ok((self.task.take().unwrap_or(HttpTask::Body(None, true)), 0)),
        };
        if data.is_empty() || self.pacer.is_none() {
            let count = data.len();
            return Ok((self.task.take().unwrap(), count));
        }
        let count = self.pacer.as_mut().unwrap().next(data.len()).await?;
        if count == 0 || count > data.len() {
            return Error::e_explain(
                InternalError,
                "request body pacer returned an invalid prefix",
            );
        }
        let prefix = data.slice(..count);
        let tail = data.slice(count..);
        let last = tail.is_empty();
        let task = if upgraded {
            HttpTask::UpgradedBody(Some(prefix), end && last)
        } else {
            HttpTask::Body(Some(prefix), end && last)
        };
        self.task = (!last).then(|| {
            if upgraded {
                HttpTask::UpgradedBody(Some(tail), end)
            } else {
                HttpTask::Body(Some(tail), end)
            }
        });
        Ok((task, count))
    }

    pub(crate) fn written(&mut self, bytes: usize) {
        if let Some(pacer) = self.pacer.as_mut() {
            pacer.written(bytes);
        }
    }

    pub(crate) fn done(&self) -> bool {
        self.task.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Pacer(Arc<AtomicUsize>);
    #[async_trait]
    impl RequestBodyPacer for Pacer {
        async fn next(&mut self, remaining: usize) -> Result<usize> {
            Ok(remaining.min(3))
        }
        fn written(&mut self, bytes: usize) {
            self.0.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn prefixes_keep_eos_and_acknowledge_only_completed_writes() {
        let accepted = Arc::new(AtomicUsize::new(0));
        let mut pending = RequestBodyTask::new(
            HttpTask::Body(Some(Bytes::from_static(b"abcdefgh")), true),
            Some(Box::new(Pacer(accepted.clone()))),
        );
        for (expected, end) in [
            (b"abc".as_slice(), false),
            (b"def".as_slice(), false),
            (b"gh".as_slice(), true),
        ] {
            let before = accepted.load(Ordering::Relaxed);
            let (task, count) = pending.next().await.unwrap();
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                before,
                "admission does not acknowledge bytes"
            );
            let HttpTask::Body(Some(data), eos) = task else {
                panic!("body prefix expected")
            };
            assert_eq!(data, expected);
            assert_eq!(eos, end);
            assert_eq!(count, data.len());
            pending.written(count);
            assert_eq!(accepted.load(Ordering::Relaxed), before + count);
        }
        assert!(pending.done());
        assert_eq!(accepted.load(Ordering::Relaxed), 8);
    }

    struct Invalid;
    #[async_trait]
    impl RequestBodyPacer for Invalid {
        async fn next(&mut self, remaining: usize) -> Result<usize> {
            Ok(remaining + 1)
        }
        fn written(&mut self, _: usize) {
            panic!("invalid prefix must never be accepted")
        }
    }

    #[tokio::test]
    async fn invalid_admission_does_not_consume_the_chunk() {
        let mut pending = RequestBodyTask::new(
            HttpTask::Body(Some(Bytes::from_static(b"a")), true),
            Some(Box::new(Invalid)),
        );
        assert!(pending.next().await.is_err());
        assert!(!pending.done());
        assert!(pending.next().await.is_err());
    }
    struct Gate(Arc<tokio::sync::Notify>);
    #[async_trait]
    impl RequestBodyPacer for Gate {
        async fn next(&mut self, remaining: usize) -> Result<usize> {
            self.0.notified().await;
            Ok(remaining)
        }
        fn written(&mut self, _: usize) {}
    }

    #[tokio::test]
    async fn cancelled_admission_keeps_the_original_body_and_end_marker() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let mut pending = RequestBodyTask::new(
            HttpTask::Body(Some(Bytes::from_static(b"body")), true),
            Some(Box::new(Gate(gate.clone()))),
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), pending.next())
                .await
                .is_err()
        );
        assert!(!pending.done());
        gate.notify_one();
        let (task, count) = pending.next().await.unwrap();
        assert_eq!(count, 4);
        assert!(matches!(task, HttpTask::Body(Some(data), true) if data == "body"));
    }
}

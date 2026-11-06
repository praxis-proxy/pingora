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

// NOTE: RunArgs carries a shutdown watch only on Unix, so this test is
// Unix-only. It releases a test-controlled watch instead of raising a process
// signal, so shutdown delivery cannot race signal-listener registration.

use pingora_core::server::{
    configuration::ServerConf, ExecutionPhase, GracefulShutdownIdle, RunArgs, Server,
};
#[cfg(unix)]
use pingora_core::server::{ShutdownSignal, ShutdownSignalWatch};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
#[cfg(unix)]
use tokio::sync::oneshot;

const GRACE_PERIOD: Duration = Duration::from_secs(10);
const PHASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Wait for the next execution phase, failing if none arrives before the timeout.
fn next_phase(phase: &mut broadcast::Receiver<ExecutionPhase>) -> ExecutionPhase {
    let deadline = Instant::now() + PHASE_TIMEOUT;
    loop {
        match phase.try_recv() {
            Ok(value) => return value,
            Err(broadcast::error::TryRecvError::Closed) => panic!("execution phase channel closed"),
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                panic!("execution phase receiver lagged by {skipped} messages")
            }
            Err(broadcast::error::TryRecvError::Empty) if Instant::now() >= deadline => {
                panic!("timed out waiting for execution phase")
            }
            Err(broadcast::error::TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(10))
            }
        }
    }
}

/// Assert that the next execution phase matches the expected phase.
fn assert_phase(phase: &mut broadcast::Receiver<ExecutionPhase>, expected: ExecutionPhase) {
    let actual = next_phase(phase);
    assert_eq!(
        std::mem::discriminant(&actual),
        std::mem::discriminant(&expected),
        "expected {expected:?} phase, got {actual:?}"
    );
}

/// A shutdown watch the test releases once the server is running.
#[cfg(unix)]
struct TestShutdownSignal {
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

#[cfg(unix)]
impl TestShutdownSignal {
    /// Create a shutdown watch that fires once the test releases it.
    fn new(release: oneshot::Receiver<()>) -> Self {
        Self {
            release: Mutex::new(Some(release)),
        }
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl ShutdownSignalWatch for TestShutdownSignal {
    /// Wait for the test to release shutdown, then request graceful termination.
    async fn recv(&self) -> ShutdownSignal {
        let release = self.release.lock().unwrap().take();
        if let Some(release) = release {
            let _ = release.await;
        }
        ShutdownSignal::GracefulTerminate
    }
}

/// Graceful shutdown ends early when the installed idle callback reports idle.
#[cfg(unix)]
#[test]
fn server_uses_idle_callback_during_graceful_shutdown() {
    let callback_grace_period = Arc::new(AtomicU64::new(0));
    let callback_grace_period_writer = Arc::clone(&callback_grace_period);
    let idle_wait: GracefulShutdownIdle = Arc::new(move |grace_period| {
        callback_grace_period_writer.store(grace_period.as_secs(), Ordering::SeqCst);
        true
    });
    let conf = ServerConf {
        grace_period_seconds: Some(GRACE_PERIOD.as_secs()),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.set_graceful_shutdown_idle(idle_wait);
    let mut phase = server.watch_execution_phase();
    let (release_tx, release_rx) = oneshot::channel();

    let join = std::thread::spawn(move || {
        server.bootstrap();
        server.run(RunArgs {
            shutdown_signal: Box::new(TestShutdownSignal::new(release_rx)),
        });
    });

    assert_phase(&mut phase, ExecutionPhase::Bootstrap);
    assert_phase(&mut phase, ExecutionPhase::BootstrapComplete);
    assert_phase(&mut phase, ExecutionPhase::Running);

    release_tx
        .send(())
        .expect("the shutdown watch should still be waiting");

    assert_phase(&mut phase, ExecutionPhase::GracefulTerminate);
    assert_phase(&mut phase, ExecutionPhase::ShutdownStarted);
    assert_phase(&mut phase, ExecutionPhase::ShutdownGracePeriod);
    let grace_period_started = Instant::now();
    assert_phase(&mut phase, ExecutionPhase::ShutdownRuntimes);
    let callback_wait = grace_period_started.elapsed();

    join.join().unwrap();

    assert_eq!(
        callback_grace_period.load(Ordering::SeqCst),
        GRACE_PERIOD.as_secs(),
        "the idle callback should receive the configured grace period"
    );
    assert!(
        callback_wait < GRACE_PERIOD,
        "the idle callback should allow shutdown before the full grace period"
    );
}

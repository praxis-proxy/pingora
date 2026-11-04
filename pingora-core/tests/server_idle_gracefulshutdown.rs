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

// NOTE: This test sends a shutdown signal to itself, so it needs to be an
// isolated test to prevent concurrency.

use pingora_core::server::{
    configuration::ServerConf, ExecutionPhase, GracefulShutdownIdle, RunArgs, Server,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const GRACE_PERIOD: Duration = Duration::from_secs(10);
const PHASE_TIMEOUT: Duration = Duration::from_secs(5);

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

    let join = std::thread::spawn(move || {
        server.bootstrap();
        server.run(RunArgs::default());
    });

    assert!(matches!(next_phase(&mut phase), ExecutionPhase::Bootstrap));
    assert!(matches!(
        next_phase(&mut phase),
        ExecutionPhase::BootstrapComplete
    ));
    assert!(matches!(next_phase(&mut phase), ExecutionPhase::Running));
    std::thread::sleep(Duration::from_millis(500));

    unsafe {
        libc::raise(libc::SIGTERM);
    }

    assert!(matches!(
        next_phase(&mut phase),
        ExecutionPhase::GracefulTerminate
    ));
    assert!(matches!(
        next_phase(&mut phase),
        ExecutionPhase::ShutdownStarted
    ));
    assert!(matches!(
        next_phase(&mut phase),
        ExecutionPhase::ShutdownGracePeriod
    ));
    let grace_period_started = Instant::now();
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownRuntimes
    ));
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

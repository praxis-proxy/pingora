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

use once_cell::sync::Lazy;
use std::{thread, time};

use clap::Parser;
use pingora_core::listeners::Listeners;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::services::listening::Service;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Response, StatusCode};
use pingora_timeout::timeout;
use std::time::Duration;

use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;

#[derive(Clone)]
pub struct EchoApp;

#[async_trait]
impl ServeHttp for EchoApp {
    async fn response(&self, http_stream: &mut ServerSession) -> Response<Vec<u8>> {
        // read timeout of 2s
        let read_timeout = 2000;
        let body = match timeout(
            Duration::from_millis(read_timeout),
            http_stream.read_request_body(),
        )
        .await
        {
            Ok(res) => match res.unwrap() {
                Some(bytes) => bytes,
                None => Bytes::from("no body!"),
            },
            Err(_) => {
                panic!("Timed out after {:?}ms", read_timeout);
            }
        };

        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html")
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(body.to_vec())
            .unwrap()
    }
}

pub struct MyServer {
    // Maybe useful in the future
    #[allow(dead_code)]
    pub handle: thread::JoinHandle<()>,
}

fn entry_point(opt: Option<Opt>) {
    env_logger::init();

    let cert_path = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));

    let mut my_server = Server::new(opt).unwrap();
    my_server.bootstrap();

    let mut listeners = Listeners::tcp("0.0.0.0:6145");
    #[cfg(unix)]
    listeners.add_uds("/tmp/echo.sock", None);

    let mut tls_settings =
        pingora_core::listeners::tls::TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    tls_settings.enable_h2();
    listeners.add_tls_with_settings("0.0.0.0:6146", None, tls_settings);

    let echo_service_http =
        Service::with_listeners("Echo Service HTTP".to_string(), listeners, EchoApp);

    // Echo service with h2c enabled + TLS listener (for testing h2c + TLS interaction)
    let mut h2c_tls_settings =
        pingora_core::listeners::tls::TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    h2c_tls_settings.enable_h2();
    let mut h2c_listeners = Listeners::tcp("0.0.0.0:6160");
    h2c_listeners.add_tls_with_settings("0.0.0.0:6161", None, h2c_tls_settings);
    let mut h2c_app = pingora_core::apps::http_app::HttpServer::new_app(EchoApp);
    h2c_app.server_options.get_or_insert_default().h2c = true;

    let echo_service_h2c =
        Service::with_listeners("Echo Service H2C".to_string(), h2c_listeners, h2c_app);

    my_server.add_service(echo_service_http);
    my_server.add_service(echo_service_h2c);
    my_server.run_forever();
}

impl MyServer {
    pub fn start() -> Self {
        let opts: Vec<String> = vec![
            "pingora".into(),
            "-c".into(),
            "tests/pingora_conf.yaml".into(),
        ];
        let server_handle = thread::spawn(|| {
            entry_point(Some(Opt::parse_from(opts)));
        });
        // wait until the server is up
        thread::sleep(time::Duration::from_secs(2));
        MyServer {
            handle: server_handle,
        }
    }
}

pub static TEST_SERVER: Lazy<MyServer> = Lazy::new(MyServer::start);

/// Install a rustls `CryptoProvider` for this test process.
///
/// Pingora installs none — selecting a provider is the application's job — and
/// `pingora-rustls` enables rustls' `custom-provider`, which removes the
/// implicit fallback to a built-in provider. Without this the server threads
/// panic on the first `ServerConfig` they build.
///
/// `aws_lc_rs` is arbitrary here; these tests exercise pingora, not a
/// provider. Repeat calls are no-ops.
#[cfg(feature = "rustls")]
fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn init() {
    #[cfg(feature = "rustls")]
    install_crypto_provider();
    let _ = *TEST_SERVER;
}

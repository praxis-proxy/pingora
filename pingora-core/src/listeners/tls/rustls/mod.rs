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

use std::sync::Arc;

use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{server::handshake, server::handshake_with_callback, TlsStream};
use log::debug;
use pingora_error::ErrorType::InternalError;
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::load_certs_and_key_files;
use pingora_rustls::ClientCertVerifier;
use pingora_rustls::ServerConfig;
use pingora_rustls::{version, TlsAcceptor as RusTlsAcceptor};

use crate::protocols::{ALPN, IO};

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_path: String,
    key_path: String,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
    custom_config: Option<Arc<ServerConfig>>,
}

/// A TLS acceptor wrapping a rustls [`RusTlsAcceptor`] with optional
/// handshake callbacks.
pub struct Acceptor {
    /// The underlying rustls acceptor.
    pub acceptor: RusTlsAcceptor,
    callbacks: Option<TlsAcceptCallbacks>,
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// _NOTE_ This function will panic if there is an error in loading
    /// certificate files or constructing the builder
    ///
    /// Todo: Return a result instead of panicking XD
    pub fn build(self) -> Acceptor {
        // rustls 0.23+ requires an explicit CryptoProvider.
        pingora_rustls::install_default_crypto_provider();

        let config = if let Some(custom_config) = self.custom_config {
            custom_config
        } else {
            let Ok(Some((certs, key))) = load_certs_and_key_files(&self.cert_path, &self.key_path)
            else {
                panic!(
                    "Failed to load provided certificates \"{}\" or key \"{}\".",
                    self.cert_path, self.key_path
                )
            };

            let builder =
                ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13]);
            let builder = if let Some(verifier) = self.client_cert_verifier {
                builder.with_client_cert_verifier(verifier)
            } else {
                builder.with_no_client_auth()
            };
            let mut config = builder
                .with_single_cert(certs, key)
                .explain_err(InternalError, |e| {
                    format!("Failed to create server listener config: {e}")
                })
                .unwrap();

            if let Some(alpn_protocols) = self.alpn_protocols {
                config.alpn_protocols = alpn_protocols;
            }

            Arc::new(config)
        };

        Acceptor {
            acceptor: RusTlsAcceptor::from(config),
            callbacks: None,
        }
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    /// Set the ALPN protocols for this endpoint.
    pub fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    /// Configure mTLS by providing a rustls client certificate verifier.
    pub fn set_client_cert_verifier(&mut self, verifier: Arc<dyn ClientCertVerifier>) {
        self.client_cert_verifier = Some(verifier);
    }

    /// Create a [`TlsSettings`] from certificate and key file paths
    /// using a Mozilla-intermediate-compatible configuration.
    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self> {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
            client_cert_verifier: None,
            custom_config: None,
        })
    }

    /// Create a new [`TlsSettings`] with a pre-built [`ServerConfig`].
    ///
    /// This allows full control over the rustls configuration,
    /// including 0-RTT, session resumption, and custom certificate
    /// resolvers.
    ///
    /// # Important
    ///
    /// When a custom config is provided, [`build`] uses it as-is and
    /// ignores every other field on [`TlsSettings`]. Calls to
    /// [`enable_h2`], [`set_alpn`], or [`set_client_cert_verifier`]
    /// made after this constructor will compile but have no effect.
    /// Configure ALPN, client-auth, and all other options directly on
    /// the [`ServerConfig`] before passing it here.
    ///
    /// `cert_path` and `key_path` are stored as empty strings because
    /// the custom config already owns its certificate chain; the
    /// empty values are never read during [`build`].
    ///
    /// [`build`]: Self::build
    /// [`enable_h2`]: Self::enable_h2
    /// [`set_alpn`]: Self::set_alpn
    /// [`set_client_cert_verifier`]: Self::set_client_cert_verifier
    /// [`ServerConfig`]: pingora_rustls::ServerConfig
    /// [`TlsSettings`]: Self
    pub fn with_server_config(config: Arc<ServerConfig>) -> Result<Self> {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_path: String::new(),
            key_path: String::new(),
            client_cert_verifier: None,
            custom_config: Some(config),
        })
    }

    /// Create a [`TlsSettings`] that uses certificate callbacks.
    ///
    /// Currently unsupported with the `rustls` feature; always
    /// returns an error.
    pub fn with_callbacks() -> Result<Self> {
        // TODO: verify if/how callback in handshake can be done using Rustls
        Error::e_explain(
            InternalError,
            "Certificate callbacks are not supported with feature \"rustls\".",
        )
    }
}

impl Acceptor {
    /// Perform the TLS handshake on the given stream.
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");
        // TODO: be able to offload this handshake in a thread pool
        if let Some(cb) = self.callbacks.as_ref() {
            handshake_with_callback(self, stream, cb).await
        } else {
            handshake(self, stream).await
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{fmt::Debug, sync::Arc};

    use pingora_rustls::ServerConfig;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;

    use super::TlsSettings;

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// A no-op cert resolver for building test [`ServerConfig`] values
    /// without real certificates.
    #[derive(Debug)]
    struct StubResolver;

    impl ResolvesServerCert for StubResolver {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    /// Build a minimal [`ServerConfig`] suitable for unit tests.
    fn stub_server_config() -> Arc<ServerConfig> {
        pingora_rustls::install_default_crypto_provider();
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(StubResolver)),
        )
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn with_server_config_stores_custom_config() {
        let config = stub_server_config();

        let settings = TlsSettings::with_server_config(config.clone()).unwrap();
        assert!(
            settings.custom_config.is_some(),
            "custom_config must be set"
        );
        assert!(
            Arc::ptr_eq(settings.custom_config.as_ref().unwrap(), &config),
            "custom_config must point to the same Arc"
        );
    }

    #[test]
    fn with_server_config_leaves_other_fields_default() {
        let config = stub_server_config();

        let settings = TlsSettings::with_server_config(config).unwrap();
        assert!(settings.alpn_protocols.is_none(), "alpn must be None");
        assert!(settings.cert_path.is_empty(), "cert_path must be empty");
        assert!(settings.key_path.is_empty(), "key_path must be empty");
        assert!(
            settings.client_cert_verifier.is_none(),
            "client_cert_verifier must be None"
        );
    }

    #[test]
    fn with_server_config_build_uses_custom_config() {
        pingora_rustls::install_default_crypto_provider();
        let mut sc = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(StubResolver));
        sc.alpn_protocols = vec![b"h2".to_vec()];
        let config = Arc::new(sc);

        let acceptor = TlsSettings::with_server_config(config).unwrap().build();
        assert_eq!(
            acceptor.acceptor.config().alpn_protocols,
            vec![b"h2".to_vec()],
            "ALPN from custom config must survive build()"
        );
    }
}

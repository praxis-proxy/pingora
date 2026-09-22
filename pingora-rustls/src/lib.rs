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

//! This module contains all the rustls specific pingora integration for things
//! like loading certificates and private keys
//!
//! # Choosing a crypto provider
//!
//! **This crate installs no [`CryptoProvider`], and there is no default.** The
//! application must install one before it builds any `ServerConfig`,
//! `ClientConfig`, listener or connector.
//!
//! rustls normally falls back to whichever built-in provider its features
//! happen to enable. This crate enables rustls' `custom-provider` feature,
//! which removes that fallback, so a missing install is a loud panic rather
//! than a silent choice nobody made:
//!
//! ```text
//! Could not automatically determine the process-level CryptoProvider from
//! Rustls crate features. Call CryptoProvider::install_default() before this
//! point to select a provider manually...
//! ```
//!
//! That is deliberate. Which implementation performs the cryptography is a
//! deployment decision — for FIPS it is *the* decision — so it is made once,
//! explicitly, in the application.
//!
//! ## Install early, in exactly one place
//!
//! Install before any service is constructed. Pingora builds its upstream
//! connectors while the proxy service is created, which is earlier than most
//! callers expect, so "before `Server::run_forever`" is not early enough —
//! install during startup, before services are added.
//!
//! ## Using aws-lc-rs
//!
//! Add the provider feature to your own `Cargo.toml`, not to this crate:
//!
//! ```toml
//! rustls = { version = "0.23", features = ["aws_lc_rs"] }
//! ```
//!
//! ```ignore
//! rustls::crypto::aws_lc_rs::default_provider()
//!     .install_default()
//!     .expect("a CryptoProvider was already installed");
//! ```
//!
//! ## Using OpenSSL
//!
//! `rustls-openssl` is a third-party provider backed by the system OpenSSL
//! library, so the cryptography is performed by `libcrypto.so` rather than by
//! a statically linked Rust implementation. Note it is a *separate crate*, not
//! a rustls feature — rustls ships only `ring` and `aws-lc-rs`, so there is no
//! `rustls = { features = ["openssl"] }` to enable. This workspace vendors it
//! (see `pingora-rustls-openssl/` and FORK.md) as
//! `quixotic-plecostomus-rustls-openssl`, keeping the `rustls_openssl` library
//! name:
//!
//! ```toml
//! rustls-openssl = { version = "0.4", package = "quixotic-plecostomus-rustls-openssl" }
//! ```
//!
//! ```ignore
//! rustls_openssl::default_provider()
//!     .install_default()
//!     .expect("a CryptoProvider was already installed");
//! ```
//!
//! Build with `OPENSSL_NO_VENDOR=1` so the `openssl` crate links the system
//! library rather than vendoring its own copy — vendoring would defeat the
//! point, since the validated module is the one the platform ships.
//!
//! ## Selecting between them at build time
//!
//! Because a provider is an ordinary dependency, the choice is an ordinary
//! feature in the application. Make them mutually exclusive and fail closed,
//! so that "no provider selected" is a build error rather than a runtime
//! panic:
//!
//! ```toml
//! [features]
//! aws-lc-rs = ["rustls/aws_lc_rs"]
//! openssl   = ["dep:rustls-openssl"]
//! ```
//!
//! ```ignore
//! #[cfg(all(feature = "openssl", feature = "aws-lc-rs"))]
//! compile_error!("select exactly one crypto provider");
//! #[cfg(not(any(feature = "openssl", feature = "aws-lc-rs")))]
//! compile_error!("no crypto provider selected");
//! ```
//!
//! ## Tests
//!
//! Test processes must install a provider too, and must not rely on some other
//! test having done it first — ordering across test threads is not guaranteed,
//! which produces failures that come and go. Install at the top of every test
//! that touches TLS; repeat calls are no-ops.
//!
//! [`CryptoProvider`]: rustls::crypto::CryptoProvider

#![warn(clippy::all)]

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use log::warn;
pub use no_debug::{Ellipses, NoDebug, WithTypeInfo};
use pingora_error::{Error, ErrorType, OrErr, Result};

use rustls::crypto::hash::{Hash, HashAlgorithm};
pub use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
pub use rustls::server::{
    ClientCertVerifierBuilder, ClientHello, ResolvesServerCert, WebPkiClientVerifier,
};
pub use rustls::sign;
pub use rustls::{
    client::WebPkiServerVerifier, crypto::CryptoProvider, version, CertificateError, ClientConfig,
    DigitallySignedStruct, Error as RusTlsError, KeyLogFile, RootCertStore, ServerConfig,
    SignatureScheme, Stream,
};

pub use rustls_native_certs::load_native_certs;
use rustls_pemfile::Item;
pub use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;
pub use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};

// This allows to skip certificate verification. Be highly cautious.
pub use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

/// Load the given file from disk as a buffered reader and use the pingora Error
/// type instead of the std::io version
fn load_file<P>(path: P) -> Result<BufReader<File>>
where
    P: AsRef<Path>,
{
    File::open(path)
        .or_err(ErrorType::FileReadError, "Failed to load file")
        .map(BufReader::new)
}

/// Read the pem file at the given path from disk
fn load_pem_file<P>(path: P) -> Result<Vec<Item>>
where
    P: AsRef<Path>,
{
    rustls_pemfile::read_all(&mut load_file(path)?)
        .map(|item_res| {
            item_res.or_err(
                ErrorType::InvalidCert,
                "Certificate in pem file could not be read",
            )
        })
        .collect()
}

/// Load the certificates from the given pem file path into the given
/// certificate store
pub fn load_ca_file_into_store<P>(path: P, cert_store: &mut RootCertStore) -> Result<()>
where
    P: AsRef<Path>,
{
    for pem_item in load_pem_file(path)? {
        // only loading certificates, handling a CA file
        let Item::X509Certificate(content) = pem_item else {
            return Error::e_explain(
                ErrorType::InvalidCert,
                "Pem file contains un-loadable certificate type",
            );
        };
        cert_store.add(content).or_err(
            ErrorType::InvalidCert,
            "Failed to load X509 certificate into root store",
        )?;
    }

    Ok(())
}

/// Attempt to load the native cas into the given root-certificate store
pub fn load_platform_certs_incl_env_into_store(ca_certs: &mut RootCertStore) -> Result<()> {
    // this includes handling of ENV vars SSL_CERT_FILE & SSL_CERT_DIR
    for cert in load_native_certs()
        .or_err(ErrorType::InvalidCert, "Failed to load native certificates")?
        .into_iter()
    {
        ca_certs.add(cert).or_err(
            ErrorType::InvalidCert,
            "Failed to load native certificate into root store",
        )?;
    }

    Ok(())
}

/// Load the certificates and private key files
pub fn load_certs_and_key_files<'a>(
    cert: &str,
    key: &str,
) -> Result<Option<(Vec<CertificateDer<'a>>, PrivateKeyDer<'a>)>> {
    let certs_file = load_pem_file(cert)?;
    let key_file = load_pem_file(key)?;

    let certs = certs_file
        .into_iter()
        .filter_map(|item| {
            if let Item::X509Certificate(cert) = item {
                Some(cert)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    // These are the currently supported pk types -
    // [https://doc.servo.org/rustls/key/struct.PrivateKey.html]
    let private_key_opt = key_file
        .into_iter()
        .filter_map(|key_item| match key_item {
            Item::Pkcs1Key(key) => Some(PrivateKeyDer::from(key)),
            Item::Pkcs8Key(key) => Some(PrivateKeyDer::from(key)),
            Item::Sec1Key(key) => Some(PrivateKeyDer::from(key)),
            _ => None,
        })
        .next();

    if let (Some(private_key), false) = (private_key_opt, certs.is_empty()) {
        Ok(Some((certs, private_key)))
    } else {
        Ok(None)
    }
}

/// Load the certificate
pub fn load_pem_file_ca(path: &String) -> Result<Vec<u8>> {
    let mut reader = load_file(path)?;
    let cas_file_items = rustls_pemfile::certs(&mut reader)
        .map(|item_res| {
            item_res.or_err(
                ErrorType::InvalidCert,
                "Failed to load certificate from file",
            )
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(cas_file_items
        .first()
        .map(|ca| ca.to_vec())
        .unwrap_or_default())
}

pub fn load_pem_file_private_key(path: &String) -> Result<Vec<u8>> {
    Ok(rustls_pemfile::private_key(&mut load_file(path)?)
        .or_err(
            ErrorType::InvalidCert,
            "Failed to load private key from file",
        )?
        .map(|key| key.secret_der().to_vec())
        .unwrap_or_default())
}

/// SHA-256 digest of `cert`, computed by the installed [`CryptoProvider`].
///
/// The digest deliberately comes from whichever provider the application
/// installed rather than from a crypto implementation of our own. A build
/// whose provider is backed by a validated module therefore computes this
/// digest inside that module too, with no further change here.
///
/// Returns an empty vector when no provider has been installed, or when the
/// installed provider offers no SHA-256 cipher suite. This digest is
/// connection metadata (see `SslDigest`), so an absent value degrades
/// observability rather than security; the caller already treats it as
/// optional.
pub fn hash_certificate(cert: &CertificateDer) -> Vec<u8> {
    let Some(hash) = sha256_provider() else {
        warn!("no SHA-256 available from the installed CryptoProvider; certificate digest omitted");
        return Vec::new();
    };
    hash.hash(cert.as_ref()).as_ref().to_vec()
}

/// Borrow a SHA-256 implementation from the process-wide [`CryptoProvider`].
///
/// rustls keeps `SupportedCipherSuite::hash_provider()` crate-private, so the
/// only public route to a `Hash` is through the TLS 1.3 suites, whose
/// `common` field is exposed. Every provider ships
/// `TLS13_AES_128_GCM_SHA256`, so this resolves in practice.
fn sha256_provider() -> Option<&'static dyn Hash> {
    CryptoProvider::get_default()?
        .cipher_suites
        .iter()
        .filter_map(|suite| suite.tls13())
        .map(|suite| suite.common.hash_provider)
        .find(|hash| hash.algorithm() == HashAlgorithm::SHA256)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install a `CryptoProvider` for this test process.
    ///
    /// This crate installs none in production — the application owns that
    /// choice — so the tests supply one themselves. Repeat calls are no-ops.
    fn install_test_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn sha256_provider_resolves_once_a_provider_is_installed() {
        install_test_provider();

        let hash = sha256_provider().expect("installed provider must offer SHA-256");
        assert_eq!(hash.algorithm(), HashAlgorithm::SHA256);
        assert_eq!(hash.output_len(), 32);
    }

    #[test]
    fn hash_certificate_matches_the_sha256_known_answer() {
        install_test_provider();

        // NIST FIPS 180-2 vector: SHA-256("abc"). `CertificateDer` does not
        // parse its input, so arbitrary bytes stand in for a certificate and
        // let this assert the digest value rather than only its length. A
        // provider wired to the wrong hash would produce 48 bytes here.
        let cert = CertificateDer::from(b"abc".to_vec());
        let expected = b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\
              \xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";

        assert_eq!(hash_certificate(&cert), expected.to_vec());
    }
}

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

//! Rustls TLS server specific implementation

use crate::listeners::TlsAccept;
use crate::protocols::tls::rustls::TlsStream;
use crate::protocols::{Ssl, IO};
use crate::{listeners::tls::Acceptor, protocols::Shutdown};
use async_trait::async_trait;
use log::warn;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

impl<S: AsyncRead + AsyncWrite + Send + Unpin> TlsStream<S> {
    async fn start_accept(mut self: Pin<&mut Self>) -> Result<bool> {
        // TODO: suspend cert callback
        let res = self.accept().await;

        match res {
            Ok(()) => Ok(true),
            Err(e) => {
                if e.etype == TLSWantX509Lookup {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn resume_accept(mut self: Pin<&mut Self>) -> Result<()> {
        // TODO: unblock cert callback
        self.accept().await
    }
}

async fn prepare_tls_stream<S: IO>(acceptor: &Acceptor, io: S) -> Result<TlsStream<S>> {
    TlsStream::from_acceptor(acceptor, io)
        .await
        .explain_err(TLSHandshakeFailure, |e| format!("tls stream error: {e}"))
}

/// Perform TLS handshake for the given connection with the given configuration
pub async fn handshake<S: IO>(acceptor: &Acceptor, io: S) -> Result<TlsStream<S>> {
    let mut stream = prepare_tls_stream(acceptor, io).await?;
    stream
        .accept()
        .await
        .or_err(TLSHandshakeFailure, "TLS accept() failed")?;
    Ok(stream)
}

/// Perform TLS handshake for the given connection with the given configuration and callbacks
pub async fn handshake_with_callback<S: IO>(
    acceptor: &Acceptor,
    io: S,
    callbacks: &(dyn TlsAccept + Send + Sync),
) -> Result<TlsStream<S>> {
    let mut tls_stream = prepare_tls_stream(acceptor, io).await?;
    let done = Pin::new(&mut tls_stream).start_accept().await?;
    if !done {
        // NOTE: certificate_callback is not invoked for rustls. Dynamic cert selection
        // should use a custom ResolvesServerCert instead.
        warn!("certificate_callback is not supported with the rustls backend; use ResolvesServerCert for dynamic cert selection");
        Pin::new(&mut tls_stream)
            .resume_accept()
            .await
            .or_err(TLSHandshakeFailure, "TLS accept() failed")?;
    }
    let extension = match tls_stream.get_ssl() {
        Some(tls_ref) => callbacks.handshake_complete_callback(tls_ref).await,
        None => None,
    };
    if let Some(extension) = extension {
        if let Some(digest_mut) = tls_stream.ssl_digest_mut() {
            digest_mut.extension.set(extension);
        }
    }
    Ok(tls_stream)
}

#[async_trait]
impl<S> Shutdown for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Sync + Unpin + Send,
{
    async fn shutdown(&mut self) {
        match <Self as AsyncWriteExt>::shutdown(self).await {
            Ok(()) => {}
            Err(e) => {
                warn!("TLS shutdown failed, {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::listeners::tls::{Acceptor, TlsSettings};
    use crate::listeners::TlsAccept;
    use crate::protocols::l4::stream::Stream;
    use crate::protocols::tls::TlsRef;
    use crate::services::listening::handshake_was_abandoned;
    use async_trait::async_trait;
    use pingora_error::{BError, ErrorType::TLSHandshakeFailure};
    use pingora_rustls::{
        load_ca_file_into_store, ClientConfig, HandshakeSignatureValid, RootCertStore, RusTlsError,
        ServerCertVerified, ServerCertVerifier, ServerName, TlsConnector, WebPkiClientVerifier,
    };
    use rustls::AlertDescription;
    use std::future::Future;
    use std::io;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: pingora_rustls::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Connect as a TLS client that trusts any server certificate and has no
    /// client certificate of its own.
    async fn tls_connect<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
    ) -> io::Result<pingora_rustls::ClientTlsStream<S>> {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from("openrusty.org").unwrap();
        connector.connect(server_name, stream).await
    }

    async fn client_task(client: DuplexStream) {
        let mut stream = tls_connect(client).await.unwrap();
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf).await;
    }

    fn cert_path() -> String {
        format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"))
    }

    fn key_path() -> String {
        format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"))
    }

    /// Accept one real TCP connection, let `client` drive the other end, and
    /// return the error from the server side of the TLS handshake.
    async fn server_handshake_error<F, Fut>(acceptor: Acceptor, client: F) -> BError
    where
        F: FnOnce(TcpStream) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(client(TcpStream::connect(addr).await.unwrap()));
        let (server, _) = listener.accept().await.unwrap();
        let err = acceptor
            .tls_handshake(Stream::from(server))
            .await
            .expect_err("the handshake should fail");
        client.await.unwrap();
        err
    }

    /// The `io::Error` at the bottom of a handshake error, if the chain kept it.
    fn io_root_cause(e: &BError) -> Option<&io::Error> {
        e.root_cause().downcast_ref::<io::Error>()
    }

    /// The rustls error that tokio-rustls wrapped in an `InvalidData` io error.
    fn rustls_root_cause(e: &BError) -> Option<&RusTlsError> {
        io_root_cause(e)?.get_ref()?.downcast_ref::<RusTlsError>()
    }

    /// Write `bytes` in place of a ClientHello, then wait for the server to hang up.
    async fn send_raw(mut stream: TcpStream, bytes: &'static [u8]) {
        stream.write_all(bytes).await.unwrap();
        let _ = stream.read_to_end(&mut Vec::new()).await;
    }

    #[tokio::test]
    async fn test_handshake_complete_callback() {
        struct CipherName(String);
        struct Callback;

        #[async_trait]
        impl TlsAccept for Callback {
            async fn handshake_complete_callback(
                &self,
                tls: &TlsRef,
            ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
                let name = tls.current_cipher_name()?.to_string();
                Some(Arc::new(CipherName(name)))
            }
        }

        let cert = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
        let key = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));

        let mut settings = TlsSettings::with_callbacks(Box::new(Callback)).unwrap();
        settings.set_certificate_chain_file(&cert).unwrap();
        settings.set_private_key_file(&key).unwrap();
        let acceptor = settings.build();

        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(client_task(client));

        let stream = acceptor.tls_handshake(server).await.unwrap();
        let digest = stream.ssl_digest().unwrap();
        let cipher = digest.extension.get::<CipherName>().unwrap();
        assert!(!cipher.0.is_empty());
    }

    #[tokio::test]
    async fn test_handshake_eof_keeps_io_cause() {
        // What a TCP health check looks like: connect, then hang up without a ClientHello.
        let acceptor = TlsSettings::intermediate(&cert_path(), &key_path())
            .unwrap()
            .build();
        let err = server_handshake_error(acceptor, |stream| async move { drop(stream) }).await;

        assert_eq!(err.etype, TLSHandshakeFailure, "{err}");
        let io_err = io_root_cause(&err).expect("the io::Error cause should survive");
        assert_eq!(io_err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
        assert!(handshake_was_abandoned(&err), "{err}");
    }

    #[tokio::test]
    async fn test_handshake_with_callback_eof_keeps_io_cause() {
        struct NoopCallback;
        impl TlsAccept for NoopCallback {}

        let mut settings = TlsSettings::with_callbacks(Box::new(NoopCallback)).unwrap();
        settings.set_certificate_chain_file(&cert_path()).unwrap();
        settings.set_private_key_file(&key_path()).unwrap();
        let err =
            server_handshake_error(settings.build(), |stream| async move { drop(stream) }).await;

        assert_eq!(err.etype, TLSHandshakeFailure, "{err}");
        let io_err = io_root_cause(&err).expect("the io::Error cause should survive");
        assert_eq!(io_err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
        assert!(handshake_was_abandoned(&err), "{err}");
    }

    #[tokio::test]
    async fn test_handshake_plaintext_keeps_io_cause() {
        // Plain HTTP sent to a TLS port.
        let acceptor = TlsSettings::intermediate(&cert_path(), &key_path())
            .unwrap()
            .build();
        let err = server_handshake_error(acceptor, |stream| {
            send_raw(stream, b"GET / HTTP/1.1\r\nHost: openrusty.org\r\n\r\n")
        })
        .await;

        assert_eq!(err.etype, TLSHandshakeFailure, "{err}");
        let io_err = io_root_cause(&err).expect("the io::Error cause should survive");
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(rustls_root_cause(&err).is_some(), "{err}");
        assert!(!handshake_was_abandoned(&err), "{err}");
    }

    #[tokio::test]
    async fn test_handshake_alert_keeps_io_cause() {
        // A fatal handshake_failure alert in place of a ClientHello.
        let acceptor = TlsSettings::intermediate(&cert_path(), &key_path())
            .unwrap()
            .build();
        let err = server_handshake_error(acceptor, |stream| {
            send_raw(stream, &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
        })
        .await;

        assert_eq!(err.etype, TLSHandshakeFailure, "{err}");
        assert!(
            matches!(
                rustls_root_cause(&err),
                Some(RusTlsError::AlertReceived(
                    AlertDescription::HandshakeFailure
                ))
            ),
            "{err}"
        );
        assert!(!handshake_was_abandoned(&err), "{err}");
    }

    #[tokio::test]
    async fn test_handshake_missing_client_cert_keeps_io_cause() {
        let mut roots = RootCertStore::empty();
        load_ca_file_into_store(cert_path(), &mut roots).unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let mut settings = TlsSettings::intermediate(&cert_path(), &key_path()).unwrap();
        settings.set_client_cert_verifier(verifier);

        // The client has no certificate to offer, so the server has to reject it.
        let err = server_handshake_error(settings.build(), |stream| async move {
            if let Ok(mut tls) = tls_connect(stream).await {
                let _ = tls.read_to_end(&mut Vec::new()).await;
            }
        })
        .await;

        assert_eq!(err.etype, TLSHandshakeFailure, "{err}");
        assert!(
            matches!(
                rustls_root_cause(&err),
                Some(RusTlsError::NoCertificatesPresented)
            ),
            "{err}"
        );
        assert!(!handshake_was_abandoned(&err), "{err}");
    }
}

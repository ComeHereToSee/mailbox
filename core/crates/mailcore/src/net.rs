//! TCP / TLS plumbing shared by IMAP, POP3 and SMTP.

use crate::error::{Error, Result};
use crate::model::{Security, ServerConfig};
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
pub enum MailStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MailStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MailStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MailStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MailStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl MailStream {
    pub fn into_plain(self) -> Result<TcpStream> {
        match self {
            MailStream::Plain(s) => Ok(s),
            MailStream::Tls(_) => Err(Error::Net("连接已经是 TLS".into())),
        }
    }
}

/// Accepts any certificate (self-hosted servers with self-signed certs, opt-in per account).
#[derive(Debug)]
struct AcceptAll(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    install_crypto_provider();
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

pub fn tls_config(accept_invalid: bool) -> Result<Arc<ClientConfig>> {
    static STRICT: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static LAX: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if accept_invalid {
        return Ok(LAX
            .get_or_init(|| {
                Arc::new(
                    ClientConfig::builder_with_provider(provider())
                        .with_safe_default_protocol_versions()
                        .expect("protocol versions")
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider())))
                        .with_no_client_auth(),
                )
            })
            .clone());
    }
    if let Some(c) = STRICT.get() {
        return Ok(c.clone());
    }
    let verifier = rustls_platform_verifier::Verifier::new(provider())
        .map_err(|e| Error::Net(format!("TLS 初始化失败: {e}")))?;
    let cfg = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Net(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    );
    Ok(STRICT.get_or_init(|| cfg).clone())
}

pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let fut = TcpStream::connect((host, port));
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .map_err(|_| Error::Net(format!("连接 {host}:{port} 超时")))?
        .map_err(|e| Error::Net(format!("无法连接 {host}:{port}: {e}")))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub async fn tls_wrap(stream: TcpStream, host: &str, accept_invalid: bool) -> Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(tls_config(accept_invalid)?);
    let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Invalid(format!("无效主机名 {host}")))?;
    tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| Error::Net(format!("{host} TLS 握手超时")))?
        .map_err(|e| Error::Net(format!("{host} TLS 握手失败: {e}")))
}

/// Opens the transport. STARTTLS upgrades are done by the protocol code after the greeting.
pub async fn connect(server: &ServerConfig) -> Result<MailStream> {
    let tcp = connect_tcp(&server.host, server.port).await?;
    match server.security {
        Security::Tls => Ok(MailStream::Tls(Box::new(tls_wrap(tcp, &server.host, server.accept_invalid_certs).await?))),
        Security::StartTls | Security::None => Ok(MailStream::Plain(tcp)),
    }
}

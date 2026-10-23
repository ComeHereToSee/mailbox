//! SMTP submission via lettre (implicit TLS, STARTTLS or plain; PLAIN/LOGIN/XOAUTH2).

use crate::error::{Error, Result};
use crate::model::{Security, ServerConfig};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use std::time::Duration;

pub enum SmtpAuth {
    Password(String),
    OAuth2(String),
    None,
}

fn transport(server: &ServerConfig, user: &str, auth: &SmtpAuth) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    crate::net::install_crypto_provider();
    let tls_params = || {
        TlsParameters::builder(server.host.clone())
            .dangerous_accept_invalid_certs(server.accept_invalid_certs)
            .dangerous_accept_invalid_hostnames(server.accept_invalid_certs)
            .build_rustls()
            .map_err(|e| Error::Smtp(format!("TLS 配置失败: {e}")))
    };
    let tls = match server.security {
        Security::Tls => Tls::Wrapper(tls_params()?),
        Security::StartTls => Tls::Required(tls_params()?),
        Security::None => Tls::Opportunistic(tls_params()?),
    };
    let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(server.host.as_str())
        .port(server.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(60)));
    let login = server.username.clone().filter(|u| !u.is_empty()).unwrap_or_else(|| user.to_string());
    match auth {
        SmtpAuth::Password(p) => {
            b = b.credentials(Credentials::new(login, p.clone())).authentication(vec![Mechanism::Plain, Mechanism::Login]);
        }
        SmtpAuth::OAuth2(token) => {
            b = b.credentials(Credentials::new(login, token.clone())).authentication(vec![Mechanism::Xoauth2]);
        }
        SmtpAuth::None => {}
    }
    Ok(b.build())
}

fn map_err(e: lettre::transport::smtp::Error) -> Error {
    let msg = e.to_string();
    if let Some(code) = e.status() {
        let c = u16::from(code);
        if c == 535 || c == 534 || c == 530 {
            return Error::Auth(format!("SMTP 登录失败 ({c}): {msg}"));
        }
        return Error::Smtp(format!("服务器拒绝 ({c}): {msg}"));
    }
    if e.is_timeout() || e.is_transient() {
        return Error::Net(format!("SMTP 网络错误: {msg}"));
    }
    Error::Smtp(msg)
}

/// Sends a pre-built RFC 5322 message to the given envelope.
pub async fn send(
    server: &ServerConfig,
    user: &str,
    auth: &SmtpAuth,
    from: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::Invalid("没有收件人".into()));
    }
    let t = transport(server, user, auth)?;
    let from = from.parse().map_err(|_| Error::Invalid(format!("无效发件人地址: {from}")))?;
    let to = recipients
        .iter()
        .map(|r| r.trim().parse().map_err(|_| Error::Invalid(format!("无效收件人地址: {r}"))))
        .collect::<Result<Vec<_>>>()?;
    let env = Envelope::new(Some(from), to).map_err(|e| Error::Invalid(e.to_string()))?;
    t.send_raw(&env, raw).await.map_err(map_err)?;
    Ok(())
}

/// Connects and authenticates without sending (account setup check).
pub async fn test(server: &ServerConfig, user: &str, auth: &SmtpAuth) -> Result<()> {
    let t = transport(server, user, auth)?;
    match t.test_connection().await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::Smtp("SMTP 服务器无响应".into())),
        Err(e) => Err(map_err(e)),
    }
}

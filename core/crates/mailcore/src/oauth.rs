//! OAuth 2.0 (authorization code + PKCE, loopback redirect) for Google and Microsoft.

use crate::error::{Error, Result};
use crate::model::OAuthClients;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Provider {
    pub id: &'static str,
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static str,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub extra: &'static [(&'static str, &'static str)],
}

pub fn provider(id: &str, clients: &OAuthClients) -> Result<Provider> {
    match id {
        "google" => {
            if clients.google_client_id.trim().is_empty() {
                return Err(Error::OAuth("尚未配置 Google OAuth 客户端 ID（设置 → OAuth 客户端）".into()));
            }
            Ok(Provider {
                id: "google",
                auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
                token_url: "https://oauth2.googleapis.com/token",
                scopes: "https://mail.google.com/ openid email profile",
                client_id: clients.google_client_id.trim().to_string(),
                client_secret: Some(clients.google_client_secret.trim().to_string()).filter(|s| !s.is_empty()),
                extra: &[("access_type", "offline"), ("prompt", "consent")],
            })
        }
        "microsoft" => {
            if clients.microsoft_client_id.trim().is_empty() {
                return Err(Error::OAuth("尚未配置 Microsoft OAuth 客户端 ID（设置 → OAuth 客户端）".into()));
            }
            Ok(Provider {
                id: "microsoft",
                auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes: "offline_access openid email profile https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send https://outlook.office.com/POP.AccessAsUser.All",
                client_id: clients.microsoft_client_id.trim().to_string(),
                client_secret: None,
                extra: &[("prompt", "select_account")],
            })
        }
        other => Err(Error::OAuth(format!("不支持的 OAuth 提供方: {other}"))),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64,
    pub email: Option<String>,
    pub provider: String,
}

pub fn pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn authorize_url(p: &Provider, redirect_uri: &str, state: &str, challenge: &str, login_hint: Option<&str>) -> String {
    let mut u = url::Url::parse(p.auth_url).expect("static url");
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("client_id", &p.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", p.scopes)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        for (k, v) in p.extra {
            q.append_pair(k, v);
        }
        if let Some(h) = login_hint.filter(|h| !h.is_empty()) {
            q.append_pair("login_hint", h);
        }
    }
    u.to_string()
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    id_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn client() -> reqwest::Client {
    crate::net::install_crypto_provider();
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap_or_default()
}

async fn token_request(p: &Provider, form: &[(&str, &str)]) -> Result<Tokens> {
    let mut form: Vec<(&str, &str)> = form.to_vec();
    form.push(("client_id", &p.client_id));
    if let Some(s) = &p.client_secret {
        form.push(("client_secret", s));
    }
    let resp = client().post(p.token_url).form(&form).send().await?;
    let body: TokenResponse = resp.json().await.map_err(|e| Error::OAuth(format!("令牌响应无法解析: {e}")))?;
    if let Some(err) = body.error {
        return Err(Error::OAuth(format!("{err}: {}", body.error_description.unwrap_or_default())));
    }
    let access = body.access_token.ok_or_else(|| Error::OAuth("没有返回 access_token".into()))?;
    Ok(Tokens {
        access_token: access,
        refresh_token: body.refresh_token,
        expires_at: crate::store::now() + body.expires_in.unwrap_or(3600),
        email: body.id_token.as_deref().and_then(email_from_id_token),
        provider: p.id.to_string(),
    })
}

pub async fn exchange_code(p: &Provider, code: &str, verifier: &str, redirect_uri: &str) -> Result<Tokens> {
    token_request(
        p,
        &[("grant_type", "authorization_code"), ("code", code), ("code_verifier", verifier), ("redirect_uri", redirect_uri)],
    )
    .await
}

pub async fn refresh(p: &Provider, refresh_token: &str) -> Result<Tokens> {
    let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", refresh_token)];
    if p.id == "microsoft" {
        // The v2.0 endpoint expects the scopes again on refresh.
        form.push(("scope", p.scopes));
    }
    let mut t = token_request(p, &form).await?;
    if t.refresh_token.is_none() {
        t.refresh_token = Some(refresh_token.to_string());
    }
    Ok(t)
}

/// Reads the e-mail claim of an ID token. The token came straight from the provider over TLS,
/// so the signature is not verified here.
pub fn email_from_id_token(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("email")
        .or_else(|| v.get("preferred_username"))
        .or_else(|| v.get("upn"))
        .and_then(|e| e.as_str())
        .map(|s| s.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_authorize_url_with_pkce() {
        let clients = OAuthClients { google_client_id: "cid.apps.googleusercontent.com".into(), ..Default::default() };
        let p = provider("google", &clients).unwrap();
        let (v, c) = pkce();
        assert_ne!(v, c);
        let u = authorize_url(&p, "http://127.0.0.1:4000/oauth/callback", "st", &c, Some("a@gmail.com"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains("access_type=offline"));
        assert!(u.contains("login_hint=a%40gmail.com"));
        assert!(u.contains("scope=https%3A%2F%2Fmail.google.com%2F"));
        assert!(provider("microsoft", &OAuthClients::default()).is_err());
    }

    #[test]
    fn reads_id_token_email() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"email":"Me@Gmail.com"}"#);
        assert_eq!(email_from_id_token(&format!("h.{payload}.s")).as_deref(), Some("me@gmail.com"));
    }
}

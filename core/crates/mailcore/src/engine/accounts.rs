//! Adding, testing, editing and removing accounts, plus the OAuth login flow.

use super::{Engine, PendingOAuth};
use crate::error::{Error, Result};
use crate::events::Event;
use crate::imap::{ImapAuth, ImapConn};
use crate::model::*;
use crate::oauth;
use crate::pop3::{Pop3Auth, Pop3Conn};
use crate::secrets;
use crate::smtp::{self, SmtpAuth};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct NewAccount {
    pub kind: AccountKind,
    pub email: String,
    pub name: String,
    pub label: String,
    pub color: String,
    pub provider: Option<String>,
    pub config: AccountConfig,
    pub password: Option<String>,
    /// Separate SMTP password when it differs from the incoming one.
    pub smtp_password: Option<String>,
    /// `state` of a finished OAuth flow (see [`Engine::start_oauth`]).
    pub oauth_state: Option<String>,
    pub skip_test: bool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct AccountTest {
    pub ok: bool,
    pub error: Option<String>,
    pub code: Option<String>,
    pub skipped: bool,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct TestReport {
    pub ok: bool,
    pub incoming: AccountTest,
    pub smtp: AccountTest,
}

impl AccountTest {
    fn from(r: Result<()>) -> AccountTest {
        match r {
            Ok(()) => AccountTest { ok: true, ..Default::default() },
            Err(e) => AccountTest { ok: false, code: Some(e.code().into()), error: Some(e.to_string()), skipped: false },
        }
    }
    fn skipped() -> AccountTest {
        AccountTest { ok: true, skipped: true, ..Default::default() }
    }
}

fn default_color(email: &str) -> String {
    const PALETTE: [&str; 8] = ["#4F7CFF", "#12B7F5", "#E5484D", "#30A46C", "#F76B15", "#8E4EC6", "#E54666", "#0090FF"];
    let h: u32 = email.bytes().fold(7u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
    PALETTE[(h % PALETTE.len() as u32) as usize].to_string()
}

impl Engine {
    fn oauth_tokens(&self, state: &str) -> Result<oauth::Tokens> {
        self.oauth_pending
            .lock()
            .get(state)
            .and_then(|p| p.tokens.clone())
            .ok_or_else(|| Error::OAuth("登录尚未完成或已过期，请重新登录".into()))
    }

    /// Checks incoming and outgoing servers with the given credentials, without saving anything.
    pub async fn test_account(&self, req: &NewAccount) -> TestReport {
        let token = match (&req.config.auth, &req.oauth_state) {
            (AuthKind::Oauth2, Some(state)) => match self.oauth_tokens(state) {
                Ok(t) => Some(t.access_token),
                Err(e) => {
                    let t = AccountTest::from(Err(e));
                    return TestReport { ok: false, incoming: t.clone(), smtp: t };
                }
            },
            _ => None,
        };
        let password = req.password.clone().unwrap_or_default();
        let incoming = match req.kind {
            AccountKind::Imap => match &req.config.imap {
                Some(s) => {
                    let auth = match &token { Some(t) => ImapAuth::OAuth2(t.clone()), None => ImapAuth::Password(password.clone()) };
                    let user = s.username.clone().filter(|u| !u.is_empty()).unwrap_or_else(|| req.email.clone());
                    AccountTest::from(async {
                        let mut c = ImapConn::connect(s, &user, &auth, req.config.send_id).await?;
                        // NetEase only complains about "Unsafe Login" on SELECT.
                        c.select("INBOX").await?;
                        c.logout().await;
                        Ok(())
                    }
                    .await)
                }
                None => AccountTest::from(Err(Error::Invalid("缺少 IMAP 服务器".into()))),
            },
            AccountKind::Pop3 => match &req.config.pop3 {
                Some(s) => {
                    let auth = match &token { Some(t) => Pop3Auth::OAuth2(t.clone()), None => Pop3Auth::Password(password.clone()) };
                    let user = s.username.clone().filter(|u| !u.is_empty()).unwrap_or_else(|| req.email.clone());
                    AccountTest::from(async {
                        let mut c = Pop3Conn::connect(s, &user, &auth).await?;
                        c.stat().await?;
                        c.quit().await
                    }
                    .await)
                }
                None => AccountTest::from(Err(Error::Invalid("缺少 POP3 服务器".into()))),
            },
            _ => AccountTest::skipped(),
        };
        let smtp = match (&req.config.smtp, req.kind) {
            (Some(s), AccountKind::Imap | AccountKind::Pop3) => {
                let auth = match &token {
                    Some(t) => SmtpAuth::OAuth2(t.clone()),
                    None => SmtpAuth::Password(req.smtp_password.clone().filter(|p| !p.is_empty()).unwrap_or(password)),
                };
                let user = s.username.clone().filter(|u| !u.is_empty()).unwrap_or_else(|| req.email.clone());
                AccountTest::from(smtp::test(s, &user, &auth).await)
            }
            (None, AccountKind::Imap | AccountKind::Pop3) => AccountTest::from(Err(Error::Invalid("缺少 SMTP 服务器".into()))),
            _ => AccountTest::skipped(),
        };
        TestReport { ok: incoming.ok && smtp.ok, incoming, smtp }
    }

    pub async fn add_account(&self, req: NewAccount) -> Result<Account> {
        let email = req.email.trim().to_lowercase();
        if crate::mime::extract_email(&email).as_deref() != Some(email.as_str()) && req.kind != AccountKind::Web {
            return Err(Error::Invalid("邮箱地址无效".into()));
        }
        if self.db.accounts()?.iter().any(|a| a.email == email && a.kind == req.kind) {
            return Err(Error::Invalid("这个账户已经添加过了".into()));
        }
        if !req.skip_test && matches!(req.kind, AccountKind::Imap | AccountKind::Pop3) {
            let report = self.test_account(&req).await;
            if !report.ok {
                let msg = report.incoming.error.or(report.smtp.error).unwrap_or_else(|| "连接失败".into());
                return Err(if report.incoming.code.as_deref() == Some("auth") || report.smtp.code.as_deref() == Some("auth") {
                    Error::Auth(msg)
                } else {
                    Error::Net(msg)
                });
            }
        }
        let provider = req.provider.as_deref().and_then(crate::autoconfig::provider);
        let label = if !req.label.trim().is_empty() {
            req.label.trim().to_string()
        } else if let Some(p) = provider {
            format!("{}·{}", p.label, email.split('@').next().unwrap_or(""))
        } else {
            email.clone()
        };
        let color = if !req.color.is_empty() {
            req.color.clone()
        } else {
            provider.map(|p| p.color.clone()).filter(|c| !c.is_empty()).unwrap_or_else(|| default_color(&email))
        };
        let name = if req.name.trim().is_empty() { email.split('@').next().unwrap_or("").to_string() } else { req.name.trim().to_string() };
        let acc = self.db.insert_account(Account {
            id: String::new(),
            kind: req.kind,
            email: email.clone(),
            name,
            label,
            color,
            provider: req.provider.clone(),
            config: req.config.clone(),
            enabled: true,
            sort_order: 0,
            created_at: 0,
        })?;
        if let Some(p) = req.password.as_deref().filter(|p| !p.is_empty()) {
            self.secrets.set(&secrets::password_key(&acc.id), p)?;
        }
        if let Some(p) = req.smtp_password.as_deref().filter(|p| !p.is_empty()) {
            self.secrets.set(&secrets::smtp_password_key(&acc.id), p)?;
        }
        if let Some(state) = &req.oauth_state {
            let tokens = self.oauth_tokens(state)?;
            self.secrets.set(&secrets::oauth_key(&acc.id), &serde_json::to_string(&tokens)?)?;
            self.oauth_pending.lock().remove(state);
        }
        self.spawn_worker(&acc);
        self.events.emit(Event::AccountsChanged);
        Ok(acc)
    }

    /// Saves edits; restarts the worker so new server settings take effect.
    pub async fn update_account(&self, acc: Account, password: Option<String>, smtp_password: Option<String>) -> Result<Account> {
        self.db.account(&acc.id)?;
        self.db.update_account(&acc)?;
        if let Some(p) = password.filter(|p| !p.is_empty()) {
            self.secrets.set(&secrets::password_key(&acc.id), &p)?;
        }
        if let Some(p) = smtp_password {
            if p.is_empty() {
                self.secrets.remove(&secrets::smtp_password_key(&acc.id))?;
            } else {
                self.secrets.set(&secrets::smtp_password_key(&acc.id), &p)?;
            }
        }
        let fresh = self.db.account(&acc.id)?;
        self.spawn_worker(&fresh);
        self.events.emit(Event::AccountsChanged);
        Ok(fresh)
    }

    /// Updates OAuth tokens of an existing account after re-login.
    pub fn reauthorize(&self, account_id: &str, oauth_state: &str) -> Result<()> {
        let tokens = self.oauth_tokens(oauth_state)?;
        self.secrets.set(&secrets::oauth_key(account_id), &serde_json::to_string(&tokens)?)?;
        self.oauth_pending.lock().remove(oauth_state);
        let acc = self.db.account(account_id)?;
        self.spawn_worker(&acc);
        Ok(())
    }

    pub async fn delete_account(&self, id: &str) -> Result<()> {
        self.stop_worker(id);
        self.db.delete_account(id)?;
        self.secrets.remove_prefix(&format!("account:{id}:"))?;
        self.events.emit(Event::AccountsChanged);
        self.emit_counts();
        Ok(())
    }

    pub fn reorder_accounts(&self, ids: &[String]) -> Result<()> {
        for (i, id) in ids.iter().enumerate() {
            let mut a = self.db.account(id)?;
            a.sort_order = i as i64;
            self.db.update_account(&a)?;
        }
        self.events.emit(Event::AccountsChanged);
        Ok(())
    }

    // ---- OAuth -----------------------------------------------------------------------------

    /// Starts a login in the user's browser. Returns (authorize URL, state).
    pub fn start_oauth(&self, provider: &str, login_hint: Option<&str>) -> Result<(String, String)> {
        let p = oauth::provider(provider, &self.settings().oauth)?;
        let port = self.port();
        if port == 0 {
            return Err(Error::OAuth("本地服务尚未启动".into()));
        }
        let host = if provider == "microsoft" { "localhost" } else { "127.0.0.1" };
        let redirect_uri = format!("http://{host}:{port}/oauth/callback");
        let (verifier, challenge) = oauth::pkce();
        let state = oauth::random_state();
        let url = oauth::authorize_url(&p, &redirect_uri, &state, &challenge, login_hint);
        self.oauth_pending.lock().insert(
            state.clone(),
            PendingOAuth {
                provider: provider.into(),
                verifier,
                redirect_uri,
                created: Instant::now(),
                tokens: None,
            },
        );
        Ok((url, state))
    }

    /// Handles the browser redirect. Returns the signed-in address.
    pub async fn finish_oauth(&self, state: &str, code: Option<&str>, error: Option<&str>) -> Result<String> {
        let (provider, verifier, redirect) = {
            let map = self.oauth_pending.lock();
            let p = map.get(state).ok_or_else(|| Error::OAuth("登录请求已过期，请重试".into()))?;
            (p.provider.clone(), p.verifier.clone(), p.redirect_uri.clone())
        };
        let result = async {
            if let Some(err) = error {
                return Err(Error::OAuth(format!("授权被拒绝: {err}")));
            }
            let code = code.ok_or_else(|| Error::OAuth("回调中没有授权码".into()))?;
            let p = oauth::provider(&provider, &self.settings().oauth)?;
            oauth::exchange_code(&p, code, &verifier, &redirect).await
        }
        .await;
        match result {
            Ok(tokens) => {
                let email = tokens.email.clone().unwrap_or_default();
                if let Some(p) = self.oauth_pending.lock().get_mut(state) {
                    p.tokens = Some(tokens);
                }
                self.events.emit(Event::OAuth { state: state.into(), ok: true, email: Some(email.clone()), error: None });
                Ok(email)
            }
            Err(e) => {
                self.events.emit(Event::OAuth { state: state.into(), ok: false, email: None, error: Some(e.to_string()) });
                Err(e)
            }
        }
    }

    pub fn oauth_status(&self, state: &str) -> Option<(bool, Option<String>)> {
        self.oauth_pending.lock().get(state).map(|p| (p.tokens.is_some(), p.tokens.as_ref().and_then(|t| t.email.clone())))
    }
}

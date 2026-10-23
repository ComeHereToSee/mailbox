//! Provider presets and auto-discovery (temporary stub with the agreed API).
#![allow(dead_code, unused_variables)]

use crate::model::{AuthKind, ServerConfig};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub label: String,
    pub color: String,
    pub domains: Vec<String>,
    pub mx_patterns: Vec<String>,
    pub imap: Option<ServerConfig>,
    pub pop3: Option<ServerConfig>,
    pub smtp: Option<ServerConfig>,
    pub auth: AuthKind,
    pub oauth_provider: Option<String>,
    pub password_label: String,
    pub help_url: Option<String>,
    pub web_url: Option<String>,
    pub help_steps: Vec<String>,
    pub send_id: bool,
    pub save_sent_copy: bool,
    pub requires_bridge: bool,
    pub notes: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Discovery {
    pub email: String,
    pub provider: Option<Provider>,
    pub imap: Vec<ServerConfig>,
    pub pop3: Vec<ServerConfig>,
    pub smtp: Vec<ServerConfig>,
    pub source: String,
}

pub fn presets() -> &'static [Provider] {
    &[]
}

pub fn provider(id: &str) -> Option<&'static Provider> {
    None
}

pub fn provider_for_domain(domain: &str) -> Option<&'static Provider> {
    None
}

pub async fn discover(email: &str) -> crate::error::Result<Discovery> {
    Ok(Discovery { email: email.into(), ..Default::default() })
}

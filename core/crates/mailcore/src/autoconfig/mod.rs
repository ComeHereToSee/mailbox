//! Provider presets and server auto-discovery.
//!
//! `presets.json` (embedded at compile time) holds hand-checked settings for the
//! providers our users actually have: the big Chinese free-mail services, their
//! enterprise offerings, and the common international ones. For any other address
//! [`discover`] walks the same chain Thunderbird uses:
//!
//! 1. preset by e-mail domain,
//! 2. MX lookup mapped to a preset (custom domains on 腾讯企业邮, Google Workspace, Microsoft 365, ...),
//! 3. Mozilla ISPDB (`autoconfig.thunderbird.net`),
//! 4. the domain's own autoconfig file (`autoconfig.{domain}` and `/.well-known/autoconfig`),
//! 5. Mozilla ISPDB for the MX host's base domain,
//! 6. DNS SRV records (RFC 6186 / RFC 8314),
//! 7. guesses such as `imap.{domain}:993` / `smtp.{domain}:465`.
//!
//! Every network step has a short timeout ([`STEP_TIMEOUT`]); a failing step just
//! falls through to the next one, so `discover` only errors for an invalid address.

use crate::error::{Error, Result};
use crate::model::{AccountConfig, AuthKind, Security, ServerConfig};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{Name, RData};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use quick_xml::events::{BytesStart, Event};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;
use std::time::Duration;

/// Timeout of each network step of the discovery chain.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(4);

/// Mozilla's ISP database (the one Thunderbird uses).
const ISPDB_URL: &str = "https://autoconfig.thunderbird.net/v1.1/";

/// Autoconfig documents are a few KB; refuse anything absurd.
const MAX_XML_BYTES: usize = 512 * 1024;

const USER_AGENT: &str = concat!("Mailbox/", env!("CARGO_PKG_VERSION"), " (autoconfig)");

/// Used when the system resolver configuration cannot be read: AliDNS, DNSPod,
/// Cloudflare, Google (the first two are reachable from mainland China).
const FALLBACK_DNS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];

/// A mail provider preset.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Provider {
    /// Stable identifier: `qq`, `163`, `gmail`, `outlook`, `icloud`, `proton`, `exmail`, ...
    pub id: String,
    /// Display name (Chinese where natural), e.g. `QQ 邮箱`.
    pub name: String,
    /// Short default account label used in notifications, e.g. `QQ`.
    pub label: String,
    /// Brand-ish hex color, e.g. `#12B7F5`.
    pub color: String,
    /// E-mail domains served (lower case). An entry `*.example.com` matches every
    /// subdomain of `example.com` but not `example.com` itself.
    pub domains: Vec<String>,
    /// Patterns matched against MX hosts to recognise custom domains. A pattern that
    /// contains a dot matches the host itself or any host below it at a label boundary
    /// (`aspmx.l.google.com` matches `alt1.aspmx.l.google.com`, `zoho.com` does not
    /// match `mx.zoho.com.cn`); a pattern without a dot is a plain substring
    /// (`qiye163mx` matches `qiye163mx01.mxmail.netease.com`). The longest matching
    /// pattern wins.
    pub mx_patterns: Vec<String>,
    pub imap: Option<ServerConfig>,
    pub pop3: Option<ServerConfig>,
    pub smtp: Option<ServerConfig>,
    /// Fallback IMAP servers, tried after `imap`.
    pub alt_imap: Vec<ServerConfig>,
    /// Fallback SMTP servers (other port / cluster), tried after `smtp`.
    pub alt_smtp: Vec<ServerConfig>,
    /// `oauth2` for the Gmail and Microsoft families, `password` otherwise.
    pub auth: AuthKind,
    /// `google` or `microsoft` when `auth == oauth2`.
    pub oauth_provider: Option<String>,
    /// What the secret is called: `授权码`, `应用专用密码`, `Bridge 密码`, `密码`, ...
    pub password_label: String,
    /// Official page explaining how to enable IMAP / generate the 授权码 or app password.
    pub help_url: Option<String>,
    /// Webmail URL, opened in the in-app browser to guide the user.
    pub web_url: Option<String>,
    /// Short Chinese step list shown next to the in-app browser.
    pub help_steps: Vec<String>,
    /// Send the IMAP `ID` command after login (required by NetEase, harmless elsewhere).
    pub send_id: bool,
    /// Append sent mail to the Sent folder. `false` where the server stores
    /// SMTP-submitted mail itself (Gmail, Outlook.com / Microsoft 365, Proton).
    pub save_sent_copy: bool,
    /// Needs Proton Mail Bridge running locally.
    pub requires_bridge: bool,
    /// Chinese caveats shown on the setup screen.
    pub notes: String,
}

impl Default for Provider {
    fn default() -> Self {
        Provider {
            id: String::new(),
            name: String::new(),
            label: String::new(),
            color: String::new(),
            domains: Vec::new(),
            mx_patterns: Vec::new(),
            imap: None,
            pop3: None,
            smtp: None,
            alt_imap: Vec::new(),
            alt_smtp: Vec::new(),
            auth: AuthKind::Password,
            oauth_provider: None,
            password_label: "密码".into(),
            help_url: None,
            web_url: None,
            help_steps: Vec::new(),
            send_id: true,
            save_sent_copy: true,
            requires_bridge: false,
            notes: String::new(),
        }
    }
}

impl Provider {
    /// Account settings pre-filled from this preset (primary servers only).
    pub fn account_config(&self) -> AccountConfig {
        AccountConfig {
            imap: self.imap.clone(),
            pop3: self.pop3.clone(),
            smtp: self.smtp.clone(),
            auth: self.auth,
            oauth_provider: self.oauth_provider.clone(),
            send_id: self.send_id,
            save_sent_copy: self.save_sent_copy,
            ..AccountConfig::default()
        }
    }

    /// A hosting provider for custom domains only (no consumer domains of its own).
    fn is_business_only(&self) -> bool {
        self.domains.iter().all(|d| d.starts_with("*."))
    }
}

static PRESETS: LazyLock<Vec<Provider>> =
    LazyLock::new(|| serde_json::from_str(include_str!("presets.json")).expect("autoconfig/presets.json is invalid"));

/// All built-in provider presets, in display order.
pub fn presets() -> &'static [Provider] {
    &PRESETS
}

/// Preset by id (`qq`, `gmail`, ...).
pub fn provider(id: &str) -> Option<&'static Provider> {
    let id = id.trim();
    presets().iter().find(|p| p.id.eq_ignore_ascii_case(id))
}

/// Preset serving `domain` (case-insensitive). A full address is accepted too.
pub fn provider_for_domain(domain: &str) -> Option<&'static Provider> {
    let domain = normalize_domain(domain);
    if domain.is_empty() {
        return None;
    }
    let all = presets();
    all.iter()
        .find(|p| p.domains.iter().any(|d| d.eq_ignore_ascii_case(&domain)))
        .or_else(|| all.iter().find(|p| p.domains.iter().any(|d| wildcard_matches(d, &domain))))
}

/// Preset whose MX patterns match the MX hosts of a custom domain. `mx_hosts` should
/// be ordered by MX preference; the first host that maps to a preset decides.
pub fn provider_for_mx(mx_hosts: &[String]) -> Option<&'static Provider> {
    mx_hosts.iter().find_map(|host| provider_for_mx_host(host))
}

fn provider_for_mx_host(host: &str) -> Option<&'static Provider> {
    let host = normalize_host(host);
    if host.is_empty() {
        return None;
    }
    let mut best: Option<(&'static Provider, usize)> = None;
    for p in presets() {
        for pattern in &p.mx_patterns {
            if mx_pattern_matches(pattern, &host) && best.is_none_or(|(_, len)| pattern.len() > len) {
                best = Some((p, pattern.len()));
            }
        }
    }
    best.map(|(p, _)| p)
}

fn mx_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if pattern.contains('.') {
        host == pattern || host.strip_suffix(pattern.as_str()).is_some_and(|rest| rest.ends_with('.'))
    } else {
        host.contains(pattern.as_str())
    }
}

fn wildcard_matches(entry: &str, domain: &str) -> bool {
    entry
        .strip_prefix("*.")
        .and_then(|suffix| domain.strip_suffix(suffix.to_ascii_lowercase().as_str()))
        .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
}

/// Preset whose incoming server is `host`, used to attach provider info (OAuth,
/// labels, notes) to settings found via autoconfig / SRV. Business-only presets win
/// over consumer ones (`outlook.office365.com` → Microsoft 365 for a custom domain).
fn provider_for_server(host: &str) -> Option<&'static Provider> {
    let host = normalize_host(host);
    if host.is_empty() || host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return None;
    }
    let mut matches = presets()
        .iter()
        .filter(|p| p.imap.iter().chain(&p.alt_imap).chain(&p.pop3).any(|s| s.host.eq_ignore_ascii_case(&host)));
    let first = matches.next()?;
    if first.is_business_only() {
        return Some(first);
    }
    Some(matches.find(|p| p.is_business_only()).unwrap_or(first))
}

fn normalize_domain(input: &str) -> String {
    let s = input.trim();
    let s = s.rsplit_once('@').map_or(s, |(_, d)| d);
    s.trim().trim_end_matches('.').to_lowercase()
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Result of [`discover`]: candidate servers in order of preference.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Discovery {
    pub email: String,
    /// Matching preset, when known (also for custom domains recognised by MX or server host).
    pub provider: Option<Provider>,
    pub imap: Vec<ServerConfig>,
    pub pop3: Vec<ServerConfig>,
    pub smtp: Vec<ServerConfig>,
    /// `preset` | `mx` | `ispdb` | `autoconfig` | `srv` | `guess`
    pub source: String,
}

impl Discovery {
    fn from_provider(email: &str, p: &Provider, source: &str) -> Discovery {
        Discovery {
            email: email.to_string(),
            provider: Some(p.clone()),
            imap: p.imap.iter().chain(&p.alt_imap).cloned().collect(),
            pop3: p.pop3.iter().cloned().collect(),
            smtp: p.smtp.iter().chain(&p.alt_smtp).cloned().collect(),
            source: source.into(),
        }
    }

    /// Account settings using the first candidate of each protocol and the
    /// provider's flags (or the defaults when no preset matched).
    pub fn account_config(&self) -> AccountConfig {
        let mut cfg = self.provider.as_ref().map(Provider::account_config).unwrap_or_default();
        cfg.imap = self.imap.first().cloned();
        cfg.pop3 = self.pop3.first().cloned();
        cfg.smtp = self.smtp.first().cloned();
        cfg
    }

    fn with_source(mut self, source: &str) -> Discovery {
        self.source = source.into();
        self
    }

    /// Dedups the lists, moves plaintext servers last, attaches a preset matched by
    /// server host and fills a missing SMTP list (from that preset, else with guesses).
    fn finish(&mut self, domain: &str) {
        for list in [&mut self.imap, &mut self.pop3, &mut self.smtp] {
            let mut seen = HashSet::new();
            list.retain(|s| seen.insert((s.host.to_ascii_lowercase(), s.port, s.security as u8)));
            list.sort_by_key(|s| s.security == Security::None);
        }
        if self.provider.is_none()
            && let Some(first) = self.imap.first().or(self.pop3.first())
        {
            self.provider = provider_for_server(&first.host).cloned();
        }
        if self.smtp.is_empty() {
            if let Some(p) = &self.provider {
                self.smtp = p.smtp.iter().chain(&p.alt_smtp).cloned().collect();
            } else if let Some(incoming) = self.imap.first().or(self.pop3.first()) {
                // Submission usually lives next to the incoming server.
                let mut hosts = vec![format!("smtp.{domain}")];
                if !incoming.host.eq_ignore_ascii_case(&hosts[0]) {
                    hosts.push(incoming.host.clone());
                }
                self.smtp = servers_for(&hosts, &SMTP_GUESS_PORTS);
            }
        }
    }
}

/// Full discovery chain for an address; see the module docs. Only fails when the
/// address itself is invalid: when nothing is found the result holds guesses.
pub async fn discover(email: &str) -> Result<Discovery> {
    let email = email.trim();
    let domain = email_domain(email)?;
    if let Some(p) = provider_for_domain(&domain) {
        return Ok(Discovery::from_provider(email, p, "preset"));
    }

    let resolver = build_resolver();
    let mx = match &resolver {
        Some(r) => lookup_mx(r, &domain).await,
        None => Vec::new(),
    };
    if let Some(p) = provider_for_mx(&mx) {
        return Ok(Discovery::from_provider(email, p, "mx"));
    }

    // The remaining sources are independent: query them concurrently and take the
    // most authoritative answer.
    let http = http_client();
    let fetch = |url: String| {
        let http = http.as_ref();
        async move {
            match http {
                Some(client) => fetch_autoconfig(client, &url, email).await,
                None => None,
            }
        }
    };
    let mx_domain = mx.first().map(|h| registrable_domain(h)).filter(|d| *d != domain);
    let encoded = utf8_percent_encode(email, NON_ALPHANUMERIC);
    let (ispdb, autoconfig, well_known, ispdb_mx, srv) = tokio::join!(
        fetch(format!("{ISPDB_URL}{domain}")),
        fetch(format!("https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={encoded}")),
        fetch(format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml")),
        async {
            match &mx_domain {
                Some(d) => fetch(format!("{ISPDB_URL}{d}")).await,
                None => None,
            }
        },
        async {
            match &resolver {
                Some(r) => discover_srv(r, &domain, email).await,
                None => None,
            }
        },
    );

    let found = ispdb
        .map(|d| d.with_source("ispdb"))
        .or_else(|| autoconfig.or(well_known).map(|d| d.with_source("autoconfig")))
        .or_else(|| ispdb_mx.map(|d| d.with_source("ispdb")))
        .or(srv);
    let mut discovery = match found {
        Some(d) => d,
        None => guess(resolver.as_ref(), &domain, email).await,
    };
    discovery.finish(&domain);
    Ok(discovery)
}

/// Validates the address and returns its domain as lower-case ASCII (IDNA).
fn email_domain(email: &str) -> Result<String> {
    let invalid = || Error::Invalid(format!("邮箱地址格式不正确: {email}"));
    let (local, domain) = email.rsplit_once('@').ok_or_else(invalid)?;
    if local.is_empty() || local.chars().any(char::is_whitespace) {
        return Err(invalid());
    }
    match url::Host::parse(domain.trim_end_matches('.')) {
        Ok(url::Host::Domain(d)) if !d.is_empty() => Ok(d),
        _ => Err(invalid()),
    }
}

/// Base domain of a host for the ISPDB lookup by MX (`mx.zoho.eu` → `zoho.eu`,
/// `mx1.example.com.cn` → `example.com.cn`). A heuristic, not a public suffix list.
fn registrable_domain(host: &str) -> String {
    let host = normalize_host(host);
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n <= 2 {
        return labels.join(".");
    }
    let generic_second_level =
        matches!(labels[n - 2], "com" | "net" | "org" | "edu" | "gov" | "co" | "ac" | "or" | "ne" | "go");
    let keep = if labels[n - 1].len() == 2 && generic_second_level { 3 } else { 2 };
    labels[n - keep..].join(".")
}

// ---------------------------------------------------------------------------
// Thunderbird autoconfig XML
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RawServer {
    outgoing: bool,
    kind: String,
    hostname: String,
    port: Option<u16>,
    socket_type: String,
    username: Option<String>,
}

/// Parses a Thunderbird `config-v1.1.xml` document (ISPDB / provider autoconfig).
///
/// Placeholders `%EMAILADDRESS%`, `%EMAILLOCALPART%` and `%EMAILDOMAIN%` are
/// substituted in host names and usernames; a username equal to the address becomes
/// `None` (the account address is the default login). `incomingServer` elements of
/// type `imap` / `pop3` and `outgoingServer` of type `smtp` are kept in document
/// order, with plaintext servers moved last. The result has `source = "autoconfig"`.
pub fn parse_autoconfig_xml(xml: &str, email: &str) -> Result<Discovery> {
    let email = email.trim();
    let (local, domain) = email.rsplit_once('@').unwrap_or((email, ""));
    let substitute = |s: &str| {
        s.replace("%EMAILADDRESS%", email).replace("%EMAILLOCALPART%", local).replace("%EMAILDOMAIN%", domain)
    };

    let mut discovery = Discovery { email: email.to_string(), source: "autoconfig".into(), ..Default::default() };
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut current: Option<RawServer> = None;

    loop {
        let event = reader.read_event().map_err(|e| Error::Invalid(format!("自动配置 XML 解析失败: {e}")))?;
        match event {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_string();
                if current.is_none() && is_server_element(&name) {
                    current = Some(RawServer {
                        outgoing: name == "outgoingServer",
                        kind: attribute(&e, "type").to_ascii_lowercase(),
                        ..Default::default()
                    });
                }
                stack.push(name);
                text.clear();
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::CData(t) => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) => {
                if let Ok(Some(c)) = r.resolve_char_ref() {
                    text.push(c);
                } else if let Some(v) = quick_xml::escape::resolve_predefined_entity(r.as_ref()) {
                    text.push_str(v);
                }
            }
            Event::End(_) => {
                let name = stack.pop().unwrap_or_default();
                if is_server_element(&name) {
                    if let Some(raw) = current.take() {
                        push_server(&mut discovery, raw, &substitute, email);
                    }
                } else if let Some(raw) = current.as_mut()
                    && stack.last().is_some_and(|parent| is_server_element(parent))
                {
                    let value = text.trim();
                    match name.as_str() {
                        "hostname" => raw.hostname = value.to_string(),
                        "port" => raw.port = value.parse().ok(),
                        "socketType" => raw.socket_type = value.to_string(),
                        "username" => raw.username = Some(value.to_string()),
                        _ => {}
                    }
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }

    for list in [&mut discovery.imap, &mut discovery.pop3, &mut discovery.smtp] {
        list.sort_by_key(|s| s.security == Security::None);
    }
    if discovery.imap.is_empty() && discovery.pop3.is_empty() && discovery.smtp.is_empty() {
        return Err(Error::NotFound("自动配置文件中没有可用的服务器".into()));
    }
    Ok(discovery)
}

fn is_server_element(name: &str) -> bool {
    name == "incomingServer" || name == "outgoingServer"
}

fn attribute(e: &BytesStart<'_>, name: &str) -> String {
    match e.try_get_attribute(name) {
        Ok(Some(a)) => a.value.trim().to_string(),
        _ => String::new(),
    }
}

fn push_server(out: &mut Discovery, raw: RawServer, substitute: &dyn Fn(&str) -> String, email: &str) {
    let host = substitute(&raw.hostname).trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('%') || host.contains(char::is_whitespace) {
        return;
    }
    let (list, tls_port, plain_port) = match (raw.outgoing, raw.kind.as_str()) {
        (false, "imap") => (&mut out.imap, 993, 143),
        (false, "pop3") => (&mut out.pop3, 995, 110),
        (true, "smtp") => (&mut out.smtp, 465, 587),
        _ => return,
    };
    let security = match raw.socket_type.to_ascii_uppercase().as_str() {
        "SSL" | "TLS" => Security::Tls,
        "STARTTLS" => Security::StartTls,
        "PLAIN" => Security::None,
        // Missing / unknown: infer from the port, never silently fall back to plaintext.
        _ if raw.port.is_none_or(|p| p == tls_port) => Security::Tls,
        _ => Security::StartTls,
    };
    let port = raw.port.filter(|p| *p != 0).unwrap_or(if security == Security::Tls { tls_port } else { plain_port });
    let username = raw
        .username
        .map(|u| substitute(&u).trim().to_string())
        .filter(|u| !u.is_empty() && !u.eq_ignore_ascii_case(email));
    list.push(ServerConfig { host, port, security, username, accept_invalid_certs: false });
}

// ---------------------------------------------------------------------------
// Network steps
// ---------------------------------------------------------------------------

fn http_client() -> Option<reqwest::Client> {
    crate::net::install_crypto_provider();
    // Never follow a redirect off HTTPS: the answer decides where the password goes.
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 || attempt.url().scheme() != "https" {
            attempt.stop()
        } else {
            attempt.follow()
        }
    });
    reqwest::Client::builder()
        .timeout(STEP_TIMEOUT)
        .connect_timeout(STEP_TIMEOUT)
        .redirect(redirect)
        .user_agent(USER_AGENT)
        .build()
        .inspect_err(|e| tracing::debug!("autoconfig: HTTP client unavailable: {e}"))
        .ok()
}

async fn fetch_autoconfig(client: &reqwest::Client, url: &str, email: &str) -> Option<Discovery> {
    let fetch = async {
        let mut resp = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/xml, text/xml;q=0.9, */*;q=0.1")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() || resp.content_length().is_some_and(|n| n > MAX_XML_BYTES as u64) {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.ok()? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_XML_BYTES {
                return None;
            }
        }
        Some(body)
    };
    let body = tokio::time::timeout(STEP_TIMEOUT, fetch).await.ok().flatten()?;
    match parse_autoconfig_xml(&String::from_utf8_lossy(&body), email) {
        Ok(d) => Some(d),
        Err(e) => {
            tracing::debug!("autoconfig: ignoring {url}: {e}");
            None
        }
    }
}

fn build_resolver() -> Option<TokioResolver> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let mut builder = TokioResolver::builder_tokio().unwrap_or_else(|e| {
        tracing::debug!("autoconfig: system DNS configuration unavailable ({e}), using public resolvers");
        let servers = FALLBACK_DNS.iter().map(|ip| NameServerConfig::udp_and_tcp(*ip)).collect();
        TokioResolver::builder_with_config(ResolverConfig::from_name_servers(servers), TokioRuntimeProvider::default())
    });
    let opts = builder.options_mut();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 2;
    builder.build().inspect_err(|e| tracing::debug!("autoconfig: DNS resolver unavailable: {e}")).ok()
}

fn fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

fn dns_host(name: &Name) -> String {
    normalize_host(&name.to_ascii())
}

/// MX hosts ordered by preference (null MX and empty answers yield nothing).
async fn lookup_mx(resolver: &TokioResolver, domain: &str) -> Vec<String> {
    let Ok(Ok(lookup)) = tokio::time::timeout(STEP_TIMEOUT, resolver.mx_lookup(fqdn(domain))).await else {
        return Vec::new();
    };
    let mut records: Vec<(u16, String)> = lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::MX(mx) => Some((mx.preference, dns_host(&mx.exchange))),
            _ => None,
        })
        .filter(|(_, host)| !host.is_empty())
        .collect();
    records.sort();
    let mut seen = HashSet::new();
    records.into_iter().filter_map(|(_, host)| seen.insert(host.clone()).then_some(host)).collect()
}

/// SRV targets ordered by priority, then descending weight. A target of `.`
/// ("service not offered") is skipped.
async fn lookup_srv(resolver: &TokioResolver, name: String) -> Vec<(String, u16)> {
    let Ok(Ok(lookup)) = tokio::time::timeout(STEP_TIMEOUT, resolver.srv_lookup(name)).await else {
        return Vec::new();
    };
    let mut records: Vec<(u16, std::cmp::Reverse<u16>, String, u16)> = lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::SRV(srv) => Some((srv.priority, std::cmp::Reverse(srv.weight), dns_host(&srv.target), srv.port)),
            _ => None,
        })
        .filter(|(_, _, host, port)| !host.is_empty() && *port != 0)
        .collect();
    records.sort();
    records.into_iter().map(|(_, _, host, port)| (host, port)).collect()
}

/// RFC 6186 / RFC 8314 service records.
async fn discover_srv(resolver: &TokioResolver, domain: &str, email: &str) -> Option<Discovery> {
    let srv = |service: &str| lookup_srv(resolver, format!("_{service}._tcp.{}", fqdn(domain)));
    let (imaps, imap, pop3s, pop3, submissions, submission) =
        tokio::join!(srv("imaps"), srv("imap"), srv("pop3s"), srv("pop3"), srv("submissions"), srv("submission"));
    let servers = |implicit: Vec<(String, u16)>, starttls: Vec<(String, u16)>| -> Vec<ServerConfig> {
        let implicit = implicit.into_iter().map(|t| (t, Security::Tls));
        let starttls = starttls.into_iter().map(|t| (t, Security::StartTls));
        implicit
            .chain(starttls)
            .map(|((host, port), security)| ServerConfig { host, port, security, ..Default::default() })
            .collect()
    };
    let discovery = Discovery {
        email: email.to_string(),
        provider: None,
        imap: servers(imaps, imap),
        pop3: servers(pop3s, pop3),
        smtp: servers(submissions, submission),
        source: "srv".into(),
    };
    (!discovery.imap.is_empty() || !discovery.pop3.is_empty()).then_some(discovery)
}

async fn resolves(resolver: &TokioResolver, host: &str) -> bool {
    matches!(
        tokio::time::timeout(STEP_TIMEOUT, resolver.lookup_ip(fqdn(host))).await,
        Ok(Ok(ips)) if ips.iter().next().is_some()
    )
}

const IMAP_GUESS_PORTS: [(u16, Security); 2] = [(993, Security::Tls), (143, Security::StartTls)];
const POP3_GUESS_PORTS: [(u16, Security); 1] = [(995, Security::Tls)];
const SMTP_GUESS_PORTS: [(u16, Security); 2] = [(465, Security::Tls), (587, Security::StartTls)];

/// Conventional host names (`imap.{d}`, `mail.{d}`, `smtp.{d}`, ...). With a resolver,
/// names that do not resolve are dropped; the bare domain is used only when none of
/// the named hosts resolves but the domain does. Without DNS answers all named hosts
/// are kept.
async fn guess(resolver: Option<&TokioResolver>, domain: &str, email: &str) -> Discovery {
    let candidates = ["imap", "mail", "pop", "pop3", "smtp"].map(|p| format!("{p}.{domain}"));
    let resolvable: HashSet<String> = match resolver {
        Some(r) => {
            let checks = candidates
                .iter()
                .map(String::as_str)
                .chain([domain])
                .map(|host| async move { resolves(r, host).await.then(|| host.to_string()) });
            futures::future::join_all(checks).await.into_iter().flatten().collect()
        }
        None => HashSet::new(),
    };
    let pick = |prefixes: &[&str]| -> Vec<String> {
        let named: Vec<String> = prefixes.iter().map(|p| format!("{p}.{domain}")).collect();
        let live: Vec<String> = named.iter().filter(|h| resolvable.contains(*h)).cloned().collect();
        if !live.is_empty() {
            live
        } else if resolvable.contains(domain) {
            vec![domain.to_string()]
        } else {
            named
        }
    };
    Discovery {
        email: email.to_string(),
        provider: None,
        imap: servers_for(&pick(&["imap", "mail"]), &IMAP_GUESS_PORTS),
        pop3: servers_for(&pick(&["pop", "pop3", "mail"]), &POP3_GUESS_PORTS),
        smtp: servers_for(&pick(&["smtp", "mail"]), &SMTP_GUESS_PORTS),
        source: "guess".into(),
    }
}

/// Every host on every port, ports outermost (all implicit-TLS candidates first).
fn servers_for(hosts: &[String], ports: &[(u16, Security)]) -> Vec<ServerConfig> {
    ports
        .iter()
        .flat_map(|&(port, security)| {
            hosts.iter().map(move |host| ServerConfig { host: host.clone(), port, security, ..Default::default() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_for_domain(d: &str) -> Option<&'static str> {
        provider_for_domain(d).map(|p| p.id.as_str())
    }

    fn id_for_mx(hosts: &[&str]) -> Option<&'static str> {
        let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        provider_for_mx(&hosts).map(|p| p.id.as_str())
    }

    #[test]
    fn presets_are_consistent() {
        let all = presets();
        assert!(all.len() >= 30, "only {} presets", all.len());
        let mut ids = HashSet::new();
        let mut domains = HashSet::new();
        let mut patterns = HashSet::new();
        for p in all {
            assert!(ids.insert(p.id.as_str()), "duplicate id {}", p.id);
            assert!(!p.name.is_empty() && !p.label.is_empty(), "{}: name/label", p.id);
            assert!(
                p.color.len() == 7 && p.color.starts_with('#') && p.color[1..].chars().all(|c| c.is_ascii_hexdigit()),
                "{}: color {}",
                p.id,
                p.color
            );
            assert!(p.imap.is_some() || p.pop3.is_some(), "{}: no incoming server", p.id);
            assert!(p.smtp.is_some(), "{}: no smtp server", p.id);
            assert!(!p.domains.is_empty() || !p.mx_patterns.is_empty(), "{}: unreachable preset", p.id);
            for d in &p.domains {
                assert_eq!(d, &d.trim().to_ascii_lowercase(), "{}: domain {d} not normalized", p.id);
                assert!(domains.insert(d.as_str()), "domain {d} listed twice");
            }
            for m in &p.mx_patterns {
                assert_eq!(m, &m.trim().to_ascii_lowercase(), "{}: mx pattern {m} not normalized", p.id);
                assert!(patterns.insert(m.as_str()), "mx pattern {m} listed twice");
            }
            let servers = p.imap.iter().chain(&p.pop3).chain(&p.smtp).chain(&p.alt_imap).chain(&p.alt_smtp);
            for s in servers {
                assert!(!s.host.is_empty() && s.port != 0, "{}: bad server {s:?}", p.id);
                assert!(s.username.is_none(), "{}: presets log in with the address", p.id);
                assert_eq!(s.accept_invalid_certs, p.requires_bridge, "{}: {s:?}", p.id);
                if p.requires_bridge {
                    assert_eq!(s.host, "127.0.0.1");
                } else {
                    assert_ne!(s.security, Security::None, "{}: plaintext server {s:?}", p.id);
                }
            }
            match p.auth {
                AuthKind::Oauth2 => assert!(
                    matches!(p.oauth_provider.as_deref(), Some("google" | "microsoft")),
                    "{}: oauth provider",
                    p.id
                ),
                AuthKind::Password => assert!(p.oauth_provider.is_none(), "{}: stray oauth provider", p.id),
            }
            for url in p.help_url.iter().chain(&p.web_url) {
                assert!(url.starts_with("https://"), "{}: {url}", p.id);
            }
            assert!(!p.password_label.is_empty() && !p.help_steps.is_empty(), "{}: guidance", p.id);
        }
        let required = [
            "qq",
            "163",
            "126",
            "yeah",
            "188",
            "gmail",
            "outlook",
            "office365",
            "icloud",
            "yahoo",
            "aol",
            "proton",
            "exmail",
            "aliyun",
            "aliyun_qiye",
            "qiye163",
            "sina",
            "sohu",
            "139",
            "189",
            "zoho",
            "fastmail",
            "gmx",
            "yandex",
            "mailru",
        ];
        for id in required {
            assert!(provider(id).is_some(), "missing preset {id}");
        }
    }

    #[test]
    fn key_provider_settings() {
        let qq = provider("qq").unwrap();
        assert_eq!(qq.imap.as_ref().unwrap().host, "imap.qq.com");
        assert_eq!(qq.smtp.as_ref().unwrap().port, 465);
        assert_eq!(qq.password_label, "授权码");
        assert!(provider("163").unwrap().send_id);

        let gmail = provider("gmail").unwrap();
        assert_eq!(gmail.auth, AuthKind::Oauth2);
        assert_eq!(gmail.oauth_provider.as_deref(), Some("google"));
        assert!(!gmail.save_sent_copy);
        assert!(gmail.alt_smtp.iter().any(|s| s.port == 587 && s.security == Security::StartTls));

        let outlook = provider("outlook").unwrap();
        assert_eq!(outlook.smtp.as_ref().unwrap().host, "smtp-mail.outlook.com");
        assert_eq!(outlook.smtp.as_ref().unwrap().security, Security::StartTls);
        assert_eq!(outlook.oauth_provider.as_deref(), Some("microsoft"));

        let icloud = provider("icloud").unwrap();
        assert!(icloud.pop3.is_none());
        assert_eq!(icloud.smtp.as_ref().unwrap().port, 587);

        let proton = provider("proton").unwrap();
        assert!(proton.requires_bridge);
        let imap = proton.imap.as_ref().unwrap();
        assert_eq!((imap.host.as_str(), imap.port, imap.security), ("127.0.0.1", 1143, Security::StartTls));
        assert!(imap.accept_invalid_certs);
        assert_eq!(proton.smtp.as_ref().unwrap().port, 1025);

        let cfg = gmail.account_config();
        assert_eq!(cfg.auth, AuthKind::Oauth2);
        assert!(!cfg.save_sent_copy);
        assert_eq!(cfg.smtp.unwrap().host, "smtp.gmail.com");
    }

    #[test]
    fn domain_lookup() {
        assert_eq!(id_for_domain("qq.com"), Some("qq"));
        assert_eq!(id_for_domain("QQ.COM"), Some("qq"));
        assert_eq!(id_for_domain("foxmail.com"), Some("qq"));
        assert_eq!(id_for_domain("Someone@Foxmail.com"), Some("qq"));
        assert_eq!(id_for_domain(" 163.com. "), Some("163"));
        assert_eq!(id_for_domain("vip.163.com"), Some("vip163"));
        assert_eq!(id_for_domain("googlemail.com"), Some("gmail"));
        assert_eq!(id_for_domain("hotmail.com"), Some("outlook"));
        assert_eq!(id_for_domain("live.cn"), Some("outlook"));
        assert_eq!(id_for_domain("me.com"), Some("icloud"));
        assert_eq!(id_for_domain("pm.me"), Some("proton"));
        assert_eq!(id_for_domain("sina.cn"), Some("sina_cn"));
        assert_eq!(id_for_domain("contoso.onmicrosoft.com"), Some("office365"));
        assert_eq!(id_for_domain("onmicrosoft.com"), None);
        assert_eq!(id_for_domain("example.com"), None);
        assert_eq!(id_for_domain(""), None);
        assert_eq!(provider("GMAIL").map(|p| p.id.as_str()), Some("gmail"));
        assert!(provider("nope").is_none());
    }

    #[test]
    fn mx_lookup_mapping() {
        assert_eq!(id_for_mx(&["mxbiz1.qq.com."]), Some("exmail"));
        assert_eq!(id_for_mx(&["MXBIZ2.QQ.COM"]), Some("exmail"));
        assert_eq!(id_for_mx(&["aspmx.l.google.com"]), Some("gmail"));
        assert_eq!(id_for_mx(&["alt1.aspmx.l.google.com"]), Some("gmail"));
        assert_eq!(id_for_mx(&["smtp.google.com"]), Some("gmail"));
        assert_eq!(id_for_mx(&["contoso-com.mail.protection.outlook.com"]), Some("office365"));
        assert_eq!(id_for_mx(&["hotmail-com.olc.protection.outlook.com"]), Some("outlook"));
        assert_eq!(id_for_mx(&["qiye163mx01.mxmail.netease.com"]), Some("qiye163"));
        assert_eq!(id_for_mx(&["mx.ym.163.com"]), Some("ym163"));
        assert_eq!(id_for_mx(&["mxw.mxhichina.com"]), Some("aliyun_qiye"));
        assert_eq!(id_for_mx(&["mx1.qiye.aliyun.com"]), Some("aliyun_qiye"));
        assert_eq!(id_for_mx(&["mx2.zoho.com"]), Some("zoho_pro"));
        assert_eq!(id_for_mx(&["in1-smtp.messagingengine.com"]), Some("fastmail"));
        assert_eq!(id_for_mx(&["mail.protonmail.ch"]), Some("proton"));
        assert_eq!(id_for_mx(&["mx01.mail.icloud.com"]), Some("icloud"));
        assert_eq!(id_for_mx(&["mx.yandex.net"]), Some("yandex"));
        // Dotted patterns match at label boundaries only.
        assert_eq!(id_for_mx(&["mx.zoho.com.cn"]), None);
        assert_eq!(id_for_mx(&["evilgoogle.com"]), None);
        assert_eq!(id_for_mx(&["mx.example.net"]), None);
        assert_eq!(id_for_mx(&[]), None);
        // The first host that maps to a preset decides.
        assert_eq!(id_for_mx(&["mx.example.net", "mxbiz2.qq.com"]), Some("exmail"));
    }

    #[test]
    fn server_host_mapping() {
        assert_eq!(provider_for_server("outlook.office365.com").map(|p| p.id.as_str()), Some("office365"));
        assert_eq!(provider_for_server("IMAP.GMAIL.COM.").map(|p| p.id.as_str()), Some("gmail"));
        assert_eq!(provider_for_server("imap.qiye.163.com").map(|p| p.id.as_str()), Some("qiye163"));
        assert!(provider_for_server("127.0.0.1").is_none());
        assert!(provider_for_server("imap.example.com").is_none());
    }

    const SAMPLE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- Sample ISPDB entry -->
<clientConfig version="1.1">
  <emailProvider id="example.com">
    <domain>example.com</domain>
    <displayName>Example &amp; Co Mail</displayName>
    <displayShortName>Example</displayShortName>
    <incomingServer type="imap">
      <hostname>imap.%EMAILDOMAIN%</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mail.example.com</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILLOCALPART%</username>
      <authentication>password-encrypted</authentication>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>pop.example.com</hostname>
      <port>110</port>
      <socketType>plain</socketType>
      <username>%EMAILLOCALPART%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>POP.Example.com</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <username><![CDATA[%EMAILLOCALPART%@corp]]></username>
    </incomingServer>
    <incomingServer type="exchange">
      <hostname>ews.example.com</hostname>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.com</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.com</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <username/>
    </outgoingServer>
    <documentation url="https://example.com/help?a=1&amp;b=2">
      <descr lang="en">Help</descr>
    </documentation>
  </emailProvider>
</clientConfig>"#;

    #[test]
    fn parses_thunderbird_xml() {
        let d = parse_autoconfig_xml(SAMPLE_XML, "alice@example.com").unwrap();
        assert_eq!(d.source, "autoconfig");
        assert_eq!(d.email, "alice@example.com");

        assert_eq!(d.imap.len(), 2);
        assert_eq!(d.imap[0].host, "imap.example.com");
        assert_eq!((d.imap[0].port, d.imap[0].security), (993, Security::Tls));
        assert_eq!(d.imap[0].username, None, "the address itself is the default login");
        assert_eq!(d.imap[1].host, "mail.example.com");
        assert_eq!((d.imap[1].port, d.imap[1].security), (143, Security::StartTls));
        assert_eq!(d.imap[1].username.as_deref(), Some("alice"));

        // Plaintext POP3 moves behind the TLS one; host names are lower-cased.
        assert_eq!(d.pop3.len(), 2);
        assert_eq!((d.pop3[0].host.as_str(), d.pop3[0].port), ("pop.example.com", 995));
        assert_eq!(d.pop3[0].security, Security::Tls);
        assert_eq!(d.pop3[0].username.as_deref(), Some("alice@corp"));
        assert_eq!((d.pop3[1].port, d.pop3[1].security), (110, Security::None));

        assert_eq!(d.smtp.len(), 2);
        assert_eq!((d.smtp[0].port, d.smtp[0].security), (465, Security::Tls));
        assert_eq!((d.smtp[1].port, d.smtp[1].security), (587, Security::StartTls));
        assert_eq!(d.smtp[1].username, None);
    }

    #[test]
    fn parses_xml_with_missing_fields() {
        let xml = r#"<clientConfig><emailProvider id="x">
            <incomingServer type="IMAP"><hostname>imap.x.org</hostname></incomingServer>
            <incomingServer type="imap"><hostname>imap2.x.org</hostname><port>143</port></incomingServer>
            <incomingServer type="imap"><hostname>%UNKNOWN%.x.org</hostname></incomingServer>
        </emailProvider></clientConfig>"#;
        let d = parse_autoconfig_xml(xml, "bob@x.org").unwrap();
        assert_eq!(d.imap.len(), 2);
        assert_eq!((d.imap[0].port, d.imap[0].security), (993, Security::Tls));
        assert_eq!((d.imap[1].port, d.imap[1].security), (143, Security::StartTls));
        assert!(d.smtp.is_empty());
    }

    #[test]
    fn rejects_bad_xml() {
        assert!(matches!(
            parse_autoconfig_xml("<clientConfig><a></b></clientConfig>", "a@b.c"),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            parse_autoconfig_xml("<clientConfig><emailProvider/></clientConfig>", "a@b.c"),
            Err(Error::NotFound(_))
        ));
        assert!(parse_autoconfig_xml("<html><body>Not found</body></html>", "a@b.c").is_err());
    }

    #[test]
    fn finish_attaches_provider_and_fills_smtp() {
        let xml = r#"<clientConfig><emailProvider id="corp.example">
            <incomingServer type="imap"><hostname>outlook.office365.com</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
            <incomingServer type="imap"><hostname>outlook.office365.com</hostname><port>993</port><socketType>SSL</socketType></incomingServer>
        </emailProvider></clientConfig>"#;
        let mut d = parse_autoconfig_xml(xml, "me@corp.example").unwrap();
        d.finish("corp.example");
        assert_eq!(d.imap.len(), 1, "duplicates removed");
        assert_eq!(d.provider.as_ref().map(|p| p.id.as_str()), Some("office365"));
        assert_eq!(d.smtp[0].host, "smtp.office365.com", "smtp taken from the matched preset");
        let cfg = d.account_config();
        assert_eq!(cfg.auth, AuthKind::Oauth2);
        assert_eq!(cfg.imap.unwrap().host, "outlook.office365.com");

        let xml = r#"<clientConfig><incomingServer type="imap"><hostname>mx.host.example</hostname></incomingServer></clientConfig>"#;
        let mut d = parse_autoconfig_xml(xml, "me@corp.example").unwrap();
        d.finish("corp.example");
        assert!(d.provider.is_none());
        let smtp: Vec<_> = d.smtp.iter().map(|s| (s.host.as_str(), s.port)).collect();
        assert_eq!(
            smtp,
            [
                ("smtp.corp.example", 465),
                ("mx.host.example", 465),
                ("smtp.corp.example", 587),
                ("mx.host.example", 587)
            ]
        );
    }

    #[test]
    fn email_validation_and_domains() {
        assert_eq!(email_domain("a@Example.COM").unwrap(), "example.com");
        assert_eq!(email_domain("a@例子.中国").unwrap(), "xn--fsqu00a.xn--fiqs8s");
        assert!(email_domain("example.com").is_err());
        assert!(email_domain("@example.com").is_err());
        assert!(email_domain("a b@example.com").is_err());
        assert!(email_domain("a@").is_err());
        assert!(email_domain("a@1.2.3.4").is_err());
        assert!(email_domain("a@exa mple.com").is_err());

        assert_eq!(registrable_domain("mx.zoho.eu."), "zoho.eu");
        assert_eq!(registrable_domain("in1-smtp.messagingengine.com"), "messagingengine.com");
        assert_eq!(registrable_domain("mx1.example.com.cn"), "example.com.cn");
        assert_eq!(registrable_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("example.org"), "example.org");
    }

    #[tokio::test]
    async fn guesses_without_dns() {
        let d = guess(None, "example.org", "x@example.org").await;
        assert_eq!(d.source, "guess");
        let imap: Vec<_> = d.imap.iter().map(|s| (s.host.as_str(), s.port)).collect();
        assert_eq!(
            imap,
            [
                ("imap.example.org", 993),
                ("mail.example.org", 993),
                ("imap.example.org", 143),
                ("mail.example.org", 143)
            ]
        );
        assert_eq!(d.smtp[0].host, "smtp.example.org");
        assert_eq!((d.smtp[0].port, d.smtp[0].security), (465, Security::Tls));
        assert!(d.smtp.iter().any(|s| s.port == 587 && s.security == Security::StartTls));
        assert!(d.pop3.iter().all(|s| s.port == 995));
    }

    #[tokio::test]
    async fn discover_uses_presets_offline() {
        let d = discover("  Someone@Foxmail.com ").await.unwrap();
        assert_eq!(d.source, "preset");
        assert_eq!(d.email, "Someone@Foxmail.com");
        assert_eq!(d.provider.as_ref().map(|p| p.id.as_str()), Some("qq"));
        assert_eq!(d.imap[0].host, "imap.qq.com");
        assert_eq!(d.pop3[0].host, "pop.qq.com");
        assert_eq!(d.smtp.iter().map(|s| s.port).collect::<Vec<_>>(), [465, 587]);

        let d = discover("x@qiye.example.onmicrosoft.com").await.unwrap();
        assert_eq!(d.provider.map(|p| p.id), Some("office365".to_string()));

        assert!(matches!(discover("not-an-address").await, Err(Error::Invalid(_))));
    }

    #[test]
    fn provider_json_defaults() {
        let p: Provider = serde_json::from_str(r#"{"id":"x"}"#).unwrap();
        assert!(p.send_id && p.save_sent_copy && !p.requires_bridge);
        assert_eq!(p.auth, AuthKind::Password);
        assert_eq!(p.password_label, "密码");
        let json = serde_json::to_value(provider("gmail").unwrap()).unwrap();
        assert_eq!(json["auth"], "oauth2");
        assert_eq!(json["imap"]["security"], "tls");
    }

    /// Hits real DNS / HTTP: `cargo test -p mailcore autoconfig -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn discover_over_network() {
        let d = discover("someone@microsoft.com").await.unwrap();
        assert_eq!(d.source, "mx");
        assert_eq!(d.provider.as_ref().map(|p| p.id.as_str()), Some("office365"));

        let d = discover("someone@t-online.de").await.unwrap();
        assert_eq!(d.source, "ispdb", "{d:?}");
        assert!(d.imap.iter().any(|s| s.host.ends_with("t-online.de")), "{d:?}");

        let d = discover("someone@this-domain-does-not-exist-mailbox.invalid").await.unwrap();
        assert_eq!(d.source, "guess");
        assert!(!d.imap.is_empty() && !d.smtp.is_empty());
    }
}

//! Notification forwarders: push a short "new mail" notice to phones or chat bots.
//!
//! Supported `Forwarder.kind` values: `bark`, `serverchan`, `pushplus`, `wecom`, `feishu`,
//! `dingtalk`, `telegram`, `ntfy`, `webhook`. See [`send`] for the config keys of each kind.

use crate::error::{Error, Result};
use crate::model::Forwarder;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::Sha256;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

const TIMEOUT: Duration = Duration::from_secs(10);
const SNIPPET_MAX_CHARS: usize = 500;
const BARK_SERVER: &str = "https://api.day.app";
const SERVERCHAN_SERVER: &str = "https://sctapi.ftqq.com";
const PUSHPLUS_SERVER: &str = "https://www.pushplus.plus";
const WECOM_WEBHOOK: &str = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send";
const DINGTALK_WEBHOOK: &str = "https://oapi.dingtalk.com/robot/send";
const TELEGRAM_API: &str = "https://api.telegram.org";
const NTFY_SERVER: &str = "https://ntfy.sh";

#[derive(Debug, Clone, Serialize)]
pub struct ForwardPayload {
    pub account_label: String,
    pub from: String,
    pub subject: String,
    pub snippet: String,
    pub date: i64,
    pub message_url: Option<String>,
}

/// Builds a reqwest client with sane timeouts (10 s) and the rustls provider installed.
pub fn http_client() -> reqwest::Client {
    client_builder().build().unwrap_or_else(|e| {
        tracing::warn!("构建 HTTP 客户端失败, 使用默认配置: {e}");
        reqwest::Client::new()
    })
}

fn client_builder() -> reqwest::ClientBuilder {
    crate::net::install_crypto_provider();
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .user_agent(concat!("Mailbox/", env!("CARGO_PKG_VERSION")))
}

/// Title used everywhere: "[{account_label}] {from}".
pub fn title(p: &ForwardPayload) -> String {
    format!("[{}] {}", p.account_label, p.from)
}

/// Sends one notification through the given forwarder. Returns `Err` with a Chinese message on
/// HTTP / API errors (including the API's own error text).
///
/// Config keys per kind:
/// - `bark`: `server` (default `https://api.day.app`), `key`, optional `sound`, `icon`
///   — or a full `url` such as `https://api.day.app/<key>`.
/// - `serverchan`: `sendkey` (Turbo `SCT…` or Server酱³ `sctp{uid}t…`).
/// - `pushplus`: `token`, optional `topic`.
/// - `wecom`: `url` (group robot webhook) or `key`.
/// - `feishu`: `url`, optional `secret`, optional `keyword`.
/// - `dingtalk`: `url` (or `access_token`), optional `secret`, optional `keyword`.
/// - `telegram`: `token`, `chat_id`, optional `api` (default `https://api.telegram.org`).
/// - `ntfy`: `server` (default `https://ntfy.sh`), `topic`, optional `token`, optional `priority`.
/// - `webhook`: `url`, optional `method` (default POST), optional `headers` object;
///   the body is the [`ForwardPayload`] as JSON (query parameters for GET).
pub async fn send(client: &reqwest::Client, f: &Forwarder, p: &ForwardPayload) -> Result<()> {
    let c = &f.config;
    match f.kind.trim().to_ascii_lowercase().as_str() {
        "bark" => bark(client, c, p).await,
        "serverchan" => serverchan(client, c, p).await,
        "pushplus" => pushplus(client, c, p).await,
        "wecom" => wecom(client, c, p).await,
        "feishu" => feishu(client, c, p).await,
        "dingtalk" => dingtalk(client, c, p).await,
        "telegram" => telegram(client, c, p).await,
        "ntfy" => ntfy(client, c, p).await,
        "webhook" => webhook(client, c, p).await,
        "" => Err(Error::Invalid("未设置转发方式".into())),
        other => Err(Error::Invalid(format!("不支持的转发方式: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

async fn bark(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "Bark";
    let (server, key) = bark_target(c)?;
    let mut body_text = snippet(p);
    if body_text.is_empty() {
        // Bark rejects an empty body.
        body_text = subject(p).to_string();
    }
    let mut body = json!({
        "device_key": key,
        "title": title(p),
        "subtitle": subject(p),
        "body": body_text,
        "group": p.account_label,
    });
    for k in ["sound", "icon", "level"] {
        if let Some(v) = opt(c, k) {
            body[k] = Value::String(v);
        }
    }
    if let Some(url) = &p.message_url {
        body["url"] = Value::String(url.clone());
    }
    let req = client.post(format!("{server}/push")).json(&body);
    let v = execute(NAME, req).await?;
    check_code(NAME, &v, "code", 200)
}

/// (server, device key) from `server` + `key`, or from a full `url` / URL pasted into `key`.
fn bark_target(c: &Map<String, Value>) -> Result<(String, String)> {
    let key = opt(c, "key");
    let pasted_url = key.as_deref().filter(|k| is_http_url(k)).map(str::to_string);
    if let Some(k) = key.filter(|k| !is_http_url(k)) {
        let server = opt(c, "server").unwrap_or_else(|| BARK_SERVER.into());
        return Ok((server.trim_end_matches('/').to_string(), k));
    }
    let Some(raw) = opt(c, "url").or(pasted_url) else {
        return Err(missing("Bark", "key"));
    };
    let url = url::Url::parse(&raw).map_err(|e| Error::Invalid(format!("Bark 地址无效: {e}")))?;
    let key = url
        .path_segments()
        .and_then(|mut s| s.find(|seg| !seg.is_empty()))
        .map(str::to_string)
        .ok_or_else(|| Error::Invalid("Bark 地址中缺少设备 Key".into()))?;
    Ok((url.origin().ascii_serialization(), key))
}

async fn serverchan(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "Server酱";
    let key = opt(c, "sendkey").or_else(|| opt(c, "key")).ok_or_else(|| missing(NAME, "sendkey"))?;
    let url = serverchan_url(&key, opt(c, "base").as_deref())?;
    let form = [
        ("title", truncate_chars(&title(p), 32)),
        ("desp", markdown(p)),
        ("short", truncate_chars(subject(p), 64)),
    ];
    let v = execute(NAME, client.post(url).form(&form)).await?;
    check_code(NAME, &v, "code", 0)
}

/// Server酱 Turbo: `https://sctapi.ftqq.com/{sendkey}.send`;
/// Server酱³ (`sctp{uid}t…` keys): `https://{uid}.push.ft07.com/send/{sendkey}.send`.
/// `base` replaces the scheme + host (tests only).
fn serverchan_url(key: &str, base: Option<&str>) -> Result<String> {
    let base = base.map(|b| b.trim_end_matches('/').to_string());
    if let Some(rest) = key.strip_prefix("sctp") {
        let uid: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if uid.is_empty() || !rest[uid.len()..].starts_with('t') {
            return Err(Error::Invalid("Server酱³ SendKey 格式不正确".into()));
        }
        let base = base.unwrap_or_else(|| format!("https://{uid}.push.ft07.com"));
        return Ok(format!("{base}/send/{key}.send"));
    }
    let base = base.unwrap_or_else(|| SERVERCHAN_SERVER.into());
    Ok(format!("{base}/{key}.send"))
}

async fn pushplus(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "PushPlus";
    let token = opt(c, "token").ok_or_else(|| missing(NAME, "token"))?;
    let base = opt(c, "base").unwrap_or_else(|| PUSHPLUS_SERVER.into());
    let mut body = json!({
        "token": token,
        "title": title(p),
        "content": markdown(p),
        "template": "markdown",
    });
    if let Some(topic) = opt(c, "topic") {
        body["topic"] = Value::String(topic);
    }
    let req = client.post(format!("{}/send", base.trim_end_matches('/'))).json(&body);
    let v = execute(NAME, req).await?;
    check_code(NAME, &v, "code", 200)
}

async fn wecom(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "企业微信";
    let url = match (opt(c, "url"), opt(c, "key")) {
        (Some(url), _) => url,
        (None, Some(key)) => format!("{WECOM_WEBHOOK}?key={}", utf8_percent_encode(&key, NON_ALPHANUMERIC)),
        (None, None) => return Err(missing(NAME, "url")),
    };
    // WeCom rejects markdown content longer than 4096 bytes.
    let body = json!({"msgtype": "markdown", "markdown": {"content": truncate_bytes(&markdown(p), 4000)}});
    let v = execute(NAME, client.post(url).json(&body)).await?;
    check_code(NAME, &v, "errcode", 0)
}

async fn feishu(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "飞书";
    let url = opt(c, "url").ok_or_else(|| missing(NAME, "url"))?;
    let text = with_keyword(c, plain_text(p));
    let mut body = json!({"msg_type": "text", "content": {"text": text}});
    if let Some(secret) = opt(c, "secret") {
        let ts = chrono::Utc::now().timestamp();
        body["timestamp"] = Value::String(ts.to_string());
        body["sign"] = Value::String(feishu_sign(ts, &secret));
    }
    let v = execute(NAME, client.post(url).json(&body)).await?;
    // Current API: {"code":0,"msg":"success"}; legacy: {"StatusCode":0,"StatusMessage":"success"}.
    let key = if v.get("code").is_some() { "code" } else { "StatusCode" };
    check_code(NAME, &v, key, 0)
}

/// base64(HMAC-SHA256(key = "{timestamp}\n{secret}", message = "")).
fn feishu_sign(timestamp: i64, secret: &str) -> String {
    let key = format!("{timestamp}\n{secret}");
    let mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    BASE64.encode(mac.finalize().into_bytes())
}

async fn dingtalk(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "钉钉";
    let mut url = match (opt(c, "url"), opt(c, "access_token")) {
        (Some(url), _) => url,
        (None, Some(token)) => {
            format!("{DINGTALK_WEBHOOK}?access_token={}", utf8_percent_encode(&token, NON_ALPHANUMERIC))
        }
        (None, None) => return Err(missing(NAME, "url")),
    };
    if let Some(secret) = opt(c, "secret") {
        let ms = chrono::Utc::now().timestamp_millis();
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(&format!("timestamp={ms}&sign={}", dingtalk_sign(ms, &secret)));
    }
    let body = json!({
        "msgtype": "markdown",
        "markdown": {"title": title(p), "text": with_keyword(c, markdown(p))},
    });
    let v = execute(NAME, client.post(url).json(&body)).await?;
    check_code(NAME, &v, "errcode", 0)
}

/// urlencode(base64(HMAC-SHA256(key = secret, message = "{timestamp_ms}\n{secret}"))).
fn dingtalk_sign(timestamp_ms: i64, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("{timestamp_ms}\n{secret}").as_bytes());
    let b64 = BASE64.encode(mac.finalize().into_bytes());
    utf8_percent_encode(&b64, NON_ALPHANUMERIC).to_string()
}

async fn telegram(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "Telegram";
    let token = opt(c, "token").ok_or_else(|| missing(NAME, "token"))?;
    let chat_id = match c.get("chat_id") {
        Some(Value::Number(n)) => Value::Number(n.clone()),
        Some(Value::String(s)) if !s.trim().is_empty() => Value::String(s.trim().to_string()),
        _ => return Err(missing(NAME, "chat_id")),
    };
    let api = opt(c, "api").unwrap_or_else(|| TELEGRAM_API.into());
    let body = json!({
        "chat_id": chat_id,
        "text": truncate_chars(&plain_text(p), 4096),
        "disable_web_page_preview": true,
    });
    let req = client.post(format!("{}/bot{token}/sendMessage", api.trim_end_matches('/'))).json(&body);
    let v = execute(NAME, req).await?;
    if v.get("ok").and_then(Value::as_bool) == Some(false) {
        let code = v.get("error_code").map(|c| c.to_string()).unwrap_or_else(|| "?".into());
        return Err(api_error(NAME, &code, &v));
    }
    Ok(())
}

async fn ntfy(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "ntfy";
    let server = opt(c, "server").unwrap_or_else(|| NTFY_SERVER.into());
    let (server, topic) = match opt(c, "topic") {
        Some(topic) => (server, topic),
        // Accept `https://ntfy.sh/mytopic` pasted into `server`.
        None => split_ntfy_topic(&server).ok_or_else(|| missing(NAME, "topic"))?,
    };
    let mut message = subject(p).to_string();
    let snip = snippet(p);
    if !snip.is_empty() {
        message.push_str("\n\n");
        message.push_str(&snip);
    }
    let mut body = json!({"topic": topic, "title": title(p), "message": message});
    if let Some(url) = &p.message_url {
        body["click"] = Value::String(url.clone());
    }
    if let Some(priority) = opt(c, "priority").and_then(|s| s.parse::<u8>().ok()) {
        body["priority"] = json!(priority);
    }
    // JSON publishing goes to the server root (https://docs.ntfy.sh/publish/#publish-as-json).
    let mut req = client.post(format!("{}/", server.trim_end_matches('/'))).json(&body);
    if let Some(token) = opt(c, "token") {
        req = req.bearer_auth(token);
    }
    execute(NAME, req).await.map(drop)
}

fn split_ntfy_topic(server: &str) -> Option<(String, String)> {
    let trimmed = server.trim_end_matches('/');
    let (base, topic) = trimmed.rsplit_once('/')?;
    if base.ends_with('/') || base.ends_with(':') || topic.is_empty() {
        return None; // no path segment after the host
    }
    Some((base.to_string(), topic.to_string()))
}

async fn webhook(client: &reqwest::Client, c: &Map<String, Value>, p: &ForwardPayload) -> Result<()> {
    const NAME: &str = "Webhook";
    let raw_url = opt(c, "url").ok_or_else(|| missing(NAME, "url"))?;
    let mut url = url::Url::parse(&raw_url).map_err(|e| Error::Invalid(format!("Webhook 地址无效: {e}")))?;
    let method_name = opt(c, "method").unwrap_or_else(|| "POST".into()).to_ascii_uppercase();
    let method = reqwest::Method::from_bytes(method_name.as_bytes())
        .map_err(|_| Error::Invalid(format!("Webhook 请求方法无效: {method_name}")))?;
    let mut req = if method == reqwest::Method::GET || method == reqwest::Method::HEAD {
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("account_label", &p.account_label)
                .append_pair("from", &p.from)
                .append_pair("subject", &p.subject)
                .append_pair("snippet", &p.snippet)
                .append_pair("date", &p.date.to_string());
            if let Some(u) = &p.message_url {
                q.append_pair("message_url", u);
            }
        }
        client.request(method, url)
    } else {
        client.request(method, url).json(p)
    };
    for (name, value) in webhook_headers(c.get("headers")) {
        req = req.header(name, value);
    }
    execute(NAME, req).await.map(drop)
}

/// `headers` as a JSON object, a JSON object encoded in a string, or "Name: value" lines.
fn webhook_headers(v: Option<&Value>) -> Vec<(String, String)> {
    let value_str = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    match v {
        Some(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), value_str(v))).collect(),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(obj @ Value::Object(_)) => webhook_headers(Some(&obj)),
            _ => s
                .lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .filter(|(k, _)| !k.is_empty())
                .collect(),
        },
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Message formatting
// ---------------------------------------------------------------------------

fn subject(p: &ForwardPayload) -> &str {
    match p.subject.trim() {
        "" => "(无主题)",
        s => s,
    }
}

fn snippet(p: &ForwardPayload) -> String {
    truncate_chars(p.snippet.trim(), SNIPPET_MAX_CHARS)
}

fn date_text(p: &ForwardPayload) -> Option<String> {
    use chrono::TimeZone;
    if p.date <= 0 {
        return None;
    }
    chrono::Local.timestamp_opt(p.date, 0).single().map(|d| d.format("%Y-%m-%d %H:%M").to_string())
}

/// Plain text body (Feishu, Telegram).
fn plain_text(p: &ForwardPayload) -> String {
    let mut s = format!("{}\n主题: {}", title(p), subject(p));
    if let Some(d) = date_text(p) {
        s.push_str(&format!("\n时间: {d}"));
    }
    let snip = snippet(p);
    if !snip.is_empty() {
        s.push_str("\n\n");
        s.push_str(&snip);
    }
    if let Some(url) = &p.message_url {
        s.push_str("\n\n");
        s.push_str(url);
    }
    s
}

/// Markdown body (Server酱, PushPlus, WeCom, DingTalk).
fn markdown(p: &ForwardPayload) -> String {
    let mut s = format!("### {}\n\n**发件人**: {}\n\n**账户**: {}", subject(p), p.from, p.account_label);
    if let Some(d) = date_text(p) {
        s.push_str(&format!("\n\n**时间**: {d}"));
    }
    let snip = snippet(p);
    if !snip.is_empty() {
        s.push_str("\n\n> ");
        s.push_str(&snip.replace('\n', "\n> "));
    }
    if let Some(url) = &p.message_url {
        s.push_str(&format!("\n\n[查看邮件]({url})"));
    }
    s
}

/// Prefix for robots with keyword security (the keyword must appear in the message).
fn with_keyword(c: &Map<String, Value>, text: String) -> String {
    match opt(c, "keyword") {
        Some(k) if !text.contains(&k) => format!("{k} {text}"),
        _ => text,
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_string(),
    }
}

fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub('…'.len_utf8());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

// ---------------------------------------------------------------------------
// Config and response helpers
// ---------------------------------------------------------------------------

/// Non-empty trimmed config value; numbers and booleans are stringified.
fn opt(c: &Map<String, Value>, key: &str) -> Option<String> {
    match c.get(key)? {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn missing(service: &str, key: &str) -> Error {
    Error::Invalid(format!("{service} 缺少配置项 {key}"))
}

fn is_http_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Sends the request and returns the JSON body (`Null` when the body is not JSON).
/// Transport failures → `Error::Net`; non-2xx statuses → `Error::Other` with the API's message.
async fn execute(service: &str, req: reqwest::RequestBuilder) -> Result<Value> {
    // `without_url` keeps tokens embedded in URLs (Telegram, Server酱, webhooks) out of error messages.
    let resp = req.send().await.map_err(|e| Error::Net(format!("{service} 请求失败: {}", e.without_url())))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| Error::Net(format!("{service} 读取响应失败: {}", e.without_url())))?;
    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = api_message(&json).unwrap_or_else(|| excerpt(&text));
        let msg = if msg.is_empty() { status.canonical_reason().unwrap_or("").to_string() } else { msg };
        return Err(Error::Other(format!("{service} 推送失败 (HTTP {}): {msg}", status.as_u16())));
    }
    Ok(json)
}

/// Fails when the JSON body carries `key` with a value other than `ok`.
fn check_code(service: &str, v: &Value, key: &str, ok: i64) -> Result<()> {
    let code = match v.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    match code {
        Some(c) if c != ok => Err(api_error(service, &c.to_string(), v)),
        _ => Ok(()),
    }
}

fn api_error(service: &str, code: &str, v: &Value) -> Error {
    let msg = api_message(v).unwrap_or_else(|| "未知错误".into());
    Error::Other(format!("{service} 推送失败: {msg} (错误码 {code})"))
}

fn api_message(v: &Value) -> Option<String> {
    ["errmsg", "msg", "message", "description", "error", "StatusMessage"]
        .iter()
        .filter_map(|k| v.get(*k))
        .find_map(|m| match m {
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        })
}

fn excerpt(text: &str) -> String {
    truncate_chars(text.trim(), 200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
    use axum::response::IntoResponse;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        query: HashMap<String, String>,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Recorded {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).expect("JSON body")
        }

        fn form(&self) -> HashMap<String, String> {
            url::form_urlencoded::parse(&self.body).into_owned().collect()
        }
    }

    #[derive(Clone, Default)]
    struct Mock {
        requests: Arc<Mutex<Vec<Recorded>>>,
        /// path → (status, JSON body); everything else gets 200 `{}`.
        replies: Arc<HashMap<String, (u16, String)>>,
    }

    impl Mock {
        fn take(&self) -> Recorded {
            let mut reqs = self.requests.lock();
            assert_eq!(reqs.len(), 1, "expected exactly one request, got {reqs:?}");
            reqs.remove(0)
        }
    }

    async fn record(State(m): State<Mock>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
        let query = uri.query().map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect()).unwrap_or_default();
        m.requests.lock().push(Recorded {
            method: method.to_string(),
            path: uri.path().to_string(),
            query,
            headers,
            body: body.to_vec(),
        });
        let (status, body) = m.replies.get(uri.path()).cloned().unwrap_or((200, "{}".into()));
        (StatusCode::from_u16(status).unwrap(), [(header::CONTENT_TYPE, "application/json")], body)
    }

    async fn mock(replies: &[(&str, u16, &str)]) -> (String, Mock) {
        let m = Mock {
            requests: Arc::default(),
            replies: Arc::new(replies.iter().map(|(p, s, b)| (p.to_string(), (*s, b.to_string()))).collect()),
        };
        let app = Router::new().fallback(record).with_state(m.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), m)
    }

    fn client() -> reqwest::Client {
        client_builder().no_proxy().build().unwrap()
    }

    fn forwarder(kind: &str, config: Value) -> Forwarder {
        let Value::Object(config) = config else { panic!("config must be an object") };
        Forwarder { id: "f1".into(), kind: kind.into(), name: kind.into(), enabled: true, config, ..Default::default() }
    }

    fn payload() -> ForwardPayload {
        ForwardPayload {
            account_label: "工作".into(),
            from: "张三 <zhangsan@example.com>".into(),
            subject: "Q4 预算审批".into(),
            snippet: "请在周五前确认预算表。\n谢谢".into(),
            date: 1_792_717_200,
            message_url: Some("mailbox://message/42".into()),
        }
    }

    async fn run(kind: &str, config: Value) -> Result<()> {
        send(&client(), &forwarder(kind, config), &payload()).await
    }

    #[test]
    fn title_format() {
        assert_eq!(title(&payload()), "[工作] 张三 <zhangsan@example.com>");
    }

    #[test]
    fn http_client_builds() {
        let _ = http_client();
    }

    #[tokio::test]
    async fn bark_with_key_and_server() {
        let (base, m) = mock(&[("/push", 200, r#"{"code":200,"message":"success"}"#)]).await;
        run("bark", json!({"server": format!("{base}/"), "key": "devKEY123", "sound": "minuet"})).await.unwrap();
        let r = m.take();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/push");
        let b = r.json();
        assert_eq!(b["device_key"], "devKEY123");
        assert_eq!(b["title"], "[工作] 张三 <zhangsan@example.com>");
        assert_eq!(b["subtitle"], "Q4 预算审批");
        assert_eq!(b["body"], "请在周五前确认预算表。\n谢谢");
        assert_eq!(b["group"], "工作");
        assert_eq!(b["sound"], "minuet");
        assert_eq!(b["url"], "mailbox://message/42");
        assert!(b.get("icon").is_none());
    }

    #[tokio::test]
    async fn bark_with_full_url_and_error() {
        let (base, m) = mock(&[("/push", 200, r#"{"code":200,"message":"success"}"#)]).await;
        run("bark", json!({"url": format!("{base}/KEYfromURL/这里改成你自己的推送内容")})).await.unwrap();
        assert_eq!(m.take().json()["device_key"], "KEYfromURL");

        let (base, _m) = mock(&[("/push", 400, r#"{"code":400,"message":"failed to get device token: device not found"}"#)]).await;
        let err = run("bark", json!({"server": base, "key": "nope"})).await.unwrap_err().to_string();
        assert!(err.contains("Bark") && err.contains("device not found"), "{err}");

        let (base, _m) = mock(&[("/push", 200, r#"{"code":500,"message":"push failed"}"#)]).await;
        let err = run("bark", json!({"server": base, "key": "k"})).await.unwrap_err().to_string();
        assert!(err.contains("push failed") && err.contains("500"), "{err}");
    }

    #[tokio::test]
    async fn serverchan_turbo_and_v3() {
        let (base, m) = mock(&[
            ("/SCT123abc.send", 200, r#"{"code":0,"message":"","data":{"pushid":"1"}}"#),
            ("/send/sctp12345tABCdef.send", 200, r#"{"code":0,"message":"SUCCESS"}"#),
            ("/SCTbad.send", 200, r#"{"code":40001,"message":"bad pushtoken"}"#),
        ])
        .await;
        run("serverchan", json!({"sendkey": "SCT123abc", "base": base})).await.unwrap();
        let r = m.take();
        assert_eq!(r.method, "POST");
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/x-www-form-urlencoded");
        let form = r.form();
        assert_eq!(form["title"], "[工作] 张三 <zhangsan@example.com>");
        assert!(form["desp"].contains("### Q4 预算审批"));
        assert!(form["desp"].contains("> 请在周五前确认预算表。\n> 谢谢"));

        run("serverchan", json!({"sendkey": "sctp12345tABCdef", "base": base})).await.unwrap();
        assert_eq!(m.take().path, "/send/sctp12345tABCdef.send");

        let err = run("serverchan", json!({"sendkey": "SCTbad", "base": base})).await.unwrap_err().to_string();
        assert!(err.contains("bad pushtoken") && err.contains("40001"), "{err}");
    }

    #[test]
    fn serverchan_endpoints() {
        assert_eq!(serverchan_url("SCT1xyz", None).unwrap(), "https://sctapi.ftqq.com/SCT1xyz.send");
        assert_eq!(serverchan_url("sctp987tKEY", None).unwrap(), "https://987.push.ft07.com/send/sctp987tKEY.send");
        assert!(serverchan_url("sctpXYZ", None).is_err());
    }

    #[tokio::test]
    async fn pushplus_json_and_error() {
        let (base, m) = mock(&[("/send", 200, r#"{"code":200,"msg":"请求成功","data":"abc"}"#)]).await;
        run("pushplus", json!({"token": "tok1", "topic": "mail", "base": base})).await.unwrap();
        let r = m.take();
        assert_eq!(r.path, "/send");
        let b = r.json();
        assert_eq!(b["token"], "tok1");
        assert_eq!(b["topic"], "mail");
        assert_eq!(b["template"], "markdown");
        assert_eq!(b["title"], "[工作] 张三 <zhangsan@example.com>");
        assert!(b["content"].as_str().unwrap().contains("[查看邮件](mailbox://message/42)"));

        let (base, _m) = mock(&[("/send", 200, r#"{"code":903,"msg":"无效的用户token","data":null}"#)]).await;
        let err = run("pushplus", json!({"token": "bad", "base": base})).await.unwrap_err().to_string();
        assert!(err.contains("无效的用户token") && err.contains("903"), "{err}");
    }

    #[tokio::test]
    async fn wecom_markdown_and_errcode() {
        let (base, m) = mock(&[
            ("/cgi-bin/webhook/send", 200, r#"{"errcode":0,"errmsg":"ok"}"#),
            ("/bad", 200, r#"{"errcode":93000,"errmsg":"invalid webhook url"}"#),
        ])
        .await;
        run("wecom", json!({"url": format!("{base}/cgi-bin/webhook/send?key=abc-123")})).await.unwrap();
        let r = m.take();
        assert_eq!(r.query["key"], "abc-123");
        let b = r.json();
        assert_eq!(b["msgtype"], "markdown");
        assert!(b["markdown"]["content"].as_str().unwrap().contains("Q4 预算审批"));

        let err = run("wecom", json!({"url": format!("{base}/bad")})).await.unwrap_err();
        assert!(matches!(err, Error::Other(_)));
        let err = err.to_string();
        assert!(err.contains("企业微信") && err.contains("invalid webhook url") && err.contains("93000"), "{err}");
    }

    #[tokio::test]
    async fn feishu_signed_text() {
        let (base, m) = mock(&[
            ("/open-apis/bot/v2/hook/abc", 200, r#"{"code":0,"msg":"success","data":{}}"#),
            ("/open-apis/bot/v2/hook/bad", 200, r#"{"code":19021,"msg":"sign match fail or timestamp is not within one hour from current time"}"#),
        ])
        .await;
        let url = format!("{base}/open-apis/bot/v2/hook/abc");
        run("feishu", json!({"url": url, "secret": "s3cr3t", "keyword": "邮件"})).await.unwrap();
        let b = m.take().json();
        assert_eq!(b["msg_type"], "text");
        let text = b["content"]["text"].as_str().unwrap();
        assert!(text.starts_with("邮件 [工作] 张三"), "{text}");
        assert!(text.contains("主题: Q4 预算审批"));
        let ts: i64 = b["timestamp"].as_str().unwrap().parse().unwrap();
        assert!((chrono::Utc::now().timestamp() - ts).abs() < 60);
        let mut mac = HmacSha256::new_from_slice(format!("{ts}\ns3cr3t").as_bytes()).unwrap();
        mac.update(b"");
        assert_eq!(b["sign"], BASE64.encode(mac.finalize().into_bytes()));

        // Without a secret no signature fields are sent.
        run("feishu", json!({"url": url})).await.unwrap();
        let b = m.take().json();
        assert!(b.get("sign").is_none() && b.get("timestamp").is_none());

        let err = run("feishu", json!({"url": format!("{base}/open-apis/bot/v2/hook/bad"), "secret": "x"}))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("飞书") && err.contains("sign match fail") && err.contains("19021"), "{err}");
    }

    #[tokio::test]
    async fn dingtalk_signed_markdown() {
        let (base, m) = mock(&[
            ("/robot/send", 200, r#"{"errcode":0,"errmsg":"ok"}"#),
            ("/robot/bad", 200, r#"{"errcode":310000,"errmsg":"keywords not in content"}"#),
        ])
        .await;
        let secret = "SECa1b2c3";
        run("dingtalk", json!({"url": format!("{base}/robot/send?access_token=tok"), "secret": secret, "keyword": "新邮件"}))
            .await
            .unwrap();
        let r = m.take();
        assert_eq!(r.path, "/robot/send");
        assert_eq!(r.query["access_token"], "tok");
        let ts: i64 = r.query["timestamp"].parse().unwrap();
        assert!((chrono::Utc::now().timestamp_millis() - ts).abs() < 60_000);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{ts}\n{secret}").as_bytes());
        // The query parser already percent-decoded the signature.
        assert_eq!(r.query["sign"], BASE64.encode(mac.finalize().into_bytes()));
        let b = r.json();
        assert_eq!(b["msgtype"], "markdown");
        assert_eq!(b["markdown"]["title"], "[工作] 张三 <zhangsan@example.com>");
        assert!(b["markdown"]["text"].as_str().unwrap().starts_with("新邮件 ### Q4 预算审批"));

        let err = run("dingtalk", json!({"url": format!("{base}/robot/bad?access_token=tok")})).await.unwrap_err().to_string();
        assert!(err.contains("钉钉") && err.contains("keywords not in content") && err.contains("310000"), "{err}");
    }

    #[test]
    fn dingtalk_sign_is_url_encoded() {
        let sign = dingtalk_sign(1_700_000_000_000, "SEC000");
        assert!(!sign.contains('+') && !sign.contains('/') && !sign.contains('='), "{sign}");
        let decoded = percent_encoding::percent_decode_str(&sign).decode_utf8().unwrap();
        assert!(BASE64.decode(decoded.as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn telegram_send_and_error() {
        let token = "123456:ABC-def";
        let (base, m) = mock(&[
            ("/bot123456:ABC-def/sendMessage", 200, r#"{"ok":true,"result":{"message_id":1}}"#),
            ("/botbad:tok/sendMessage", 400, r#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#),
        ])
        .await;
        run("telegram", json!({"token": token, "chat_id": -1001234, "api": base})).await.unwrap();
        let r = m.take();
        assert_eq!(r.path, "/bot123456:ABC-def/sendMessage");
        let b = r.json();
        assert_eq!(b["chat_id"], -1001234);
        assert_eq!(b["disable_web_page_preview"], true);
        assert!(b["text"].as_str().unwrap().starts_with("[工作] 张三 <zhangsan@example.com>\n主题: Q4 预算审批"));

        run("telegram", json!({"token": token, "chat_id": "@mychannel", "api": base})).await.unwrap();
        assert_eq!(m.take().json()["chat_id"], "@mychannel");

        let err = run("telegram", json!({"token": "bad:tok", "chat_id": "1", "api": base})).await.unwrap_err().to_string();
        assert!(err.contains("chat not found") && err.contains("400"), "{err}");
        assert!(!err.contains("bad:tok"), "token must not leak into errors: {err}");
    }

    #[tokio::test]
    async fn ntfy_json_publish() {
        let (base, m) = mock(&[]).await;
        run("ntfy", json!({"server": base, "topic": "mail-alerts", "token": "tk_123", "priority": "4"})).await.unwrap();
        let r = m.take();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/");
        assert_eq!(r.headers[header::AUTHORIZATION], "Bearer tk_123");
        let b = r.json();
        assert_eq!(b["topic"], "mail-alerts");
        assert_eq!(b["title"], "[工作] 张三 <zhangsan@example.com>");
        assert_eq!(b["message"], "Q4 预算审批\n\n请在周五前确认预算表。\n谢谢");
        assert_eq!(b["click"], "mailbox://message/42");
        assert_eq!(b["priority"], 4);

        // Topic taken from a pasted topic URL.
        run("ntfy", json!({"server": format!("{base}/pasted")})).await.unwrap();
        let r = m.take();
        assert_eq!(r.path, "/");
        assert_eq!(r.json()["topic"], "pasted");
        assert!(matches!(run("ntfy", json!({"server": base})).await, Err(Error::Invalid(_))));

        let (base, _m) = mock(&[("/", 403, r#"{"code":40301,"http":403,"error":"forbidden"}"#)]).await;
        let err = run("ntfy", json!({"server": base, "topic": "t"})).await.unwrap_err().to_string();
        assert!(err.contains("ntfy") && err.contains("forbidden") && err.contains("403"), "{err}");
    }

    #[tokio::test]
    async fn webhook_custom_method_and_headers() {
        let (base, m) = mock(&[("/fail", 500, "internal oops")]).await;
        run("webhook", json!({"url": format!("{base}/hook"), "method": "put", "headers": {"X-Token": "t1", "X-Num": 7}}))
            .await
            .unwrap();
        let r = m.take();
        assert_eq!(r.method, "PUT");
        assert_eq!(r.path, "/hook");
        assert_eq!(r.headers["x-token"], "t1");
        assert_eq!(r.headers["x-num"], "7");
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
        let b = r.json();
        assert_eq!(b["account_label"], "工作");
        assert_eq!(b["from"], "张三 <zhangsan@example.com>");
        assert_eq!(b["subject"], "Q4 预算审批");
        assert_eq!(b["date"], 1_792_717_200);
        assert_eq!(b["message_url"], "mailbox://message/42");

        run("webhook", json!({"url": format!("{base}/get?x=1"), "method": "GET", "headers": "Authorization: Bearer abc"}))
            .await
            .unwrap();
        let r = m.take();
        assert_eq!(r.method, "GET");
        assert_eq!(r.query["x"], "1");
        assert_eq!(r.query["subject"], "Q4 预算审批");
        assert_eq!(r.headers[header::AUTHORIZATION], "Bearer abc");
        assert!(r.body.is_empty());

        let err = run("webhook", json!({"url": format!("{base}/fail")})).await.unwrap_err().to_string();
        assert!(err.contains("HTTP 500") && err.contains("internal oops"), "{err}");
    }

    #[tokio::test]
    async fn invalid_configs() {
        assert!(matches!(run("carrier-pigeon", json!({})).await, Err(Error::Invalid(_))));
        assert!(matches!(run("", json!({})).await, Err(Error::Invalid(_))));
        assert!(matches!(run("bark", json!({})).await, Err(Error::Invalid(_))));
        assert!(matches!(run("telegram", json!({"token": "t"})).await, Err(Error::Invalid(_))));
        assert!(matches!(run("webhook", json!({"url": "not a url"})).await, Err(Error::Invalid(_))));
        assert!(matches!(run("webhook", json!({"url": "http://127.0.0.1:9/", "method": "BAD METHOD"})).await, Err(Error::Invalid(_))));
    }

    #[tokio::test]
    async fn network_errors_are_net() {
        // Port 9 (discard) on localhost is not listening.
        let err = run("wecom", json!({"url": "http://127.0.0.1:9/send?key=secret"})).await.unwrap_err();
        assert!(matches!(err, Error::Net(_)), "{err:?}");
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn truncation_is_char_safe() {
        assert_eq!(truncate_chars("你好世界", 2), "你好…");
        assert_eq!(truncate_chars("abc", 5), "abc");
        let t = truncate_bytes(&"中".repeat(2000), 4000);
        assert!(t.len() <= 4000 && t.ends_with('…'));
        assert_eq!(truncate_bytes("short", 10), "short");
    }
}

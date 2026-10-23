//! Parsing received mail (headers, bodies, attachments) and building outgoing mail.

pub mod build;

use crate::html;
use crate::model::{Attachment, EmailAddress, Unsubscribe};
use mail_parser::{Address, HeaderValue, Message, MessageParser, MimeHeaders, PartType};
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default)]
pub struct Headers {
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub subject: String,
    pub from: EmailAddress,
    pub sender: Option<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub reply_to: Vec<EmailAddress>,
    pub date: Option<i64>,
    pub list_id: Option<String>,
    pub unsubscribe: Option<Unsubscribe>,
    pub precedence: Option<String>,
    pub auto_submitted: bool,
    pub read_receipt_to: Option<String>,
    pub multipart_mixed: bool,
    pub priority_high: bool,
    /// Lower-cased names of all headers present (used for bulk-mail detection).
    pub header_names: Vec<String>,
    pub feedback_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Body {
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub snippet: String,
    pub search_text: String,
    pub calendar: Option<String>,
    pub encrypted: bool,
    pub signed: bool,
}

fn parser() -> MessageParser {
    MessageParser::default()
}

fn addr_list(a: Option<&Address>) -> Vec<EmailAddress> {
    let Some(a) = a else { return Vec::new() };
    a.iter()
        .filter_map(|x| x.address().map(|e| EmailAddress::new(x.name(), e)))
        .filter(|e| !e.email.is_empty())
        .collect()
}

fn ids(v: &HeaderValue) -> Vec<String> {
    match v {
        HeaderValue::Text(t) => t.split_whitespace().map(|s| s.trim_matches(['<', '>']).to_string()).filter(|s| !s.is_empty()).collect(),
        HeaderValue::TextList(l) => l.iter().map(|s| s.trim_matches(['<', '>']).to_string()).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    }
}

/// Decodes raw 8-bit header values sent without RFC 2047 encoding (common with old GBK mailers).
fn raw_header_fallback(raw: &[u8], name: &str) -> Option<String> {
    let end = find_header_end(raw);
    let head = &raw[..end];
    let needle = format!("\n{}:", name.to_ascii_lowercase());
    let lower: Vec<u8> = head.iter().map(|b| b.to_ascii_lowercase()).collect();
    let pos = if lower.starts_with(&needle.as_bytes()[1..]) {
        0
    } else {
        lower.windows(needle.len()).position(|w| w == needle.as_bytes())? + 1
    };
    let mut start = pos + name.len() + 1;
    let mut value = Vec::new();
    loop {
        let line_end = head[start..].iter().position(|&b| b == b'\n').map(|p| start + p).unwrap_or(head.len());
        value.extend_from_slice(&head[start..line_end]);
        if line_end + 1 < head.len() && (head[line_end + 1] == b' ' || head[line_end + 1] == b'\t') {
            start = line_end + 1;
        } else {
            break;
        }
    }
    let (text, _, had_errors) = encoding_rs::GB18030.decode(&value);
    if had_errors {
        return None;
    }
    Some(text.trim().replace(['\r', '\n'], ""))
}

fn find_header_end(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|p| p + 1))
        .unwrap_or(raw.len())
}

fn unsubscribe(msg: &Message) -> Option<Unsubscribe> {
    let mut u = Unsubscribe::default();
    let mut urls: Vec<String> = Vec::new();
    match msg.list_unsubscribe() {
        HeaderValue::Address(a) => {
            for x in a.iter() {
                if let Some(e) = x.address() {
                    urls.push(e.to_string());
                }
            }
        }
        HeaderValue::Text(t) => urls.extend(t.split(',').map(|s| s.trim().trim_matches(['<', '>']).to_string())),
        HeaderValue::TextList(l) => urls.extend(l.iter().map(|s| s.trim().trim_matches(['<', '>']).to_string())),
        _ => {}
    }
    for url in urls {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("http") && u.http.is_none() {
            u.http = Some(url);
        } else if lower.starts_with("mailto:") && u.mailto.is_none() {
            u.mailto = Some(url);
        }
    }
    if u.http.is_none() && u.mailto.is_none() {
        return None;
    }
    u.one_click = msg
        .header_raw("List-Unsubscribe-Post")
        .map(|v| v.to_ascii_lowercase().contains("one-click"))
        .unwrap_or(false);
    Some(u)
}

fn text_of(v: &HeaderValue) -> Option<String> {
    match v {
        HeaderValue::Text(t) => Some(t.to_string()),
        HeaderValue::TextList(l) => Some(l.join(" ")),
        HeaderValue::Address(a) => a.first().and_then(|x| x.address().map(String::from)),
        _ => None,
    }
}

pub fn parse_headers(raw: &[u8]) -> Headers {
    let Some(msg) = parser().parse_headers(raw) else {
        return Headers::default();
    };
    headers_of(&msg, raw)
}

fn headers_of(msg: &Message, raw: &[u8]) -> Headers {
    let mut subject = msg.subject().unwrap_or("").to_string();
    if subject.contains('\u{FFFD}') {
        if let Some(fixed) = raw_header_fallback(raw, "Subject") {
            subject = fixed;
        }
    }
    let mut from = addr_list(msg.from()).into_iter().next().unwrap_or_default();
    if from.name.as_deref().is_some_and(|n| n.contains('\u{FFFD}')) {
        if let Some(fixed) = raw_header_fallback(raw, "From") {
            if let Some((name, _)) = fixed.rsplit_once('<') {
                let n = name.trim().trim_matches('"').trim();
                if !n.is_empty() {
                    from.name = Some(n.to_string());
                }
            }
        }
    }
    let header_names: Vec<String> = msg.headers().iter().map(|h| h.name().to_ascii_lowercase()).collect();
    let content_type = msg.root_part().content_type();
    Headers {
        message_id: msg.message_id().map(|s| s.trim_matches(['<', '>']).to_string()),
        in_reply_to: ids(msg.in_reply_to()).into_iter().next(),
        references: ids(msg.references()),
        subject: subject.trim().to_string(),
        from,
        sender: addr_list(msg.sender()).into_iter().next(),
        to: addr_list(msg.to()),
        cc: addr_list(msg.cc()),
        bcc: addr_list(msg.bcc()),
        reply_to: addr_list(msg.reply_to()),
        date: msg.date().map(|d| d.to_timestamp()),
        list_id: text_of(msg.list_id()),
        unsubscribe: unsubscribe(msg),
        precedence: msg.header_raw("Precedence").map(|s| s.trim().to_ascii_lowercase()),
        auto_submitted: msg.header_raw("Auto-Submitted").map(|s| !s.trim().eq_ignore_ascii_case("no")).unwrap_or(false),
        read_receipt_to: msg
            .header_raw("Disposition-Notification-To")
            .and_then(|v| extract_email(v)),
        multipart_mixed: content_type
            .map(|c| c.ctype().eq_ignore_ascii_case("multipart") && c.subtype().is_some_and(|s| s.eq_ignore_ascii_case("mixed")))
            .unwrap_or(false),
        priority_high: msg.header_raw("X-Priority").map(|p| p.trim().starts_with('1') || p.trim().starts_with('2')).unwrap_or(false)
            || msg.header_raw("Importance").map(|p| p.trim().eq_ignore_ascii_case("high")).unwrap_or(false),
        header_names,
        feedback_id: msg.header_raw("Feedback-ID").map(|s| s.trim().to_string()),
    }
}

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());

pub fn extract_email(s: &str) -> Option<String> {
    EMAIL_RE.find(s).map(|m| m.as_str().to_string())
}

static QUOTE_MARKERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^(-{2,}\s*(Original Message|原始邮件|Forwarded message|转发的邮件)\s*-{2,}|On .{5,80} wrote:|在 .{2,60}写道[:：]|发件人[:：]|From: .+@.+|-{5,}\s*$|_{10,})",
    )
    .unwrap()
});
static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// First ~200 characters of the new text of a message (quoted history removed).
pub fn snippet(text: &str) -> String {
    let cut = QUOTE_MARKERS.find(text).map(|m| &text[..m.start()]).unwrap_or(text);
    let lines: Vec<&str> = cut.lines().filter(|l| !l.trim_start().starts_with('>')).collect();
    let joined = WS.replace_all(&lines.join(" "), " ").trim().to_string();
    let base = if joined.is_empty() { WS.replace_all(text, " ").trim().to_string() } else { joined };
    base.chars().take(200).collect()
}

fn part_mime(part: &mail_parser::MessagePart) -> String {
    part.content_type()
        .map(|c| match c.subtype() {
            Some(s) => format!("{}/{}", c.ctype(), s),
            None => c.ctype().to_string(),
        })
        .unwrap_or_else(|| "application/octet-stream".into())
        .to_ascii_lowercase()
}

fn default_filename(mime: &str, index: usize) -> String {
    let ext = match mime {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "application/pdf" => "pdf",
        "text/calendar" => "ics",
        "message/rfc822" => "eml",
        "text/plain" => "txt",
        "text/html" => "html",
        _ => "bin",
    };
    format!("附件{}.{ext}", index + 1)
}

pub fn parse_message(raw: &[u8]) -> Option<Message<'_>> {
    parser().parse(raw)
}

/// Parses a complete message: headers plus decoded bodies and attachment metadata.
pub fn parse_full(raw: &[u8]) -> (Headers, Body) {
    let Some(msg) = parse_message(raw) else {
        let text = String::from_utf8_lossy(raw).to_string();
        return (Headers::default(), Body { snippet: snippet(&text), search_text: text.clone(), text: Some(text), ..Default::default() });
    };
    let headers = headers_of(&msg, raw);
    let body = body_of(&msg);
    (headers, body)
}

fn body_of(msg: &Message) -> Body {
    let mut body = Body::default();
    let mut texts = Vec::new();
    for id in &msg.text_body {
        if let Some(p) = msg.parts.get(*id as usize) {
            if let PartType::Text(t) = &p.body {
                texts.push(t.to_string());
            }
        }
    }
    let mut htmls = Vec::new();
    for id in &msg.html_body {
        if let Some(p) = msg.parts.get(*id as usize) {
            if let PartType::Html(h) = &p.body {
                htmls.push(h.to_string());
            }
        }
    }
    if !htmls.is_empty() {
        body.html = Some(htmls.join("<hr>"));
    }
    if !texts.is_empty() {
        body.text = Some(texts.join("\n\n"));
    }
    let html_text = body.html.as_deref().map(html::html_to_text);
    let plain = body.text.clone().or(html_text.clone()).unwrap_or_default();

    let html_src = body.html.clone().unwrap_or_default();
    for (n, id) in msg.attachments.iter().enumerate() {
        let Some(p) = msg.parts.get(*id as usize) else { continue };
        let mime = part_mime(p);
        let content_id = p.content_id().map(|c| c.trim_matches(['<', '>']).to_string());
        let referenced = content_id.as_ref().map(|c| html_src.contains(&format!("cid:{c}"))).unwrap_or(false);
        let inline = referenced || (p.content_disposition().map(|d| d.is_inline()).unwrap_or(false) && mime.starts_with("image/"));
        if mime == "text/calendar" && body.calendar.is_none() {
            body.calendar = p.text_contents().map(String::from).or_else(|| Some(String::from_utf8_lossy(p.contents()).to_string()));
        }
        let filename = p
            .attachment_name()
            .map(String::from)
            .or_else(|| {
                if let PartType::Message(m) = &p.body {
                    m.subject().map(|s| format!("{s}.eml"))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| default_filename(&mime, n));
        body.attachments.push(Attachment {
            id: *id as i64,
            filename,
            mime_type: mime,
            size: p.contents().len() as i64,
            content_id,
            inline,
        });
    }
    // Invitations sent as an alternative part, not as an attachment.
    if body.calendar.is_none() {
        for p in &msg.parts {
            if part_mime(p) == "text/calendar" {
                body.calendar = p.text_contents().map(String::from);
                break;
            }
        }
    }
    let root = part_mime(msg.root_part());
    body.encrypted = root == "multipart/encrypted" || root == "application/pkcs7-mime" || root == "application/x-pkcs7-mime";
    body.signed = root == "multipart/signed";
    body.snippet = snippet(&plain);
    let names: Vec<&str> = body.attachments.iter().filter(|a| !a.inline).map(|a| a.filename.as_str()).collect();
    body.search_text = format!("{plain}\n{}", names.join(" "));
    body
}

/// Decoded bytes of attachment part `index` (as reported in [`Attachment::id`]).
pub fn part_bytes(raw: &[u8], index: usize) -> Option<(String, String, Vec<u8>)> {
    let msg = parse_message(raw)?;
    let p = msg.parts.get(index)?;
    let mime = part_mime(p);
    let data = match &p.body {
        PartType::Message(m) => m.raw_message().to_vec(),
        _ => p.contents().to_vec(),
    };
    let name = p.attachment_name().map(String::from).unwrap_or_else(|| default_filename(&mime, index));
    Some((name, mime, data))
}

/// Decoded bytes of the part with the given Content-ID.
pub fn cid_bytes(raw: &[u8], cid: &str) -> Option<(String, Vec<u8>)> {
    let msg = parse_message(raw)?;
    let wanted = cid.trim_matches(['<', '>']);
    for p in &msg.parts {
        if p.content_id().map(|c| c.trim_matches(['<', '>']) == wanted).unwrap_or(false) {
            return Some((part_mime(p), p.contents().to_vec()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTI: &str = "From: =?GB2312?B?1cXI/Q==?= <zhangsan@corp.cn>\r\n\
To: \"Li Si\" <lisi@corp.cn>, wang@x.com\r\n\
Cc: boss@corp.cn\r\n\
Subject: =?UTF-8?B?5pys5ZGo5oql5Lu35Y2V?=\r\n\
Message-ID: <abc123@corp.cn>\r\n\
In-Reply-To: <parent@corp.cn>\r\n\
References: <root@corp.cn> <parent@corp.cn>\r\n\
Date: Thu, 22 Oct 2026 10:00:00 +0800\r\n\
List-Unsubscribe: <https://shop.example/unsub?u=1>, <mailto:unsub@shop.example>\r\n\
List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
Disposition-Notification-To: zhangsan@corp.cn\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"B1\"\r\n\r\n\
--B1\r\n\
Content-Type: multipart/related; boundary=\"B2\"\r\n\r\n\
--B2\r\n\
Content-Type: text/html; charset=utf-8\r\n\r\n\
<p>请查收<b>报价单</b></p><img src=\"cid:logo@corp\">\r\n\
--B2\r\n\
Content-Type: image/png\r\n\
Content-ID: <logo@corp>\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
iVBORw0KGgo=\r\n\
--B2--\r\n\
--B1\r\n\
Content-Type: application/pdf; name=\"=?UTF-8?B?5oql5Lu35Y2VLnBkZg==?=\"\r\n\
Content-Disposition: attachment; filename=\"=?UTF-8?B?5oql5Lu35Y2VLnBkZg==?=\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
JVBERi0xLjQK\r\n\
--B1--\r\n";

    #[test]
    fn parses_headers_and_body() {
        let (h, b) = parse_full(MULTI.as_bytes());
        assert_eq!(h.subject, "本周报价单");
        assert_eq!(h.from.name.as_deref(), Some("张三"));
        assert_eq!(h.from.email, "zhangsan@corp.cn");
        assert_eq!(h.to.len(), 2);
        assert_eq!(h.cc[0].email, "boss@corp.cn");
        assert_eq!(h.message_id.as_deref(), Some("abc123@corp.cn"));
        assert_eq!(h.in_reply_to.as_deref(), Some("parent@corp.cn"));
        assert_eq!(h.references, vec!["root@corp.cn", "parent@corp.cn"]);
        assert_eq!(h.date, Some(1792634400));
        let u = h.unsubscribe.unwrap();
        assert!(u.one_click);
        assert_eq!(u.http.as_deref(), Some("https://shop.example/unsub?u=1"));
        assert_eq!(h.read_receipt_to.as_deref(), Some("zhangsan@corp.cn"));
        assert!(b.html.as_deref().unwrap().contains("报价单"));
        assert_eq!(b.attachments.len(), 2);
        let pdf = b.attachments.iter().find(|a| a.mime_type == "application/pdf").unwrap();
        assert_eq!(pdf.filename, "报价单.pdf");
        assert!(!pdf.inline);
        let logo = b.attachments.iter().find(|a| a.content_id.is_some()).unwrap();
        assert!(logo.inline);
        assert_eq!(b.snippet, "请查收报价单");
        let (name, mime, bytes) = part_bytes(MULTI.as_bytes(), pdf.id as usize).unwrap();
        assert_eq!((name.as_str(), mime.as_str()), ("报价单.pdf", "application/pdf"));
        assert!(bytes.starts_with(b"%PDF"));
        let (m, png) = cid_bytes(MULTI.as_bytes(), "logo@corp").unwrap();
        assert_eq!(m, "image/png");
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']));
    }

    #[test]
    fn raw_gbk_subject_fallback() {
        let mut raw = b"From: a@b.com\r\nSubject: ".to_vec();
        let (gbk, _, _) = encoding_rs::GBK.encode("会议通知");
        raw.extend_from_slice(&gbk);
        raw.extend_from_slice(b"\r\nContent-Type: text/plain; charset=gbk\r\n\r\n");
        let (body, _, _) = encoding_rs::GBK.encode("明天开会");
        raw.extend_from_slice(&body);
        let (h, b) = parse_full(&raw);
        assert_eq!(h.subject, "会议通知");
        assert_eq!(b.text.as_deref().map(str::trim), Some("明天开会"));
    }

    #[test]
    fn snippet_strips_quotes() {
        let s = snippet("好的，没问题。\n\n在 2026年10月22日 周四 10:00，张三 写道：\n> 可以吗？");
        assert_eq!(s, "好的，没问题。");
        let s = snippet("Thanks!\n\n------------------ 原始邮件 ------------------\n发件人: x");
        assert_eq!(s, "Thanks!");
    }
}

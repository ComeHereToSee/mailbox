//! Building RFC 5322 messages for sending.

use crate::error::{Error, Result};
use crate::model::EmailAddress;
use base64::Engine;
use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::content_type::ContentType;
use mail_builder::headers::raw::Raw;
use mail_builder::mime::MimePart;
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default)]
pub struct OutAttachment {
    pub filename: String,
    pub mime: String,
    pub data: Vec<u8>,
    /// Set for inline images referenced from the HTML as `cid:`.
    pub content_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Outgoing {
    pub from: EmailAddress,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub html: Option<String>,
    pub text: String,
    pub attachments: Vec<OutAttachment>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub message_id: String,
    pub date: i64,
    pub read_receipt: bool,
    pub priority_high: bool,
    /// iMIP part: (method, ics text).
    pub calendar: Option<(String, String)>,
    pub extra_headers: Vec<(String, String)>,
}

pub fn new_message_id(from: &str) -> String {
    let domain = from.rsplit_once('@').map(|(_, d)| d).filter(|d| !d.is_empty()).unwrap_or("mailbox.local");
    format!("{}@{}", uuid::Uuid::new_v4().simple(), domain)
}

fn addr(a: &EmailAddress) -> Address<'_> {
    match &a.name {
        Some(n) if !n.is_empty() => Address::new_address(Some(n.as_str()), a.email.as_str()),
        _ => Address::new_address(None::<&str>, a.email.as_str()),
    }
}

fn addr_list(v: &[EmailAddress]) -> Address<'_> {
    Address::new_list(v.iter().map(addr).collect())
}

/// Serializes the message. `include_bcc` keeps the Bcc header (for the Sent copy only).
pub fn build(o: &Outgoing, include_bcc: bool) -> Result<Vec<u8>> {
    if o.from.email.is_empty() {
        return Err(Error::Invalid("缺少发件人".into()));
    }
    let mut b = MessageBuilder::new()
        .from(addr(&o.from))
        .subject(o.subject.as_str())
        .message_id(o.message_id.as_str())
        .date(o.date)
        .header("MIME-Version", Raw::new("1.0"))
        .header("X-Mailer", Raw::new(concat!("Mailbox/", env!("CARGO_PKG_VERSION"))));
    if !o.to.is_empty() {
        b = b.to(addr_list(&o.to));
    }
    if !o.cc.is_empty() {
        b = b.cc(addr_list(&o.cc));
    }
    if include_bcc && !o.bcc.is_empty() {
        b = b.bcc(addr_list(&o.bcc));
    }
    if let Some(r) = o.reply_to.as_deref().filter(|r| !r.trim().is_empty()) {
        b = b.reply_to(Address::new_address(None::<&str>, r.trim()));
    }
    if let Some(irt) = &o.in_reply_to {
        b = b.in_reply_to(irt.as_str());
    }
    if !o.references.is_empty() {
        b = b.references(o.references.iter().map(String::as_str).collect::<Vec<_>>());
    }
    if o.read_receipt {
        b = b.header("Disposition-Notification-To", Raw::new(o.from.email.as_str()));
    }
    if o.priority_high {
        b = b.header("X-Priority", Raw::new("1 (Highest)")).header("Importance", Raw::new("High"));
    }
    for (k, v) in &o.extra_headers {
        b = b.header(k.as_str(), Raw::new(v.as_str()));
    }

    let mut alternative = vec![MimePart::new(ContentType::new("text/plain").attribute("charset", "utf-8"), o.text.as_str())];
    if let Some(html) = &o.html {
        alternative.push(MimePart::new(ContentType::new("text/html").attribute("charset", "utf-8"), html.as_str()));
    }
    if let Some((method, ics)) = &o.calendar {
        alternative.push(MimePart::new(
            ContentType::new("text/calendar").attribute("method", method.as_str()).attribute("charset", "utf-8"),
            ics.as_str(),
        ));
    }
    let mut body = if alternative.len() == 1 { alternative.pop().unwrap() } else { MimePart::new("multipart/alternative", alternative) };

    let inline: Vec<&OutAttachment> = o.attachments.iter().filter(|a| a.content_id.is_some()).collect();
    if !inline.is_empty() {
        let mut parts = vec![body];
        for a in inline {
            parts.push(
                MimePart::new(a.mime.as_str(), a.data.as_slice())
                    .inline()
                    .cid(a.content_id.as_deref().unwrap_or_default()),
            );
        }
        body = MimePart::new("multipart/related", parts);
    }
    let files: Vec<&OutAttachment> = o.attachments.iter().filter(|a| a.content_id.is_none()).collect();
    if !files.is_empty() || o.calendar.as_ref().is_some_and(|(m, _)| m == "REQUEST") {
        let mut parts = vec![body];
        for a in files {
            parts.push(MimePart::new(a.mime.as_str(), a.data.as_slice()).attachment(a.filename.as_str()));
        }
        if let Some((method, ics)) = o.calendar.as_ref().filter(|(m, _)| m == "REQUEST") {
            parts.push(
                MimePart::new(ContentType::new("application/ics").attribute("method", method.as_str()), ics.as_bytes())
                    .attachment("invite.ics"),
            );
        }
        body = MimePart::new("multipart/mixed", parts);
    }
    b = b.body(body);
    b.write_to_vec().map_err(Error::Io)
}

static DATA_IMG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)src\s*=\s*["']data:(image/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=\s]+)["']"#).unwrap());

/// Replaces `data:` images (pasted into the editor) with `cid:` references and returns the parts.
pub fn extract_data_images(html: &str, domain: &str) -> (String, Vec<OutAttachment>) {
    let mut parts = Vec::new();
    let out = DATA_IMG.replace_all(html, |caps: &regex::Captures| {
        let mime = caps[1].to_ascii_lowercase();
        let b64: String = caps[2].chars().filter(|c| !c.is_whitespace()).collect();
        match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(data) => {
                let cid = format!("img{}.{}@{}", parts.len() + 1, &uuid::Uuid::new_v4().simple().to_string()[..8], domain);
                let ext = mime.rsplit('/').next().unwrap_or("png").replace("jpeg", "jpg");
                parts.push(OutAttachment { filename: format!("image{}.{ext}", parts.len() + 1), mime, data, content_id: Some(cid.clone()) });
                format!("src=\"cid:{cid}\"")
            }
            Err(_) => caps[0].to_string(),
        }
    });
    (out.into_owned(), parts)
}

pub fn guess_mime(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "zip" => "application/zip",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        "gz" | "tgz" => "application/gzip",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pages" => "application/vnd.apple.pages",
        "numbers" => "application/vnd.apple.numbers",
        "key" => "application/vnd.apple.keynote",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "eml" => "message/rfc822",
        "ics" => "text/calendar",
        "json" => "application/json",
        "xml" => "application/xml",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_back() {
        let (html, inline) = extract_data_images(r#"<p>你好</p><img src="data:image/png;base64,iVBORw0KGgo=">"#, "x.com");
        assert_eq!(inline.len(), 1);
        assert!(html.contains("cid:img1."));
        let mut atts = inline;
        atts.push(OutAttachment { filename: "合同.pdf".into(), mime: "application/pdf".into(), data: b"%PDF-1.4".to_vec(), content_id: None });
        let o = Outgoing {
            from: EmailAddress::new(Some("张三"), "zhangsan@x.com"),
            to: vec![EmailAddress::new(Some("李四"), "lisi@y.com")],
            bcc: vec![EmailAddress::new(None, "secret@z.com")],
            subject: "合同 v2".into(),
            html: Some(html),
            text: "你好".into(),
            attachments: atts,
            in_reply_to: Some("p@y.com".into()),
            references: vec!["r@y.com".into(), "p@y.com".into()],
            message_id: new_message_id("zhangsan@x.com"),
            date: 1_792_634_400,
            read_receipt: true,
            ..Default::default()
        };
        let raw = build(&o, false).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(!s.contains("secret@z.com"));
        assert!(s.contains("multipart/related"));
        let (h, b) = crate::mime::parse_full(&raw);
        assert_eq!(h.subject, "合同 v2");
        assert_eq!(h.from.name.as_deref(), Some("张三"));
        assert_eq!(h.in_reply_to.as_deref(), Some("p@y.com"));
        assert_eq!(h.references.len(), 2);
        assert_eq!(h.read_receipt_to.as_deref(), Some("zhangsan@x.com"));
        assert!(b.html.unwrap().contains("你好"));
        assert_eq!(b.attachments.iter().filter(|a| !a.inline).count(), 1);
        assert_eq!(b.attachments.iter().find(|a| !a.inline).unwrap().filename, "合同.pdf");
        let with_bcc = String::from_utf8_lossy(&build(&o, true).unwrap()).to_string();
        assert!(with_bcc.contains("secret@z.com"));
    }

    #[test]
    fn calendar_reply_part() {
        let o = Outgoing {
            from: EmailAddress::new(None, "me@x.com"),
            to: vec![EmailAddress::new(None, "org@y.com")],
            subject: "已接受: 会议".into(),
            text: "已接受".into(),
            calendar: Some(("REPLY".into(), "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nEND:VCALENDAR\r\n".into())),
            message_id: "a@x.com".into(),
            date: 0,
            ..Default::default()
        };
        let s = String::from_utf8(build(&o, false).unwrap()).unwrap();
        assert!(s.contains("text/calendar"));
        assert!(s.to_lowercase().contains("method=\"reply\"") || s.to_lowercase().contains("method=reply"));
    }
}

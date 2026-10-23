//! HTML helpers: sanitizing mail HTML for display, HTML → text, and phishing hints.

use lol_html::{RewriteStrSettings, element, rewrite_str};
use regex::Regex;
use std::cell::{Cell, RefCell};
use std::sync::LazyLock;

#[derive(Debug, Default, Clone)]
pub struct Sanitized {
    pub html: String,
    pub has_remote: bool,
    pub trackers: i64,
    pub warnings: Vec<String>,
}

const TRACKER_HOSTS: &[&str] = &[
    "mailtrack.io", "list-manage.com/track", "sendgrid.net/wf/open", "mandrillapp.com/track", "hubspotemail.net",
    "mailchimp.com/track", "open.convertkit", "pixel.", "/open.php", "/track/open", "/o.gif", "/pixel", "trk.",
    "emltrk.com", "mixmax.com/api/track", "yesware.com/t/", "bananatag.com", "streak.com", "superhuman.com",
    "getnotify.com", "mailstat.us", "edm.", "/wf/open", "e.customeriomail.com", "click.email.", "t.e2ma.net",
];

fn is_remote(url: &str) -> bool {
    let u = url.trim_start().to_ascii_lowercase();
    u.starts_with("http://") || u.starts_with("https://") || u.starts_with("//")
}

fn looks_like_tracker(src: &str, width: Option<String>, height: Option<String>) -> bool {
    let tiny = |v: Option<String>| {
        v.map(|s| s.trim().trim_end_matches("px").parse::<f32>().map(|n| n <= 2.0).unwrap_or(false)).unwrap_or(false)
    };
    if tiny(width) && tiny(height) {
        return true;
    }
    let lower = src.to_ascii_lowercase();
    TRACKER_HOSTS.iter().any(|h| lower.contains(h))
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url.trim()).ok().and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_lowercase()))
}

static URL_IN_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?\s*$").unwrap());
static CSS_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)url\(\s*['"]?\s*(https?:)?//"#).unwrap());

/// Makes mail HTML safe to show in a WebView with JavaScript disabled:
/// drops active content and event handlers, rewrites `cid:` to `mailbox-cid://<message>/<cid>`,
/// removes tracking pixels and reports whether remote resources remain.
pub fn sanitize(html: &str, message_id: i64, block_trackers: bool) -> Sanitized {
    let has_remote = Cell::new(false);
    let trackers = Cell::new(0i64);
    let warnings: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let current_href: RefCell<Option<String>> = RefCell::new(None);

    let settings = RewriteStrSettings::new()
        .append_element_content_handler(element!(
            "script, noscript, iframe, frame, frameset, object, embed, applet, base, link, meta[http-equiv], form, input[type=password]",
            |el| {
                el.remove();
                Ok(())
            }
        ))
        .append_element_content_handler(element!("*", |el| {
            let names: Vec<String> = el.attributes().iter().map(|a| a.name()).collect();
            for name in names {
                let lower = name.to_ascii_lowercase();
                if lower.starts_with("on") || lower == "srcdoc" || lower == "formaction" {
                    el.remove_attribute(&name);
                    continue;
                }
                if matches!(lower.as_str(), "href" | "src" | "action" | "background" | "poster") {
                    if let Some(v) = el.get_attribute(&name) {
                        let t = v.trim_start().to_ascii_lowercase();
                        if t.starts_with("javascript:") || t.starts_with("vbscript:") || t.starts_with("data:text/html") {
                            el.remove_attribute(&name);
                        } else if lower != "href" && is_remote(&v) {
                            has_remote.set(true);
                        }
                    }
                }
                if lower == "style" {
                    if let Some(v) = el.get_attribute(&name) {
                        if CSS_URL.is_match(&v) {
                            has_remote.set(true);
                        }
                        if v.to_ascii_lowercase().contains("expression(") {
                            el.remove_attribute(&name);
                        }
                    }
                }
            }
            Ok(())
        }))
        .append_element_content_handler(element!("img", |el| {
            let src = el.get_attribute("src").unwrap_or_default();
            if let Some(cid) = src.trim().strip_prefix("cid:") {
                let enc = percent_encoding::utf8_percent_encode(cid, percent_encoding::NON_ALPHANUMERIC).to_string();
                el.set_attribute("src", &format!("mailbox-cid://{message_id}/{enc}"))?;
            } else if is_remote(&src) && looks_like_tracker(&src, el.get_attribute("width"), el.get_attribute("height")) {
                trackers.set(trackers.get() + 1);
                if block_trackers {
                    el.remove();
                }
            }
            Ok(())
        }))
        .append_element_content_handler(element!("a[href]", |el| {
            *current_href.borrow_mut() = el.get_attribute("href");
            Ok(())
        }))
        .append_element_content_handler(lol_html::text!("a[href]", |t| {
            let text = t.as_str();
            if let Some(href) = current_href.borrow().as_ref() {
                if URL_IN_TEXT.is_match(text) && is_remote(href) {
                    let shown = if text.trim().contains("://") { text.trim().to_string() } else { format!("http://{}", text.trim()) };
                    if let (Some(a), Some(b)) = (host_of(&shown), host_of(href)) {
                        if a != b && !b.ends_with(&format!(".{a}")) && !a.ends_with(&format!(".{b}")) {
                            let w = format!("链接显示为 {a}，实际指向 {b}");
                            let mut ws = warnings.borrow_mut();
                            if !ws.contains(&w) && ws.len() < 5 {
                                ws.push(w);
                            }
                        }
                    }
                }
            }
            Ok(())
        }));

    let out = rewrite_str(html, settings).unwrap_or_else(|_| escape_text(&html_to_text(html)));
    // Remote stylesheets referenced from <style> blocks.
    let has_remote = has_remote.get() || STYLE_IMPORT.is_match(&out);
    Sanitized { html: out, has_remote, trackers: trackers.get(), warnings: warnings.into_inner() }
}

static STYLE_IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)@import\s+(url\()?\s*['"]?(https?:)?//"#).unwrap());

pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(https?://[^\s<>"'）)】]+)"#).unwrap());

/// Turns plain text into simple HTML with clickable links and preserved line breaks.
pub fn text_to_html(text: &str) -> String {
    let escaped = escape_text(text);
    let linked = URL_RE.replace_all(&escaped, r#"<a href="$1">$1</a>"#);
    let mut out = String::from("<div style=\"white-space: pre-wrap; word-wrap: break-word;\">");
    for line in linked.split('\n') {
        if line.starts_with("&gt;") {
            out.push_str("<span style=\"color:#888\">");
            out.push_str(line.trim_end_matches('\r'));
            out.push_str("</span>\n");
        } else {
            out.push_str(line.trim_end_matches('\r'));
            out.push('\n');
        }
    }
    out.push_str("</div>");
    out
}

static DROP_BLOCKS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<(head|style|script|title|noscript)\b.*?</\s*(head|style|script|title|noscript)\s*>").unwrap());
static COMMENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").unwrap());
static BREAKS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<\s*(br|/p|/div|/tr|/h[1-6]|/blockquote|/table|hr|/ul|/ol|p|div)\b[^>]*>").unwrap());
static LIST_ITEM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<\s*li\b[^>]*>").unwrap());
static CELL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<\s*/t[dh]\s*>").unwrap());
static TAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<[^>]*>").unwrap());
static BLANK_LINES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n[ \t\u{a0}]*(\n[ \t\u{a0}]*){2,}").unwrap());
static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t\u{a0}]{2,}").unwrap());

pub fn html_to_text(html: &str) -> String {
    let s = DROP_BLOCKS.replace_all(html, "");
    let s = COMMENTS.replace_all(&s, "");
    let s = LIST_ITEM.replace_all(&s, "\n• ");
    let s = BREAKS.replace_all(&s, "\n");
    let s = CELL.replace_all(&s, " ");
    let s = TAGS.replace_all(&s, "");
    let s = decode_entities(&s);
    let s = SPACES.replace_all(&s, " ");
    let s: String = s.lines().map(|l| l.trim_end()).collect::<Vec<_>>().join("\n");
    BLANK_LINES.replace_all(&s, "\n\n").trim().to_string()
}

pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let end = rest[1..].find(|c: char| c == ';' || c == '&' || c.is_whitespace()).map(|i| i + 1);
        match end {
            Some(e) if rest.as_bytes().get(e) == Some(&b';') && e <= 12 => {
                let ent = &rest[1..e];
                let decoded = if let Some(num) = ent.strip_prefix('#') {
                    let code = if let Some(hex) = num.strip_prefix(['x', 'X']) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        num.parse().ok()
                    };
                    code.and_then(char::from_u32).map(|c| c.to_string())
                } else {
                    named_entity(ent).map(String::from)
                };
                match decoded {
                    Some(d) => {
                        out.push_str(&d);
                        rest = &rest[e + 1..];
                    }
                    None => {
                        out.push('&');
                        rest = &rest[1..];
                    }
                }
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn named_entity(name: &str) -> Option<&'static str> {
    Some(match name {
        "nbsp" => " ",
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "copy" => "©",
        "reg" => "®",
        "trade" => "™",
        "hellip" => "…",
        "mdash" => "—",
        "ndash" => "–",
        "lsquo" => "‘",
        "rsquo" => "’",
        "ldquo" => "“",
        "rdquo" => "”",
        "middot" => "·",
        "bull" => "•",
        "yen" => "¥",
        "euro" => "€",
        "pound" => "£",
        "times" => "×",
        "divide" => "÷",
        "laquo" => "«",
        "raquo" => "»",
        "zwnj" => "",
        "zwj" => "",
        "shy" => "",
        "ensp" | "emsp" | "thinsp" => " ",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_active_content() {
        let s = sanitize(
            r#"<html><head><script>alert(1)</script><link rel=stylesheet href="http://x/a.css"></head>
            <body onload="evil()"><a href="javascript:alert(1)">x</a><img src="cid:logo@x"><iframe src="http://x"></iframe>
            <img src="https://tracker.mailtrack.io/open?x" width="1" height="1"><img src="https://cdn.shop.com/a.png"></body></html>"#,
            42,
            true,
        );
        assert!(!s.html.contains("<script"));
        assert!(!s.html.contains("onload"));
        assert!(!s.html.contains("javascript:"));
        assert!(!s.html.contains("<iframe"));
        assert!(!s.html.contains("<link"));
        assert!(s.html.contains("mailbox-cid://42/logo%40x"));
        assert!(!s.html.contains("mailtrack"));
        assert_eq!(s.trackers, 1);
        assert!(s.has_remote);
    }

    #[test]
    fn detects_mismatched_links() {
        let s = sanitize(r#"<a href="https://evil.example.ru/login">https://www.icbc.com.cn</a> <a href="https://a.b.com/x">b.com</a>"#, 1, true);
        assert_eq!(s.warnings.len(), 1);
        assert!(s.warnings[0].contains("icbc.com.cn"));
    }

    #[test]
    fn converts_html_to_text() {
        let t = html_to_text("<html><head><style>p{}</style></head><body><p>你好&nbsp;世界</p><ul><li>一</li><li>二</li></ul>&lt;ok&gt; &#20013;&#x6587;</body></html>");
        assert_eq!(t, "你好 世界\n\n• 一\n• 二\n<ok> 中文");
    }

    #[test]
    fn text_to_html_links() {
        let h = text_to_html("见 https://example.com/a?b=1\n> quoted");
        assert!(h.contains(r#"<a href="https://example.com/a?b=1">"#));
        assert!(h.contains("color:#888"));
    }
}

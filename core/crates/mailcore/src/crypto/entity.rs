//! Raw MIME entity handling for the crypto layer.
//!
//! Signatures cover exact bytes (RFC 3156 §5, RFC 8551 §3.1.1), so this works on the raw message
//! instead of a decoded tree: header blocks, `Content-Type` parameters, multipart bodies split
//! precisely at their delimiters, and transfer decoding of leaf bodies.

use base64::Engine;
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use rand::Rng;
use std::borrow::Cow;

#[derive(Debug, Clone, Default)]
pub struct ContentType {
    /// Lower-cased `type/subtype`; `text/plain` when the header is missing.
    pub mime: String,
    /// Parameters with lower-cased names.
    pub params: Vec<(String, String)>,
}

impl ContentType {
    pub fn parse(value: &str) -> ContentType {
        let mut pieces = split_params(value).into_iter();
        let mime = pieces.next().unwrap_or_default().trim().to_ascii_lowercase();
        let mut params = Vec::new();
        for p in pieces {
            if let Some((k, v)) = p.split_once('=') {
                params.push((k.trim().to_ascii_lowercase(), unquote(v.trim())));
            }
        }
        ContentType { mime: if mime.is_empty() { "text/plain".into() } else { mime }, params }
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Lower-cased parameter value.
    pub fn param_lc(&self, name: &str) -> String {
        self.param(name).unwrap_or_default().trim().to_ascii_lowercase()
    }
}

fn split_params(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escape = false;
    for c in v.chars() {
        if escape {
            cur.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escape = true;
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn unquote(v: &str) -> String {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        v.to_string()
    }
}

/// One header field: name, unfolded value and the raw bytes of the (possibly folded) field.
#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub name: String,
    pub value: String,
    pub raw: &'a [u8],
}

/// A MIME entity borrowed from a raw message.
#[derive(Debug, Clone)]
pub struct Entity<'a> {
    pub raw: &'a [u8],
    pub body: &'a [u8],
    pub fields: Vec<Field<'a>>,
    pub ctype: ContentType,
}

impl<'a> Entity<'a> {
    pub fn parse(raw: &'a [u8]) -> Entity<'a> {
        let (header, body) = split_header_body(raw);
        let fields = parse_fields(header);
        let ctype = fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case("content-type"))
            .map(|f| ContentType::parse(&f.value))
            .unwrap_or_else(|| ContentType { mime: "text/plain".into(), params: Vec::new() });
        Entity { raw, body, fields, ctype }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.name.eq_ignore_ascii_case(name)).map(|f| f.value.as_str())
    }

    pub fn is_multipart(&self) -> bool {
        self.ctype.mime.starts_with("multipart/")
    }

    /// Raw bytes of each body part of a multipart entity, exactly as delimited by RFC 2046: the
    /// line break before a delimiter line belongs to the delimiter.
    pub fn parts(&self) -> Vec<&'a [u8]> {
        let Some(boundary) = self.ctype.param("boundary").filter(|b| !b.is_empty()) else { return Vec::new() };
        split_multipart(self.body, boundary.as_bytes())
    }

    pub fn children(&self) -> Vec<Entity<'a>> {
        self.parts().into_iter().map(Entity::parse).collect()
    }

    /// The body with its Content-Transfer-Encoding removed.
    pub fn decoded_body(&self) -> Vec<u8> {
        let cte = self.header("content-transfer-encoding").unwrap_or("").trim().to_ascii_lowercase();
        match cte.as_str() {
            "base64" => decode_base64(self.body),
            "quoted-printable" => decode_qp(self.body),
            _ => self.body.to_vec(),
        }
    }

    /// Decoded text of a `text/*` body, converted from its charset.
    pub fn text(&self) -> String {
        let bytes = self.decoded_body();
        let charset = self.ctype.param_lc("charset");
        decode_charset(&bytes, &charset)
    }
}

pub fn decode_charset(bytes: &[u8], charset: &str) -> String {
    match encoding_rs::Encoding::for_label(charset.as_bytes()) {
        Some(enc) if enc != encoding_rs::UTF_8 => enc.decode(bytes).0.into_owned(),
        _ => match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                let (s, _, had_errors) = encoding_rs::GB18030.decode(bytes);
                if had_errors { String::from_utf8_lossy(bytes).into_owned() } else { s.into_owned() }
            }
        },
    }
}

/// Splits at the first empty line. An entity starting with an empty line has no header fields.
pub fn split_header_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if raw.starts_with(b"\r\n") {
        return (&raw[..0], &raw[2..]);
    }
    if raw.starts_with(b"\n") {
        return (&raw[..0], &raw[1..]);
    }
    let mut i = 0;
    while let Some(p) = memchr(b'\n', &raw[i..]) {
        let nl = i + p;
        let rest = &raw[nl + 1..];
        if rest.starts_with(b"\r\n") {
            return (&raw[..nl + 1], &raw[nl + 3..]);
        }
        if rest.starts_with(b"\n") {
            return (&raw[..nl + 1], &raw[nl + 2..]);
        }
        i = nl + 1;
    }
    (raw, &raw[raw.len()..])
}

fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

/// Header fields of a header block, with folded lines joined.
pub fn parse_fields(header: &[u8]) -> Vec<Field<'_>> {
    let mut out: Vec<Field<'_>> = Vec::new();
    let mut start = 0;
    let mut lines: Vec<(usize, usize)> = Vec::new(); // (start, end incl. line break)
    while start < header.len() {
        let end = memchr(b'\n', &header[start..]).map(|p| start + p + 1).unwrap_or(header.len());
        lines.push((start, end));
        start = end;
    }
    let mut i = 0;
    while i < lines.len() {
        let (s, mut e) = lines[i];
        let mut j = i + 1;
        while j < lines.len() && matches!(header[lines[j].0], b' ' | b'\t') {
            e = lines[j].1;
            j += 1;
        }
        let raw = &header[s..e];
        let text = String::from_utf8_lossy(raw);
        if let Some((name, value)) = text.split_once(':') {
            let unfolded: String = value.replace("\r\n", "").replace('\n', "");
            out.push(Field { name: name.trim().to_string(), value: unfolded.trim().to_string(), raw });
        }
        i = j;
    }
    out
}

fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(boundary);
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;
    let mut pos = 0;
    loop {
        let line_end = memchr(b'\n', &body[pos..]).map(|p| pos + p).unwrap_or(body.len());
        let mut line = &body[pos..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if let Some(rest) = line.strip_prefix(delim.as_slice()) {
            let close = rest.starts_with(b"--");
            let tail = if close { &rest[2..] } else { rest };
            if tail.iter().all(|c| *c == b' ' || *c == b'\t') {
                if let Some(s) = current {
                    let mut e = pos;
                    if e > s && body[e - 1] == b'\n' {
                        e -= 1;
                        if e > s && body[e - 1] == b'\r' {
                            e -= 1;
                        }
                    }
                    parts.push(&body[s..e]);
                }
                if close {
                    return parts;
                }
                current = Some((line_end + 1).min(body.len()));
            }
        }
        if line_end >= body.len() {
            break;
        }
        pos = line_end + 1;
    }
    // No closing delimiter (truncated message): keep what we have.
    if let Some(s) = current.filter(|s| *s < body.len()) {
        parts.push(&body[s..]);
    }
    parts
}

pub fn decode_base64(data: &[u8]) -> Vec<u8> {
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let clean: Vec<u8> = data.iter().copied().filter(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/').collect();
    LENIENT.decode(clean).unwrap_or_default()
}

pub fn decode_qp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let c = data[i];
        if c == b'=' {
            if data[i + 1..].starts_with(b"\r\n") {
                i += 3;
                continue;
            }
            if data[i + 1..].starts_with(b"\n") {
                i += 2;
                continue;
            }
            if i + 2 < data.len() {
                let hex = std::str::from_utf8(&data[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(b) = hex {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Line endings converted to CRLF (canonical form for signing, RFC 3156 §5 / RFC 8551 §3.1.1).
pub fn to_crlf(data: &[u8]) -> Cow<'_, [u8]> {
    let bare = data.iter().enumerate().any(|(i, &b)| b == b'\n' && (i == 0 || data[i - 1] != b'\r'));
    if !bare {
        return Cow::Borrowed(data);
    }
    let mut out = Vec::with_capacity(data.len() + data.len() / 32);
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    Cow::Owned(out)
}

/// Base64 with 76-character CRLF-terminated lines.
pub fn base64_lines(data: &[u8]) -> String {
    let enc = STANDARD.encode(data);
    let mut out = String::with_capacity(enc.len() + enc.len() / 38 + 2);
    for chunk in enc.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

/// A fresh multipart boundary that does not occur in `content`.
pub fn boundary(content: &[u8]) -> String {
    loop {
        let bytes: [u8; 12] = rand::thread_rng().r#gen();
        let b = format!("=_mbx_{}", hex::encode(bytes));
        if !content.windows(b.len()).any(|w| w == b.as_bytes()) {
            return b;
        }
    }
}

/// Splits an outgoing message into the top-level header fields (CRLF terminated, everything but
/// `Content-*`) and the MIME entity to protect: the `Content-*` fields plus the body, in
/// canonical CRLF form.
pub fn split_for_protection(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (header, body) = split_header_body(raw);
    let mut top = Vec::new();
    let mut entity = Vec::new();
    for f in parse_fields(header) {
        let target = if f.name.to_ascii_lowercase().starts_with("content-") { &mut entity } else { &mut top };
        let mut field = to_crlf(f.raw).into_owned();
        if !field.ends_with(b"\r\n") {
            field.extend_from_slice(b"\r\n");
        }
        target.extend_from_slice(&field);
    }
    if entity.is_empty() {
        entity.extend_from_slice(b"Content-Type: text/plain; charset=us-ascii\r\n");
    }
    entity.extend_from_slice(b"\r\n");
    entity.extend_from_slice(&to_crlf(body));
    (top, entity)
}

/// `multipart/*` body: an informational preamble, the parts and the closing delimiter.
pub fn multipart_body(boundary: &str, preamble: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(preamble.as_bytes());
    out.extend_from_slice(b"\r\n");
    for p in parts {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        out.extend_from_slice(p);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

/// A text/plain; charset=utf-8 entity (base64, so any content survives transport).
pub fn text_entity(text: &str) -> Vec<u8> {
    let mut out = b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    out.extend_from_slice(base64_lines(text.as_bytes()).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_params() {
        let ct = ContentType::parse(
            "Multipart/Signed; micalg=pgp-sha256;\r\n protocol=\"application/pgp-signature\"; boundary=\"a;b\\\"c\"",
        );
        assert_eq!(ct.mime, "multipart/signed");
        assert_eq!(ct.param("protocol"), Some("application/pgp-signature"));
        assert_eq!(ct.param("boundary"), Some("a;b\"c"));
        assert_eq!(ct.param("micalg"), Some("pgp-sha256"));
    }

    #[test]
    fn splits_parts_exactly() {
        let raw = b"Content-Type: multipart/signed; boundary=XY\r\n\r\npre\r\n--XY\r\nContent-Type: text/plain\r\n\r\nhello\r\n\r\n--XY  \r\nsig\r\n--XY--\r\nepilogue";
        let e = Entity::parse(raw);
        let parts = e.parts();
        assert_eq!(parts, vec![&b"Content-Type: text/plain\r\n\r\nhello\r\n"[..], &b"sig"[..]]);
        let c = Entity::parse(parts[0]);
        assert_eq!(c.body, b"hello\r\n");
        let lf = b"Content-Type: multipart/mixed; boundary=\"q\"\n\n--q\n\nbody\n--q--\n";
        let e = Entity::parse(lf);
        assert_eq!(e.parts(), vec![&b"\nbody"[..]]);
        assert_eq!(Entity::parse(e.parts()[0]).body, b"body");
    }

    #[test]
    fn transfer_decoding_and_crlf() {
        assert_eq!(decode_qp(b"caf=C3=A9 =\r\nbar=3D"), "café bar=".as_bytes());
        assert_eq!(decode_base64(b"aGVs\r\nbG8=\r\n"), b"hello");
        assert_eq!(to_crlf(b"a\nb\r\nc\n").as_ref(), b"a\r\nb\r\nc\r\n");
        let (top, ent) = split_for_protection(b"From: a@b.c\nSubject: x\n y\nContent-Type: text/plain\nMIME-Version: 1.0\n\nhi\n");
        assert_eq!(top, b"From: a@b.c\r\nSubject: x\r\n y\r\nMIME-Version: 1.0\r\n");
        assert_eq!(ent, b"Content-Type: text/plain\r\n\r\nhi\r\n");
    }
}

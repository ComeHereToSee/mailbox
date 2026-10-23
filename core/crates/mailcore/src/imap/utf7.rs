//! IMAP modified UTF-7 (RFC 3501 §5.1.3) used for folder names like `&XfJT0ZAB-` (已发送).

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;

pub fn decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 1..];
        let end = rest.find('-').unwrap_or(rest.len());
        let chunk = &rest[..end];
        if chunk.is_empty() {
            out.push('&');
        } else {
            let b64 = chunk.replace(',', "/");
            match STANDARD_NO_PAD.decode(b64.trim_end_matches('=')) {
                Ok(bytes) => {
                    let units: Vec<u16> = bytes.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                    out.push_str(&String::from_utf16_lossy(&units));
                }
                Err(_) => {
                    out.push('&');
                    out.push_str(chunk);
                    out.push('-');
                }
            }
        }
        rest = if end < rest.len() { &rest[end + 1..] } else { "" };
    }
    out.push_str(rest);
    out
}

pub fn encode(s: &str) -> String {
    let mut out = String::new();
    let mut buf: Vec<u16> = Vec::new();
    let flush = |buf: &mut Vec<u16>, out: &mut String| {
        if buf.is_empty() {
            return;
        }
        let bytes: Vec<u8> = buf.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&STANDARD_NO_PAD.encode(bytes).replace('/', ","));
        out.push('-');
        buf.clear();
    };
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut buf, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut tmp = [0u16; 2];
            buf.extend_from_slice(c.encode_utf16(&mut tmp));
        }
    }
    flush(&mut buf, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        assert_eq!(decode("&XfJT0ZAB-"), "已发送");
        assert_eq!(decode("&g0l6P3ux-"), "草稿箱");
        assert_eq!(decode("INBOX"), "INBOX");
        assert_eq!(decode("Tom &- Jerry"), "Tom & Jerry");
        assert_eq!(decode("&U,BTFw-"), "台北");
        for s in ["已发送", "草稿箱", "Tom & Jerry", "Work/项目 2024", "日本語", "😀 emoji"] {
            assert_eq!(decode(&encode(s)), s);
        }
        assert_eq!(encode("已发送"), "&XfJT0ZAB-");
    }
}

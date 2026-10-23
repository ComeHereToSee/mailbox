//! A small BER/DER reader for the CMS structures of received S/MIME mail.
//!
//! Real S/MIME agents (OpenSSL in streaming mode, Outlook, Apple Mail) emit BER with indefinite
//! lengths and chunked (constructed) OCTET STRINGs, which strict DER decoders reject. This reader
//! accepts both and keeps the exact encoded bytes of every element, which signature verification
//! needs (signed attributes, issuer names).

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
const MAX_DEPTH: usize = 48;

#[derive(Debug)]
pub struct BerError;

pub type BerResult<T> = std::result::Result<T, BerError>;

/// One element: identifier octet, content octets and the complete encoding.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    /// First identifier octet (class, constructed bit and tag number < 31).
    pub tag: u8,
    pub content: &'a [u8],
    /// The whole element as encoded (identifier, length, content and a trailing end-of-contents).
    pub raw: &'a [u8],
    pub indefinite: bool,
}

impl<'a> Tlv<'a> {
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// Elements contained in a constructed element.
    pub fn children(&self) -> BerResult<Vec<Tlv<'a>>> {
        if !self.constructed() {
            return Err(BerError);
        }
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (t, r) = parse_depth(rest, 1)?;
            out.push(t);
            rest = r;
        }
        Ok(out)
    }

    /// Content of a string type, joining the chunks of a constructed (BER) encoding.
    pub fn octets(&self) -> BerResult<Vec<u8>> {
        let mut out = Vec::new();
        self.octets_into(&mut out, 0)?;
        Ok(out)
    }

    fn octets_into(&self, out: &mut Vec<u8>, depth: usize) -> BerResult<()> {
        if depth > MAX_DEPTH {
            return Err(BerError);
        }
        if self.constructed() {
            for c in self.children()? {
                c.octets_into(out, depth + 1)?;
            }
        } else {
            out.extend_from_slice(self.content);
        }
        Ok(())
    }

    /// The single element inside an EXPLICIT tag.
    pub fn explicit(&self) -> BerResult<Tlv<'a>> {
        self.children()?.into_iter().next().ok_or(BerError)
    }

    pub fn is_oid(&self, oid: &der::oid::ObjectIdentifier) -> bool {
        self.tag == OID && self.content == oid.as_bytes()
    }

    pub fn oid(&self) -> Option<der::oid::ObjectIdentifier> {
        if self.tag != OID {
            return None;
        }
        der::oid::ObjectIdentifier::from_bytes(self.content).ok()
    }

    /// The raw encoding with a different identifier octet, e.g. `[0] IMPLICIT SET OF` → `SET OF`.
    pub fn retagged(&self, tag: u8) -> Vec<u8> {
        let mut v = self.raw.to_vec();
        if let Some(first) = v.first_mut() {
            *first = tag;
        }
        v
    }
}

/// Parses one element from the start of `input`, returning it and the remaining bytes.
pub fn parse(input: &[u8]) -> BerResult<(Tlv<'_>, &[u8])> {
    parse_depth(input, 0)
}

fn parse_depth(input: &[u8], depth: usize) -> BerResult<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH || input.len() < 2 {
        return Err(BerError);
    }
    let tag = input[0];
    let mut pos = 1;
    if tag & 0x1f == 0x1f {
        // High tag number: skip the base-128 continuation octets.
        while pos < input.len() && input[pos] & 0x80 != 0 {
            pos += 1;
        }
        pos += 1;
    }
    let first = *input.get(pos).ok_or(BerError)?;
    pos += 1;
    if first == 0x80 {
        // Indefinite length: children until end-of-contents (00 00).
        if tag & 0x20 == 0 {
            return Err(BerError);
        }
        let start = pos;
        let mut rest = &input[pos..];
        loop {
            if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                let content_end = input.len() - rest.len();
                let end = content_end + 2;
                return Ok((Tlv { tag, content: &input[start..content_end], raw: &input[..end], indefinite: true }, &input[end..]));
            }
            let (_, r) = parse_depth(rest, depth + 1)?;
            rest = r;
        }
    }
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || pos + n > input.len() {
            return Err(BerError);
        }
        let mut l = 0usize;
        for &b in &input[pos..pos + n] {
            l = (l << 8) | b as usize;
        }
        pos += n;
        l
    };
    let end = pos.checked_add(len).ok_or(BerError)?;
    if end > input.len() {
        return Err(BerError);
    }
    let tlv = Tlv { tag, content: &input[pos..end], raw: &input[..end], indefinite: false };
    if tlv.constructed() && depth < MAX_DEPTH {
        // Validate nested structure early so `children()` cannot fail later on bad lengths.
        let mut rest = tlv.content;
        while !rest.is_empty() {
            rest = parse_depth(rest, depth + 1)?.1;
        }
    }
    Ok((tlv, &input[end..]))
}

/// Parses exactly one element (trailing garbage after it is ignored, as some agents pad).
pub fn parse_one(input: &[u8]) -> BerResult<Tlv<'_>> {
    parse(input).map(|(t, _)| t)
}

// ------------------------------------------------------------------ DER writing

/// One DER element with a definite length.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(items: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &items.concat())
}

/// DER `SET OF`: elements sorted by their encodings.
pub fn set_of(mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort();
    tlv(SET, &items.concat())
}

pub fn oid(o: &der::oid::ObjectIdentifier) -> Vec<u8> {
    tlv(OID, o.as_bytes())
}

pub fn small_int(n: u8) -> Vec<u8> {
    if n < 0x80 { tlv(INTEGER, &[n]) } else { tlv(INTEGER, &[0, n]) }
}

pub fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, data)
}

/// `AlgorithmIdentifier` without parameters (or with NULL when `null` is set, as RSA needs).
pub fn alg_id(o: &der::oid::ObjectIdentifier, null: bool) -> Vec<u8> {
    if null { seq(&[&oid(o), &[0x05, 0x00]]) } else { seq(&[&oid(o)]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_der() {
        assert_eq!(tlv(0x04, &[1, 2]), vec![4, 2, 1, 2]);
        let long = tlv(0x04, &[0u8; 300]);
        assert_eq!(&long[..4], &[4, 0x82, 0x01, 0x2c]);
        assert_eq!(set_of(vec![vec![2, 1, 9], vec![2, 1, 1]]), vec![0x31, 6, 2, 1, 1, 2, 1, 9]);
        assert_eq!(small_int(200), vec![2, 2, 0, 200]);
        let t = parse_one(&long).unwrap();
        assert_eq!(t.content.len(), 300);
    }

    #[test]
    fn definite_and_indefinite() {
        // SEQUENCE { INTEGER 5, [0] (indefinite) { OCTET STRING "ab", OCTET STRING "c" } }
        let ber = [0x30, 0x80, 0x02, 0x01, 0x05, 0xa0, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0];
        let t = parse_one(&ber).unwrap();
        assert!(t.indefinite);
        assert_eq!(t.raw.len(), ber.len());
        let kids = t.children().unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].content, &[5]);
        assert_eq!(kids[1].octets().unwrap(), b"abc");
        let der = [0x30, 0x03, 0x02, 0x01, 0x07];
        let t = parse_one(&der).unwrap();
        assert_eq!(t.children().unwrap()[0].content, &[7]);
        assert!(parse_one(&[0x30, 0x05, 0x02]).is_err());
        assert!(parse_one(&[0x30, 0x80, 0x02, 0x01]).is_err());
    }
}

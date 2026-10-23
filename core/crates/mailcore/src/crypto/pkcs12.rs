//! PKCS#12 (RFC 7292) reading: the private keys and certificates of a `.p12` / `.pfx` file.
//!
//! Supports password integrity (HMAC-SHA1/SHA-2 MAC), PBES2 (PBKDF2 + AES-CBC / 3DES, the OpenSSL 3
//! default) and the legacy PKCS#12 PBEs (SHA-1 with 3DES, 2-key 3DES, RC2-40 and RC2-128) still
//! produced by macOS Keychain and Windows. BER encodings are accepted.

use super::ber::{self, Tlv};
use super::hashes::{HashAlg, cbc_decrypt, with_hash};
use der::oid::ObjectIdentifier as Oid;
use hmac::Mac;

const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ID_ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
const KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.1");
const SHROUDED_KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.2");
const CERT_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.3");
const SAFE_CONTENTS_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.6");
const X509_CERTIFICATE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.22.1");
const LOCAL_KEY_ID: Oid = Oid::new_unwrap("1.2.840.113549.1.9.21");
const PBE_SHA1_3DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.3");
const PBE_SHA1_2DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.4");
const PBE_SHA1_RC2_128: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.5");
const PBE_SHA1_RC2_40: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
const PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");
const PBKDF2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.12");
const HMAC_SHA1: Oid = Oid::new_unwrap("1.2.840.113549.2.7");
const HMAC_SHA224: Oid = Oid::new_unwrap("1.2.840.113549.2.8");
const HMAC_SHA256: Oid = Oid::new_unwrap("1.2.840.113549.2.9");
const HMAC_SHA384: Oid = Oid::new_unwrap("1.2.840.113549.2.10");
const HMAC_SHA512: Oid = Oid::new_unwrap("1.2.840.113549.2.11");
const AES128_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES192_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES256_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.42");
const DES_EDE3_CBC: Oid = Oid::new_unwrap("1.2.840.113549.3.7");

#[derive(Debug, PartialEq)]
pub enum P12Error {
    Malformed,
    BadPassword,
    Unsupported(String),
}

impl From<ber::BerError> for P12Error {
    fn from(_: ber::BerError) -> Self {
        P12Error::Malformed
    }
}

type P12Result<T> = std::result::Result<T, P12Error>;

#[derive(Debug, Default)]
pub struct Contents {
    /// PKCS#8 `PrivateKeyInfo` DER and the bag's localKeyId.
    pub keys: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// Certificate DER and the bag's localKeyId.
    pub certs: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

/// The password as PKCS#12 wants it for its own KDF: UTF-16BE with a terminating NUL.
fn bmp_password(password: &str) -> Vec<u8> {
    let mut out: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

/// RFC 7292 appendix B.2 key derivation (`id` 1 = key, 2 = IV, 3 = MAC key).
fn kdf(alg: HashAlg, pass: &[u8], salt: &[u8], id: u8, iterations: u32, n: usize) -> Vec<u8> {
    let (u, v) = (alg.output_len(), alg.block_len());
    let fill = |s: &[u8]| -> Vec<u8> {
        if s.is_empty() {
            return Vec::new();
        }
        let len = v * s.len().div_ceil(v);
        (0..len).map(|i| s[i % s.len()]).collect()
    };
    let d = vec![id; v];
    let mut i_buf = [fill(salt), fill(pass)].concat();
    let mut out = Vec::with_capacity(n + u);
    loop {
        let mut a = alg.digest(&[d.as_slice(), i_buf.as_slice()].concat());
        for _ in 1..iterations.max(1) {
            a = alg.digest(&a);
        }
        out.extend_from_slice(&a);
        if out.len() >= n {
            break;
        }
        let b: Vec<u8> = (0..v).map(|i| a[i % a.len()]).collect();
        for chunk in i_buf.chunks_mut(v) {
            let mut carry = 1u16;
            for k in (0..chunk.len()).rev() {
                let sum = chunk[k] as u16 + b[k] as u16 + carry;
                chunk[k] = sum as u8;
                carry = sum >> 8;
            }
        }
    }
    out.truncate(n);
    out
}

fn int_value(t: &Tlv) -> P12Result<u32> {
    if t.tag != ber::INTEGER || t.content.is_empty() || t.content.len() > 5 {
        return Err(P12Error::Malformed);
    }
    Ok(t.content.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64).min(u32::MAX as u64) as u32)
}

fn hmac_alg(oid: &Oid) -> Option<HashAlg> {
    Some(match *oid {
        HMAC_SHA1 => HashAlg::Sha1,
        HMAC_SHA224 => HashAlg::Sha224,
        HMAC_SHA256 => HashAlg::Sha256,
        HMAC_SHA384 => HashAlg::Sha384,
        HMAC_SHA512 => HashAlg::Sha512,
        _ => return None,
    })
}

fn hmac_ok(alg: HashAlg, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    with_hash!(alg, D => {
        let Ok(mut mac) = <hmac::Hmac<D> as Mac>::new_from_slice(key) else { return false };
        mac.update(data);
        mac.verify_slice(expected).is_ok()
    })
}

/// Parses a PFX and returns its keys and certificates.
pub fn parse(pfx: &[u8], password: &str) -> P12Result<Contents> {
    let top = ber::parse_one(pfx)?;
    let kids = top.children()?;
    let auth_safe = kids.get(1).ok_or(P12Error::Malformed)?.children()?;
    if !auth_safe.first().is_some_and(|t| t.is_oid(&ID_DATA)) {
        return Err(P12Error::Unsupported("仅支持密码保护的 PKCS#12 文件".into()));
    }
    let auth_bytes = auth_safe.get(1).ok_or(P12Error::Malformed)?.explicit()?.octets()?;

    // Candidate encodings of the password; an empty password is written either way by different tools.
    let mut passwords = vec![bmp_password(password)];
    if password.is_empty() {
        passwords.push(Vec::new());
    }
    if let Some(mac_data) = kids.get(2) {
        let m = mac_data.children()?;
        let digest_info = m.first().ok_or(P12Error::Malformed)?.children()?;
        let alg_oid = digest_info.first().ok_or(P12Error::Malformed)?.children()?.first().and_then(|t| t.oid());
        let expected = digest_info.get(1).ok_or(P12Error::Malformed)?.octets()?;
        let salt = m.get(1).ok_or(P12Error::Malformed)?.octets()?;
        let iterations = m.get(2).map(int_value).transpose()?.unwrap_or(1);
        // Unknown MAC schemes (e.g. PBMAC1) are not checked; decryption still needs the password.
        if let Some(alg) = alg_oid.as_ref().and_then(|o| hmac_alg(o).or(HashAlg::from_digest_oid(o))) {
            let ok = passwords.iter().position(|p| {
                let key = kdf(alg, p, &salt, 3, iterations, alg.output_len());
                hmac_ok(alg, &key, &auth_bytes, &expected)
            });
            match ok {
                Some(i) => passwords = vec![passwords.swap_remove(i)],
                None => return Err(P12Error::BadPassword),
            }
        }
    }

    let mut contents = Contents::default();
    let safes = ber::parse_one(&auth_bytes)?;
    for ci in safes.children()? {
        let c = ci.children()?;
        let ct = c.first().ok_or(P12Error::Malformed)?;
        let body = c.get(1).ok_or(P12Error::Malformed)?.explicit()?;
        let safe_contents = if ct.is_oid(&ID_DATA) {
            body.octets()?
        } else if ct.is_oid(&ID_ENCRYPTED_DATA) {
            // EncryptedData { version, EncryptedContentInfo { type, alg, [0] IMPLICIT content } }
            let eci = body.children()?.get(1).ok_or(P12Error::Malformed)?.children()?;
            let alg = eci.get(1).ok_or(P12Error::Malformed)?;
            let data = eci.get(2).ok_or(P12Error::Malformed)?.octets()?;
            pbe_decrypt(alg, &data, password, &passwords)?
        } else {
            continue;
        };
        read_bags(&safe_contents, password, &passwords, &mut contents, 0)?;
    }
    Ok(contents)
}

fn read_bags(safe_contents: &[u8], password: &str, bmp: &[Vec<u8>], out: &mut Contents, depth: usize) -> P12Result<()> {
    if depth > 4 {
        return Err(P12Error::Malformed);
    }
    for bag in ber::parse_one(safe_contents)?.children()? {
        let b = bag.children()?;
        let id = b.first().ok_or(P12Error::Malformed)?;
        let value = b.get(1).ok_or(P12Error::Malformed)?.explicit()?;
        let local_id = b.get(2).and_then(|attrs| local_key_id(attrs).ok().flatten());
        if id.is_oid(&KEY_BAG) {
            out.keys.push((value.raw.to_vec(), local_id));
        } else if id.is_oid(&SHROUDED_KEY_BAG) {
            let v = value.children()?;
            let alg = v.first().ok_or(P12Error::Malformed)?;
            let data = v.get(1).ok_or(P12Error::Malformed)?.octets()?;
            out.keys.push((pbe_decrypt(alg, &data, password, bmp)?, local_id));
        } else if id.is_oid(&CERT_BAG) {
            let v = value.children()?;
            if v.first().is_some_and(|t| t.is_oid(&X509_CERTIFICATE)) {
                let der = v.get(1).ok_or(P12Error::Malformed)?.explicit()?.octets()?;
                out.certs.push((der, local_id));
            }
        } else if id.is_oid(&SAFE_CONTENTS_BAG) {
            read_bags(value.raw, password, bmp, out, depth + 1)?;
        }
    }
    Ok(())
}

fn local_key_id(attrs: &Tlv) -> P12Result<Option<Vec<u8>>> {
    for a in attrs.children()? {
        let k = a.children()?;
        if k.first().is_some_and(|t| t.is_oid(&LOCAL_KEY_ID)) {
            let v = k.get(1).ok_or(P12Error::Malformed)?.children()?;
            return Ok(v.first().map(|t| t.octets()).transpose()?);
        }
    }
    Ok(None)
}

/// Decrypts with a password-based scheme (`alg` is the AlgorithmIdentifier).
fn pbe_decrypt(alg: &Tlv, data: &[u8], password: &str, bmp: &[Vec<u8>]) -> P12Result<Vec<u8>> {
    let a = alg.children()?;
    let oid = a.first().and_then(|t| t.oid()).ok_or(P12Error::Malformed)?;
    let params = a.get(1).ok_or(P12Error::Malformed)?;
    if oid == PBES2 {
        return pbes2_decrypt(params, data, password);
    }
    let p = params.children()?;
    let salt = p.first().ok_or(P12Error::Malformed)?.octets()?;
    let iterations = int_value(p.get(1).ok_or(P12Error::Malformed)?)?;
    let (key_len, iv_len) = match oid {
        PBE_SHA1_3DES => (24, 8),
        PBE_SHA1_2DES => (16, 8),
        PBE_SHA1_RC2_128 => (16, 8),
        PBE_SHA1_RC2_40 => (5, 8),
        other => return Err(P12Error::Unsupported(format!("不支持的加密算法 {other}"))),
    };
    for pw in bmp {
        let key = kdf(HashAlg::Sha1, pw, &salt, 1, iterations, key_len);
        let iv = kdf(HashAlg::Sha1, pw, &salt, 2, iterations, iv_len);
        let plain = match oid {
            PBE_SHA1_3DES => cbc_decrypt::<des::TdesEde3>(&key, &iv, data),
            PBE_SHA1_2DES => cbc_decrypt::<des::TdesEde2>(&key, &iv, data),
            _ => rc2_decrypt(&key, key_len * 8, &iv, data),
        };
        if let Some(p) = plain {
            return Ok(p);
        }
    }
    Err(P12Error::BadPassword)
}

fn rc2_decrypt(key: &[u8], effective_bits: usize, iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use cbc::cipher::{BlockDecryptMut, InnerIvInit, block_padding::Pkcs7};
    let cipher = rc2::Rc2::new_with_eff_key_len(key, effective_bits);
    cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, iv).ok()?.decrypt_padded_vec_mut::<Pkcs7>(data).ok()
}

fn pbes2_decrypt(params: &Tlv, data: &[u8], password: &str) -> P12Result<Vec<u8>> {
    let p = params.children()?;
    let kdf_alg = p.first().ok_or(P12Error::Malformed)?.children()?;
    let enc_alg = p.get(1).ok_or(P12Error::Malformed)?.children()?;
    if !kdf_alg.first().is_some_and(|t| t.is_oid(&PBKDF2)) {
        return Err(P12Error::Unsupported("不支持的密钥派生算法".into()));
    }
    let kp = kdf_alg.get(1).ok_or(P12Error::Malformed)?.children()?;
    let salt = kp.first().ok_or(P12Error::Malformed)?.octets()?;
    let iterations = int_value(kp.get(1).ok_or(P12Error::Malformed)?)?;
    let mut prf = HashAlg::Sha1;
    for t in kp.iter().skip(2) {
        if t.tag == ber::SEQUENCE {
            let o = t.children()?.first().and_then(|x| x.oid()).ok_or(P12Error::Malformed)?;
            prf = hmac_alg(&o).ok_or_else(|| P12Error::Unsupported(format!("不支持的 PRF {o}")))?;
        }
    }
    let cipher = enc_alg.first().and_then(|t| t.oid()).ok_or(P12Error::Malformed)?;
    let iv = enc_alg.get(1).ok_or(P12Error::Malformed)?.octets()?;
    let key_len = match cipher {
        AES128_CBC => 16,
        AES192_CBC => 24,
        AES256_CBC => 32,
        DES_EDE3_CBC => 24,
        other => return Err(P12Error::Unsupported(format!("不支持的加密算法 {other}"))),
    };
    let mut key = vec![0u8; key_len];
    with_hash!(prf, D => pbkdf2::pbkdf2_hmac::<D>(password.as_bytes(), &salt, iterations, &mut key));
    let plain = match cipher {
        AES128_CBC => cbc_decrypt::<aes::Aes128>(&key, &iv, data),
        AES192_CBC => cbc_decrypt::<aes::Aes192>(&key, &iv, data),
        AES256_CBC => cbc_decrypt::<aes::Aes256>(&key, &iv, data),
        _ => cbc_decrypt::<des::TdesEde3>(&key, &iv, data),
    };
    plain.ok_or(P12Error::BadPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_vectors() {
        // Test vectors from the BouncyCastle PKCS12 KDF tests (password "smeg", SHA-1).
        let salt = hex::decode("0a58cf64530d823f").unwrap();
        let pass = bmp_password("smeg");
        assert_eq!(hex::encode(kdf(HashAlg::Sha1, &pass, &salt, 1, 1, 24)), "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3");
        assert_eq!(hex::encode(kdf(HashAlg::Sha1, &pass, &salt, 2, 1, 8)), "79993dfe048d3b76");
    }

    #[test]
    fn reads_openssl_files() {
        let modern = parse(include_bytes!("testdata/alice.p12"), "alice-pass").unwrap();
        assert_eq!((modern.keys.len(), modern.certs.len()), (1, 1));
        assert_eq!(modern.keys[0].1, modern.certs[0].1);
        let legacy = parse(include_bytes!("testdata/bob_legacy.p12"), "bob-pass").unwrap();
        assert_eq!((legacy.keys.len(), legacy.certs.len()), (1, 1));
        assert_eq!(parse(include_bytes!("testdata/bob.p12"), "wrong").unwrap_err(), P12Error::BadPassword);
    }
}

//! S/MIME (RFC 8551): CMS SignedData / EnvelopedData (RFC 5652) for received and sent mail.
//!
//! Received CMS is read with the BER reader (real agents emit indefinite lengths); sent CMS is
//! written as DER. Supported: RSA PKCS#1 v1.5 / PSS and ECDSA P-256 / P-384 signatures with
//! SHA-1/SHA-2, RSA PKCS#1 v1.5 / OAEP key transport, AES-128/192/256-CBC and 3DES content
//! encryption. Sending uses RSA PKCS#1 v1.5 + SHA-256 and AES-256-CBC. Certificate chains are
//! not validated; a signature is trusted when it verifies and the certificate belongs to the
//! sender's address.

use super::ber::{self, Tlv};
use super::entity::{self, Entity};
use super::hashes::{HashAlg, cbc_decrypt, with_hash};
use super::pkcs12::{self, P12Error};
use super::{KeyInfo, Keys, Plan, Request, SignatureStatus, StoredKey, join_addrs};
use crate::error::{Error, Result};
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use der::oid::ObjectIdentifier as Oid;
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
const ID_ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.3");
const ID_AUTH_ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.23");
const ID_COMPRESSED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.9");
const ATTR_CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
const ATTR_MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
const ATTR_SIGNING_TIME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.5");
const ATTR_SMIME_CAPABILITIES: Oid = Oid::new_unwrap("1.2.840.113549.1.9.15");
const EMAIL_ADDRESS: Oid = Oid::new_unwrap("1.2.840.113549.1.9.1");
const COMMON_NAME: Oid = Oid::new_unwrap("2.5.4.3");
const SUBJECT_ALT_NAME: Oid = Oid::new_unwrap("2.5.29.17");
const SUBJECT_KEY_ID: Oid = Oid::new_unwrap("2.5.29.14");
const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const RSAES_OAEP: Oid = Oid::new_unwrap("1.2.840.113549.1.1.7");
const RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
const SHA1_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.5");
const SHA256_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");
const SHA224_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.14");
const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const ECDSA_SHA1: Oid = Oid::new_unwrap("1.2.840.10045.4.1");
const ECDSA_SHA224: Oid = Oid::new_unwrap("1.2.840.10045.4.3.1");
const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");
const CURVE_P256: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
const CURVE_P384: Oid = Oid::new_unwrap("1.3.132.0.34");
const AES128_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES192_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES256_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.42");
const DES_EDE3_CBC: Oid = Oid::new_unwrap("1.2.840.113549.3.7");

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ------------------------------------------------------------------ certificates

/// A certificate with the fields the mail code needs.
pub struct ParsedCert {
    pub der: Vec<u8>,
    pub cert: Certificate,
    /// Raw DER of the issuer Name and the serial number's content octets (CMS recipient / signer ids).
    issuer: Vec<u8>,
    serial: Vec<u8>,
    ski: Option<Vec<u8>>,
    pub emails: Vec<String>,
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
}

impl ParsedCert {
    pub fn parse(der: &[u8]) -> Option<ParsedCert> {
        let cert = Certificate::from_der(der).ok()?;
        let tbs = ber::parse_one(der).ok()?.children().ok()?.into_iter().next()?;
        let kids = tbs.children().ok()?;
        let i = usize::from(kids.first()?.tag == 0xa0);
        let serial = kids.get(i)?.content.to_vec();
        let issuer = kids.get(i + 2)?.raw.to_vec();
        let tbs_cert = &cert.tbs_certificate;
        let mut emails = Vec::new();
        let mut names = Vec::new();
        for rdn in tbs_cert.subject.0.iter() {
            for atv in rdn.0.iter() {
                let Some(v) = any_string(&atv.value) else { continue };
                if atv.oid == EMAIL_ADDRESS {
                    push_unique(&mut emails, v.trim().to_ascii_lowercase());
                } else if atv.oid == COMMON_NAME {
                    push_unique(&mut names, v.trim().to_string());
                }
            }
        }
        let mut ski = None;
        for ext in tbs_cert.extensions.iter().flatten() {
            let value = ext.extn_value.as_bytes();
            if ext.extn_id == SUBJECT_ALT_NAME {
                // GeneralNames; rfc822Name is [1] IMPLICIT IA5String.
                if let Ok(names) = ber::parse_one(value).and_then(|t| t.children()) {
                    for n in names.iter().filter(|n| n.tag == 0x81) {
                        push_unique(&mut emails, String::from_utf8_lossy(n.content).trim().to_ascii_lowercase());
                    }
                }
            } else if ext.extn_id == SUBJECT_KEY_ID {
                ski = ber::parse_one(value).ok().map(|t| t.content.to_vec());
            }
        }
        emails.retain(|e| e.contains('@'));
        Some(ParsedCert {
            der: der.to_vec(),
            not_before: tbs_cert.validity.not_before.to_unix_duration().as_secs() as i64,
            not_after: tbs_cert.validity.not_after.to_unix_duration().as_secs() as i64,
            cert,
            issuer,
            serial,
            ski,
            emails,
            names,
        })
    }

    fn id(&self) -> String {
        hex::encode_upper(Sha256::digest(&self.der))
    }

    fn info(&self, has_secret: bool) -> KeyInfo {
        KeyInfo {
            id: self.id(),
            kind: "smime".into(),
            emails: self.emails.clone(),
            names: self.names.clone(),
            has_secret,
            created: self.not_before,
            expires: Some(self.not_after),
        }
    }

    fn pem(&self) -> Result<String> {
        der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, &self.der)
            .map_err(|e| Error::Other(format!("证书编码失败：{e}")))
    }

    fn rsa_public(&self) -> Option<RsaPublicKey> {
        let spki = self.cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
        RsaPublicKey::from_public_key_der(&spki).ok()
    }

    fn valid_now(&self) -> bool {
        let t = now();
        self.not_before <= t + 86_400 && t <= self.not_after
    }

    fn display(&self) -> String {
        match (self.names.first(), self.emails.first()) {
            (Some(n), Some(e)) => format!("{n} <{e}>"),
            (Some(n), None) => n.clone(),
            (None, Some(e)) => e.clone(),
            (None, None) => self.id(),
        }
    }

    /// Matches a CMS SignerIdentifier / RecipientIdentifier.
    fn matches_id(&self, id: &Tlv) -> bool {
        match id.tag {
            ber::SEQUENCE => id.children().is_ok_and(|k| {
                k.len() >= 2 && k[0].raw == self.issuer.as_slice() && k[1].content == self.serial.as_slice()
            }),
            0x80 => self.ski.as_deref() == Some(id.content),
            _ => false,
        }
    }
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !s.is_empty() && !v.contains(&s) {
        v.push(s);
    }
}

fn any_string(a: &der::Any) -> Option<String> {
    use der::{Tag, Tagged};
    let bytes = a.value();
    match a.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::TeletexString | Tag::VisibleString => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        Tag::BmpString => {
            let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

/// The first certificate in PEM text, or DER.
fn cert_der(input: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
        let end_marker = "-----END CERTIFICATE-----";
        let end = text[start..].find(end_marker).map(|p| start + p + end_marker.len())?;
        let (label, der) = der::pem::decode_vec(text[start..end].as_bytes()).ok()?;
        return (label == "CERTIFICATE").then_some(der);
    }
    (input.first() == Some(&0x30)).then(|| input.to_vec())
}

/// A keyring certificate, with its RSA private key when we have one.
pub struct CertKey {
    pub info: KeyInfo,
    pub parsed: ParsedCert,
    pub key: Option<RsaPrivateKey>,
}

impl CertKey {
    pub fn load(stored: &StoredKey) -> Option<CertKey> {
        let parsed = ParsedCert::parse(&cert_der(stored.public.as_bytes())?)?;
        let public = parsed.rsa_public();
        let key = stored
            .secret
            .as_deref()
            .and_then(|pem| RsaPrivateKey::from_pkcs8_pem(pem).ok())
            .filter(|k| public.as_ref().is_some_and(|p| p.n() == k.n() && p.e() == k.e()));
        Some(CertKey { info: stored.info.clone(), parsed, key })
    }

    fn has_email(&self, addr: &str) -> bool {
        self.parsed.emails.iter().any(|e| e == addr)
    }
}

pub fn import_certificate(input: &[u8]) -> Result<StoredKey> {
    let der = cert_der(input).ok_or_else(|| Error::Invalid("无法识别的证书格式（需要 PEM 或 DER）".into()))?;
    let parsed = ParsedCert::parse(&der).ok_or_else(|| Error::Invalid("无法解析证书".into()))?;
    Ok(StoredKey { info: parsed.info(false), public: parsed.pem()?, secret: None })
}

pub fn import_pkcs12(data: &[u8], password: &str) -> Result<StoredKey> {
    let contents = pkcs12::parse(data, password).map_err(|e| match e {
        P12Error::BadPassword => Error::Invalid("证书密码错误".into()),
        P12Error::Malformed => Error::Invalid("无法解析 PKCS#12 证书文件".into()),
        P12Error::Unsupported(m) => Error::Invalid(m),
    })?;
    let certs: Vec<(ParsedCert, Option<Vec<u8>>)> =
        contents.certs.into_iter().filter_map(|(der, id)| ParsedCert::parse(&der).map(|c| (c, id))).collect();
    for (key_der, key_id) in &contents.keys {
        let rsa = RsaPrivateKey::from_pkcs8_der(key_der).ok();
        let by_public = |c: &ParsedCert| match (&rsa, c.rsa_public()) {
            (Some(k), Some(p)) => p.n() == k.n() && p.e() == k.e(),
            _ => false,
        };
        let cert = certs
            .iter()
            .find(|(c, _)| by_public(c))
            .or_else(|| certs.iter().find(|(_, id)| id.is_some() && id == key_id))
            .map(|(c, _)| c);
        let Some(cert) = cert else { continue };
        let key_pem = der::pem::encode_string("PRIVATE KEY", der::pem::LineEnding::LF, key_der)
            .map_err(|e| Error::Other(format!("私钥编码失败：{e}")))?;
        return Ok(StoredKey { info: cert.info(true), public: cert.pem()?, secret: Some(key_pem) });
    }
    Err(Error::Invalid("证书文件中没有与证书匹配的私钥".into()))
}

pub fn encryption_cert_for<'k>(keys: &'k Keys, addr: &str) -> Option<&'k CertKey> {
    keys.smime
        .iter()
        .filter(|c| c.has_email(addr) && c.parsed.valid_now() && c.parsed.rsa_public().is_some())
        .max_by_key(|c| (c.key.is_some(), c.parsed.not_before))
}

fn signing_cert_for<'k>(keys: &'k Keys, addr: &str) -> Option<&'k CertKey> {
    keys.smime
        .iter()
        .filter(|c| c.key.is_some() && c.has_email(addr) && c.parsed.valid_now())
        .max_by_key(|c| c.parsed.not_before)
}

// ------------------------------------------------------------------ receiving

pub enum Outcome {
    Decrypted(Vec<u8>),
    DecryptFailed(String),
    Signed(Vec<u8>, SignatureStatus, Option<Box<StoredKey>>),
    Unsupported(String),
    /// Nothing to show differently, e.g. a certs-only message.
    Ignore,
}

/// application/pkcs7-mime: enveloped-data is decrypted, signed-data verified and unwrapped.
pub fn process_pkcs7_mime(e: &Entity, keys: &Keys, from: &str) -> Outcome {
    process_cms(&e.decoded_body(), keys, from)
}

fn content_info(der: &[u8]) -> Option<(Tlv<'_>, Tlv<'_>)> {
    let kids = ber::parse_one(der).ok()?.children().ok()?;
    let ct = *kids.first()?;
    let content = kids.get(1)?.explicit().ok()?;
    Some((ct, content))
}

fn process_cms(der: &[u8], keys: &Keys, from: &str) -> Outcome {
    let Some((ct, content)) = content_info(der) else {
        return Outcome::Unsupported("无法解析 S/MIME 数据".into());
    };
    if ct.is_oid(&ID_ENVELOPED_DATA) {
        match decrypt_enveloped(&content, keys) {
            Ok(data) => Outcome::Decrypted(wrap_bare_cms(data)),
            Err(msg) => Outcome::DecryptFailed(msg),
        }
    } else if ct.is_oid(&ID_SIGNED_DATA) {
        let v = verify_signed_data(&content, None, keys, from);
        match v.content {
            Some(inner) => Outcome::Signed(inner, v.status, v.signer.map(Box::new)),
            None => Outcome::Ignore,
        }
    } else if ct.is_oid(&ID_AUTH_ENVELOPED_DATA) {
        Outcome::DecryptFailed("暂不支持 AES-GCM（AuthEnvelopedData）加密的 S/MIME 邮件".into())
    } else if ct.is_oid(&ID_COMPRESSED_DATA) {
        Outcome::Unsupported("暂不支持压缩的 S/MIME 邮件".into())
    } else {
        Outcome::Unsupported("不支持的 S/MIME 内容类型".into())
    }
}

/// Decrypted content that is itself a bare CMS object (not a MIME entity) gets a MIME wrapper.
fn wrap_bare_cms(data: Vec<u8>) -> Vec<u8> {
    if data.first() == Some(&0x30) && content_info(&data).is_some_and(|(ct, _)| ct.is_oid(&ID_SIGNED_DATA)) {
        let mut out = b"Content-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
        out.extend_from_slice(entity::base64_lines(&data).as_bytes());
        return out;
    }
    data
}

fn decrypt_enveloped(ed: &Tlv, keys: &Keys) -> std::result::Result<Vec<u8>, String> {
    let bad = || "加密邮件格式无效".to_string();
    let kids = ed.children().map_err(|_| bad())?;
    let mut i = 1;
    if kids.get(i).is_some_and(|t| t.tag == 0xa0) {
        i += 1; // originatorInfo
    }
    let recipients = kids.get(i).ok_or_else(bad)?.children().map_err(|_| bad())?;
    let eci = kids.get(i + 1).ok_or_else(bad)?.children().map_err(|_| bad())?;
    let alg = eci.get(1).ok_or_else(bad)?;
    let ciphertext = eci.get(2).ok_or_else(bad)?.octets().map_err(|_| bad())?;

    let mut matched = false;
    let mut without_key = false;
    let mut error = None;
    for ri in recipients.iter().filter(|r| r.tag == ber::SEQUENCE) {
        let Ok(k) = ri.children() else { continue };
        let (Some(rid), Some(key_alg), Some(enc_key)) = (k.get(1), k.get(2), k.get(3)) else { continue };
        let Ok(enc_key) = enc_key.octets() else { continue };
        for c in keys.smime.iter().filter(|c| c.parsed.matches_id(rid)) {
            matched = true;
            let Some(private) = &c.key else {
                without_key = true;
                continue;
            };
            let cek = match unwrap_key(private, key_alg, &enc_key) {
                Ok(cek) => cek,
                Err(e) => {
                    error = Some(e);
                    continue;
                }
            };
            match decrypt_content(alg, &cek, &ciphertext) {
                Ok(data) => return Ok(data),
                Err(e) => error = Some(e),
            }
        }
    }
    Err(if !matched {
        "没有可解密此邮件的证书私钥（邮件不是加密给你的证书的）".into()
    } else if without_key && error.is_none() {
        "缺少证书对应的私钥，无法解密".into()
    } else {
        error.unwrap_or_else(|| "邮件解密失败".into())
    })
}

fn alg_parts<'a>(alg: &Tlv<'a>) -> Option<(Oid, Option<Tlv<'a>>)> {
    let k = alg.children().ok()?;
    Some((k.first()?.oid()?, k.get(1).copied()))
}

/// Hash of an AlgorithmIdentifier found inside RSASSA-PSS / RSAES-OAEP parameters.
fn hash_param(t: &Tlv) -> Option<HashAlg> {
    let (oid, _) = alg_parts(&t.explicit().ok()?)?;
    HashAlg::from_digest_oid(&oid)
}

/// The MGF1 hash of a `[1] maskGenAlgorithm` parameter.
fn mgf_param(t: &Tlv) -> Option<HashAlg> {
    let (_, params) = alg_parts(&t.explicit().ok()?)?;
    HashAlg::from_digest_oid(&alg_parts(&params?)?.0)
}

fn unwrap_key(key: &RsaPrivateKey, alg: &Tlv, enc: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let (oid, params) = alg_parts(alg).ok_or_else(|| "加密邮件格式无效".to_string())?;
    let fail = |_| "无法解密邮件密钥：证书私钥不匹配".to_string();
    if oid == RSA_ENCRYPTION {
        return key.decrypt(Pkcs1v15Encrypt, enc).map_err(fail);
    }
    if oid != RSAES_OAEP {
        return Err(format!("不支持的密钥传输算法 {oid}"));
    }
    let (mut hash, mut mgf) = (HashAlg::Sha1, HashAlg::Sha1);
    for p in params.and_then(|p| p.children().ok()).unwrap_or_default() {
        match p.tag {
            0xa0 => hash = hash_param(&p).ok_or("不支持的 OAEP 参数")?,
            0xa1 => mgf = mgf_param(&p).ok_or("不支持的 OAEP 参数")?,
            _ => {}
        }
    }
    with_hash!(hash, H => with_hash!(mgf, M => key.decrypt(Oaep::new_with_mgf_hash::<H, M>(), enc).map_err(fail)))
}

fn decrypt_content(alg: &Tlv, key: &[u8], data: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let (oid, params) = alg_parts(alg).ok_or_else(|| "加密邮件格式无效".to_string())?;
    let iv = params.and_then(|p| p.octets().ok()).unwrap_or_default();
    let plain = match oid {
        AES128_CBC => cbc_decrypt::<aes::Aes128>(key, &iv, data),
        AES192_CBC => cbc_decrypt::<aes::Aes192>(key, &iv, data),
        AES256_CBC => cbc_decrypt::<aes::Aes256>(key, &iv, data),
        DES_EDE3_CBC => cbc_decrypt::<des::TdesEde3>(key, &iv, data),
        other => return Err(format!("不支持的内容加密算法 {other}")),
    };
    plain.ok_or_else(|| "邮件解密失败：数据已损坏".into())
}

struct Verified {
    status: SignatureStatus,
    content: Option<Vec<u8>>,
    signer: Option<StoredKey>,
}

enum SigCheck<'a> {
    Valid(&'a ParsedCert),
    Invalid(Option<&'a ParsedCert>),
    Missing,
    Unsupported,
}

/// Verifies SignedData. `detached` is the signed content of a multipart/signed message.
fn verify_signed_data(sd: &Tlv, detached: Option<&[u8]>, keys: &Keys, from: &str) -> Verified {
    let mut out = Verified { status: status(SigCheck::Unsupported, from), content: None, signer: None };
    let Ok(kids) = sd.children() else { return out };
    let econtent = kids
        .get(2)
        .and_then(|e| e.children().ok())
        .and_then(|e| e.get(1).copied())
        .and_then(|c| c.explicit().ok())
        .and_then(|o| o.octets().ok());
    let embedded: Vec<ParsedCert> = kids
        .iter()
        .skip(3)
        .filter(|t| t.tag == 0xa0)
        .flat_map(|t| t.children().unwrap_or_default())
        .filter(|c| c.tag == ber::SEQUENCE && !c.indefinite)
        .filter_map(|c| ParsedCert::parse(c.raw))
        .collect();
    let signer_infos = kids.iter().skip(3).rfind(|t| t.tag == ber::SET).and_then(|t| t.children().ok()).unwrap_or_default();
    out.content = econtent.clone();
    let Some(content) = detached.or(econtent.as_deref()) else { return out };

    let mut check = SigCheck::Unsupported;
    for si in &signer_infos {
        let c = check_signer_info(si, content, &embedded, keys);
        let done = matches!(c, SigCheck::Valid(_));
        if !matches!(c, SigCheck::Unsupported) || matches!(check, SigCheck::Unsupported) {
            check = c;
        }
        if done {
            break;
        }
    }
    if let SigCheck::Valid(cert) = &check
        && embedded.iter().any(|c| std::ptr::eq(c, *cert))
    {
        out.signer = cert.pem().ok().map(|pem| StoredKey { info: cert.info(false), public: pem, secret: None });
    }
    out.status = status(check, from);
    out
}

fn check_signer_info<'a>(si: &Tlv, content: &[u8], embedded: &'a [ParsedCert], keys: &'a Keys) -> SigCheck<'a> {
    let Ok(k) = si.children() else { return SigCheck::Unsupported };
    let (Some(sid), Some(digest_alg)) = (k.get(1), k.get(2)) else { return SigCheck::Unsupported };
    let (signed_attrs, rest) = match k.get(3) {
        Some(t) if t.tag == 0xa0 => (Some(*t), &k[4..]),
        _ => (None, k.get(3..).unwrap_or_default()),
    };
    let (Some(sig_alg), Some(sig)) = (rest.first(), rest.get(1)) else { return SigCheck::Unsupported };
    let Ok(signature) = sig.octets() else { return SigCheck::Unsupported };
    let cert = embedded
        .iter()
        .find(|c| c.matches_id(sid))
        .or_else(|| keys.smime.iter().map(|c| &c.parsed).find(|c| c.matches_id(sid)));
    let Some(cert) = cert else { return SigCheck::Missing };
    let Some(hash) = alg_parts(digest_alg).and_then(|(o, _)| HashAlg::from_digest_oid(&o)) else {
        return SigCheck::Unsupported;
    };
    let digest = hash.digest(content);
    let signed: Vec<u8> = match signed_attrs {
        Some(attrs) => {
            let Some(md) = attribute(&attrs, &ATTR_MESSAGE_DIGEST).and_then(|v| v.octets().ok()) else {
                return SigCheck::Invalid(Some(cert));
            };
            if md != digest {
                return SigCheck::Invalid(Some(cert));
            }
            attrs.retagged(ber::SET)
        }
        None => content.to_vec(),
    };
    match verify_raw(cert, sig_alg, hash, &signed, &signature) {
        Some(true) => SigCheck::Valid(cert),
        Some(false) => SigCheck::Invalid(Some(cert)),
        None => SigCheck::Unsupported,
    }
}

/// The first value of a signed attribute.
fn attribute<'a>(attrs: &Tlv<'a>, oid: &Oid) -> Option<Tlv<'a>> {
    for a in attrs.children().ok()? {
        let k = a.children().ok()?;
        if k.first()?.is_oid(oid) {
            return k.get(1)?.children().ok()?.first().copied();
        }
    }
    None
}

/// Checks a signature over `data`. None when the algorithm is not supported.
fn verify_raw(cert: &ParsedCert, sig_alg: &Tlv, digest_hash: HashAlg, data: &[u8], sig: &[u8]) -> Option<bool> {
    let (oid, params) = alg_parts(sig_alg)?;
    let rsa_hash = match oid {
        RSA_ENCRYPTION => Some(digest_hash),
        SHA1_WITH_RSA => Some(HashAlg::Sha1),
        SHA224_WITH_RSA => Some(HashAlg::Sha224),
        SHA256_WITH_RSA => Some(HashAlg::Sha256),
        SHA384_WITH_RSA => Some(HashAlg::Sha384),
        SHA512_WITH_RSA => Some(HashAlg::Sha512),
        _ => None,
    };
    if let Some(h) = rsa_hash {
        let key = cert.rsa_public()?;
        let hashed = h.digest(data);
        return Some(with_hash!(h, D => key.verify(Pkcs1v15Sign::new::<D>(), &hashed, sig).is_ok()));
    }
    if oid == RSASSA_PSS {
        let key = cert.rsa_public()?;
        let (mut h, mut salt) = (HashAlg::Sha1, 20usize);
        for p in params.and_then(|p| p.children().ok()).unwrap_or_default() {
            match p.tag {
                0xa0 => h = hash_param(&p)?,
                0xa2 => salt = p.explicit().ok().filter(|i| i.tag == ber::INTEGER && i.content.len() <= 2)?.content.iter().fold(0usize, |a, b| (a << 8) | *b as usize),
                _ => {}
            }
        }
        let hashed = h.digest(data);
        return Some(with_hash!(h, D => key.verify(Pss::new_with_salt::<D>(salt), &hashed, sig).is_ok()));
    }
    let ec_hash = match oid {
        ECDSA_SHA1 => HashAlg::Sha1,
        ECDSA_SHA224 => HashAlg::Sha224,
        ECDSA_SHA256 => HashAlg::Sha256,
        ECDSA_SHA384 => HashAlg::Sha384,
        ECDSA_SHA512 => HashAlg::Sha512,
        EC_PUBLIC_KEY => digest_hash,
        _ => return None,
    };
    let spki = &cert.cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != EC_PUBLIC_KEY {
        return Some(false);
    }
    let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<Oid>().ok())?;
    let point = spki.subject_public_key.raw_bytes();
    let hashed = ec_hash.digest(data);
    match curve {
        CURVE_P256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).ok()?;
            let s = p256::ecdsa::Signature::from_der(sig).ok()?;
            Some(key.verify_prehash(&hashed, &s).is_ok())
        }
        CURVE_P384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).ok()?;
            let s = p384::ecdsa::Signature::from_der(sig).ok()?;
            Some(key.verify_prehash(&hashed, &s).is_ok())
        }
        _ => None,
    }
}

fn status(check: SigCheck, from: &str) -> SignatureStatus {
    let mut s = SignatureStatus { kind: "smime".into(), ..Default::default() };
    match check {
        SigCheck::Valid(c) => {
            s.key_id = Some(c.id());
            s.signer = c.emails.iter().find(|e| *e == from).or(c.emails.first()).cloned().or_else(|| Some(c.id()));
            let matches = from.is_empty() || c.emails.iter().any(|e| e == from);
            if !matches {
                s.message = format!("签名本身有效，但签名证书（{}）与发件人 {from} 不一致", c.display());
            } else {
                s.valid = true;
                s.message = format!("签名有效（{}）", c.display());
                if now() > c.not_after {
                    let date = chrono::DateTime::from_timestamp(c.not_after, 0).map(|d| d.format("%Y-%m-%d").to_string());
                    s.message.push_str(&format!("，但证书已于 {} 过期", date.unwrap_or_default()));
                }
            }
        }
        SigCheck::Invalid(c) => {
            s.key_id = c.map(|c| c.id());
            s.signer = c.and_then(|c| c.emails.first().cloned());
            s.message = "签名无效：邮件内容可能已被篡改".into();
        }
        SigCheck::Missing => s.message = "缺少发件人的证书，无法验证".into(),
        SigCheck::Unsupported => s.message = "不支持的签名格式或算法，无法验证".into(),
    }
    s
}

/// multipart/signed; protocol="application/pkcs7-signature": the signed entity and the result.
pub fn verify_detached_mime(e: &Entity, keys: &Keys, from: &str) -> Option<(Vec<u8>, SignatureStatus, Option<StoredKey>)> {
    let parts = e.parts();
    if parts.len() < 2 {
        return None;
    }
    let content = entity::to_crlf(parts[0]);
    let der = Entity::parse(parts[1]).decoded_body();
    let v = match content_info(&der) {
        Some((ct, sd)) if ct.is_oid(&ID_SIGNED_DATA) => verify_signed_data(&sd, Some(&content), keys, from),
        _ => Verified { status: status(SigCheck::Unsupported, from), content: None, signer: None },
    };
    Some((parts[0].to_vec(), v.status, v.signer))
}

// ------------------------------------------------------------------ sending

pub struct SmimePlan<'k> {
    signer: Option<&'k CertKey>,
    recipients: Vec<&'k CertKey>,
    encrypt: bool,
}

pub fn plan<'k>(req: &Request, keys: &'k Keys) -> Result<Plan<'k>> {
    let signer = if req.sign {
        Some(
            signing_cert_for(keys, req.from)
                .ok_or_else(|| Error::Invalid(format!("没有 {} 的 S/MIME 证书和私钥，无法签名", req.from)))?,
        )
    } else {
        None
    };
    let mut recipients: Vec<&CertKey> = Vec::new();
    if req.encrypt {
        let mut missing = Vec::new();
        for r in req.recipients {
            match encryption_cert_for(keys, r) {
                Some(c) => recipients.push(c),
                None => missing.push(r.clone()),
            }
        }
        if !missing.is_empty() {
            return Err(Error::Invalid(format!("以下收件人没有可用的 S/MIME 证书，无法加密：{}", join_addrs(&missing))));
        }
        let own = encryption_cert_for(keys, req.from).ok_or_else(|| {
            Error::Invalid(format!("没有发件人 {} 自己的 S/MIME 证书，加密后将无法阅读已发送的邮件", req.from))
        })?;
        recipients.push(own);
        let mut seen = std::collections::HashSet::new();
        recipients.retain(|c| seen.insert(c.info.id.clone()));
    }
    Ok(Plan::Smime(SmimePlan { signer, recipients, encrypt: req.encrypt }))
}

fn attr(oid: &Oid, value: Vec<u8>) -> Vec<u8> {
    ber::seq(&[&ber::oid(oid), &ber::set_of(vec![value])])
}

fn issuer_and_serial(c: &ParsedCert) -> Vec<u8> {
    ber::seq(&[&c.issuer, &ber::tlv(ber::INTEGER, &c.serial)])
}

/// Detached SignedData (DER) over `content`: RSA PKCS#1 v1.5 with SHA-256, signer certificate included.
fn sign_detached(content: &[u8], signer: &CertKey) -> Result<Vec<u8>> {
    let key = signer.key.as_ref().ok_or_else(|| Error::Invalid("缺少证书私钥".into()))?;
    let cert = &signer.parsed;
    let time = chrono::Utc::now().format("%y%m%d%H%M%SZ").to_string();
    let caps = ber::seq(&[
        &ber::alg_id(&AES256_CBC, false),
        &ber::alg_id(&AES192_CBC, false),
        &ber::alg_id(&AES128_CBC, false),
        &ber::alg_id(&DES_EDE3_CBC, false),
    ]);
    let attrs = ber::set_of(vec![
        attr(&ATTR_CONTENT_TYPE, ber::oid(&ID_DATA)),
        attr(&ATTR_SIGNING_TIME, ber::tlv(0x17, time.as_bytes())),
        attr(&ATTR_MESSAGE_DIGEST, ber::octet_string(&Sha256::digest(content))),
        attr(&ATTR_SMIME_CAPABILITIES, caps),
    ]);
    let signature = key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&attrs))
        .map_err(|e| Error::Invalid(format!("签名失败：{e}")))?;
    let mut attrs_implicit = attrs;
    attrs_implicit[0] = 0xa0;
    let sha256 = ber::alg_id(&super::hashes::SHA256, false);
    let signer_info = ber::seq(&[
        &ber::small_int(1),
        &issuer_and_serial(cert),
        &sha256,
        &attrs_implicit,
        &ber::alg_id(&RSA_ENCRYPTION, true),
        &ber::octet_string(&signature),
    ]);
    let signed_data = ber::seq(&[
        &ber::small_int(1),
        &ber::set_of(vec![sha256.clone()]),
        &ber::seq(&[&ber::oid(&ID_DATA)]),
        &ber::tlv(0xa0, &cert.der),
        &ber::set_of(vec![signer_info]),
    ]);
    Ok(ber::seq(&[&ber::oid(&ID_SIGNED_DATA), &ber::tlv(0xa0, &signed_data)]))
}

/// EnvelopedData (DER): AES-256-CBC content, RSA PKCS#1 v1.5 key transport to each recipient.
fn envelope(content: &[u8], recipients: &[&CertKey]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
        .map_err(|e| Error::Other(e.to_string()))?
        .encrypt_padded_vec_mut::<Pkcs7>(content);
    let mut infos = Vec::new();
    for c in recipients {
        let public = c.parsed.rsa_public().ok_or_else(|| Error::Invalid(format!("{} 的证书不是 RSA 证书，无法加密", c.parsed.display())))?;
        let enc = public.encrypt(&mut rng, Pkcs1v15Encrypt, &key).map_err(|e| Error::Invalid(format!("加密失败：{e}")))?;
        infos.push(ber::seq(&[
            &ber::small_int(0),
            &issuer_and_serial(&c.parsed),
            &ber::alg_id(&RSA_ENCRYPTION, true),
            &ber::octet_string(&enc),
        ]));
    }
    let eci = ber::seq(&[
        &ber::oid(&ID_DATA),
        &ber::seq(&[&ber::oid(&AES256_CBC), &ber::octet_string(&iv)]),
        &ber::tlv(0x80, &ciphertext),
    ]);
    let enveloped = ber::seq(&[&ber::small_int(0), &ber::set_of(infos), &eci]);
    Ok(ber::seq(&[&ber::oid(&ID_ENVELOPED_DATA), &ber::tlv(0xa0, &enveloped)]))
}

impl SmimePlan<'_> {
    /// Returns the top-level Content-* header lines and the body.
    pub fn execute(self, entity: &[u8]) -> Result<(String, Vec<u8>)> {
        let protected = match self.signer {
            Some(signer) => {
                let p7s = sign_detached(entity, signer)?;
                let sig_part = format!(
                    "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n\
                     Content-Transfer-Encoding: base64\r\n\
                     Content-Disposition: attachment; filename=\"smime.p7s\"\r\n\
                     Content-Description: S/MIME Cryptographic Signature\r\n\r\n{}",
                    entity::base64_lines(&p7s)
                );
                let b = entity::boundary(entity);
                let body = entity::multipart_body(
                    &b,
                    "This is a cryptographically signed message in MIME format.",
                    &[entity, sig_part.as_bytes()],
                );
                let ct = format!(
                    "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256;\r\n boundary=\"{b}\"\r\n"
                );
                if !self.encrypt {
                    return Ok((ct, body));
                }
                let mut e = ct.into_bytes();
                e.extend_from_slice(b"\r\n");
                e.extend_from_slice(&body);
                e
            }
            None => entity.to_vec(),
        };
        let p7m = envelope(&protected, &self.recipients)?;
        let headers = "Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\n\
                       Content-Transfer-Encoding: base64\r\n\
                       Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\
                       Content-Description: S/MIME Encrypted Message\r\n"
            .to_string();
        Ok((headers, entity::base64_lines(&p7m).into_bytes()))
    }
}

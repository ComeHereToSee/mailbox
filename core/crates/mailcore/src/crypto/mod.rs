//! End-to-end encryption and signatures: OpenPGP (PGP/MIME, RFC 3156, and inline) and S/MIME
//! (RFC 8551) for reading and sending mail.
//!
//! Everything is pure Rust: OpenPGP through rPGP, S/MIME and PKCS#12 through a small BER/DER
//! layer on top of the RustCrypto primitives. Received messages go through
//! [`process_incoming`], which decrypts and verifies and hands back the protected inner entity;
//! outgoing ones through [`protect_outgoing`], which wraps a built message.

mod ber;
mod entity;
mod hashes;
mod pgp;
mod pkcs12;
mod smime;

#[cfg(test)]
mod tests;

use crate::error::{Error, Result};
use entity::Entity;
use serde::{Deserialize, Serialize};

pub use pgp::generate_pgp;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// Fingerprint (upper-case hex) for PGP, SHA-256 of the certificate DER (upper-case hex) for S/MIME.
    pub id: String,
    /// `"pgp"` or `"smime"`.
    pub kind: String,
    /// Lower-case addresses from the user ids / the certificate's SAN and subject.
    pub emails: Vec<String>,
    /// User id names / certificate common names.
    pub names: Vec<String>,
    pub has_secret: bool,
    pub created: i64,
    pub expires: Option<i64>,
}

/// Stored key material. `public` = ASCII-armored public key (PGP) or PEM certificate (S/MIME).
/// `secret` = armored secret key (PGP, may be passphrase protected) or PKCS#8 PEM private key
/// (S/MIME, unencrypted).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredKey {
    pub info: KeyInfo,
    pub public: String,
    pub secret: Option<String>,
}

/// Imports an armored OpenPGP public or secret key block (the first key in it; a secret key wins
/// over a public one).
pub fn import_pgp(armored: &str) -> Result<StoredKey> {
    pgp::import(armored)
}

/// Imports a `.p12` / `.pfx` file holding a certificate and its private key.
pub fn import_pkcs12(der: &[u8], password: &str) -> Result<StoredKey> {
    smime::import_pkcs12(der, password)
}

/// Imports someone else's S/MIME certificate (PEM or DER).
pub fn import_certificate(pem_or_der: &[u8]) -> Result<StoredKey> {
    smime::import_certificate(pem_or_der)
}

/// Something that can find keys. The engine implements it over its key store.
pub trait Keyring {
    fn keys(&self) -> Vec<StoredKey>;
    /// Passphrase for a PGP secret key (by [`KeyInfo::id`]), if the user stored one.
    fn passphrase(&self, key_id: &str) -> Option<String>;
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct SignatureStatus {
    /// `"pgp"` or `"smime"`.
    pub kind: String,
    pub valid: bool,
    /// E-mail address (or key id) of the signer.
    pub signer: Option<String>,
    pub key_id: Option<String>,
    /// Human readable result, e.g. "签名有效（张三 <a@b.com>）".
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Incoming {
    /// The decrypted / unwrapped inner MIME entity (headers + body), ready for `mime::parse_full`.
    pub inner: Option<Vec<u8>>,
    pub encrypted: bool,
    pub decrypted: bool,
    pub decrypt_error: Option<String>,
    pub signature: Option<SignatureStatus>,
    /// The certificate an S/MIME signer attached to a valid signature, so the engine can add it to
    /// the key store (needed to encrypt replies to that sender).
    pub signer_certificate: Option<StoredKey>,
}

/// The keyring's keys, parsed once per operation.
pub(crate) struct Keys<'a> {
    pub pgp: Vec<pgp::PgpKey>,
    pub smime: Vec<smime::CertKey>,
    pub ring: &'a dyn Keyring,
}

impl<'a> Keys<'a> {
    fn load(ring: &'a dyn Keyring) -> Keys<'a> {
        let mut pgp_keys = Vec::new();
        let mut smime_keys = Vec::new();
        for k in ring.keys() {
            match k.info.kind.as_str() {
                "pgp" => pgp_keys.extend(pgp::PgpKey::load(&k)),
                "smime" => smime_keys.extend(smime::CertKey::load(&k)),
                _ => {}
            }
        }
        Keys { pgp: pgp_keys, smime: smime_keys, ring }
    }
}

fn normalize_addr(a: &str) -> String {
    let a = a.trim();
    let a = match (a.rfind('<'), a.rfind('>')) {
        (Some(s), Some(e)) if e > s => &a[s + 1..e],
        _ => a,
    };
    a.trim().to_ascii_lowercase()
}

/// Inspects a received raw RFC 5322 message: decrypts PGP/MIME, inline PGP and S/MIME
/// enveloped-data with the keyring's secret keys and verifies PGP/MIME, inline PGP and S/MIME
/// (detached and opaque) signatures. `from` is the From address the signer must match.
///
/// A plain message gives `Incoming::default()`.
pub fn process_incoming(raw: &[u8], from: &str, keyring: &dyn Keyring) -> Incoming {
    let keys = Keys::load(keyring);
    let from = normalize_addr(from);
    let mut out = Incoming::default();
    let mut current: Option<Vec<u8>> = None;
    // A few layers at most: e.g. S/MIME enveloped → opaque signed → MIME entity.
    for depth in 0..4 {
        let bytes: &[u8] = current.as_deref().unwrap_or(raw);
        let e = Entity::parse(bytes);
        let next = match classify(&e) {
            Kind::PgpEncrypted => {
                out.encrypted = true;
                match pgp::decrypt_mime(&e, &keys, &from) {
                    Ok((inner, sig)) => {
                        out.decrypted = true;
                        if out.signature.is_none() {
                            out.signature = sig;
                        }
                        Some(inner)
                    }
                    Err(msg) => {
                        out.decrypt_error = Some(msg);
                        None
                    }
                }
            }
            Kind::PgpSigned => pgp::verify_mime(&e, &keys, &from).map(|(inner, sig)| {
                out.signature.get_or_insert(sig);
                inner
            }),
            Kind::SmimeDetached => smime::verify_detached_mime(&e, &keys, &from).map(|(inner, sig, cert)| {
                if out.signature.is_none() {
                    out.signature = Some(sig);
                    out.signer_certificate = cert;
                }
                inner
            }),
            Kind::Smime => match smime::process_pkcs7_mime(&e, &keys, &from) {
                smime::Outcome::Decrypted(inner) => {
                    out.encrypted = true;
                    out.decrypted = true;
                    Some(inner)
                }
                smime::Outcome::DecryptFailed(msg) => {
                    out.encrypted = true;
                    out.decrypt_error = Some(msg);
                    None
                }
                smime::Outcome::Signed(inner, sig, cert) => {
                    if out.signature.is_none() {
                        out.signature = Some(sig);
                        out.signer_certificate = cert.map(|c| *c);
                    }
                    Some(inner)
                }
                smime::Outcome::Unsupported(msg) => {
                    out.decrypt_error.get_or_insert(msg);
                    None
                }
                smime::Outcome::Ignore => None,
            },
            Kind::Plain if depth == 0 => pgp::process_inline(bytes, &keys, &from, &mut out),
            Kind::Plain => None,
        };
        match next {
            Some(n) => current = Some(n),
            None => break,
        }
    }
    out.inner = current;
    out
}

enum Kind {
    PgpEncrypted,
    PgpSigned,
    SmimeDetached,
    Smime,
    Plain,
}

fn classify(e: &Entity) -> Kind {
    let protocol = e.ctype.param_lc("protocol");
    match e.ctype.mime.as_str() {
        "multipart/encrypted" => {
            let first_is_pgp = e.children().first().is_some_and(|c| c.ctype.mime == "application/pgp-encrypted");
            if protocol == "application/pgp-encrypted" || first_is_pgp { Kind::PgpEncrypted } else { Kind::Plain }
        }
        "multipart/signed" => match protocol.as_str() {
            "application/pgp-signature" => Kind::PgpSigned,
            "application/pkcs7-signature" | "application/x-pkcs7-signature" => Kind::SmimeDetached,
            _ => Kind::Plain,
        },
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => Kind::Smime,
        "application/octet-stream" => {
            let name = e.ctype.param_lc("name");
            let disposition = e.header("content-disposition").unwrap_or("").to_ascii_lowercase();
            if name.ends_with(".p7m") || disposition.contains(".p7m") { Kind::Smime } else { Kind::Plain }
        }
        _ => Kind::Plain,
    }
}

pub struct OutgoingCrypto<'a> {
    pub sign: bool,
    pub encrypt: bool,
    /// `"pgp"` or `"smime"`. The other one is used when only it can do what is asked.
    pub prefer: &'a str,
    pub from: &'a str,
    /// All To/Cc/Bcc addresses (lower-case).
    pub recipients: &'a [String],
}

/// Wraps an already built message (raw RFC 5322 from `mime::build::build`) into PGP/MIME or
/// S/MIME. The top-level headers stay, the `Content-*` headers and the body become the protected
/// entity, which is then signed (multipart/signed) and/or encrypted (multipart/encrypted for
/// PGP, application/pkcs7-mime for S/MIME). Encrypted mail is also encrypted to the sender's own
/// key so the Sent copy stays readable.
pub fn protect_outgoing(raw: &[u8], opts: &OutgoingCrypto, keyring: &dyn Keyring) -> Result<Vec<u8>> {
    if !opts.sign && !opts.encrypt {
        return Ok(raw.to_vec());
    }
    let keys = Keys::load(keyring);
    let from = normalize_addr(opts.from);
    if from.is_empty() {
        return Err(Error::Invalid("缺少发件人".into()));
    }
    let mut recipients: Vec<String> = Vec::new();
    for r in opts.recipients {
        let r = normalize_addr(r);
        if !r.is_empty() && !recipients.contains(&r) {
            recipients.push(r);
        }
    }
    if opts.encrypt && recipients.is_empty() {
        return Err(Error::Invalid("没有收件人，无法加密".into()));
    }
    let (top, entity) = entity::split_for_protection(raw);
    let req = Request { sign: opts.sign, encrypt: opts.encrypt, from: &from, recipients: &recipients };
    let smime_first = opts.prefer.eq_ignore_ascii_case("smime");
    let first = if smime_first { smime::plan(&req, &keys) } else { pgp::plan(&req, &keys) };
    match first {
        Ok(plan) => plan.execute(&top, &entity, &keys),
        Err(err) => {
            let second = if smime_first { pgp::plan(&req, &keys) } else { smime::plan(&req, &keys) };
            match second {
                Ok(plan) => plan.execute(&top, &entity, &keys),
                Err(_) => Err(err),
            }
        }
    }
}

pub(crate) struct Request<'a> {
    pub sign: bool,
    pub encrypt: bool,
    pub from: &'a str,
    pub recipients: &'a [String],
}

/// A protection both sides can do, chosen before anything is built.
pub(crate) enum Plan<'k> {
    Pgp(pgp::PgpPlan<'k>),
    Smime(smime::SmimePlan<'k>),
}

impl Plan<'_> {
    fn execute(self, top: &[u8], entity: &[u8], keys: &Keys) -> Result<Vec<u8>> {
        let (content_headers, body) = match self {
            Plan::Pgp(p) => p.execute(entity, keys)?,
            Plan::Smime(p) => p.execute(entity)?,
        };
        let mut out = top.to_vec();
        if !top.windows(13).any(|w| w.eq_ignore_ascii_case(b"mime-version:")) {
            out.extend_from_slice(b"MIME-Version: 1.0\r\n");
        }
        out.extend_from_slice(content_headers.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Which recipients have usable encryption keys (for the composer's lock toggle): an OpenPGP key
/// with a valid encryption (sub)key or an S/MIME certificate with an RSA key.
pub fn recipients_with_keys(recipients: &[String], keyring: &dyn Keyring) -> (Vec<String>, Vec<String>) {
    let keys = Keys::load(keyring);
    let mut have = Vec::new();
    let mut missing = Vec::new();
    for r in recipients {
        let a = normalize_addr(r);
        if a.is_empty() {
            continue;
        }
        if pgp::encryption_key_for(&keys, &a).is_some() || smime::encryption_cert_for(&keys, &a).is_some() {
            have.push(r.clone());
        } else {
            missing.push(r.clone());
        }
    }
    (have, missing)
}

/// "a@x.com、b@y.com" for error messages.
fn join_addrs(v: &[String]) -> String {
    v.join("、")
}

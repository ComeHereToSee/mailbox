//! Round trips through the real pipeline (`mime::build` → `protect_outgoing` → `process_incoming`
//! → `mime::parse_full`) and interoperability with messages written by GnuPG and OpenSSL
//! (fixtures in `testdata/`, produced by `testdata/gen.sh`).

use super::*;
use crate::mime::build::{OutAttachment, Outgoing, build};
use crate::model::EmailAddress;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Default, Clone)]
struct Ring {
    keys: Vec<StoredKey>,
    passphrases: HashMap<String, String>,
}

impl Keyring for Ring {
    fn keys(&self) -> Vec<StoredKey> {
        self.keys.clone()
    }
    fn passphrase(&self, key_id: &str) -> Option<String> {
        self.passphrases.get(key_id).cloned()
    }
}

fn ring(keys: &[&StoredKey]) -> Ring {
    Ring { keys: keys.iter().map(|k| (*k).clone()).collect(), passphrases: HashMap::new() }
}

fn public_only(k: &StoredKey) -> StoredKey {
    StoredKey { info: KeyInfo { has_secret: false, ..k.info.clone() }, public: k.public.clone(), secret: None }
}

const BODY: &str = "你好，这是一封机密邮件。\nTrailing space here \n-- \n张三";
const ATTACHMENT: &[u8] = b"%PDF-1.4 secret attachment";

fn message(from: &str, to: &str) -> Vec<u8> {
    let o = Outgoing {
        from: EmailAddress::new(Some("张三"), from),
        to: vec![EmailAddress::new(None, to)],
        subject: "合同（机密）".into(),
        text: BODY.into(),
        html: Some("<p>你好，这是一封机密邮件。</p>".into()),
        attachments: vec![OutAttachment {
            filename: "合同.pdf".into(),
            mime: "application/pdf".into(),
            data: ATTACHMENT.to_vec(),
            content_id: None,
        }],
        message_id: "m1@x.example".into(),
        in_reply_to: Some("parent@x.example".into()),
        date: 1_792_634_400,
        ..Default::default()
    };
    build(&o, false).unwrap()
}

/// The inner entity parses to the original body and attachment.
fn check_inner(inner: &[u8]) {
    let (h, b) = crate::mime::parse_full(inner);
    assert!(h.subject.is_empty(), "inner entity has no Subject");
    assert_eq!(b.text.as_deref().map(|t| t.replace("\r\n", "\n")), Some(BODY.to_string()));
    assert!(b.html.unwrap().contains("机密邮件"));
    let att = b.attachments.iter().find(|a| !a.inline).expect("attachment");
    assert_eq!(att.filename, "合同.pdf");
    let (_, mime, data) = crate::mime::part_bytes(inner, att.id as usize).unwrap();
    assert_eq!(mime, "application/pdf");
    assert_eq!(data, ATTACHMENT);
}

fn opts<'a>(sign: bool, encrypt: bool, prefer: &'a str, from: &'a str, to: &'a [String]) -> OutgoingCrypto<'a> {
    OutgoingCrypto { sign, encrypt, prefer, from, recipients: to }
}

/// Flips one character inside the first body part of a multipart/signed message.
fn tamper(raw: &[u8]) -> Vec<u8> {
    let s = String::from_utf8(raw.to_vec()).unwrap();
    let pos = s.find("JVBER").expect("attachment base64 in the signed part");
    let mut v = raw.to_vec();
    v[pos + 1] = b'W';
    v
}

fn top_header(raw: &[u8], name: &str) -> String {
    let e = entity::Entity::parse(raw);
    e.header(name).unwrap_or_default().to_string()
}

struct PgpKeys {
    alice: StoredKey,
    bob: StoredKey,
    carol: StoredKey,
}

fn pgp_keys() -> &'static PgpKeys {
    static KEYS: OnceLock<PgpKeys> = OnceLock::new();
    KEYS.get_or_init(|| PgpKeys {
        alice: generate_pgp("Alice 爱丽丝", "Alice@Example.com", None).unwrap(),
        bob: generate_pgp("Bob", "bob@example.org", None).unwrap(),
        carol: generate_pgp("", "carol@example.net", None).unwrap(),
    })
}

#[test]
fn pgp_key_generation_and_import() {
    let k = pgp_keys();
    assert_eq!(k.alice.info.kind, "pgp");
    assert_eq!(k.alice.info.emails, vec!["alice@example.com"]);
    assert_eq!(k.alice.info.names, vec!["Alice 爱丽丝"]);
    assert!(k.alice.info.has_secret);
    assert_eq!(k.alice.info.id.len(), 40);
    assert!(k.alice.info.id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
    assert!(k.alice.public.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    assert!(k.alice.secret.as_deref().unwrap().contains("BEGIN PGP PRIVATE KEY BLOCK"));
    // Re-importing the public or the secret block gives the same key.
    let public = import_pgp(&k.alice.public).unwrap();
    assert_eq!(public.info, KeyInfo { has_secret: false, ..k.alice.info.clone() });
    let secret = import_pgp(k.alice.secret.as_deref().unwrap()).unwrap();
    assert_eq!(secret.info, k.alice.info);
    assert!(import_pgp("not a key").is_err());
}

#[test]
fn pgp_round_trips() {
    let k = pgp_keys();
    let sender = ring(&[&k.alice, &public_only(&k.bob)]);
    let receiver = ring(&[&k.bob, &public_only(&k.alice)]);
    let to = vec!["bob@example.org".to_string()];
    let raw = message("alice@example.com", "bob@example.org");
    let (_, entity) = entity::split_for_protection(&raw);

    // Sign only.
    let signed = protect_outgoing(&raw, &opts(true, false, "pgp", "alice@example.com", &to), &sender).unwrap();
    let ct = top_header(&signed, "content-type");
    assert!(ct.starts_with("multipart/signed;") && ct.contains("application/pgp-signature"), "{ct}");
    let (h, _) = crate::mime::parse_full(&signed);
    assert_eq!(h.subject, "合同（机密）");
    assert_eq!(h.in_reply_to.as_deref(), Some("parent@x.example"));
    let inc = process_incoming(&signed, "Alice <alice@example.com>", &receiver);
    assert!(!inc.encrypted && !inc.decrypted);
    let sig = inc.signature.clone().unwrap();
    assert!(sig.valid, "{sig:?}");
    assert_eq!(sig.kind, "pgp");
    assert_eq!(sig.signer.as_deref(), Some("alice@example.com"));
    assert_eq!(sig.key_id.as_deref(), Some(k.alice.info.id.as_str()));
    assert_eq!(sig.message, "签名有效（Alice 爱丽丝 <Alice@Example.com>）");
    assert_eq!(inc.inner.as_deref(), Some(entity.as_slice()));
    check_inner(inc.inner.as_deref().unwrap());

    // Tampering is detected; a signature by someone else's key is not trusted for this From.
    let bad = process_incoming(&tamper(&signed), "alice@example.com", &receiver).signature.unwrap();
    assert!(!bad.valid);
    assert!(bad.message.contains("签名无效"), "{}", bad.message);
    let spoof = process_incoming(&signed, "ceo@example.com", &receiver).signature.unwrap();
    assert!(!spoof.valid && spoof.message.contains("不属于发件人"), "{}", spoof.message);
    // LF line endings (e.g. a message saved to disk) still verify thanks to canonicalization.
    let lf = String::from_utf8(signed.clone()).unwrap().replace("\r\n", "\n");
    assert!(process_incoming(lf.as_bytes(), "alice@example.com", &receiver).signature.unwrap().valid);
    // Without the signer's key.
    let unknown = process_incoming(&signed, "alice@example.com", &ring(&[&k.bob])).signature.unwrap();
    assert!(!unknown.valid);
    assert_eq!(unknown.message, "缺少发件人的公钥，无法验证");

    // Encrypt only.
    let enc = protect_outgoing(&raw, &opts(false, true, "pgp", "alice@example.com", &to), &sender).unwrap();
    let ct = top_header(&enc, "content-type");
    assert!(ct.starts_with("multipart/encrypted;") && ct.contains("application/pgp-encrypted"), "{ct}");
    assert!(!String::from_utf8_lossy(&enc).contains("JVBER"), "body must not leak");
    assert_eq!(crate::mime::parse_full(&enc).0.subject, "合同（机密）");
    let inc = process_incoming(&enc, "alice@example.com", &receiver);
    assert!(inc.encrypted && inc.decrypted, "{:?}", inc.decrypt_error);
    assert!(inc.signature.is_none());
    assert_eq!(inc.inner.as_deref(), Some(entity.as_slice()));
    check_inner(inc.inner.as_deref().unwrap());
    // The Sent copy is readable by the sender.
    let own = process_incoming(&enc, "alice@example.com", &sender);
    assert!(own.decrypted, "{:?}", own.decrypt_error);
    // Someone else cannot read it.
    let other = process_incoming(&enc, "alice@example.com", &ring(&[&k.carol]));
    assert!(other.encrypted && !other.decrypted && other.inner.is_none());
    assert!(other.decrypt_error.unwrap().contains("没有可解密此邮件的私钥"));

    // Sign and encrypt.
    let both = protect_outgoing(&raw, &opts(true, true, "pgp", "alice@example.com", &to), &sender).unwrap();
    let inc = process_incoming(&both, "alice@example.com", &receiver);
    assert!(inc.decrypted, "{:?}", inc.decrypt_error);
    assert!(inc.signature.as_ref().unwrap().valid, "{:?}", inc.signature);
    check_inner(inc.inner.as_deref().unwrap());
    // Encrypted and signed, but the receiver lacks the sender's key.
    let inc = process_incoming(&both, "alice@example.com", &ring(&[&k.bob]));
    assert!(inc.decrypted);
    assert!(!inc.signature.unwrap().valid);
}

#[test]
fn pgp_missing_keys() {
    let k = pgp_keys();
    let sender = ring(&[&k.alice, &public_only(&k.bob)]);
    let raw = message("alice@example.com", "bob@example.org");
    let to = vec!["bob@example.org".to_string(), "nokey@example.net".to_string(), "x@y.org".to_string()];
    let err = protect_outgoing(&raw, &opts(false, true, "pgp", "alice@example.com", &to), &sender).unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("nokey@example.net、x@y.org")), "{err}");
    // No secret key to sign with.
    let err = protect_outgoing(&raw, &opts(true, false, "pgp", "alice@example.com", &[]), &ring(&[&public_only(&k.alice)]))
        .unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("alice@example.com")), "{err}");
    // The sender has no key of their own: the Sent copy would be unreadable.
    let err = protect_outgoing(
        &raw,
        &opts(false, true, "pgp", "alice@example.com", &["bob@example.org".to_string()]),
        &ring(&[&public_only(&k.bob)]),
    )
    .unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("自己的")), "{err}");
    // Nothing requested: unchanged.
    assert_eq!(protect_outgoing(&raw, &opts(false, false, "pgp", "a@b.c", &[]), &sender).unwrap(), raw);

    let (have, missing) = recipients_with_keys(&to, &sender);
    assert_eq!(have, vec!["bob@example.org"]);
    assert_eq!(missing, vec!["nokey@example.net", "x@y.org"]);
}

#[test]
fn pgp_passphrase_protected_key() {
    let k = pgp_keys();
    let dana = generate_pgp("Dana", "dana@example.com", Some("geheim")).unwrap();
    let id = dana.info.id.clone();
    let mut sender = ring(&[&dana, &public_only(&k.bob)]);
    let raw = message("dana@example.com", "bob@example.org");
    let to = vec!["bob@example.org".to_string()];
    let err = protect_outgoing(&raw, &opts(true, false, "pgp", "dana@example.com", &to), &sender).unwrap_err();
    assert!(err.to_string().contains("密码"), "{err}");
    sender.passphrases.insert(id.clone(), "wrong".into());
    let err = protect_outgoing(&raw, &opts(true, false, "pgp", "dana@example.com", &to), &sender).unwrap_err();
    assert_eq!(err.to_string(), "参数错误: 私钥密码错误，无法签名");
    sender.passphrases.insert(id.clone(), "geheim".into());
    let enc = protect_outgoing(&raw, &opts(true, true, "pgp", "dana@example.com", &to), &sender).unwrap();
    let inc = process_incoming(&enc, "dana@example.com", &ring(&[&k.bob, &public_only(&dana)]));
    assert!(inc.decrypted && inc.signature.unwrap().valid);
    // Dana reading her Sent copy needs the passphrase.
    let locked = process_incoming(&enc, "dana@example.com", &ring(&[&dana]));
    assert!(!locked.decrypted);
    assert!(locked.decrypt_error.unwrap().contains("密码"));
    assert!(process_incoming(&enc, "dana@example.com", &sender).decrypted);
}

struct SmimeKeys {
    alice: StoredKey,
    bob: StoredKey,
}

fn smime_keys() -> &'static SmimeKeys {
    static KEYS: OnceLock<SmimeKeys> = OnceLock::new();
    KEYS.get_or_init(|| SmimeKeys {
        alice: import_pkcs12(include_bytes!("testdata/alice.p12"), "alice-pass").unwrap(),
        bob: import_pkcs12(include_bytes!("testdata/bob.p12"), "bob-pass").unwrap(),
    })
}

#[test]
fn smime_import() {
    let k = smime_keys();
    assert_eq!(k.alice.info.kind, "smime");
    assert_eq!(k.alice.info.emails, vec!["alice@example.com"]);
    assert_eq!(k.alice.info.names, vec!["爱丽丝 Alice"]);
    assert!(k.alice.info.has_secret);
    assert_eq!(k.alice.info.id.len(), 64);
    assert!(k.alice.info.expires.unwrap() > k.alice.info.created);
    assert!(k.alice.public.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(k.alice.secret.as_deref().unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
    // Legacy 3DES / RC2 PKCS#12 and the bare certificate describe the same certificate.
    let legacy = import_pkcs12(include_bytes!("testdata/bob_legacy.p12"), "bob-pass").unwrap();
    assert_eq!(legacy.info, k.bob.info);
    let cert = import_certificate(include_bytes!("testdata/bob.crt")).unwrap();
    assert_eq!(cert.info, KeyInfo { has_secret: false, ..k.bob.info.clone() });
    assert!(cert.secret.is_none());
    // DER works as well.
    let der = der::pem::decode_vec(cert.public.as_bytes()).unwrap().1;
    assert_eq!(import_certificate(&der).unwrap().info.id, cert.info.id);
    let err = import_pkcs12(include_bytes!("testdata/bob.p12"), "nope").unwrap_err();
    assert_eq!(err.to_string(), "参数错误: 证书密码错误");
    assert!(import_certificate(b"garbage").is_err());
}

#[test]
fn smime_round_trips() {
    let k = smime_keys();
    let sender = ring(&[&k.alice, &public_only(&k.bob)]);
    let receiver = ring(&[&k.bob, &public_only(&k.alice)]);
    let to = vec!["bob@example.org".to_string()];
    let raw = message("alice@example.com", "bob@example.org");
    let (_, entity) = entity::split_for_protection(&raw);

    // Sign only (detached, multipart/signed).
    let signed = protect_outgoing(&raw, &opts(true, false, "smime", "alice@example.com", &to), &sender).unwrap();
    let ct = top_header(&signed, "content-type");
    assert!(ct.starts_with("multipart/signed;") && ct.contains("application/pkcs7-signature"), "{ct}");
    let inc = process_incoming(&signed, "alice@example.com", &receiver);
    let sig = inc.signature.clone().unwrap();
    assert!(sig.valid, "{sig:?}");
    assert_eq!(sig.kind, "smime");
    assert_eq!(sig.message, "签名有效（爱丽丝 Alice <alice@example.com>）");
    assert_eq!(sig.key_id.as_deref(), Some(k.alice.info.id.as_str()));
    assert_eq!(inc.inner.as_deref(), Some(entity.as_slice()));
    check_inner(inc.inner.as_deref().unwrap());
    // The certificate travels with the signature: a receiver without it can still verify and
    // gets the certificate to store.
    let fresh = process_incoming(&signed, "alice@example.com", &ring(&[&k.bob]));
    assert!(fresh.signature.unwrap().valid);
    assert_eq!(fresh.signer_certificate.unwrap().info, public_only(&k.alice).info);
    let bad = process_incoming(&tamper(&signed), "alice@example.com", &receiver).signature.unwrap();
    assert!(!bad.valid && bad.message.contains("签名无效"), "{bad:?}");
    let spoof = process_incoming(&signed, "ceo@example.com", &receiver).signature.unwrap();
    assert!(!spoof.valid && spoof.message.contains("不一致"), "{}", spoof.message);

    // Encrypt only.
    let enc = protect_outgoing(&raw, &opts(false, true, "smime", "alice@example.com", &to), &sender).unwrap();
    let ct = top_header(&enc, "content-type");
    assert!(ct.starts_with("application/pkcs7-mime;") && ct.contains("enveloped-data"), "{ct}");
    assert_eq!(crate::mime::parse_full(&enc).0.subject, "合同（机密）");
    let inc = process_incoming(&enc, "alice@example.com", &receiver);
    assert!(inc.encrypted && inc.decrypted, "{:?}", inc.decrypt_error);
    assert!(inc.signature.is_none());
    assert_eq!(inc.inner.as_deref(), Some(entity.as_slice()));
    check_inner(inc.inner.as_deref().unwrap());
    assert!(process_incoming(&enc, "alice@example.com", &sender).decrypted, "Sent copy readable");
    let other = process_incoming(&enc, "alice@example.com", &ring(&[&public_only(&k.bob)]));
    assert!(other.encrypted && !other.decrypted);
    assert!(other.decrypt_error.unwrap().contains("私钥"));

    // Sign and encrypt (signed entity inside the envelope).
    let both = protect_outgoing(&raw, &opts(true, true, "smime", "alice@example.com", &to), &sender).unwrap();
    let inc = process_incoming(&both, "alice@example.com", &receiver);
    assert!(inc.decrypted, "{:?}", inc.decrypt_error);
    assert!(inc.signature.as_ref().unwrap().valid, "{:?}", inc.signature);
    assert_eq!(inc.inner.as_deref(), Some(entity.as_slice()));
    check_inner(inc.inner.as_deref().unwrap());

    // Missing certificates.
    let to2 = vec!["bob@example.org".to_string(), "nocert@example.net".to_string()];
    let err = protect_outgoing(&raw, &opts(false, true, "smime", "alice@example.com", &to2), &sender).unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("nocert@example.net") && m.contains("S/MIME")), "{err}");
    let err = protect_outgoing(&raw, &opts(true, false, "smime", "bob@example.org", &[]), &sender).unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("bob@example.org")), "{err}");
    let (have, missing) = recipients_with_keys(&to2, &sender);
    assert_eq!((have, missing), (vec!["bob@example.org".to_string()], vec!["nocert@example.net".to_string()]));
}

#[test]
fn falls_back_to_the_protocol_that_works() {
    let s = smime_keys();
    let p = pgp_keys();
    // Bob has only an S/MIME certificate, Carol only an OpenPGP key.
    let sender = ring(&[&s.alice, &p.alice, &public_only(&s.bob), &public_only(&p.carol)]);
    let raw = message("alice@example.com", "bob@example.org");
    let out = protect_outgoing(&raw, &opts(true, true, "pgp", "alice@example.com", &["bob@example.org".into()]), &sender)
        .unwrap();
    assert!(top_header(&out, "content-type").starts_with("application/pkcs7-mime"));
    let out = protect_outgoing(&raw, &opts(false, true, "smime", "alice@example.com", &["carol@example.net".into()]), &sender)
        .unwrap();
    assert!(top_header(&out, "content-type").starts_with("multipart/encrypted"));
    // Neither works for both together: the preferred protocol's error.
    let both = vec!["bob@example.org".to_string(), "carol@example.net".to_string()];
    let err = protect_outgoing(&raw, &opts(false, true, "pgp", "alice@example.com", &both), &sender).unwrap_err();
    assert!(err.to_string().contains("PGP 公钥") && err.to_string().contains("bob@example.org"), "{err}");
    let (have, missing) = recipients_with_keys(&both, &sender);
    assert_eq!(have.len(), 2);
    assert!(missing.is_empty());
}

#[test]
fn plain_messages_are_left_alone() {
    let raw = message("alice@example.com", "bob@example.org");
    let inc = process_incoming(&raw, "alice@example.com", &Ring::default());
    assert!(inc.inner.is_none() && inc.signature.is_none() && !inc.encrypted);
}

// ------------------------------------------------------------------ GnuPG interop

fn gpg_ring() -> Ring {
    let carol = import_pgp(include_str!("testdata/gpg_carol_sec.asc")).unwrap();
    let dave = import_pgp(include_str!("testdata/gpg_dave_pub.asc")).unwrap();
    let mut r = ring(&[&carol, &dave]);
    r.passphrases.insert(carol.info.id.clone(), "carol-pass".into());
    r
}

/// The text body and attachment of the fixture entity.
fn check_fixture_inner(inner: &[u8]) {
    let (_, b) = crate::mime::parse_full(inner);
    assert_eq!(b.text.as_deref().map(str::trim), Some("你好，这是来自 OpenSSL 的测试邮件。"));
    let att = b.attachments.iter().find(|a| !a.inline).expect("attachment");
    assert_eq!(att.filename, "report.pdf");
    assert_eq!(crate::mime::part_bytes(inner, att.id as usize).unwrap().2, b"%PDF-1.4 test");
}

#[test]
fn gnupg_keys_import() {
    let carol = import_pgp(include_str!("testdata/gpg_carol_sec.asc")).unwrap();
    assert_eq!(carol.info.emails, vec!["carol@example.net"]);
    assert_eq!(carol.info.names, vec!["Carol"]);
    assert!(carol.info.has_secret);
    let dave = import_pgp(include_str!("testdata/gpg_dave_pub.asc")).unwrap();
    assert_eq!(dave.info.names, vec!["Dave 戴"]);
    assert!(!dave.info.has_secret);
    let dave_sec = import_pgp(include_str!("testdata/gpg_dave_sec.asc")).unwrap();
    assert_eq!(dave_sec.info.id, dave.info.id);
    let (have, _) = recipients_with_keys(&["carol@example.net".into(), "dave@example.net".into()], &gpg_ring());
    assert_eq!(have.len(), 2);
}

#[test]
fn gnupg_pgp_mime_encrypted_and_signed() {
    let inc = process_incoming(include_bytes!("testdata/gpg_encrypted.eml"), "dave@example.net", &gpg_ring());
    assert!(inc.encrypted && inc.decrypted, "{:?}", inc.decrypt_error);
    let sig = inc.signature.unwrap();
    assert!(sig.valid, "{sig:?}");
    assert_eq!(sig.message, "签名有效（Dave 戴 <dave@example.net>）");
    check_fixture_inner(&inc.inner.unwrap());
    // Without Carol's passphrase.
    let mut r = gpg_ring();
    r.passphrases.clear();
    let inc = process_incoming(include_bytes!("testdata/gpg_encrypted.eml"), "dave@example.net", &r);
    assert!(inc.encrypted && !inc.decrypted);
    assert!(inc.decrypt_error.unwrap().contains("密码"));
}

#[test]
fn gnupg_pgp_mime_signed() {
    let raw = include_bytes!("testdata/gpg_signed.eml");
    let inc = process_incoming(raw, "dave@example.net", &gpg_ring());
    let sig = inc.signature.unwrap();
    assert!(sig.valid, "{sig:?}");
    check_fixture_inner(&inc.inner.unwrap());
    assert!(!process_incoming(&tamper(raw), "dave@example.net", &gpg_ring()).signature.unwrap().valid);
}

#[test]
fn gnupg_inline() {
    let inc = process_incoming(include_bytes!("testdata/gpg_clearsigned.eml"), "dave@example.net", &gpg_ring());
    assert!(!inc.encrypted);
    assert!(inc.signature.as_ref().unwrap().valid, "{:?}", inc.signature);
    let (_, b) = crate::mime::parse_full(&inc.inner.unwrap());
    let text = b.text.unwrap().replace("\r\n", "\n");
    assert_eq!(text.trim(), "你好 Carol，\n这是一封明文签名的邮件。\n- 以短横线开头的行");

    let inc = process_incoming(include_bytes!("testdata/gpg_inline_encrypted.eml"), "dave@example.net", &gpg_ring());
    assert!(inc.encrypted && inc.decrypted, "{:?}", inc.decrypt_error);
    assert!(inc.signature.unwrap().valid);
    let (_, b) = crate::mime::parse_full(&inc.inner.unwrap());
    assert_eq!(b.text.unwrap().replace("\r\n", "\n").trim(), "内联加密的正文\n第二行");
}

#[test]
fn inline_pgp_inside_multipart() {
    // A webmail-style message: the armored block in text/plain plus an HTML alternative and an attachment.
    let fixture = include_str!("testdata/gpg_inline_encrypted.eml");
    let block = &fixture[fixture.find("-----BEGIN PGP MESSAGE-----").unwrap()..];
    let raw = format!(
        "From: dave@example.net\r\nTo: carol@example.net\r\nSubject: inline\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"m\"\r\n\r\n--m\r\n\
         Content-Type: multipart/alternative; boundary=\"a\"\r\n\r\n--a\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nHi Carol,\r\n\r\n{block}\r\n--a\r\n\
         Content-Type: text/html; charset=utf-8\r\n\r\n<pre>{block}</pre>\r\n--a--\r\n--m\r\n\
         Content-Type: text/plain; name=\"notes.txt\"\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n\r\n\
         -----BEGIN PGP MESSAGE-----\r\nnot touched\r\n--m--\r\n"
    );
    let inc = process_incoming(raw.as_bytes(), "dave@example.net", &gpg_ring());
    assert!(inc.encrypted && inc.decrypted, "{:?}", inc.decrypt_error);
    assert!(inc.signature.unwrap().valid);
    let inner = inc.inner.unwrap();
    let (h, b) = crate::mime::parse_full(&inner);
    assert_eq!(h.subject, "inline");
    assert!(b.html.is_none(), "the armored HTML alternative is dropped");
    let text = b.text.unwrap().replace("\r\n", "\n");
    assert!(text.starts_with("Hi Carol,\n\n内联加密的正文\n第二行"), "{text}");
    assert_eq!(b.attachments.iter().filter(|a| !a.inline).map(|a| a.filename.as_str()).collect::<Vec<_>>(), ["notes.txt"]);
}

// ------------------------------------------------------------------ OpenSSL interop

fn alice_ring() -> Ring {
    let k = smime_keys();
    ring(&[&k.alice, &import_certificate(include_bytes!("testdata/bob.crt")).unwrap()])
}

#[test]
fn openssl_signed() {
    for raw in [&include_bytes!("testdata/openssl_signed.eml")[..], &include_bytes!("testdata/openssl_opaque.eml")[..]] {
        let inc = process_incoming(raw, "bob@example.org", &alice_ring());
        assert!(!inc.encrypted);
        let sig = inc.signature.unwrap();
        assert!(sig.valid, "{sig:?}");
        assert_eq!(sig.message, "签名有效（Bob Wang <bob@example.org>）");
        assert!(inc.signer_certificate.is_some());
        check_fixture_inner(&inc.inner.unwrap());
    }
    let tampered = tamper(include_bytes!("testdata/openssl_signed.eml"));
    assert!(!process_incoming(&tampered, "bob@example.org", &alice_ring()).signature.unwrap().valid);
    // ECDSA P-256, certificate only in the message.
    let inc = process_incoming(include_bytes!("testdata/openssl_ecdsa_signed.eml"), "eve@example.net", &alice_ring());
    assert!(inc.signature.as_ref().unwrap().valid, "{:?}", inc.signature);
    check_fixture_inner(&inc.inner.unwrap());
}

#[test]
fn openssl_encrypted() {
    for (name, raw) in [
        ("aes256", &include_bytes!("testdata/openssl_encrypted.eml")[..]),
        ("ber 3des", &include_bytes!("testdata/openssl_ber_3des.eml")[..]),
    ] {
        let inc = process_incoming(raw, "bob@example.org", &alice_ring());
        assert!(inc.encrypted && inc.decrypted, "{name}: {:?}", inc.decrypt_error);
        assert!(inc.signature.is_none());
        check_fixture_inner(&inc.inner.unwrap());
    }
    for (name, raw) in [
        ("signed+encrypted", &include_bytes!("testdata/openssl_signed_encrypted.eml")[..]),
        ("oaep+pss", &include_bytes!("testdata/openssl_oaep_pss.eml")[..]),
    ] {
        let inc = process_incoming(raw, "bob@example.org", &alice_ring());
        assert!(inc.decrypted, "{name}: {:?}", inc.decrypt_error);
        assert!(inc.signature.as_ref().is_some_and(|s| s.valid), "{name}: {:?}", inc.signature);
        check_fixture_inner(&inc.inner.unwrap());
    }
    // Bob cannot read mail encrypted to Alice.
    let k = smime_keys();
    let inc = process_incoming(include_bytes!("testdata/openssl_encrypted.eml"), "bob@example.org", &ring(&[&k.bob]));
    assert!(inc.encrypted && !inc.decrypted && inc.decrypt_error.is_some());
}

//! OpenPGP through rPGP: key import and selection, PGP/MIME (RFC 3156) and inline messages.
//!
//! Key semantics rPGP leaves to applications are handled here: only user ids and subkeys with a
//! valid self-signature count, revoked and expired keys are skipped, key flags pick the signing
//! and encryption components.

use super::entity::{self, Entity};
use super::{Incoming, KeyInfo, Keys, Plan, Request, SignatureStatus, StoredKey, join_addrs};
use crate::error::{Error, Result};
use ::pgp::composed::{
    ArmorOptions, CleartextSignedMessage, DecryptionOptions, Deserializable, DetachedSignature, EncryptionCaps, Esk,
    KeyType, Message, MessageBuilder, PublicOrSecret, SecretKeyParamsBuilder, SignedPublicKey, SignedPublicSubKey,
    SignedSecretKey, SubkeyParamsBuilder, TheRing,
};
use ::pgp::crypto::ecc_curve::ECCCurve;
use ::pgp::crypto::hash::HashAlgorithm;
use ::pgp::crypto::sym::SymmetricKeyAlgorithm;
use ::pgp::packet::{KeyFlags, PublicKey, PublicSubkey, Signature, SignatureType};
use ::pgp::types::{CompressionAlgorithm, KeyDetails, Password, SigningKey, Tag, Timestamp, VerifyingKey};

/// A parsed keyring entry.
pub struct PgpKey {
    pub info: KeyInfo,
    pub public: SignedPublicKey,
    pub secret: Option<SignedSecretKey>,
    /// Valid user ids, primary first.
    pub uids: Vec<String>,
}

impl PgpKey {
    pub fn load(stored: &StoredKey) -> Option<PgpKey> {
        let (public, _) = SignedPublicKey::from_reader_single(stored.public.as_bytes()).ok()?;
        let secret = stored
            .secret
            .as_deref()
            .and_then(|s| SignedSecretKey::from_reader_single(s.as_bytes()).ok())
            .map(|(k, _)| k)
            .filter(|k| k.fingerprint() == public.fingerprint());
        let uids = valid_uids(&public);
        Some(PgpKey { info: stored.info.clone(), public, secret, uids })
    }

    fn has_email(&self, addr: &str) -> bool {
        self.info.emails.iter().any(|e| e == addr)
    }

    fn display(&self) -> String {
        self.uids.first().cloned().unwrap_or_else(|| self.info.id.clone())
    }
}

fn now() -> u32 {
    chrono::Utc::now().timestamp().clamp(0, u32::MAX as i64) as u32
}

fn pgp_err(context: &str, e: impl std::fmt::Display) -> Error {
    Error::Invalid(format!("{context}：{e}"))
}

// ------------------------------------------------------------------ import & key info

pub fn import(armored: &str) -> Result<StoredKey> {
    let (iter, _) =
        PublicOrSecret::from_reader_many(armored.trim().as_bytes()).map_err(|e| pgp_err("无法解析 PGP 密钥", e))?;
    let mut first_public = None;
    let mut secret = None;
    for k in iter.flatten() {
        match k {
            PublicOrSecret::Secret(s) => {
                secret = Some(s);
                break;
            }
            PublicOrSecret::Public(p) => {
                first_public.get_or_insert(p);
            }
        }
    }
    let opts = ArmorOptions::default;
    if let Some(sk) = secret {
        let public = sk.to_public_key();
        return Ok(StoredKey {
            info: key_info(&public, true),
            public: public.to_armored_string(opts()).map_err(|e| pgp_err("无法导出公钥", e))?,
            secret: Some(sk.to_armored_string(opts()).map_err(|e| pgp_err("无法导出私钥", e))?),
        });
    }
    let public = first_public.ok_or_else(|| Error::Invalid("未找到 PGP 密钥".into()))?;
    Ok(StoredKey {
        info: key_info(&public, false),
        public: public.to_armored_string(opts()).map_err(|e| pgp_err("无法导出公钥", e))?,
        secret: None,
    })
}

fn key_info(k: &SignedPublicKey, has_secret: bool) -> KeyInfo {
    let mut emails = Vec::new();
    let mut names = Vec::new();
    for uid in valid_uids(k) {
        let (name, email) = split_uid(&uid);
        if let Some(e) = email.filter(|e| !emails.contains(e)) {
            emails.push(e);
        }
        if let Some(n) = name.filter(|n| !names.contains(n)) {
            names.push(n);
        }
    }
    let created = k.primary_key.created_at();
    KeyInfo {
        id: fingerprint(k),
        kind: "pgp".into(),
        emails,
        names,
        has_secret,
        created: created.as_secs() as i64,
        expires: expires_at(created, primary_binding(k)),
    }
}

fn fingerprint(k: &impl KeyDetails) -> String {
    format!("{:X}", k.fingerprint())
}

/// "Name (comment) <a@b.c>" → (Some("Name (comment)"), Some("a@b.c")).
fn split_uid(uid: &str) -> (Option<String>, Option<String>) {
    let uid = uid.trim();
    if let (Some(s), Some(e)) = (uid.rfind('<'), uid.rfind('>'))
        && e > s
    {
        let email = uid[s + 1..e].trim().to_ascii_lowercase();
        let name = uid[..s].trim().trim_matches('"').trim().to_string();
        return ((!name.is_empty()).then_some(name), email.contains('@').then_some(email));
    }
    if uid.contains('@') && !uid.contains(' ') {
        return (None, Some(uid.to_ascii_lowercase()));
    }
    ((!uid.is_empty()).then(|| uid.to_string()), None)
}

fn issued_by(sig: &Signature, key: &impl KeyDetails) -> bool {
    let ids = sig.issuer_key_id();
    let fps = sig.issuer_fingerprint();
    if ids.is_empty() && fps.is_empty() {
        return true;
    }
    ids.iter().any(|id| **id == key.legacy_key_id()) || fps.iter().any(|fp| **fp == key.fingerprint())
}

fn created_secs(sig: &Signature) -> u32 {
    sig.created().map(|t| t.as_secs()).unwrap_or(0)
}

/// The newest valid self-certification of a user id, unless that is a revocation.
fn user_self_sig<'a>(primary: &PublicKey, user: &'a ::pgp::types::SignedUser) -> Option<&'a Signature> {
    let mut sigs: Vec<&Signature> = user.signatures.iter().filter(|s| issued_by(s, primary)).collect();
    sigs.sort_by_key(|s| std::cmp::Reverse(created_secs(s)));
    let sig = sigs.into_iter().find(|s| s.verify_certification(primary, Tag::UserId, &user.id).is_ok())?;
    (sig.typ() != Some(SignatureType::CertRevocation)).then_some(sig)
}

fn valid_uids(k: &SignedPublicKey) -> Vec<String> {
    let mut out: Vec<(bool, String)> = Vec::new();
    for u in &k.details.users {
        if let Some(sig) = user_self_sig(&k.primary_key, u) {
            out.push((sig.is_primary(), String::from_utf8_lossy(u.id.id()).into_owned()));
        }
    }
    out.sort_by_key(|(primary, _)| !*primary);
    out.into_iter().map(|(_, s)| s).collect()
}

/// The self-signature carrying the primary key's flags and expiration: the primary user id's,
/// else the newest user id's, else a direct-key signature.
fn primary_binding(k: &SignedPublicKey) -> Option<&Signature> {
    let mut best: Option<&Signature> = None;
    for u in &k.details.users {
        if let Some(sig) = user_self_sig(&k.primary_key, u) {
            best = match best {
                None => Some(sig),
                Some(b) if sig.is_primary() && !b.is_primary() => Some(sig),
                Some(b) if sig.is_primary() == b.is_primary() && created_secs(sig) > created_secs(b) => Some(sig),
                keep => keep,
            };
        }
    }
    best.or_else(|| {
        k.details
            .direct_signatures
            .iter()
            .filter(|s| s.verify_key(&k.primary_key).is_ok())
            .max_by_key(|s| created_secs(s))
    })
}

fn revoked(k: &SignedPublicKey) -> bool {
    k.details.revocation_signatures.iter().any(|s| s.verify_key(&k.primary_key).is_ok())
}

fn expires_at(created: Timestamp, sig: Option<&Signature>) -> Option<i64> {
    let d = sig?.key_expiration_time()?;
    (d.as_secs() > 0).then(|| created.as_secs() as i64 + d.as_secs() as i64)
}

fn alive(created: Timestamp, sig: Option<&Signature>) -> bool {
    expires_at(created, sig).is_none_or(|e| e > now() as i64)
}

fn no_flags(f: &KeyFlags) -> bool {
    !(f.certify() || f.sign() || f.encrypt_comms() || f.encrypt_storage() || f.authentication())
}

/// The newest valid binding signature of a subkey (None when revoked or unbound).
fn subkey_binding<'a>(primary: &PublicKey, key: &PublicSubkey, sigs: &'a [Signature]) -> Option<&'a Signature> {
    let revoked = sigs
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation) && s.verify_subkey_binding(primary, key).is_ok());
    if revoked {
        return None;
    }
    sigs.iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .filter(|s| s.verify_subkey_binding(primary, key).is_ok())
        .max_by_key(|s| created_secs(s))
}

/// A valid binding that allows signing (including the subkey's back-signature).
fn signing_binding(primary: &PublicKey, key: &PublicSubkey, sigs: &[Signature]) -> bool {
    let Some(b) = subkey_binding(primary, key, sigs) else { return false };
    b.key_flags().sign()
        && key.algorithm().can_sign()
        && alive(key.created_at(), Some(b))
        && b.embedded_signature().is_some_and(|bs| bs.verify_primary_key_binding(key, primary).is_ok())
}

enum EncTarget<'a> {
    Primary(&'a SignedPublicKey),
    Sub(&'a SignedPublicSubKey),
}

/// The newest valid encryption subkey, else the primary key if it may encrypt.
fn encryption_target(k: &SignedPublicKey) -> Option<EncTarget<'_>> {
    let primary_sig = primary_binding(k);
    if revoked(k) || !alive(k.primary_key.created_at(), primary_sig) {
        return None;
    }
    let sub = k
        .public_subkeys
        .iter()
        .filter(|sk| sk.key.algorithm().can_encrypt())
        .filter_map(|sk| subkey_binding(&k.primary_key, &sk.key, &sk.signatures).map(|b| (sk, b)))
        .filter(|(sk, b)| {
            let f = b.key_flags();
            (f.encrypt_comms() || f.encrypt_storage()) && alive(sk.key.created_at(), Some(b))
        })
        .max_by_key(|(sk, _)| sk.key.created_at().as_secs());
    if let Some((sk, _)) = sub {
        return Some(EncTarget::Sub(sk));
    }
    let flags = primary_sig.map(|s| s.key_flags()).unwrap_or_default();
    let allowed = flags.encrypt_comms() || flags.encrypt_storage() || no_flags(&flags);
    (k.primary_key.algorithm().can_encrypt() && allowed).then_some(EncTarget::Primary(k))
}

pub fn encryption_key_for<'k>(keys: &'k Keys, addr: &str) -> Option<&'k PgpKey> {
    keys.pgp
        .iter()
        .filter(|k| k.has_email(addr) && encryption_target(&k.public).is_some())
        .max_by_key(|k| (k.secret.is_some(), k.info.created))
}

fn signing_key_for<'k>(keys: &'k Keys, addr: &str) -> Option<&'k PgpKey> {
    keys.pgp
        .iter()
        .filter(|k| k.has_email(addr) && k.secret.as_ref().is_some_and(|s| signer_of(s, &k.public).is_some()))
        .max_by_key(|k| k.info.created)
}

/// The component of a secret key that signs: the newest signing subkey, else the primary.
fn signer_of<'a>(sk: &'a SignedSecretKey, public: &SignedPublicKey) -> Option<(&'a dyn SigningKey, bool)> {
    let primary = sk.primary_key.public_key();
    let sub = sk
        .secret_subkeys
        .iter()
        .filter(|s| signing_binding(primary, s.key.public_key(), &s.signatures))
        .max_by_key(|s| s.key.public_key().created_at().as_secs());
    if let Some(s) = sub {
        return Some((&s.key as &dyn SigningKey, s.key.secret_params().is_encrypted()));
    }
    let primary_sig = primary_binding(public);
    let flags = primary_sig.map(|s| s.key_flags()).unwrap_or_default();
    let ok = primary.algorithm().can_sign()
        && (flags.sign() || no_flags(&flags))
        && !revoked(public)
        && alive(primary.created_at(), primary_sig);
    ok.then_some((&sk.primary_key as &dyn SigningKey, sk.primary_key.secret_params().is_encrypted()))
}

fn password(locked: bool, stored: Option<String>) -> Result<Password> {
    match stored {
        Some(p) => Ok(Password::from(p)),
        None if locked => Err(Error::Invalid("签名私钥受密码保护，请先保存私钥密码".into())),
        None => Ok(Password::empty()),
    }
}

fn micalg(h: HashAlgorithm) -> &'static str {
    match h {
        HashAlgorithm::Sha1 => "pgp-sha1",
        HashAlgorithm::Sha224 => "pgp-sha224",
        HashAlgorithm::Sha384 => "pgp-sha384",
        HashAlgorithm::Sha512 => "pgp-sha512",
        HashAlgorithm::Sha3_256 => "pgp-sha3-256",
        HashAlgorithm::Sha3_512 => "pgp-sha3-512",
        _ => "pgp-sha256",
    }
}

/// A signing hash at least as strong as SHA-256.
fn signing_hash(key: &dyn SigningKey) -> HashAlgorithm {
    match key.hash_alg() {
        h @ (HashAlgorithm::Sha256
        | HashAlgorithm::Sha384
        | HashAlgorithm::Sha512
        | HashAlgorithm::Sha3_256
        | HashAlgorithm::Sha3_512) => h,
        _ => HashAlgorithm::Sha256,
    }
}

/// Generates a new Ed25519 / Curve25519 key pair (v4, readable by GnuPG and every current client).
pub fn generate_pgp(name: &str, email: &str, passphrase: Option<&str>) -> Result<StoredKey> {
    let email = email.trim();
    if !email.contains('@') {
        return Err(Error::Invalid("无效的邮箱地址".into()));
    }
    let uid = if name.trim().is_empty() { format!("<{email}>") } else { format!("{} <{email}>", name.trim()) };
    let passphrase = passphrase.filter(|p| !p.is_empty()).map(String::from);
    let gen_err = |e: &dyn std::fmt::Display| Error::Other(format!("生成密钥失败：{e}"));
    let subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_encrypt(EncryptionCaps::All)
        .passphrase(passphrase.clone())
        .build()
        .map_err(|e| gen_err(&e))?;
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(uid)
        .passphrase(passphrase)
        .preferred_symmetric_algorithms(
            vec![SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES192, SymmetricKeyAlgorithm::AES128].into(),
        )
        .preferred_hash_algorithms(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512].into())
        .preferred_compression_algorithms(vec![CompressionAlgorithm::ZLIB, CompressionAlgorithm::ZIP].into())
        .subkeys(vec![subkey])
        .build()
        .map_err(|e| gen_err(&e))?;
    let sk = params.generate(rand::thread_rng()).map_err(|e| gen_err(&e))?;
    let armored = sk.to_armored_string(ArmorOptions::default()).map_err(|e| gen_err(&e))?;
    import(&armored)
}

// ------------------------------------------------------------------ verification

enum Check<'k> {
    Valid(&'k PgpKey),
    Invalid(Option<&'k PgpKey>),
    Missing(String),
    Malformed,
}

fn has_issuer(sig: &Signature) -> bool {
    !(sig.issuer_key_id().is_empty() && sig.issuer_fingerprint().is_empty())
}

/// Candidate verifying components of the keyring for a signature (primary and signing subkeys);
/// every key when the signature does not name its issuer.
fn candidates<'k>(sig: &Signature, keys: &'k Keys) -> Vec<(&'k PgpKey, &'k dyn VerifyingKey)> {
    let mut out: Vec<(&PgpKey, &dyn VerifyingKey)> = Vec::new();
    for k in &keys.pgp {
        let p = &k.public.primary_key;
        if issued_by(sig, p) {
            out.push((k, p));
        }
        for sk in &k.public.public_subkeys {
            if issued_by(sig, &sk.key) && signing_binding(p, &sk.key, &sk.signatures) {
                out.push((k, &sk.key));
            }
        }
    }
    out
}

fn issuer_hex(sig: &Signature) -> String {
    if let Some(fp) = sig.issuer_fingerprint().first() {
        return format!("{fp:X}");
    }
    sig.issuer_key_id().first().map(|id| hex::encode_upper(id.as_ref())).unwrap_or_default()
}

/// Checks signatures with `verify(index, key)`; the first one that verifies wins.
fn check_sigs<'k>(sigs: &[&Signature], keys: &'k Keys, verify: impl Fn(usize, &dyn VerifyingKey) -> bool) -> Check<'k> {
    let mut result = Check::Malformed;
    for (i, sig) in sigs.iter().enumerate() {
        let cands = candidates(sig, keys);
        if cands.is_empty() {
            if matches!(result, Check::Malformed) {
                result = Check::Missing(issuer_hex(sig));
            }
            continue;
        }
        for (k, c) in &cands {
            if verify(i, *c) {
                return Check::Valid(k);
            }
        }
        if has_issuer(sig) {
            result = Check::Invalid(cands.first().map(|(k, _)| *k));
        } else if matches!(result, Check::Malformed) {
            result = Check::Missing(String::new());
        }
    }
    result
}

fn status(check: Check, from: &str) -> SignatureStatus {
    let mut s = SignatureStatus { kind: "pgp".into(), ..Default::default() };
    match check {
        Check::Valid(k) => {
            let matches = from.is_empty() || k.has_email(from);
            s.key_id = Some(k.info.id.clone());
            s.signer = k
                .info
                .emails
                .iter()
                .find(|e| *e == from)
                .or(k.info.emails.first())
                .cloned()
                .or_else(|| Some(k.info.id.clone()));
            if matches {
                s.valid = true;
                s.message = format!("签名有效（{}）", k.display());
            } else {
                s.message = format!("签名本身有效，但签名密钥（{}）不属于发件人 {from}", k.display());
            }
        }
        Check::Invalid(k) => {
            s.key_id = k.map(|k| k.info.id.clone());
            s.signer = k.and_then(|k| k.info.emails.first().cloned());
            s.message = "签名无效：邮件内容可能已被篡改".into();
        }
        Check::Missing(issuer) => {
            if !issuer.is_empty() {
                s.key_id = Some(issuer.clone());
                s.signer = Some(issuer);
            }
            s.message = "缺少发件人的公钥，无法验证".into();
        }
        Check::Malformed => s.message = "签名格式无效，无法验证".into(),
    }
    s
}

fn verify_detached(sig_data: &[u8], content: &[u8], keys: &Keys, from: &str) -> SignatureStatus {
    let sigs: Vec<DetachedSignature> = match DetachedSignature::from_reader_many(sig_data) {
        Ok((iter, _)) => iter.flatten().collect(),
        Err(_) => Vec::new(),
    };
    let refs: Vec<&Signature> = sigs.iter().map(|s| &s.signature).collect();
    let check = check_sigs(&refs, keys, |i, key| verify_with(refs[i], key, content));
    status(check, from)
}

fn verify_with(sig: &Signature, key: &dyn VerifyingKey, content: &[u8]) -> bool {
    struct Dyn<'a>(&'a dyn VerifyingKey);
    impl std::fmt::Debug for Dyn<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }
    impl KeyDetails for Dyn<'_> {
        fn version(&self) -> ::pgp::types::KeyVersion {
            self.0.version()
        }
        fn legacy_key_id(&self) -> ::pgp::types::KeyId {
            self.0.legacy_key_id()
        }
        fn fingerprint(&self) -> ::pgp::types::Fingerprint {
            self.0.fingerprint()
        }
        fn algorithm(&self) -> ::pgp::crypto::public_key::PublicKeyAlgorithm {
            self.0.algorithm()
        }
        fn created_at(&self) -> Timestamp {
            self.0.created_at()
        }
        fn legacy_v3_expiration_days(&self) -> Option<u16> {
            self.0.legacy_v3_expiration_days()
        }
        fn public_params(&self) -> &::pgp::types::PublicParams {
            self.0.public_params()
        }
    }
    impl VerifyingKey for Dyn<'_> {
        fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &::pgp::types::SignatureBytes) -> ::pgp::errors::Result<()> {
            self.0.verify(hash, data, sig)
        }
    }
    sig.verify(&Dyn(key), content).is_ok()
}

/// multipart/signed; protocol="application/pgp-signature": returns the signed entity and the result.
pub fn verify_mime(e: &Entity, keys: &Keys, from: &str) -> Option<(Vec<u8>, SignatureStatus)> {
    let parts = e.parts();
    if parts.len() < 2 {
        return None;
    }
    let signed = entity::to_crlf(parts[0]);
    let sig = Entity::parse(parts[1]).decoded_body();
    let status = verify_detached(&sig, &signed, keys, from);
    Some((parts[0].to_vec(), status))
}

// ------------------------------------------------------------------ decryption

fn parse_message(data: &[u8]) -> ::pgp::errors::Result<Message<'_>> {
    match find(data, b"-----BEGIN PGP MESSAGE-----") {
        Some(start) => Message::from_armor(&data[start..]).map(|(m, _)| m),
        None => Message::from_bytes(data),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn addressed_to(msg: &Message, sk: &SignedSecretKey) -> bool {
    let Message::Encrypted { esk, .. } = msg else { return false };
    esk.iter().any(|e| match e {
        Esk::PublicKeyEncryptedSessionKey(p) => {
            p.match_identity(sk.primary_key.public_key())
                || sk.secret_subkeys.iter().any(|s| p.match_identity(s.key.public_key()))
        }
        Esk::SymKeyEncryptedSessionKey(_) => false,
    })
}

/// Reads a (decrypted) message: decompresses, returns the literal data and checks signatures.
fn read_message(mut msg: Message<'_>, keys: &Keys, from: &str) -> std::result::Result<(Vec<u8>, Option<SignatureStatus>), String> {
    let fail = |e: &dyn std::fmt::Display| format!("邮件解密失败：数据已损坏（{e}）");
    if msg.is_compressed() {
        msg = msg.decompress().map_err(|e| fail(&e))?;
    }
    if msg.is_signed() {
        msg = msg.decompress().map_err(|e| fail(&e))?;
    }
    let data = msg.as_data_vec().map_err(|e| fail(&e))?;
    let sig = match &msg {
        Message::Signed { reader, .. } => {
            let sigs: Vec<&Signature> = (0..reader.num_signatures()).filter_map(|i| reader.signature(i)).collect();
            let check = check_sigs(&sigs, keys, |i, key| msg.verify_nested_explicit(i, key).is_ok());
            Some(status(check, from))
        }
        _ => None,
    };
    Ok((data, sig))
}

/// Decrypts an OpenPGP message (armored or binary) with the keyring's secret keys.
fn decrypt(data: &[u8], keys: &Keys, from: &str) -> std::result::Result<(Vec<u8>, Option<SignatureStatus>), String> {
    let probe = parse_message(data).map_err(|e| format!("无法解析加密邮件：{e}"))?;
    if !probe.is_encrypted() {
        // Signed-only OpenPGP message.
        return read_message(probe, keys, from);
    }
    let mut addressed = false;
    let mut locked = false;
    let mut last_error = None;
    for k in &keys.pgp {
        let Some(sk) = &k.secret else { continue };
        if !addressed_to(&probe, sk) {
            continue;
        }
        addressed = true;
        let stored = keys.ring.passphrase(&k.info.id);
        let is_locked = sk.primary_key.secret_params().is_encrypted()
            || sk.secret_subkeys.iter().any(|s| s.key.secret_params().is_encrypted());
        let pw = stored.map(Password::from).unwrap_or_else(Password::empty);
        let Ok(msg) = parse_message(data) else { continue };
        // GnuPG 2.3+ sends its own OCB format to keys that advertise AEAD support.
        let ring = TheRing {
            secret_keys: vec![sk],
            key_passwords: vec![&pw],
            decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
            ..Default::default()
        };
        match msg.decrypt_the_ring(ring, true) {
            Ok((m, _)) => match read_message(m, keys, from) {
                Ok(r) => return Ok(r),
                Err(e) => last_error = Some(e),
            },
            Err(e) => {
                if is_locked {
                    locked = true;
                }
                last_error = Some(format!("邮件解密失败：{e}"));
            }
        }
    }
    Err(if !addressed {
        "没有可解密此邮件的私钥（邮件不是加密给你的密钥的）".into()
    } else if locked {
        "无法解锁私钥：密码错误或未保存私钥密码".into()
    } else {
        last_error.unwrap_or_else(|| "邮件解密失败".into())
    })
}

/// multipart/encrypted; protocol="application/pgp-encrypted": the decrypted inner entity.
pub fn decrypt_mime(e: &Entity, keys: &Keys, from: &str) -> std::result::Result<(Vec<u8>, Option<SignatureStatus>), String> {
    let parts = e.children();
    let payload = parts
        .iter()
        .find(|p| p.ctype.mime == "application/octet-stream")
        .or_else(|| parts.get(1))
        .ok_or_else(|| "加密邮件格式无效".to_string())?;
    decrypt(&payload.decoded_body(), keys, from)
}

// ------------------------------------------------------------------ inline PGP

const BEGIN_MSG: &str = "-----BEGIN PGP MESSAGE-----";
const END_MSG: &str = "-----END PGP MESSAGE-----";
const BEGIN_SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const END_SIG: &str = "-----END PGP SIGNATURE-----";

/// The first text/plain body (not an attachment) with inline PGP, as (byte range to replace, text).
fn find_inline(root: &[u8], e: &Entity, alternative: Option<(usize, usize)>, depth: usize) -> Option<((usize, usize), String)> {
    if depth > 8 {
        return None;
    }
    let range = {
        let start = e.raw.as_ptr() as usize - root.as_ptr() as usize;
        (start, start + e.raw.len())
    };
    if e.is_multipart() {
        let alt = (e.ctype.mime == "multipart/alternative").then_some(range);
        return e.children().iter().find_map(|c| find_inline(root, c, alt.or(alternative), depth + 1));
    }
    let attachment = e.header("content-disposition").is_some_and(|d| d.trim().to_ascii_lowercase().starts_with("attachment"));
    if e.ctype.mime != "text/plain" || attachment {
        return None;
    }
    let text = e.text();
    (text.contains(BEGIN_MSG) || text.contains(BEGIN_SIGNED)).then(|| (alternative.unwrap_or(range), text))
}

/// Inline PGP in a text/plain part: decrypts / verifies and returns the message with that part
/// (or its multipart/alternative) replaced by the plain text.
pub fn process_inline(raw: &[u8], keys: &Keys, from: &str, out: &mut Incoming) -> Option<Vec<u8>> {
    let root = Entity::parse(raw);
    let ((start, end), text) = find_inline(raw, &root, None, 0)?;
    let new_text = if let Some(s) = text.find(BEGIN_SIGNED) {
        let e = text[s..].find(END_SIG).map(|p| s + p + END_SIG.len())?;
        let (msg, _) = CleartextSignedMessage::from_string(&text[s..e]).ok()?;
        let sigs: Vec<&Signature> = msg.signatures().iter().collect();
        let signed = msg.signed_text();
        let check = check_sigs(&sigs, keys, |i, key| verify_with(sigs[i], key, signed.as_bytes()));
        out.signature = Some(status(check, from));
        format!("{}{}{}", &text[..s], signed, &text[e..])
    } else {
        let s = text.find(BEGIN_MSG)?;
        let e = text[s..].find(END_MSG).map(|p| s + p + END_MSG.len())?;
        let block = &text.as_bytes()[s..e];
        out.encrypted = parse_message(block).is_ok_and(|m| m.is_encrypted());
        match decrypt(block, keys, from) {
            Ok((data, sig)) => {
                out.decrypted = out.encrypted;
                out.signature = sig;
                format!("{}{}{}", &text[..s], entity::decode_charset(&data, "utf-8"), &text[e..])
            }
            Err(msg) => {
                out.decrypt_error = Some(msg);
                return None;
            }
        }
    };
    let replacement = entity::text_entity(&new_text);
    if start == 0 && end == raw.len() {
        return Some(replacement);
    }
    let mut inner = raw[..start].to_vec();
    inner.extend_from_slice(&replacement);
    inner.extend_from_slice(&raw[end..]);
    Some(inner)
}

// ------------------------------------------------------------------ sending

pub struct PgpPlan<'k> {
    signer: Option<&'k PgpKey>,
    recipients: Vec<&'k PgpKey>,
    encrypt: bool,
}

pub fn plan<'k>(req: &Request, keys: &'k Keys) -> Result<Plan<'k>> {
    let signer = if req.sign {
        Some(
            signing_key_for(keys, req.from)
                .ok_or_else(|| Error::Invalid(format!("没有 {} 的 PGP 私钥，无法签名", req.from)))?,
        )
    } else {
        None
    };
    let mut recipients = Vec::new();
    if req.encrypt {
        let mut missing = Vec::new();
        for r in req.recipients {
            match encryption_key_for(keys, r) {
                Some(k) => recipients.push(k),
                None => missing.push(r.clone()),
            }
        }
        if !missing.is_empty() {
            return Err(Error::Invalid(format!("以下收件人没有可用的 PGP 公钥，无法加密：{}", join_addrs(&missing))));
        }
        let own = encryption_key_for(keys, req.from).ok_or_else(|| {
            Error::Invalid(format!("没有发件人 {} 自己的 PGP 公钥，加密后将无法阅读已发送的邮件", req.from))
        })?;
        recipients.push(own);
        let mut seen = std::collections::HashSet::new();
        recipients.retain(|k| seen.insert(k.info.id.clone()));
    }
    Ok(Plan::Pgp(PgpPlan { signer, recipients, encrypt: req.encrypt }))
}

impl PgpPlan<'_> {
    /// Returns the top-level Content-Type header line(s) and the body.
    pub fn execute(self, entity: &[u8], keys: &Keys) -> Result<(String, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let signer = match self.signer {
            Some(k) => {
                let sk = k.secret.as_ref().ok_or_else(|| Error::Invalid("缺少私钥".into()))?;
                let (key, locked) = signer_of(sk, &k.public).ok_or_else(|| Error::Invalid("私钥不能用于签名".into()))?;
                Some((key, password(locked, keys.ring.passphrase(&k.info.id))?, locked))
            }
            None => None,
        };
        let locked = signer.as_ref().is_some_and(|s| s.2);
        if !self.encrypt {
            let (key, pw, _) = signer.ok_or_else(|| Error::Invalid("缺少签名私钥".into()))?;
            let hash = signing_hash(key);
            let sig = DetachedSignature::sign_binary_data(&mut rng, &Box::new(key), &pw, hash, entity)
                .map_err(|e| sign_error(e, locked))?;
            let armored = sig.to_armored_string(ArmorOptions::default()).map_err(|e| pgp_err("签名失败", e))?;
            let sig_part = format!(
                "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n\
                 Content-Description: OpenPGP digital signature\r\n\
                 Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n{}",
                armored.replace("\r\n", "\n").replace('\n', "\r\n")
            );
            let b = entity::boundary(entity);
            let body = entity::multipart_body(
                &b,
                "This is an OpenPGP/MIME signed message (RFC 4880 and 3156)",
                &[entity, sig_part.as_bytes()],
            );
            let ct = format!(
                "Content-Type: multipart/signed; micalg={}; protocol=\"application/pgp-signature\";\r\n boundary=\"{b}\"\r\n",
                micalg(hash)
            );
            return Ok((ct, body));
        }

        let mut builder = MessageBuilder::from_bytes("", entity.to_vec()).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for k in &self.recipients {
            let res = match encryption_target(&k.public) {
                Some(EncTarget::Sub(s)) => builder.encrypt_to_key(&mut rng, s).map(|_| ()),
                Some(EncTarget::Primary(p)) => builder.encrypt_to_key(&mut rng, p).map(|_| ()),
                None => return Err(Error::Invalid(format!("{} 的公钥不能用于加密", k.display()))),
            };
            res.map_err(|e| pgp_err("加密失败", e))?;
        }
        if let Some((key, pw, _)) = signer {
            let hash = signing_hash(key);
            builder.sign(key, pw, hash);
        }
        let armored = builder.to_armored_string(&mut rng, ArmorOptions::default()).map_err(|e| sign_error(e, locked))?;
        let version = "Content-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n";
        let payload = format!(
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
             Content-Description: OpenPGP encrypted message\r\n\
             Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n{}",
            armored.replace("\r\n", "\n").replace('\n', "\r\n")
        );
        let b = entity::boundary(payload.as_bytes());
        let body = entity::multipart_body(
            &b,
            "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)",
            &[version.as_bytes(), payload.as_bytes()],
        );
        let ct = format!("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n boundary=\"{b}\"\r\n");
        Ok((ct, body))
    }
}

/// A signing failure with a passphrase-protected key is almost always a wrong passphrase.
fn sign_error(e: ::pgp::errors::Error, locked: bool) -> Error {
    if locked {
        Error::Invalid("私钥密码错误，无法签名".into())
    } else {
        Error::Invalid(format!("签名或加密失败：{e}"))
    }
}

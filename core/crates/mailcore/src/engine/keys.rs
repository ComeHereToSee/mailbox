//! OpenPGP / S/MIME key store. Keys (including secret keys) and their passphrases live in the
//! encrypted secrets file, never in the database.

use super::Engine;
use crate::crypto::{self, KeyInfo, Keyring, StoredKey};
use crate::error::{Error, Result};
use crate::model::{Draft, SignatureInfo};
use base64::Engine as _;
use serde::Deserialize;

const KEYRING: &str = "crypto:keyring";

fn pass_key(id: &str) -> String {
    format!("crypto:pass:{id}")
}

/// Serializes read-modify-write of the key list.
static KEY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn key_lock() -> std::sync::MutexGuard<'static, ()> {
    KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the key import endpoint accepts: armored / PEM text, or a binary file as base64.
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct KeyImport {
    pub text: Option<String>,
    pub data_base64: Option<String>,
    /// Password of a .p12 / .pfx file.
    pub password: Option<String>,
    /// Passphrase of an imported PGP secret key, remembered for signing / decrypting.
    pub passphrase: Option<String>,
}

pub(crate) struct EngineKeyring<'a> {
    engine: &'a Engine,
    keys: Vec<StoredKey>,
}

impl Keyring for EngineKeyring<'_> {
    fn keys(&self) -> Vec<StoredKey> {
        self.keys.clone()
    }

    fn passphrase(&self, key_id: &str) -> Option<String> {
        self.engine.secrets.get(&pass_key(key_id))
    }
}

/// Cheap byte check so plain mail skips loading the keyring.
pub(crate) fn may_be_protected(raw: &[u8]) -> bool {
    const NEEDLES: [&[u8]; 4] = [b"multipart/signed", b"multipart/encrypted", b"pkcs7-mime", b"-----begin pgp"];
    let lower = raw.to_ascii_lowercase();
    NEEDLES.iter().any(|n| lower.windows(n.len()).any(|w| w == *n))
}

impl From<crypto::SignatureStatus> for SignatureInfo {
    fn from(s: crypto::SignatureStatus) -> Self {
        SignatureInfo { kind: s.kind, valid: s.valid, signer: s.signer, key_id: s.key_id, message: s.message }
    }
}

impl Engine {
    pub(crate) fn stored_keys(&self) -> Vec<StoredKey> {
        self.secrets.get(KEYRING).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn save_keys(&self, keys: &[StoredKey]) -> Result<()> {
        self.secrets.set(KEYRING, &serde_json::to_string(keys)?)
    }

    pub(crate) fn keyring(&self) -> EngineKeyring<'_> {
        EngineKeyring { engine: self, keys: self.stored_keys() }
    }

    pub fn list_keys(&self) -> Vec<KeyInfo> {
        let mut v: Vec<KeyInfo> = self.stored_keys().into_iter().map(|k| k.info).collect();
        v.sort_by(|a, b| b.has_secret.cmp(&a.has_secret).then_with(|| a.emails.cmp(&b.emails)));
        v
    }

    /// Adds a key, merging with an existing entry of the same id (a secret key is never dropped
    /// by re-importing the public half).
    pub(crate) fn add_key(&self, mut k: StoredKey) -> Result<KeyInfo> {
        let _guard = key_lock();
        let mut keys = self.stored_keys();
        if let Some(old) = keys.iter().position(|o| o.info.id == k.info.id) {
            let old = keys.remove(old);
            if k.secret.is_none() && old.secret.is_some() {
                k.secret = old.secret;
                k.info.has_secret = true;
            }
        }
        let info = k.info.clone();
        keys.push(k);
        self.save_keys(&keys)?;
        Ok(info)
    }

    pub fn import_key(&self, req: KeyImport) -> Result<KeyInfo> {
        let key = if let Some(text) = req.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            if text.contains("-----BEGIN PGP") {
                crypto::import_pgp(text)?
            } else if text.contains("-----BEGIN CERTIFICATE") {
                crypto::import_certificate(text.as_bytes())?
            } else {
                return Err(Error::Invalid("无法识别的密钥格式：请粘贴 PGP 公钥 / 私钥或 PEM 证书".into()));
            }
        } else if let Some(b64) = req.data_base64.as_deref() {
            let data = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| Error::Invalid("文件内容无效".into()))?;
            if let Ok(text) = std::str::from_utf8(&data) {
                if text.contains("-----BEGIN") {
                    return self.import_key(KeyImport { text: Some(text.to_string()), ..req });
                }
            }
            match req.password.as_deref() {
                Some(pw) => crypto::import_pkcs12(&data, pw)?,
                None => match crypto::import_certificate(&data) {
                    Ok(k) => k,
                    // Binary OpenPGP (.gpg) is not supported; a .p12 needs its password.
                    Err(_) => return Err(Error::Invalid("如果这是 .p12 / .pfx 文件，请输入它的密码".into())),
                },
            }
        } else {
            return Err(Error::Invalid("没有要导入的内容".into()));
        };
        let id = key.info.id.clone();
        let info = self.add_key(key)?;
        if let Some(p) = req.passphrase.filter(|p| !p.is_empty()) {
            self.secrets.set(&pass_key(&id), &p)?;
        }
        Ok(info)
    }

    pub fn generate_key(&self, name: &str, email: &str, passphrase: Option<&str>) -> Result<KeyInfo> {
        let passphrase = passphrase.filter(|p| !p.is_empty());
        let key = crypto::generate_pgp(name, email, passphrase)?;
        let id = key.info.id.clone();
        let info = self.add_key(key)?;
        if let Some(p) = passphrase {
            self.secrets.set(&pass_key(&id), p)?;
        }
        Ok(info)
    }

    /// Public key (armored / PEM), or the secret key when `secret` is set.
    pub fn export_key(&self, id: &str, secret: bool) -> Result<String> {
        let k = self
            .stored_keys()
            .into_iter()
            .find(|k| k.info.id == id)
            .ok_or_else(|| Error::NotFound("密钥不存在".into()))?;
        if secret {
            k.secret.ok_or_else(|| Error::NotFound("这把密钥没有私钥".into()))
        } else {
            Ok(k.public)
        }
    }

    pub fn delete_key(&self, id: &str) -> Result<()> {
        let _guard = key_lock();
        let mut keys = self.stored_keys();
        keys.retain(|k| k.info.id != id);
        self.save_keys(&keys)?;
        self.secrets.remove(&pass_key(id))
    }

    pub fn set_key_passphrase(&self, id: &str, passphrase: Option<&str>) -> Result<()> {
        match passphrase.filter(|p| !p.is_empty()) {
            Some(p) => self.secrets.set(&pass_key(id), p),
            None => self.secrets.remove(&pass_key(id)),
        }
    }

    /// (recipients with an encryption key, recipients without) for the composer's lock toggle.
    pub fn recipient_keys(&self, recipients: &[String]) -> (Vec<String>, Vec<String>) {
        crypto::recipients_with_keys(recipients, &self.keyring())
    }

    /// Decrypts / verifies a received message. Returns the processing result and, when the
    /// message was protected, the inner entity to display.
    pub(crate) fn unprotect(&self, raw: &[u8], from: &str) -> crypto::Incoming {
        if !may_be_protected(raw) {
            return crypto::Incoming::default();
        }
        let mut inc = crypto::process_incoming(raw, from, &self.keyring());
        // Remember S/MIME certificates from valid signatures so replies can be encrypted.
        if let Some(cert) = inc.signer_certificate.take() {
            if !self.stored_keys().iter().any(|k| k.info.id == cert.info.id) {
                if let Err(err) = self.add_key(cert) {
                    tracing::warn!(error = %err, "could not store signer certificate");
                }
            }
        }
        inc
    }

    /// The bytes attachments and inline images are read from: the decrypted entity when the
    /// message is protected.
    pub(crate) fn content_view(&self, raw: Vec<u8>, from: &str) -> Vec<u8> {
        self.unprotect(&raw, from).inner.unwrap_or(raw)
    }

    /// Signs / encrypts an outgoing message as the draft asks.
    pub(crate) fn protect(&self, d: &Draft, from: &str, recipients: &[String], raw: Vec<u8>) -> Result<Vec<u8>> {
        if !d.sign && !d.encrypt {
            return Ok(raw);
        }
        let prefer = self.settings().crypto_prefer;
        let opts = crypto::OutgoingCrypto { sign: d.sign, encrypt: d.encrypt, prefer: &prefer, from, recipients };
        crypto::protect_outgoing(&raw, &opts, &self.keyring())
    }

    /// Fails early (before queueing) when encryption cannot work.
    pub(crate) fn check_protection(&self, d: &Draft) -> Result<()> {
        if !d.encrypt {
            return Ok(());
        }
        let recipients: Vec<String> =
            d.to.iter().chain(d.cc.iter()).chain(d.bcc.iter()).map(|a| a.email.trim().to_lowercase()).collect();
        let (_, missing) = self.recipient_keys(&recipients);
        if !missing.is_empty() {
            return Err(Error::Invalid(format!("这些收件人没有公钥，无法加密：{}", missing.join("、"))));
        }
        Ok(())
    }
}

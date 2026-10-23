//! Message bodies: download on demand, parse, sanitize and expose attachments.

use super::Engine;
use crate::error::{Error, Result};
use crate::html;
use crate::mime::{self, Body, Headers};
use crate::model::*;
use crate::store::StoredMessage;
use sha2::{Digest, Sha256};

/// Saves a downloaded message, updates snippet / search index / attachments.
pub(crate) fn store_body(e: &Engine, id: MessageId, raw: &[u8]) -> Result<(Headers, Body)> {
    let hash = hex::encode(Sha256::digest(raw));
    let path = e.paths.blob(&hash);
    if !path.exists() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::paths::write_private(&path, &e.secrets.seal(raw)?)?;
    }
    let (h, b) = mime::parse_full(raw);
    e.db.set_message_body(id, &hash, &b.snippet, &b.search_text, &b.attachments, h.unsubscribe.as_ref())?;
    Ok((h, b))
}

/// Message files are encrypted at rest with the master key.
pub(crate) fn read_blob(e: &Engine, hash: &str) -> Option<Vec<u8>> {
    let data = std::fs::read(e.paths.blob(hash)).ok()?;
    e.secrets.open_sealed(data).ok()
}

fn spoof_warnings(m: &StoredMessage, h: &Headers) -> Vec<String> {
    let mut w = Vec::new();
    if let Some(name) = &m.summary.from.name {
        if let Some(shown) = mime::extract_email(name) {
            if !shown.eq_ignore_ascii_case(&m.summary.from.email) {
                w.push(format!("发件人名称显示为 {shown}，实际地址是 {}", m.summary.from.email));
            }
        }
    }
    if let Some(sender) = &h.sender {
        let dom = |e: &str| e.rsplit_once('@').map(|(_, d)| d.to_lowercase()).unwrap_or_default();
        if !sender.email.is_empty() && dom(&sender.email) != dom(&m.summary.from.email) && m.summary.from.name.is_some() {
            w.push(format!("此邮件由 {} 代发", sender.email));
        }
    }
    w
}

impl Engine {
    /// Raw RFC 5322 bytes, downloading from the server when not cached yet.
    pub async fn raw_message(&self, id: MessageId) -> Result<Vec<u8>> {
        let m = self.db.message(id)?;
        if let Some(raw) = m.blob.as_deref().and_then(|h| read_blob(self, h)) {
            return Ok(raw);
        }
        let acc = self.db.account(&m.summary.account_id)?;
        if acc.kind != AccountKind::Imap || m.folder_local {
            return Err(Error::NotFound("邮件内容不在本地".into()));
        }
        let uid = m.uid.ok_or_else(|| Error::NotFound("邮件正在同步，请稍候".into()))?;
        let path = m.folder_path.clone();
        let fetched = self
            .with_ondemand(&acc, move |c| Box::pin(async move { c.fetch_bodies(&path, &[uid]).await }))
            .await?;
        let raw = fetched
            .into_iter()
            .find(|f| f.uid == uid)
            .and_then(|f| f.body)
            .ok_or_else(|| Error::NotFound("服务器上已找不到这封邮件".into()))?;
        store_body(self, id, &raw)?;
        Ok(raw)
    }

    pub async fn message_detail(&self, id: MessageId) -> Result<MessageDetail> {
        let raw = self.raw_message(id).await;
        let m = self.db.message(id)?;
        let settings = self.settings();
        let mut d = MessageDetail {
            summary: m.summary.clone(),
            cc: m.cc.clone(),
            bcc: m.bcc.clone(),
            reply_to: m.reply_to.clone(),
            message_id: m.message_id.clone(),
            in_reply_to: m.in_reply_to.clone(),
            references: m.references.clone(),
            unsubscribe: m.unsubscribe.clone(),
            folder_role: m.folder_role,
            ..Default::default()
        };
        let raw = match raw {
            Ok(r) => r,
            Err(err) => {
                d.warnings.push(format!("正文未能加载：{err}"));
                return Ok(d);
            }
        };
        let (h, outer) = mime::parse_full(&raw);
        let inc = self.unprotect(&raw, &m.summary.from.email);
        let b = match &inc.inner {
            Some(inner) => mime::parse_full(inner).1,
            None => outer,
        };
        d.body_loaded = true;
        d.attachments = b.attachments.clone();
        d.summary.has_attachments = b.attachments.iter().any(|a| !a.inline);
        d.text = b.text.clone();
        d.encrypted = b.encrypted || inc.encrypted;
        d.decrypted = inc.decrypted;
        d.decrypt_error = inc.decrypt_error;
        d.signed = b.signed || inc.signature.is_some();
        d.signature = inc.signature.map(Into::into);
        d.read_receipt_to = h.read_receipt_to.clone();
        let html_src = b.html.clone().unwrap_or_else(|| html::text_to_html(b.text.as_deref().unwrap_or("")));
        let s = html::sanitize(&html_src, id, settings.block_trackers);
        d.html = Some(s.html);
        d.has_remote_content = s.has_remote;
        d.trackers = s.trackers;
        d.warnings.extend(s.warnings);
        d.warnings.extend(spoof_warnings(&m, &h));
        let from = m.summary.from.email.to_lowercase();
        d.allow_remote = match settings.load_remote_images.as_str() {
            "always" => true,
            "contacts" => self.db.trusts_images(&from)? || self.db.is_known_contact(&from)?,
            _ => self.db.trusts_images(&from)?,
        };
        if let Some(cal) = &b.calendar {
            let own = self.db.own_addresses()?;
            d.invite = crate::ics::parse_invite(cal, &own);
        }
        if d.unsubscribe.is_none() {
            d.unsubscribe = h.unsubscribe.clone();
        }
        Ok(d)
    }

    /// Every message of a conversation with bodies (reader thread view).
    pub async fn thread_detail(&self, id: MessageId) -> Result<Vec<MessageDetail>> {
        let m = self.db.message(id)?;
        let include_trash = matches!(m.folder_role, FolderRole::Trash | FolderRole::Junk);
        let mut out = Vec::new();
        let mut seen_mids = std::collections::HashSet::new();
        for s in self.db.thread(&m.summary.thread_id, include_trash)? {
            // The same message can live in several folders (Gmail labels); show it once.
            if let Some(mid) = self.db.message(s.id)?.message_id {
                if !seen_mids.insert(mid) {
                    continue;
                }
            }
            out.push(self.message_detail(s.id).await?);
        }
        if out.is_empty() {
            out.push(self.message_detail(id).await?);
        }
        Ok(out)
    }

    /// Raw message, or its decrypted inner entity when it is encrypted / signed.
    async fn protected_view(&self, id: MessageId) -> Result<Vec<u8>> {
        let raw = self.raw_message(id).await?;
        let from = self.db.message(id)?.summary.from.email;
        Ok(self.content_view(raw, &from))
    }

    /// (filename, mime type, bytes) of an attachment.
    pub async fn attachment(&self, id: MessageId, attachment_id: i64) -> Result<(String, String, Vec<u8>)> {
        let raw = self.protected_view(id).await?;
        mime::part_bytes(&raw, attachment_id as usize).ok_or_else(|| Error::NotFound("附件不存在".into()))
    }

    /// Saves an attachment into the cache directory and returns its path (Quick Look / drag out).
    pub async fn attachment_file(&self, id: MessageId, attachment_id: i64) -> Result<std::path::PathBuf> {
        let (name, _, data) = self.attachment(id, attachment_id).await?;
        let safe: String = name.chars().map(|c| if c == '/' || c == ':' || c == '\\' { '_' } else { c }).collect();
        let dir = self.paths.attachments().join(format!("{id}-{attachment_id}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(if safe.is_empty() { "attachment".into() } else { safe });
        std::fs::write(&path, data)?;
        Ok(path)
    }

    pub async fn cid_part(&self, id: MessageId, cid: &str) -> Result<(String, Vec<u8>)> {
        let raw = self.protected_view(id).await?;
        mime::cid_bytes(&raw, cid).ok_or_else(|| Error::NotFound("内嵌图片不存在".into()))
    }

    /// Opening a message: mark it read (per settings) and trust its sender's images if asked.
    pub async fn open_message(&self, id: MessageId) -> Result<MessageDetail> {
        let d = self.message_detail(id).await?;
        let s = self.settings();
        if s.mark_read_on_open && s.mark_read_delay_secs == 0 && !d.summary.flags.seen {
            self.act(&[id], super::Action::Read).await?;
        }
        Ok(d)
    }
}

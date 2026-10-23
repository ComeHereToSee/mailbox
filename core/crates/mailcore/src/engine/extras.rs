//! Server-side search, running a rule on existing mail, and mbox / eml import & export.

use super::{Engine, detail, imap_worker, newmail};
use crate::error::{Error, Result};
use crate::imap::uid_set;
use crate::model::*;
use crate::rules::{self, RuleInput};
use crate::store::{ListQuery, NewMessage, OpKind, now};
use std::io::Write;
use std::path::Path;

/// Splits an mbox file into raw messages (mboxrd: `>From ` lines are unescaped).
pub fn split_mbox(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut in_msg = false;
    for line in data.split_inclusive(|b| *b == b'\n') {
        if line.starts_with(b"From ") {
            if in_msg && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            in_msg = true;
            continue;
        }
        if !in_msg {
            continue;
        }
        let trimmed: &[u8] = line;
        let unescaped = {
            let n = trimmed.iter().take_while(|b| **b == b'>').count();
            if n > 0 && trimmed[n..].starts_with(b"From ") { &trimmed[1..] } else { trimmed }
        };
        cur.extend_from_slice(unescaped);
    }
    if in_msg && !cur.is_empty() {
        out.push(cur);
    }
    for m in out.iter_mut() {
        while m.ends_with(b"\n\n") || m.ends_with(b"\r\n\r\n") {
            m.pop();
            if m.ends_with(b"\r") {
                m.pop();
            }
        }
    }
    out
}

fn mbox_escape(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 64);
    for line in raw.split_inclusive(|b| *b == b'\n') {
        let n = line.iter().take_while(|b| **b == b'>').count();
        if line[n..].starts_with(b"From ") {
            out.push(b'>');
        }
        out.extend_from_slice(line);
    }
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

impl Engine {
    /// IMAP SEARCH on the server (finds mail outside the local sync window).
    pub async fn server_search(&self, account_id: &str, folder_id: Option<FolderId>, q: &str) -> Result<Vec<MessageSummary>> {
        let acc = self.db.account(account_id)?;
        if acc.kind != AccountKind::Imap {
            return Err(Error::Invalid("只有 IMAP 账户支持服务器搜索".into()));
        }
        let folder = match folder_id {
            Some(id) => self.db.folder(id)?,
            None => self
                .db
                .folder_by_role(&acc.id, FolderRole::All)?
                .or(self.db.folder_by_role(&acc.id, FolderRole::Inbox)?)
                .ok_or_else(|| Error::NotFound("收件箱".into()))?,
        };
        let path = folder.path.clone();
        let text = q.to_string();
        let fetched = self
            .with_ondemand(&acc, move |c| {
                Box::pin(async move {
                    let mut uids = c.server_search(&path, &text).await?;
                    if uids.len() > 100 {
                        uids = uids[uids.len() - 100..].to_vec();
                    }
                    if uids.is_empty() {
                        return Ok(Vec::new());
                    }
                    c.fetch_headers(&path, &uid_set(&uids)).await
                })
            })
            .await?;
        let mut out = Vec::new();
        for fm in &fetched {
            let id = match self.db.message_by_uid(folder.id, fm.uid)? {
                Some(id) => id,
                None => self.db.insert_message(&imap_worker::to_new_message(self, &acc, &folder, fm))?.0,
            };
            out.push(self.db.message(id)?.summary);
        }
        out.sort_by(|a, b| b.date.cmp(&a.date));
        Ok(out)
    }

    /// Applies one rule to the existing inbox messages. Returns how many matched.
    pub async fn run_rule_on_inbox(&self, rule: &Rule) -> Result<usize> {
        let msgs = self.db.list_messages(&ListQuery { limit: 2000, ..Default::default() })?;
        let mut n = 0;
        for s in msgs {
            if let Some(acc) = &rule.account_id {
                if !acc.is_empty() && *acc != s.account_id {
                    continue;
                }
            }
            let m = self.db.message(s.id)?;
            let body = if rule.conditions.iter().any(|c| c.field == "body") {
                m.blob.as_deref().and_then(|h| detail::read_blob(self, h)).map(|raw| crate::mime::parse_full(&raw).1.search_text)
            } else {
                None
            };
            let to: Vec<String> = m.summary.to.iter().map(|a| a.email.clone()).collect();
            let cc: Vec<String> = m.cc.iter().map(|a| a.email.clone()).collect();
            let input = RuleInput {
                account_id: &m.summary.account_id,
                from: &m.summary.from.email,
                from_name: m.summary.from.name.as_deref().unwrap_or(""),
                to: &to,
                cc: &cc,
                subject: &m.summary.subject,
                body: body.as_deref(),
                has_attachment: m.summary.has_attachments,
                list_id: m.list_id.as_deref(),
                raw_headers: None,
            };
            if rules::rule_matches(rule, &input) {
                let out = rules::evaluate(std::slice::from_ref(rule), &input);
                newmail::apply_outcome(self, &m.summary.account_id, m.summary.id, &m.summary.from.email, &out).await;
                n += 1;
            }
        }
        self.changed(None);
        Ok(n)
    }

    /// Imports an .mbox file, a single .eml or a directory of .eml files into a folder.
    pub async fn import_messages(&self, folder_id: FolderId, path: &Path) -> Result<usize> {
        let folder = self.db.folder(folder_id)?;
        let acc = self.db.account(&folder.account_id)?;
        let mut raws = Vec::new();
        if path.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("eml")) {
                    raws.push(std::fs::read(&p)?);
                }
            }
        } else {
            let data = std::fs::read(path)?;
            if data.starts_with(b"From ") {
                raws = split_mbox(&data);
            } else {
                raws.push(data);
            }
        }
        let server = acc.kind == AccountKind::Imap && !folder.local;
        for raw in &raws {
            if server {
                let blob = format!("{}.eml", uuid::Uuid::new_v4().simple());
                crate::paths::write_private(&self.paths.uploads().join(&blob), raw)?;
                self.db.enqueue_op(&acc.id, &OpKind::Append { folder: folder.id, blob, flags: vec!["seen".into()], replace_uid: None })?;
            } else {
                let h = crate::mime::parse_headers(raw);
                let nm = NewMessage {
                    account_id: acc.id.clone(),
                    folder_id: folder.id,
                    remote_id: Some(format!("import:{}", uuid::Uuid::new_v4().simple())),
                    message_id: h.message_id.clone(),
                    in_reply_to: h.in_reply_to.clone(),
                    references: h.references.clone(),
                    subject: h.subject.clone(),
                    from: h.from.clone(),
                    to: h.to.clone(),
                    cc: h.cc.clone(),
                    date: h.date.unwrap_or_else(now),
                    size: raw.len() as i64,
                    flags: Flags { seen: true, ..Default::default() },
                    ..Default::default()
                };
                let (id, _) = self.db.insert_message(&nm)?;
                detail::store_body(self, id, raw)?;
            }
        }
        if server {
            self.wake(Some(&acc.id));
        }
        self.changed(Some(&acc.id));
        Ok(raws.len())
    }

    /// Exports messages to an mbox file or a directory of .eml files.
    pub async fn export_messages(&self, ids: Option<Vec<MessageId>>, folder_id: Option<FolderId>, path: &Path, format: &str) -> Result<usize> {
        let ids = match (ids, folder_id) {
            (Some(ids), _) => ids,
            (None, Some(f)) => self
                .db
                .list_messages(&ListQuery { mailbox: Mailbox::Folder(f), limit: 1000, ..Default::default() })?
                .into_iter()
                .map(|m| m.id)
                .collect(),
            _ => return Err(Error::Invalid("请指定要导出的邮件".into())),
        };
        let mut n = 0;
        if format == "eml" {
            std::fs::create_dir_all(path)?;
            for id in ids {
                let raw = self.raw_message(id).await?;
                let m = self.db.message(id)?;
                let name: String = m.summary.subject.chars().filter(|c| !"/\\:*?\"<>|".contains(*c)).take(60).collect();
                std::fs::write(path.join(format!("{id}-{}.eml", if name.is_empty() { "无主题".into() } else { name })), raw)?;
                n += 1;
            }
        } else {
            let mut f = std::fs::File::create(path)?;
            for id in ids {
                let raw = self.raw_message(id).await?;
                let m = self.db.message(id)?;
                let date = chrono::DateTime::from_timestamp(m.summary.date, 0).unwrap_or_default().format("%a %b %e %H:%M:%S %Y");
                let from = if m.summary.from.email.is_empty() { "MAILER-DAEMON".to_string() } else { m.summary.from.email.clone() };
                writeln!(f, "From {from} {date}")?;
                f.write_all(&mbox_escape(&raw))?;
                writeln!(f)?;
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbox_roundtrip() {
        let a = b"Subject: a\n\nhello\n>From me\nFrom here\n".to_vec();
        let b = b"Subject: b\n\nworld\n".to_vec();
        let mut mbox = Vec::new();
        for m in [&a, &b] {
            mbox.extend_from_slice(b"From x@y Thu Jan  1 00:00:00 2026\n");
            mbox.extend_from_slice(&mbox_escape(m));
            mbox.push(b'\n');
        }
        let parts = split_mbox(&mbox);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], a);
        assert_eq!(parts[1], b);
    }
}

#[derive(serde::Serialize, Debug, Default)]
pub struct StorageReport {
    pub database_bytes: u64,
    pub messages_bytes: u64,
    pub cache_bytes: u64,
    pub message_count: i64,
}

fn dir_size(path: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(path) else { return 0 };
    rd.flatten()
        .map(|e| {
            let p = e.path();
            if p.is_dir() { dir_size(&p) } else { e.metadata().map(|m| m.len()).unwrap_or(0) }
        })
        .sum()
}

impl Engine {
    pub fn storage_report(&self) -> Result<StorageReport> {
        let db_path = self.paths.db();
        let wal = db_path.with_extension("db-wal");
        let database_bytes = [db_path, wal].iter().filter_map(|p| std::fs::metadata(p).ok()).map(|m| m.len()).sum();
        let message_count = self.db.count_messages(&Mailbox::All, false)?
            + self.db.count_messages(&Mailbox::Unified(FolderRole::Trash), false)?
            + self.db.count_messages(&Mailbox::Unified(FolderRole::Junk), false)?;
        Ok(StorageReport {
            database_bytes,
            messages_bytes: dir_size(&self.paths.root.join("blobs")),
            cache_bytes: dir_size(&self.paths.attachments()) + dir_size(&self.paths.tmp()),
            message_count,
        })
    }

    /// Drops cached mail older than each account's sync window (it stays on the server),
    /// deletes unreferenced message files and clears the attachment cache. Returns bytes freed.
    pub fn cleanup(&self) -> Result<u64> {
        let before = self.storage_report()?;
        for acc in self.db.accounts()? {
            if acc.kind != AccountKind::Imap || acc.config.sync_days == 0 || acc.provider.as_deref() == Some("demo") {
                continue;
            }
            let cutoff = now() - acc.config.sync_days as i64 * 86_400;
            for f in self.db.folders(Some(&acc.id))? {
                if f.local {
                    continue;
                }
                let old = self.db.messages_older_than(f.id, cutoff)?;
                self.db.delete_messages(&old)?;
            }
        }
        let blobs = self.paths.root.join("blobs");
        if let Ok(dirs) = std::fs::read_dir(&blobs) {
            for d in dirs.flatten() {
                let prefix = d.file_name().to_string_lossy().to_string();
                let Ok(files) = std::fs::read_dir(d.path()) else { continue };
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().to_string();
                    let hash = format!("{prefix}{}", name.trim_end_matches(".eml"));
                    if !self.db.blob_in_use(&hash)? {
                        let _ = std::fs::remove_file(f.path());
                    }
                }
            }
        }
        for dir in [self.paths.attachments(), self.paths.tmp()] {
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::create_dir_all(&dir);
        }
        let _ = self.db.write(|c| {
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); INSERT INTO messages_fts(messages_fts) VALUES('optimize');")?;
            Ok(())
        });
        let after = self.storage_report()?;
        let total = |r: &StorageReport| r.database_bytes + r.messages_bytes + r.cache_bytes;
        self.changed(None);
        Ok(total(&before).saturating_sub(total(&after)))
    }
}

#[derive(serde::Serialize, Debug, Default)]
pub struct SieveStatus {
    pub supported: bool,
    pub scripts: Vec<crate::sieve::SieveScript>,
    pub active_script: Option<String>,
    pub error: Option<String>,
}

impl Engine {
    async fn sieve_connect(&self, acc: &Account) -> Result<crate::sieve::SieveConn> {
        let imap = acc.config.imap.as_ref().ok_or_else(|| Error::Invalid("服务器规则只支持 IMAP 账户".into()))?;
        let server = crate::sieve::server_for(imap);
        let auth = match self.credentials(acc).await? {
            super::Cred::Password(p) => crate::sieve::SieveAuth::Password(p),
            super::Cred::OAuth(t) => crate::sieve::SieveAuth::OAuth2(t),
        };
        crate::sieve::SieveConn::connect(&server, &Engine::login_name(acc, imap), &auth).await
    }

    /// Scripts on the server (ManageSieve). `supported` is false when the server has no ManageSieve.
    pub async fn sieve_status(&self, account_id: &str) -> Result<SieveStatus> {
        let acc = self.db.account(account_id)?;
        let mut c = match self.sieve_connect(&acc).await {
            Ok(c) => c,
            Err(e) if e.is_connection() => return Ok(SieveStatus { error: Some(e.to_string()), ..Default::default() }),
            Err(e) => return Err(e),
        };
        let scripts = c.list().await?;
        let active_script = match scripts.iter().find(|s| s.active) {
            Some(s) => Some(c.get(&s.name).await?),
            None => None,
        };
        c.logout().await;
        Ok(SieveStatus { supported: true, scripts, active_script, error: None })
    }

    /// Uploads the account's rules as the active server-side Sieve script. Returns the script.
    pub async fn sieve_upload(&self, account_id: &str) -> Result<String> {
        let acc = self.db.account(account_id)?;
        let rules: Vec<Rule> = self.db.kv_list("rules")?;
        let folder_for = |name: &str| self.find_folder(&acc.id, name).and_then(|id| self.db.folder(id).ok()).map(|f| f.path);
        let script = crate::sieve::rules_to_sieve(&rules, &acc.id, &folder_for);
        let mut c = self.sieve_connect(&acc).await?;
        c.check(&script).await?;
        c.put(crate::sieve::SCRIPT_NAME, &script).await?;
        c.activate(crate::sieve::SCRIPT_NAME).await?;
        c.logout().await;
        Ok(script)
    }

    pub async fn sieve_remove(&self, account_id: &str) -> Result<()> {
        let acc = self.db.account(account_id)?;
        let mut c = self.sieve_connect(&acc).await?;
        if c.list().await?.iter().any(|s| s.name == crate::sieve::SCRIPT_NAME) {
            c.activate("").await.ok();
            c.delete(crate::sieve::SCRIPT_NAME).await?;
        }
        c.logout().await;
        Ok(())
    }
}

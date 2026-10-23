use super::{Db, now};
use crate::error::{Error, Result};
use crate::model::*;
use crate::search;
use rusqlite::types::Value;
use rusqlite::{OptionalExtension, Row, Transaction, params, params_from_iter};

/// A message as discovered by a sync worker.
#[derive(Debug, Clone, Default)]
pub struct NewMessage {
    pub account_id: String,
    pub folder_id: FolderId,
    pub uid: Option<u32>,
    pub remote_id: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub subject: String,
    pub from: EmailAddress,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub reply_to: Vec<EmailAddress>,
    pub date: i64,
    pub size: i64,
    pub flags: Flags,
    pub labels: Vec<String>,
    pub has_attachments: bool,
    pub snippet: String,
    pub category: Category,
    pub list_id: Option<String>,
    pub unsubscribe: Option<Unsubscribe>,
    pub blob: Option<String>,
    pub modseq: Option<u64>,
    /// Plain text used for the search index when the body is known.
    pub body_text: Option<String>,
    pub attachments: Vec<Attachment>,
}

/// Internal view of a message row with fields the API does not expose.
#[derive(Debug, Clone, Default)]
pub struct StoredMessage {
    pub summary: MessageSummary,
    pub uid: Option<u32>,
    pub remote_id: Option<String>,
    pub folder_path: String,
    pub folder_role: FolderRole,
    pub folder_local: bool,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub reply_to: Vec<EmailAddress>,
    pub blob: Option<String>,
    pub size: i64,
    pub unsubscribe: Option<Unsubscribe>,
    pub list_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ListQuery {
    pub mailbox: Mailbox,
    pub search: Option<String>,
    pub threads: bool,
    /// Pagination cursor: (sort_date, id) of the last row of the previous page.
    pub before: Option<(i64, i64)>,
    pub limit: i64,
    pub account_id: Option<String>,
}

impl Default for ListQuery {
    fn default() -> Self {
        ListQuery {
            mailbox: Mailbox::Unified(FolderRole::Inbox),
            search: None,
            threads: false,
            before: None,
            limit: 100,
            account_id: None,
        }
    }
}

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

fn from_json<T: serde::de::DeserializeOwned + Default>(s: Option<String>) -> T {
    s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn summary_from_row(r: &Row) -> rusqlite::Result<MessageSummary> {
    Ok(MessageSummary {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        folder_id: r.get("folder_id")?,
        thread_id: r.get("thread_id")?,
        subject: r.get("subject")?,
        from: EmailAddress { name: r.get("from_name")?, email: r.get("from_email")? },
        to: from_json(r.get("to_json")?),
        date: r.get("date")?,
        snippet: r.get("snippet")?,
        flags: Flags {
            seen: r.get("seen")?,
            flagged: r.get("flagged")?,
            answered: r.get("answered")?,
            forwarded: r.get("forwarded")?,
            draft: r.get("draft")?,
        },
        has_attachments: r.get("has_attachments")?,
        labels: from_json(r.get("labels")?),
        category: Category::parse(&r.get::<_, String>("category")?),
        pinned: r.get("pinned")?,
        snoozed_until: r.get("snoozed_until")?,
        is_vip: r.get::<_, Option<bool>>("is_vip")?.unwrap_or(false),
        thread_count: r.get::<_, Option<i64>>("thread_count").ok().flatten().unwrap_or(1),
        thread_unread: r.get::<_, Option<i64>>("thread_unread").ok().flatten().unwrap_or(0),
    })
}

fn stored_from_row(r: &Row) -> rusqlite::Result<StoredMessage> {
    let refs: String = r.get("refs")?;
    Ok(StoredMessage {
        summary: summary_from_row(r)?,
        uid: r.get("uid")?,
        remote_id: r.get("remote_id")?,
        folder_path: r.get("folder_path")?,
        folder_role: FolderRole::parse(&r.get::<_, String>("folder_role")?),
        folder_local: r.get("folder_local")?,
        message_id: r.get("message_id")?,
        in_reply_to: r.get("in_reply_to")?,
        references: refs.split_whitespace().map(String::from).collect(),
        cc: from_json(r.get("cc_json")?),
        bcc: from_json(r.get("bcc_json")?),
        reply_to: from_json(r.get("reply_to_json")?),
        blob: r.get("blob")?,
        size: r.get("size")?,
        unsubscribe: r.get::<_, Option<String>>("unsubscribe")?.and_then(|s| serde_json::from_str(&s).ok()),
        list_id: r.get("list_id")?,
    })
}

const VIP_COL: &str = "(m.from_email IN (SELECT email FROM contacts WHERE vip = 1)) AS is_vip";

fn normalize_subject(s: &str) -> String {
    let mut s = s.trim();
    loop {
        let lower = s.to_lowercase();
        let mut stripped = false;
        for p in ["re:", "fw:", "fwd:", "回复:", "回复：", "答复:", "答复：", "转发:", "转发：", "aw:", "sv:", "re：", "fw："] {
            if lower.starts_with(p) {
                s = s[p.len()..].trim_start();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    s.to_lowercase()
}

fn has_reply_prefix(s: &str) -> bool {
    normalize_subject(s) != s.trim().to_lowercase()
}

/// Finds or creates the conversation id for a message.
fn assign_thread(tx: &Transaction, m: &NewMessage) -> Result<String> {
    let mut candidates: Vec<String> = Vec::new();
    let mut parents: Vec<&str> = m.references.iter().map(String::as_str).collect();
    if let Some(irt) = &m.in_reply_to {
        parents.push(irt);
    }
    if let Some(mid) = &m.message_id {
        parents.push(mid);
    }
    for p in parents.iter().rev() {
        if let Some(t) = tx
            .query_row(
                "SELECT thread_id FROM messages WHERE account_id = ? AND message_id = ? LIMIT 1",
                params![m.account_id, p],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            if !candidates.contains(&t) {
                candidates.push(t);
            }
        }
    }
    // Replies that arrived before their parent.
    if let Some(mid) = &m.message_id {
        let mut st = tx.prepare("SELECT DISTINCT thread_id FROM messages WHERE account_id = ? AND in_reply_to = ?")?;
        for t in st.query_map(params![m.account_id, mid], |r| r.get::<_, String>(0))? {
            let t = t?;
            if !candidates.contains(&t) {
                candidates.push(t);
            }
        }
    }
    if candidates.is_empty() && m.references.is_empty() && m.in_reply_to.is_none() && has_reply_prefix(&m.subject) {
        let norm = normalize_subject(&m.subject);
        if norm.chars().count() >= 4 {
            let mut st = tx.prepare(
                "SELECT thread_id, subject FROM messages WHERE account_id = ? AND date > ? AND date <= ?
                 ORDER BY date DESC LIMIT 200",
            )?;
            let rows = st.query_map(params![m.account_id, m.date - 30 * 86_400, m.date + 86_400], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (t, subj) = row?;
                if normalize_subject(&subj) == norm {
                    candidates.push(t);
                    break;
                }
            }
        }
    }
    match candidates.len() {
        0 => Ok(m
            .message_id
            .clone()
            .or_else(|| m.references.first().cloned())
            .unwrap_or_else(super::new_id)),
        _ => {
            let keep = candidates[0].clone();
            for other in &candidates[1..] {
                tx.execute("UPDATE messages SET thread_id = ? WHERE thread_id = ?", params![keep, other])?;
            }
            Ok(keep)
        }
    }
}

fn address_text(m: &NewMessage) -> String {
    let mut s = String::new();
    for a in std::iter::once(&m.from).chain(m.to.iter()).chain(m.cc.iter()) {
        if let Some(n) = &a.name {
            s.push_str(n);
            s.push(' ');
        }
        s.push_str(&a.email);
        s.push(' ');
    }
    s
}

fn index_fts(tx: &Transaction, id: MessageId, subject: &str, addresses: &str, body: &str, attachments: &str) -> Result<()> {
    tx.execute("DELETE FROM messages_fts WHERE rowid = ?", [id])?;
    tx.execute(
        "INSERT INTO messages_fts (rowid, subject, addresses, body, attachments) VALUES (?, ?, ?, ?, ?)",
        params![id, search::segment(subject), search::segment(addresses), search::segment(body), search::segment(attachments)],
    )?;
    Ok(())
}

fn insert_attachments(tx: &Transaction, id: MessageId, atts: &[Attachment]) -> Result<()> {
    tx.execute("DELETE FROM attachments WHERE message_id = ?", [id])?;
    for (i, a) in atts.iter().enumerate() {
        let idx = if a.id > 0 { a.id } else { i as i64 };
        tx.execute(
            "INSERT INTO attachments (message_id, part_index, filename, mime_type, size, content_id, inline)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, idx, a.filename, a.mime_type, a.size, a.content_id, a.inline],
        )?;
    }
    Ok(())
}

pub(crate) fn mailbox_filter(db: &Db, mailbox: &Mailbox) -> Result<search::Filter> {
    let mut f = search::Filter::default();
    let not_trash = "f.role NOT IN ('trash', 'junk')";
    match mailbox {
        Mailbox::Unified(role) => {
            f.push("f.role = ?", [Value::Text(role.as_str().into())]);
            if *role == FolderRole::Inbox {
                f.push("m.snoozed_until IS NULL", []);
            }
        }
        Mailbox::AccountRole(acc, role) => {
            f.push("m.account_id = ? AND f.role = ?", [Value::Text(acc.clone()), Value::Text(role.as_str().into())]);
            if *role == FolderRole::Inbox {
                f.push("m.snoozed_until IS NULL", []);
            }
        }
        Mailbox::Folder(id) => {
            f.push("m.folder_id = ?", [Value::Integer(*id)]);
            if db.folder(*id)?.role == FolderRole::Inbox {
                f.push("m.snoozed_until IS NULL", []);
            }
        }
        Mailbox::Starred => f.push(format!("m.flagged = 1 AND {not_trash}"), []),
        Mailbox::Unread => f.push("m.seen = 0 AND f.role IN ('inbox', 'custom', 'archive') AND m.snoozed_until IS NULL", []),
        Mailbox::Snoozed => f.push("m.snoozed_until IS NOT NULL", []),
        Mailbox::Pinned => f.push(format!("m.pinned = 1 AND {not_trash}"), []),
        Mailbox::Attachments => f.push(format!("m.has_attachments = 1 AND {not_trash}"), []),
        Mailbox::Vip => f.push(format!("m.from_email IN (SELECT email FROM contacts WHERE vip = 1) AND {not_trash}"), []),
        Mailbox::Category(c) => {
            f.push("f.role = 'inbox' AND m.snoozed_until IS NULL AND m.category = ?", [Value::Text(c.as_str().into())])
        }
        Mailbox::Label(acc, label) => f.push(
            "m.account_id = ? AND m.labels LIKE ?",
            [Value::Text(acc.clone()), Value::Text(format!("%\"{}\"%", label.replace('"', "")))],
        ),
        Mailbox::Smart(id) => {
            let sf: SmartFolder = db.kv_get("smart_folders", id)?.ok_or_else(|| Error::NotFound(format!("smart folder {id}")))?;
            f.push(not_trash, []);
            let inner = search::compile(&sf.query);
            if !inner.is_empty() {
                f.push(inner.sql(), inner.params);
            }
        }
        Mailbox::All => f.push(not_trash, []),
    }
    f.push("m.hidden = 0", []);
    Ok(f)
}

impl Db {
    /// Inserts a message or refreshes an existing copy. Returns `(id, inserted)`.
    pub fn insert_message(&self, m: &NewMessage) -> Result<(MessageId, bool)> {
        self.tx(|tx| {
            // Same server message already known?
            let existing: Option<MessageId> = if let Some(uid) = m.uid {
                tx.query_row(
                    "SELECT id FROM messages WHERE folder_id = ? AND uid = ?",
                    params![m.folder_id, uid],
                    |r| r.get(0),
                )
                .optional()?
            } else if let Some(rid) = &m.remote_id {
                tx.query_row(
                    "SELECT id FROM messages WHERE folder_id = ? AND remote_id = ?",
                    params![m.folder_id, rid],
                    |r| r.get(0),
                )
                .optional()?
            } else {
                None
            };
            if let Some(id) = existing {
                update_flags_tx(tx, id, &m.flags, &m.labels, m.modseq)?;
                return Ok((id, false));
            }
            // A locally moved copy waiting for its new UID.
            if m.uid.is_some() {
                let pending: Option<MessageId> = match &m.message_id {
                    Some(mid) => tx
                        .query_row(
                            "SELECT id FROM messages WHERE folder_id = ? AND uid IS NULL AND remote_id IS NULL AND message_id = ? LIMIT 1",
                            params![m.folder_id, mid],
                            |r| r.get(0),
                        )
                        .optional()?,
                    None => tx
                        .query_row(
                            "SELECT id FROM messages WHERE folder_id = ? AND uid IS NULL AND remote_id IS NULL AND message_id IS NULL
                             AND subject = ? AND date = ? LIMIT 1",
                            params![m.folder_id, m.subject, m.date],
                            |r| r.get(0),
                        )
                        .optional()?,
                };
                if let Some(id) = pending {
                    tx.execute("UPDATE messages SET uid = ?, modseq = ? WHERE id = ?", params![m.uid, m.modseq.map(|v| v as i64), id])?;
                    update_flags_tx(tx, id, &m.flags, &m.labels, m.modseq)?;
                    return Ok((id, false));
                }
            }
            let thread_id = assign_thread(tx, m)?;
            let created = now();
            tx.execute(
                "INSERT INTO messages (account_id, folder_id, uid, remote_id, message_id, in_reply_to, refs, thread_id,
                    subject, from_name, from_email, to_json, cc_json, bcc_json, reply_to_json, date, sort_date, size,
                    seen, flagged, answered, forwarded, draft, labels, has_attachments, snippet, category, list_id,
                    unsubscribe, blob, modseq, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    m.account_id,
                    m.folder_id,
                    m.uid,
                    m.remote_id,
                    m.message_id,
                    m.in_reply_to,
                    m.references.join(" "),
                    thread_id,
                    m.subject,
                    m.from.name,
                    m.from.email.to_lowercase(),
                    json(&m.to),
                    json(&m.cc),
                    json(&m.bcc),
                    json(&m.reply_to),
                    m.date,
                    m.date,
                    m.size,
                    m.flags.seen,
                    m.flags.flagged,
                    m.flags.answered,
                    m.flags.forwarded,
                    m.flags.draft,
                    json(&m.labels),
                    m.has_attachments,
                    m.snippet,
                    m.category.as_str(),
                    m.list_id,
                    m.unsubscribe.as_ref().map(json),
                    m.blob,
                    m.modseq.map(|v| v as i64),
                    created
                ],
            )?;
            let id = tx.last_insert_rowid();
            let att_names = m.attachments.iter().map(|a| a.filename.as_str()).collect::<Vec<_>>().join(" ");
            index_fts(tx, id, &m.subject, &address_text(m), m.body_text.as_deref().unwrap_or(""), &att_names)?;
            if !m.attachments.is_empty() {
                insert_attachments(tx, id, &m.attachments)?;
            }
            Ok((id, true))
        })
    }

    /// Stores the downloaded body of a message.
    pub fn set_message_body(
        &self,
        id: MessageId,
        blob: &str,
        snippet: &str,
        body_text: &str,
        attachments: &[Attachment],
        unsubscribe: Option<&Unsubscribe>,
    ) -> Result<()> {
        self.tx(|tx| {
            tx.execute(
                "UPDATE messages SET blob = ?, snippet = ?, has_attachments = ?, unsubscribe = COALESCE(?, unsubscribe) WHERE id = ?",
                params![blob, snippet, attachments.iter().any(|a| !a.inline), unsubscribe.map(json), id],
            )?;
            let (subject, from_name, from_email, to_json, cc_json): (String, Option<String>, String, String, String) = tx.query_row(
                "SELECT subject, from_name, from_email, to_json, cc_json FROM messages WHERE id = ?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            let fake = NewMessage {
                from: EmailAddress { name: from_name, email: from_email },
                to: from_json(Some(to_json)),
                cc: from_json(Some(cc_json)),
                ..Default::default()
            };
            let names = attachments.iter().map(|a| a.filename.as_str()).collect::<Vec<_>>().join(" ");
            index_fts(tx, id, &subject, &address_text(&fake), body_text, &names)?;
            insert_attachments(tx, id, attachments)?;
            Ok(())
        })
    }

    pub fn update_flags(&self, id: MessageId, flags: &Flags, labels: &[String], modseq: Option<u64>) -> Result<()> {
        self.tx(|tx| update_flags_tx(tx, id, flags, labels, modseq))
    }

    pub fn message(&self, id: MessageId) -> Result<StoredMessage> {
        self.read(|c| {
            c.query_row(
                &format!(
                    "SELECT m.*, f.path AS folder_path, f.role AS folder_role, f.local AS folder_local, {VIP_COL}
                     FROM messages m JOIN folders f ON f.id = m.folder_id WHERE m.id = ?"
                ),
                [id],
                stored_from_row,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("message {id}")))
        })
    }

    pub fn messages_by_ids(&self, ids: &[MessageId]) -> Result<Vec<StoredMessage>> {
        ids.iter().map(|id| self.message(*id)).filter(|r| !matches!(r, Err(Error::NotFound(_)))).collect()
    }

    pub fn attachments(&self, id: MessageId) -> Result<Vec<Attachment>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT part_index, filename, mime_type, size, content_id, inline FROM attachments WHERE message_id = ? ORDER BY id",
            )?;
            let rows = st
                .query_map([id], |r| {
                    Ok(Attachment {
                        id: r.get(0)?,
                        filename: r.get(1)?,
                        mime_type: r.get(2)?,
                        size: r.get(3)?,
                        content_id: r.get(4)?,
                        inline: r.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// UIDs and flags of the cached messages of a folder.
    pub fn folder_uids(&self, folder_id: FolderId) -> Result<Vec<(MessageId, u32, Flags)>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT id, uid, seen, flagged, answered, forwarded, draft FROM messages WHERE folder_id = ? AND uid IS NOT NULL",
            )?;
            let rows = st
                .query_map([folder_id], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        Flags { seen: r.get(2)?, flagged: r.get(3)?, answered: r.get(4)?, forwarded: r.get(5)?, draft: r.get(6)? },
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn folder_remote_ids(&self, folder_id: FolderId) -> Result<Vec<(MessageId, String, i64)>> {
        self.read(|c| {
            let mut st =
                c.prepare("SELECT id, remote_id, created_at FROM messages WHERE folder_id = ? AND remote_id IS NOT NULL")?;
            let rows = st
                .query_map([folder_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn max_uid(&self, folder_id: FolderId) -> Result<Option<u32>> {
        self.read(|c| Ok(c.query_row("SELECT MAX(uid) FROM messages WHERE folder_id = ?", [folder_id], |r| r.get(0))?))
    }

    pub fn delete_messages(&self, ids: &[MessageId]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        self.tx(|tx| {
            for id in ids {
                tx.execute("DELETE FROM messages_fts WHERE rowid = ?", [id])?;
                tx.execute("DELETE FROM messages WHERE id = ?", [id])?;
            }
            Ok(())
        })
    }

    /// Applies a local flag change to many messages.
    pub fn set_flag(&self, ids: &[MessageId], column: &str, value: bool) -> Result<()> {
        let col = match column {
            "seen" | "flagged" | "answered" | "forwarded" | "draft" | "pinned" | "hidden" => column,
            _ => return Err(Error::Invalid(format!("flag {column}"))),
        };
        self.tx(|tx| {
            for id in ids {
                tx.execute(&format!("UPDATE messages SET {col} = ? WHERE id = ?"), params![value, id])?;
            }
            Ok(())
        })
    }

    pub fn set_labels(&self, id: MessageId, labels: &[String]) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE messages SET labels = ? WHERE id = ?", params![json(&labels), id])?;
            Ok(())
        })
    }

    pub fn set_category(&self, id: MessageId, category: Category) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE messages SET category = ? WHERE id = ?", params![category.as_str(), id])?;
            Ok(())
        })
    }

    /// Moves messages locally; the UID is cleared until the target folder sync picks them up.
    pub fn move_local(&self, ids: &[MessageId], folder_id: FolderId, keep_uid: bool) -> Result<()> {
        self.tx(|tx| {
            for id in ids {
                if keep_uid {
                    tx.execute("UPDATE messages SET folder_id = ? WHERE id = ?", params![folder_id, id])?;
                } else {
                    tx.execute("UPDATE messages SET folder_id = ?, uid = NULL WHERE id = ?", params![folder_id, id])?;
                }
            }
            Ok(())
        })
    }

    pub fn set_uid(&self, id: MessageId, uid: Option<u32>) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE messages SET uid = ? WHERE id = ?", params![uid, id])?;
            Ok(())
        })
    }

    pub fn snooze(&self, ids: &[MessageId], until: Option<i64>) -> Result<()> {
        self.tx(|tx| {
            for id in ids {
                tx.execute("UPDATE messages SET snoozed_until = ? WHERE id = ?", params![until, id])?;
            }
            Ok(())
        })
    }

    /// Wakes up snoozed messages whose time has come: unsnooze, mark unread, move to top.
    pub fn wake_snoozed(&self, at: i64) -> Result<Vec<MessageId>> {
        self.tx(|tx| {
            let ids: Vec<MessageId> = {
                let mut st = tx.prepare("SELECT id FROM messages WHERE snoozed_until IS NOT NULL AND snoozed_until <= ?")?;
                st.query_map([at], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for id in &ids {
                tx.execute(
                    "UPDATE messages SET snoozed_until = NULL, seen = 0, sort_date = ? WHERE id = ?",
                    params![at, id],
                )?;
            }
            Ok(ids)
        })
    }

    pub fn list_messages(&self, q: &ListQuery) -> Result<Vec<MessageSummary>> {
        let mut filter = mailbox_filter(self, &q.mailbox)?;
        if let Some(acc) = &q.account_id {
            filter.push("m.account_id = ?", [Value::Text(acc.clone())]);
        }
        if let Some(s) = q.search.as_deref().filter(|s| !s.trim().is_empty()) {
            let sf = search::compile(s);
            if !sf.is_empty() {
                filter.push(sf.sql(), sf.params);
            }
        }
        let mut params = filter.params.clone();
        let cursor = match q.before {
            Some((d, id)) => {
                params.push(Value::Integer(d));
                params.push(Value::Integer(d));
                params.push(Value::Integer(id));
                "AND (sort_date < ? OR (sort_date = ? AND id < ?))"
            }
            None => "",
        };
        params.push(Value::Integer(q.limit.clamp(1, 1000)));
        let where_sql = filter.sql();
        let sql = if q.threads {
            format!(
                "WITH scoped AS (SELECT m.*, {VIP_COL} FROM messages m JOIN folders f ON f.id = m.folder_id WHERE {where_sql}),
                 ranked AS (SELECT s.*,
                    ROW_NUMBER() OVER (PARTITION BY s.thread_id ORDER BY s.sort_date DESC, s.id DESC) AS rn,
                    COUNT(*) OVER (PARTITION BY s.thread_id) AS thread_count,
                    SUM(CASE WHEN s.seen = 0 THEN 1 ELSE 0 END) OVER (PARTITION BY s.thread_id) AS thread_unread
                    FROM scoped s)
                 SELECT * FROM ranked WHERE rn = 1 {cursor} ORDER BY sort_date DESC, id DESC LIMIT ?"
            )
        } else {
            format!(
                "SELECT * FROM (SELECT m.*, {VIP_COL}, 1 AS thread_count, (1 - m.seen) AS thread_unread
                   FROM messages m JOIN folders f ON f.id = m.folder_id WHERE {where_sql})
                 WHERE 1 {cursor} ORDER BY sort_date DESC, id DESC LIMIT ?"
            )
        };
        self.read(|c| {
            let mut st = c.prepare(&sql)?;
            let rows = st.query_map(params_from_iter(params.iter()), summary_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn count_messages(&self, mailbox: &Mailbox, unread_only: bool) -> Result<i64> {
        let mut filter = mailbox_filter(self, mailbox)?;
        if unread_only {
            filter.push("m.seen = 0", []);
        }
        let sql = format!("SELECT COUNT(*) FROM messages m JOIN folders f ON f.id = m.folder_id WHERE {}", filter.sql());
        self.read(|c| Ok(c.query_row(&sql, params_from_iter(filter.params.iter()), |r| r.get(0))?))
    }

    /// All messages of a conversation in date order (trash / junk excluded unless `include_trash`).
    pub fn thread(&self, thread_id: &str, include_trash: bool) -> Result<Vec<MessageSummary>> {
        let extra = if include_trash { "" } else { "AND f.role NOT IN ('trash', 'junk')" };
        self.read(|c| {
            let mut st = c.prepare(&format!(
                "SELECT m.*, {VIP_COL} FROM messages m JOIN folders f ON f.id = m.folder_id
                 WHERE m.thread_id = ? AND m.hidden = 0 {extra} ORDER BY m.date, m.id"
            ))?;
            let rows = st.query_map([thread_id], summary_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn thread_ids(&self, thread_id: &str) -> Result<Vec<MessageId>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT id FROM messages WHERE thread_id = ?")?;
            let rows = st.query_map([thread_id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Messages in a folder without a downloaded body, newest first.
    pub fn messages_without_body(&self, folder_id: FolderId, max_size: i64, limit: i64) -> Result<Vec<(MessageId, u32)>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT id, uid FROM messages WHERE folder_id = ? AND blob IS NULL AND uid IS NOT NULL AND size <= ?
                 ORDER BY date DESC LIMIT ?",
            )?;
            let rows = st
                .query_map(params![folder_id, max_size, limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Messages older than the sync window, used to trim the local cache.
    pub fn messages_older_than(&self, folder_id: FolderId, ts: i64) -> Result<Vec<MessageId>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT id FROM messages WHERE folder_id = ? AND date < ? AND flagged = 0 AND pinned = 0 AND uid IS NOT NULL",
            )?;
            let rows = st.query_map(params![folder_id, ts], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn blob_in_use(&self, hash: &str) -> Result<bool> {
        self.read(|c| Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE blob = ?)", [hash], |r| r.get(0))?))
    }

    pub fn find_by_message_id(&self, account_id: &str, message_id: &str) -> Result<Vec<MessageId>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT id FROM messages WHERE account_id = ? AND message_id = ?")?;
            let rows = st.query_map(params![account_id, message_id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Recent unread inbox messages across all accounts (menu bar mini inbox).
    pub fn recent_unread(&self, limit: i64) -> Result<Vec<MessageSummary>> {
        self.list_messages(&ListQuery {
            mailbox: Mailbox::Unread,
            limit,
            ..Default::default()
        })
    }
}

fn update_flags_tx(tx: &Transaction, id: MessageId, flags: &Flags, labels: &[String], modseq: Option<u64>) -> Result<()> {
    tx.execute(
        "UPDATE messages SET seen = ?, flagged = ?, answered = ?, forwarded = ?, draft = ?,
           labels = CASE WHEN ? = '[]' THEN labels ELSE ? END, modseq = COALESCE(?, modseq) WHERE id = ?",
        params![
            flags.seen,
            flags.flagged,
            flags.answered,
            flags.forwarded,
            flags.draft,
            json(&labels),
            json(&labels),
            modseq.map(|v| v as i64),
            id
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{FolderSpec, test_db};

    fn setup(db: &Db) -> (String, FolderId) {
        let a = db.insert_account(Account { email: "me@example.com".into(), ..Default::default() }).unwrap();
        let f = db
            .upsert_folder(
                &a.id,
                &FolderSpec { path: "INBOX".into(), name: "INBOX".into(), delimiter: None, role: FolderRole::Inbox, selectable: true },
            )
            .unwrap();
        (a.id, f)
    }

    fn msg(acc: &str, folder: FolderId, uid: u32, mid: &str, subject: &str, date: i64) -> NewMessage {
        NewMessage {
            account_id: acc.into(),
            folder_id: folder,
            uid: Some(uid),
            message_id: Some(mid.into()),
            subject: subject.into(),
            from: EmailAddress::new(Some("李四"), "lisi@corp.cn"),
            date,
            body_text: Some("请查收本季度的报价单和合同".into()),
            ..Default::default()
        }
    }

    #[test]
    fn insert_list_search_thread() {
        let (_d, db) = test_db();
        let (acc, inbox) = setup(&db);
        let (a, ins) = db.insert_message(&msg(&acc, inbox, 1, "a@x", "季度报价", 100)).unwrap();
        assert!(ins);
        let (a2, ins2) = db.insert_message(&msg(&acc, inbox, 1, "a@x", "季度报价", 100)).unwrap();
        assert_eq!((a, false), (a2, ins2));
        let mut reply = msg(&acc, inbox, 2, "b@x", "回复：季度报价", 200);
        reply.in_reply_to = Some("a@x".into());
        reply.references = vec!["a@x".into()];
        let (b, _) = db.insert_message(&reply).unwrap();
        assert_eq!(db.message(a).unwrap().summary.thread_id, db.message(b).unwrap().summary.thread_id);

        let list = db.list_messages(&ListQuery::default()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, b);
        let threads = db.list_messages(&ListQuery { threads: true, ..Default::default() }).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].thread_count, 2);

        let found = db.list_messages(&ListQuery { search: Some("报价单".into()), ..Default::default() }).unwrap();
        assert_eq!(found.len(), 2);
        let found = db.list_messages(&ListQuery { search: Some("from:lisi 合同".into()), ..Default::default() }).unwrap();
        assert_eq!(found.len(), 2);
        let none = db.list_messages(&ListQuery { search: Some("发票".into()), ..Default::default() }).unwrap();
        assert!(none.is_empty());

        // pagination
        let page = db.list_messages(&ListQuery { before: Some((200, b)), ..Default::default() }).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, a);
    }

    #[test]
    fn reply_before_parent_merges_threads() {
        let (_d, db) = test_db();
        let (acc, inbox) = setup(&db);
        let mut reply = msg(&acc, inbox, 2, "child@x", "Re: Plan", 200);
        reply.in_reply_to = Some("parent@x".into());
        let (c, _) = db.insert_message(&reply).unwrap();
        let (p, _) = db.insert_message(&msg(&acc, inbox, 1, "parent@x", "Plan", 100)).unwrap();
        assert_eq!(db.message(c).unwrap().summary.thread_id, db.message(p).unwrap().summary.thread_id);
    }

    #[test]
    fn moved_message_adopts_new_uid() {
        let (_d, db) = test_db();
        let (acc, inbox) = setup(&db);
        let archive = db
            .upsert_folder(
                &acc,
                &FolderSpec { path: "Archive".into(), name: "Archive".into(), delimiter: None, role: FolderRole::Archive, selectable: true },
            )
            .unwrap();
        let (id, _) = db.insert_message(&msg(&acc, inbox, 7, "m@x", "Hello", 100)).unwrap();
        db.move_local(&[id], archive, false).unwrap();
        let (id2, inserted) = db.insert_message(&msg(&acc, archive, 33, "m@x", "Hello", 100)).unwrap();
        assert_eq!(id, id2);
        assert!(!inserted);
        assert_eq!(db.message(id).unwrap().uid, Some(33));
    }

    #[test]
    fn snooze_hides_and_wakes() {
        let (_d, db) = test_db();
        let (acc, inbox) = setup(&db);
        let (id, _) = db.insert_message(&msg(&acc, inbox, 1, "s@x", "Later", 100)).unwrap();
        db.set_flag(&[id], "seen", true).unwrap();
        db.snooze(&[id], Some(500)).unwrap();
        assert!(db.list_messages(&ListQuery::default()).unwrap().is_empty());
        assert_eq!(db.list_messages(&ListQuery { mailbox: Mailbox::Snoozed, ..Default::default() }).unwrap().len(), 1);
        assert_eq!(db.wake_snoozed(600).unwrap(), vec![id]);
        let list = db.list_messages(&ListQuery::default()).unwrap();
        assert_eq!(list.len(), 1);
        assert!(!list[0].flags.seen);
    }
}

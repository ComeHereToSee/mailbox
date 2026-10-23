//! POP3 worker: downloads new messages into a local inbox, honours leave-on-server rules.

use super::imap_worker::wait_for;
use super::{Cred, Engine, detail, newmail};
use crate::error::{Error, Result};
use crate::model::*;
use crate::pop3::{Pop3Auth, Pop3Conn};
use crate::store::{NewMessage, OpKind, now};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Messages imported on the very first connection.
const INITIAL_LIMIT: usize = 500;

pub(super) async fn run(e: Engine, account_id: String, wake: Arc<Notify>, cancel: CancellationToken) {
    let mut backoff = 30u64;
    while !cancel.is_cancelled() {
        let Ok(acc) = e.db.account(&account_id) else { break };
        e.set_status(&acc.id, SyncState::Syncing, None);
        let interval = acc.config.poll_interval_secs.max(60) as u64;
        match pass(&e, &acc).await {
            Ok(()) => {
                backoff = 30;
                e.set_status(&acc.id, SyncState::Idle, None);
                wait_for(&wake, &cancel, interval).await;
            }
            Err(err) => {
                tracing::warn!(account = %acc.email, error = %err, "pop3 sync failed");
                let state = if err.is_auth() { SyncState::Error } else { SyncState::Offline };
                e.set_status(&acc.id, state, Some(err.to_string()));
                wait_for(&wake, &cancel, if err.is_auth() { 900 } else { backoff }).await;
                backoff = (backoff * 2).min(900);
            }
        }
    }
}

async fn pass(e: &Engine, acc: &Account) -> Result<()> {
    let server = acc.config.pop3.clone().ok_or_else(|| Error::Invalid("未配置 POP3 服务器".into()))?;
    let inbox_id = e.db.ensure_local_folder(&acc.id, FolderRole::Inbox, "收件箱")?;
    e.db.ensure_local_folder(&acc.id, FolderRole::Sent, "已发送")?;
    e.db.ensure_local_folder(&acc.id, FolderRole::Trash, "已删除")?;
    let inbox = e.db.folder(inbox_id)?;
    let auth = match e.credentials(acc).await? {
        Cred::Password(p) => Pop3Auth::Password(p),
        Cred::OAuth(t) => Pop3Auth::OAuth2(t),
    };
    let user = Engine::login_name(acc, &server);
    let mut c = Pop3Conn::connect(&server, &user, &auth).await?;
    let list = c.uidl().await?;
    let known = e.db.account_remote_ids(&acc.id)?;
    let initial = known.is_empty() && inbox.last_sync.is_none();

    let mut new: Vec<&(u32, String)> = list.iter().filter(|(_, u)| !known.contains_key(u)).collect();
    if initial && new.len() > INITIAL_LIMIT {
        new = new[new.len() - INITIAL_LIMIT..].to_vec();
    }
    let mut new_ids = Vec::new();
    let mut downloaded: HashSet<String> = HashSet::new();
    for (n, uidl) in new.iter().rev() {
        let raw = c.retr(*n).await?;
        let h = crate::mime::parse_headers(&raw);
        let date = h.date.unwrap_or_else(now);
        let known_sender = e.db.is_known_contact(&h.from.email).unwrap_or(false);
        let nm = NewMessage {
            account_id: acc.id.clone(),
            folder_id: inbox.id,
            remote_id: Some(uidl.clone()),
            message_id: h.message_id.clone(),
            in_reply_to: h.in_reply_to.clone(),
            references: h.references.clone(),
            subject: h.subject.clone(),
            from: h.from.clone(),
            to: h.to.clone(),
            cc: h.cc.clone(),
            bcc: h.bcc.clone(),
            reply_to: h.reply_to.clone(),
            date,
            size: raw.len() as i64,
            // Old mail imported on first sync should not light up as unread.
            flags: Flags { seen: initial && date < now() - 3 * 86_400, ..Default::default() },
            category: crate::categorize::categorize(&h, known_sender),
            list_id: h.list_id.clone(),
            unsubscribe: h.unsubscribe.clone(),
            has_attachments: h.multipart_mixed,
            ..Default::default()
        };
        let (id, inserted) = e.db.insert_message(&nm)?;
        detail::store_body(e, id, &raw)?;
        downloaded.insert(uidl.clone());
        if inserted && !initial {
            new_ids.push(id);
        }
    }

    // Server-side deletions.
    let mut delete: HashSet<String> = HashSet::new();
    let pending = e.db.due_ops(&acc.id)?;
    for op in &pending {
        if let OpKind::PopDelete { uidls } = &op.kind {
            delete.extend(uidls.iter().cloned());
        }
    }
    if !acc.config.pop_leave_on_server {
        delete.extend(downloaded.iter().cloned());
        delete.extend(known.keys().cloned());
    } else if let Some(days) = acc.config.pop_delete_after_days.filter(|d| *d > 0) {
        let cutoff = now() - days as i64 * 86_400;
        delete.extend(known.iter().filter(|(_, (_, created))| *created < cutoff).map(|(u, _)| u.clone()));
    }
    for (n, uidl) in &list {
        if delete.contains(uidl) {
            c.dele(*n).await?;
        }
    }
    c.quit().await?;
    for op in pending {
        if matches!(op.kind, OpKind::PopDelete { .. }) {
            e.db.finish_op(op.id)?;
        }
    }
    e.db.set_folder_state(inbox.id, None, None, None)?;
    if !downloaded.is_empty() {
        e.changed(Some(&acc.id));
    }
    if !new_ids.is_empty() {
        newmail::process(e, acc, None, &inbox, &new_ids).await;
    }
    Ok(())
}

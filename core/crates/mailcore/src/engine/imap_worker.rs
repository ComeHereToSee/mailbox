//! Per-account IMAP worker: folder list, incremental sync, flag / expunge reconciliation,
//! body prefetch and an IDLE watcher on INBOX.

use super::{Engine, detail, newmail, ops};
use crate::error::{Error, Result};
use crate::events::Event;
use crate::imap::{FetchedMessage, ImapConn, uid_set};
use crate::model::*;
use crate::store::{FolderSpec, NewMessage, now};
use async_imap::extensions::idle::IdleResponse;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Newest messages fetched per folder on first sync.
const INITIAL_LIMIT: usize = 3000;
/// Bodies larger than this are only downloaded on demand.
const PREFETCH_MAX_SIZE: i64 = 2 * 1024 * 1024;

pub(super) async fn wait_for(wake: &Notify, cancel: &CancellationToken, secs: u64) {
    tokio::select! {
        _ = wake.notified() => {}
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs(secs.max(1))) => {}
    }
}

fn is_connection_error(e: &Error) -> bool {
    matches!(e, Error::Net(_) | Error::Imap(_) | Error::Io(_))
}

pub(super) async fn run(e: Engine, account_id: String, wake: Arc<Notify>, cancel: CancellationToken) {
    let mut conn: Option<ImapConn> = None;
    let mut backoff = 5u64;
    let mut folders_refreshed: Option<Instant> = None;
    let mut full_sync_at: Option<Instant> = None;
    while !cancel.is_cancelled() {
        let Ok(acc) = e.db.account(&account_id) else { break };
        if conn.is_none() {
            e.set_status(&acc.id, SyncState::Connecting, None);
            match e.imap_connect(&acc).await {
                Ok(c) => {
                    conn = Some(c);
                    backoff = 5;
                }
                Err(err) => {
                    let auth = err.is_auth();
                    tracing::warn!(account = %acc.email, error = %err, "imap connect failed");
                    e.set_status(&acc.id, if auth { SyncState::Error } else { SyncState::Offline }, Some(err.to_string()));
                    let wait = if auth { 900 } else { backoff };
                    backoff = (backoff * 2).min(600);
                    wait_for(&wake, &cancel, wait).await;
                    continue;
                }
            }
        }
        let c = conn.as_mut().expect("connected");
        e.set_status(&acc.id, SyncState::Syncing, None);
        let interval = acc.config.poll_interval_secs.max(60) as u64;
        let full = full_sync_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(interval));
        match sync_pass(&e, &acc, c, &mut folders_refreshed, full).await {
            Ok(()) => {
                if full {
                    full_sync_at = Some(Instant::now());
                }
                e.set_status(&acc.id, SyncState::Idle, None);
            }
            Err(err) => {
                tracing::warn!(account = %acc.email, error = %err, "sync failed");
                let state = if err.is_auth() { SyncState::Error } else { SyncState::Offline };
                e.set_status(&acc.id, state, Some(err.to_string()));
                if is_connection_error(&err) || err.is_auth() {
                    if let Some(c) = conn.take() {
                        c.logout().await;
                    }
                }
                wait_for(&wake, &cancel, backoff).await;
                backoff = (backoff * 2).min(600);
                continue;
            }
        }
        let next_op = e
            .db
            .next_op_time(&acc.id)
            .ok()
            .flatten()
            .map(|t| (t - now()).max(1) as u64)
            .unwrap_or(u64::MAX);
        let requested = !e.folder_requests.lock().get(&acc.id).is_none_or(|s| s.is_empty());
        if !requested {
            wait_for(&wake, &cancel, interval.min(next_op)).await;
        }
        if let Some(c) = conn.as_mut() {
            if c.noop().await.is_err() {
                conn = None;
            }
        }
    }
    if let Some(c) = conn {
        c.logout().await;
    }
}

async fn sync_pass(
    e: &Engine,
    acc: &Account,
    c: &mut ImapConn,
    folders_refreshed: &mut Option<Instant>,
    full: bool,
) -> Result<()> {
    if folders_refreshed.is_none_or(|t| t.elapsed() > Duration::from_secs(1800)) {
        refresh_folders(e, acc, c).await?;
        *folders_refreshed = Some(Instant::now());
    }
    if ops::process(e, acc, c).await? {
        refresh_folders(e, acc, c).await?;
    }
    let requested: HashSet<FolderId> = e.folder_requests.lock().remove(&acc.id).unwrap_or_default();
    let mut folders: Vec<Folder> = e
        .db
        .folders(Some(&acc.id))?
        .into_iter()
        .filter(|f| f.selectable && !f.local)
        .collect();
    folders.sort_by_key(|f| (!requested.contains(&f.id), f.role.rank()));
    let mut synced = Vec::new();
    for f in &folders {
        let wanted = requested.contains(&f.id)
            || f.role == FolderRole::Inbox
            || (full && e.db.folder_sync_enabled(f.id).unwrap_or(true));
        if !wanted {
            continue;
        }
        sync_folder(e, acc, c, f).await?;
        synced.push(f.clone());
    }
    // Bodies after headers so new mail shows up first.
    let deadline = Instant::now() + Duration::from_secs(20);
    for f in &synced {
        if Instant::now() > deadline {
            break;
        }
        prefetch(e, acc, c, f, deadline).await?;
    }
    Ok(())
}

pub(super) async fn refresh_folders(e: &Engine, acc: &Account, c: &mut ImapConn) -> Result<()> {
    let remote = c.list_folders().await?;
    let mut keep = Vec::new();
    for rf in &remote {
        let existed = e.db.folder_by_path(&acc.id, &rf.path)?.is_some();
        let id = e.db.upsert_folder(
            &acc.id,
            &FolderSpec {
                path: rf.path.clone(),
                name: rf.name.clone(),
                delimiter: rf.delimiter.clone(),
                role: rf.role,
                selectable: rf.selectable,
            },
        )?;
        if !existed && matches!(rf.role, FolderRole::All | FolderRole::Flagged | FolderRole::Important) {
            // Virtual folders duplicate every message; synced only on demand.
            e.db.set_folder_sync_enabled(id, false)?;
        }
        keep.push(rf.path.clone());
    }
    e.db.prune_folders(&acc.id, &keep)?;
    e.events.emit(Event::FoldersChanged { account_id: acc.id.clone() });
    Ok(())
}

fn imap_date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default().format("%d-%b-%Y").to_string()
}

pub(super) fn to_new_message(e: &Engine, acc: &Account, folder: &Folder, fm: &FetchedMessage) -> NewMessage {
    let h = crate::mime::parse_headers(fm.header.as_deref().unwrap_or_default());
    let known = e.db.is_known_contact(&h.from.email).unwrap_or(false);
    let category = crate::categorize::categorize(&h, known);
    NewMessage {
        account_id: acc.id.clone(),
        folder_id: folder.id,
        uid: Some(fm.uid),
        remote_id: None,
        message_id: h.message_id.clone(),
        in_reply_to: h.in_reply_to.clone(),
        references: h.references.clone(),
        subject: h.subject.clone(),
        from: h.from.clone(),
        to: h.to.clone(),
        cc: h.cc.clone(),
        bcc: h.bcc.clone(),
        reply_to: h.reply_to.clone(),
        date: h.date.or(fm.internal_date).unwrap_or_else(now),
        size: fm.size as i64,
        flags: fm.flags.clone(),
        labels: fm.labels.iter().filter(|l| !l.starts_with("\\\\")).cloned().collect(),
        has_attachments: h.multipart_mixed,
        snippet: String::new(),
        category,
        list_id: h.list_id.clone(),
        unsubscribe: h.unsubscribe.clone(),
        blob: None,
        modseq: fm.modseq,
        body_text: None,
        attachments: Vec::new(),
    }
}

async fn sync_folder(e: &Engine, acc: &Account, c: &mut ImapConn, f: &Folder) -> Result<()> {
    let info = c.select(&f.path).await?;
    let mut validity_changed = false;
    if let (Some(old), Some(new)) = (f.uidvalidity, info.uidvalidity) {
        if old != new {
            tracing::info!(folder = %f.path, "UIDVALIDITY changed, resyncing");
            e.db.clear_folder(f.id)?;
            validity_changed = true;
        }
    }
    let max_local = if validity_changed { None } else { e.db.max_uid(f.id)? };
    let initial = f.last_sync.is_none() || max_local.is_none();
    let mut new_ids = Vec::new();

    if info.exists > 0 {
        let uids: Vec<u32> = match max_local {
            Some(max) => {
                if info.uidnext.is_none_or(|n| n > max + 1) {
                    c.uid_search(&f.path, &format!("UID {}:*", max + 1)).await?.into_iter().filter(|u| *u > max).collect()
                } else {
                    Vec::new()
                }
            }
            None => {
                let q = if acc.config.sync_days > 0 {
                    format!("SINCE {}", imap_date(now() - acc.config.sync_days as i64 * 86_400))
                } else {
                    "ALL".to_string()
                };
                let mut uids = c.uid_search(&f.path, &q).await?;
                if uids.is_empty() && acc.config.sync_days > 0 {
                    // Quiet folder: still show the latest few messages.
                    let all = c.uid_search(&f.path, "ALL").await?;
                    uids = all.into_iter().rev().take(50).collect();
                    uids.sort_unstable();
                }
                if uids.len() > INITIAL_LIMIT {
                    uids = uids[uids.len() - INITIAL_LIMIT..].to_vec();
                }
                uids
            }
        };
        let is_sent = f.role == FolderRole::Sent;
        for chunk in uids.rchunks(200) {
            let fetched = c.fetch_headers(&f.path, &uid_set(chunk)).await?;
            let mut contacts = Vec::new();
            for fm in &fetched {
                let nm = to_new_message(e, acc, f, fm);
                if is_sent {
                    contacts.extend(nm.to.iter().chain(nm.cc.iter()).cloned());
                }
                let (id, inserted) = e.db.insert_message(&nm)?;
                if inserted {
                    new_ids.push(id);
                }
            }
            if !contacts.is_empty() {
                e.db.record_contacts(&contacts, 1)?;
            }
            e.changed(Some(&acc.id));
        }
    }

    if !initial {
        let local = e.db.folder_uids(f.id)?;
        if !local.is_empty() {
            let by_uid: HashMap<u32, (MessageId, Flags)> = local.iter().map(|(id, uid, fl)| (*uid, (*id, fl.clone()))).collect();
            let min_uid = local.iter().map(|(_, u, _)| *u).min().unwrap_or(1);
            let changed = match (c.caps.condstore, f.highest_modseq) {
                (true, Some(ms)) if info.highest_modseq != Some(ms) => {
                    c.fetch_flags(&f.path, &format!("{min_uid}:*"), Some(ms)).await?
                }
                (true, Some(_)) => Vec::new(),
                _ => c.fetch_flags(&f.path, &format!("{min_uid}:*"), None).await?,
            };
            let mut any = false;
            for fm in changed {
                if let Some((id, old)) = by_uid.get(&fm.uid) {
                    if *old != fm.flags || !fm.labels.is_empty() {
                        e.db.update_flags(*id, &fm.flags, &fm.labels, fm.modseq)?;
                        any = true;
                    }
                }
            }
            // Expunged on the server (by another client).
            let remote: HashSet<u32> = c.uid_search(&f.path, &format!("UID {min_uid}:*")).await?.into_iter().collect();
            let gone: Vec<MessageId> = local
                .iter()
                .filter(|(_, uid, _)| !remote.contains(uid))
                .map(|(id, _, _)| *id)
                .collect();
            if !gone.is_empty() {
                e.db.delete_messages(&gone)?;
                any = true;
            }
            if any {
                e.changed(Some(&acc.id));
            }
        }
    }
    e.db.set_folder_state(f.id, info.uidvalidity, info.uidnext, info.highest_modseq)?;

    if !initial && f.role == FolderRole::Inbox && !new_ids.is_empty() {
        newmail::process(e, acc, Some(c), f, &new_ids).await;
    }
    Ok(())
}

async fn prefetch(e: &Engine, acc: &Account, c: &mut ImapConn, f: &Folder, deadline: Instant) -> Result<()> {
    if !e.db.folder_sync_enabled(f.id)? && f.role != FolderRole::Inbox {
        return Ok(());
    }
    while Instant::now() < deadline {
        let missing = e.db.messages_without_body(f.id, PREFETCH_MAX_SIZE, 25)?;
        if missing.is_empty() {
            break;
        }
        let uid_to_id: HashMap<u32, MessageId> = missing.iter().map(|(id, uid)| (*uid, *id)).collect();
        let uids: Vec<u32> = missing.iter().map(|(_, u)| *u).collect();
        let fetched = c.fetch_bodies(&f.path, &uids).await?;
        let mut got = HashSet::new();
        for fm in fetched {
            if let (Some(id), Some(raw)) = (uid_to_id.get(&fm.uid), fm.body.as_ref()) {
                detail::store_body(e, *id, raw)?;
                got.insert(fm.uid);
            }
        }
        if got.is_empty() {
            // Server returned nothing for these UIDs (expunged meanwhile); stop for this pass.
            break;
        }
        e.changed(Some(&acc.id));
    }
    Ok(())
}

/// Keeps an IDLE connection on INBOX and wakes the worker when the server reports changes.
pub(super) async fn idle_loop(e: Engine, account_id: String, wake: Arc<Notify>, cancel: CancellationToken) {
    let mut backoff = 10u64;
    // Let the main worker do the first sync before opening a second connection.
    wait_for(&Notify::new(), &cancel, 5).await;
    while !cancel.is_cancelled() {
        let Ok(acc) = e.db.account(&account_id) else { return };
        let conn = match e.imap_connect(&acc).await {
            Ok(c) if c.caps.idle => c,
            Ok(c) => {
                c.logout().await;
                return;
            }
            Err(err) => {
                tracing::debug!(account = %acc.email, error = %err, "idle connect failed");
                wait_for(&Notify::new(), &cancel, backoff).await;
                backoff = (backoff * 2).min(900);
                continue;
            }
        };
        backoff = 10;
        let inbox = e
            .db
            .folder_by_role(&acc.id, FolderRole::Inbox)
            .ok()
            .flatten()
            .map(|f| f.path)
            .unwrap_or_else(|| "INBOX".into());
        let mut conn = conn;
        if conn.select(&inbox).await.is_err() {
            wait_for(&Notify::new(), &cancel, 60).await;
            continue;
        }
        let mut session = conn.session;
        loop {
            let mut handle = session.idle();
            if handle.init().await.is_err() {
                break;
            }
            let outcome = {
                let (fut, _stop) = handle.wait_with_timeout(Duration::from_secs(25 * 60));
                tokio::select! {
                    r = fut => Some(r),
                    _ = cancel.cancelled() => None,
                }
            };
            match outcome {
                None => return,
                Some(Ok(IdleResponse::NewData(_))) => wake.notify_one(),
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            }
            match tokio::time::timeout(Duration::from_secs(30), handle.done()).await {
                Ok(Ok(s)) => session = s,
                _ => break,
            }
        }
        wait_for(&Notify::new(), &cancel, 3).await;
    }
}

//! Applies queued server changes (flags, moves, deletes, appends, folders, drafts).

use super::Engine;
use crate::error::{Error, Result};
use crate::imap::ImapConn;
use crate::model::*;
use crate::store::{Op, OpKind};
use std::collections::HashMap;

enum Applied {
    Done,
    /// Some messages are not on the server yet (pending move); retry the rest later.
    Partial(OpKind),
    FoldersChanged,
}

/// Runs all due ops. Returns whether the folder list changed.
pub(super) async fn process(e: &Engine, acc: &Account, c: &mut ImapConn) -> Result<bool> {
    let mut folders_changed = false;
    for op in e.db.due_ops(&acc.id)? {
        match apply(e, acc, c, &op).await {
            Ok(Applied::Done) => e.db.finish_op(op.id)?,
            Ok(Applied::Partial(rest)) => {
                if op.attempts >= 20 {
                    e.db.finish_op(op.id)?;
                } else {
                    e.db.replace_op(op.id, &rest)?;
                    e.db.fail_op(op.id, op.attempts, "等待服务器分配 UID")?;
                }
            }
            Ok(Applied::FoldersChanged) => {
                e.db.finish_op(op.id)?;
                folders_changed = true;
            }
            Err(err) if err.is_connection() || err.is_auth() => {
                e.db.fail_op(op.id, op.attempts, &err.to_string())?;
                return Err(err);
            }
            Err(err) => {
                tracing::warn!(op = op.kind.name(), error = %err, "op rejected by server");
                if op.attempts >= 2 {
                    e.db.finish_op(op.id)?;
                } else {
                    e.db.fail_op(op.id, op.attempts, &err.to_string())?;
                }
            }
        }
    }
    Ok(folders_changed)
}

/// Groups messages by (folder path, uid); returns the ids still waiting for a UID.
fn group_by_folder(e: &Engine, ids: &[MessageId]) -> Result<(HashMap<String, Vec<u32>>, Vec<MessageId>)> {
    let mut groups: HashMap<String, Vec<u32>> = HashMap::new();
    let mut pending = Vec::new();
    for m in e.db.messages_by_ids(ids)? {
        if m.folder_local {
            continue;
        }
        match m.uid {
            Some(uid) => groups.entry(m.folder_path.clone()).or_default().push(uid),
            None => pending.push(m.summary.id),
        }
    }
    Ok((groups, pending))
}

fn read_blob(e: &Engine, name: &str) -> Result<Vec<u8>> {
    let path = e.paths.uploads().join(name);
    std::fs::read(&path).map_err(|err| Error::NotFound(format!("待上传邮件 {}: {err}", path.display())))
}

fn remove_blob(e: &Engine, name: &str) {
    let _ = std::fs::remove_file(e.paths.uploads().join(name));
}

async fn drafts_folder(e: &Engine, acc: &Account, c: &mut ImapConn) -> Result<Folder> {
    if let Some(f) = e.db.folder_by_role(&acc.id, FolderRole::Drafts)?.filter(|f| !f.local) {
        return Ok(f);
    }
    c.create_folder("Drafts").await.ok();
    super::imap_worker::refresh_folders(e, acc, c).await?;
    e.db.folder_by_path(&acc.id, "Drafts")?.ok_or_else(|| Error::NotFound("Drafts 文件夹".into()))
}

async fn find_draft_uids(c: &mut ImapConn, path: &str, draft_id: &str) -> Result<Vec<u32>> {
    let safe: String = draft_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    c.uid_search(path, &format!("HEADER X-Mailbox-Draft-Id \"{safe}\"")).await
}

async fn apply(e: &Engine, acc: &Account, c: &mut ImapConn, op: &Op) -> Result<Applied> {
    match &op.kind {
        OpKind::Flags { message_ids, flag, add } => {
            let (groups, pending) = group_by_folder(e, message_ids)?;
            for (path, uids) in groups {
                c.store_flag(&path, &uids, flag, *add).await?;
            }
            if pending.is_empty() {
                Ok(Applied::Done)
            } else {
                Ok(Applied::Partial(OpKind::Flags { message_ids: pending, flag: flag.clone(), add: *add }))
            }
        }
        OpKind::Labels { message_ids, add, remove } => {
            let (groups, _) = group_by_folder(e, message_ids)?;
            for (path, uids) in groups {
                c.store_labels(&path, &uids, add, true).await?;
                c.store_labels(&path, &uids, remove, false).await?;
            }
            Ok(Applied::Done)
        }
        OpKind::Move { from, to, uids } => {
            let (Ok(src), Ok(dst)) = (e.db.folder(*from), e.db.folder(*to)) else { return Ok(Applied::Done) };
            if src.local || dst.local {
                return Ok(Applied::Done);
            }
            c.move_uids(&src.path, uids, &dst.path).await?;
            e.folder_requests.lock().entry(acc.id.clone()).or_default().insert(dst.id);
            Ok(Applied::Done)
        }
        OpKind::Expunge { folder, uids } => {
            let Ok(f) = e.db.folder(*folder) else { return Ok(Applied::Done) };
            if !f.local {
                c.expunge_uids(&f.path, uids).await?;
            }
            Ok(Applied::Done)
        }
        OpKind::Append { folder, blob, flags, replace_uid } => {
            let Ok(f) = e.db.folder(*folder) else {
                remove_blob(e, blob);
                return Ok(Applied::Done);
            };
            let raw = match read_blob(e, blob) {
                Ok(r) => r,
                Err(_) => return Ok(Applied::Done),
            };
            c.append(&f.path, flags, &raw).await?;
            if let Some(uid) = replace_uid {
                c.expunge_uids(&f.path, &[*uid]).await?;
            }
            remove_blob(e, blob);
            e.folder_requests.lock().entry(acc.id.clone()).or_default().insert(f.id);
            Ok(Applied::Done)
        }
        OpKind::ReplaceDraft { draft_id, blob } => {
            let f = drafts_folder(e, acc, c).await?;
            let raw = match read_blob(e, blob) {
                Ok(r) => r,
                Err(_) => return Ok(Applied::Done),
            };
            let old = find_draft_uids(c, &f.path, draft_id).await?;
            c.append(&f.path, &["draft".into(), "seen".into()], &raw).await?;
            if !old.is_empty() {
                c.expunge_uids(&f.path, &old).await?;
            }
            remove_blob(e, blob);
            e.folder_requests.lock().entry(acc.id.clone()).or_default().insert(f.id);
            Ok(Applied::Done)
        }
        OpKind::DeleteDraft { draft_id } => {
            if let Some(f) = e.db.folder_by_role(&acc.id, FolderRole::Drafts)?.filter(|f| !f.local) {
                let old = find_draft_uids(c, &f.path, draft_id).await?;
                if !old.is_empty() {
                    c.expunge_uids(&f.path, &old).await?;
                }
                e.folder_requests.lock().entry(acc.id.clone()).or_default().insert(f.id);
            }
            Ok(Applied::Done)
        }
        OpKind::CreateFolder { path } => {
            if let Err(err) = c.create_folder(path).await {
                if err.is_connection() {
                    return Err(err);
                }
                tracing::info!(path, error = %err, "create folder failed (may already exist)");
            }
            Ok(Applied::FoldersChanged)
        }
        OpKind::RenameFolder { from, to } => {
            c.rename_folder(from, to).await?;
            Ok(Applied::FoldersChanged)
        }
        OpKind::DeleteFolder { path } => {
            c.delete_folder(path).await?;
            Ok(Applied::FoldersChanged)
        }
        OpKind::PopDelete { .. } => Ok(Applied::Done),
    }
}

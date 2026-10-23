//! User actions on messages: applied locally at once, queued for the server, undoable.

use super::{Engine, UndoEntry};
use crate::error::{Error, Result};
use crate::model::*;
use crate::store::{OpKind, StoredMessage, now};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Seconds destructive ops wait before running, so they can still be undone.
const UNDO_WINDOW: i64 = 8;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Read,
    Unread,
    Flag,
    Unflag,
    Archive,
    Trash,
    /// Permanent delete.
    Delete,
    Spam,
    NotSpam,
    MoveToInbox,
    Move { folder_id: FolderId },
    Label { #[serde(default)] add: Vec<String>, #[serde(default)] remove: Vec<String> },
    Snooze { until: i64 },
    Unsnooze,
    Pin,
    Unpin,
    Category { category: Category },
}

#[derive(Serialize, Debug, Default)]
pub struct ActionResult {
    pub affected: usize,
    pub undo_token: Option<String>,
}

impl Engine {
    pub async fn act(&self, ids: &[MessageId], action: Action) -> Result<ActionResult> {
        let msgs = self.db.messages_by_ids(ids)?;
        if msgs.is_empty() {
            return Ok(ActionResult::default());
        }
        let snapshots = self.db.snapshot(&msgs.iter().map(|m| m.summary.id).collect::<Vec<_>>())?;
        let mut by_account: HashMap<String, Vec<StoredMessage>> = HashMap::new();
        for m in msgs {
            by_account.entry(m.summary.account_id.clone()).or_default().push(m);
        }
        let mut ops = Vec::new();
        let mut affected = 0;
        for (account_id, msgs) in &by_account {
            let acc = self.db.account(account_id)?;
            affected += msgs.len();
            ops.extend(self.act_account(&acc, msgs, &action)?.into_iter().map(|id| (account_id.clone(), id)));
            self.wake(Some(account_id));
        }
        self.changed(None);
        let inverse = !matches!(
            action,
            Action::Archive | Action::Trash | Action::Delete | Action::Spam | Action::NotSpam | Action::MoveToInbox | Action::Move { .. }
        );
        let token = crate::store::new_id();
        self.undo.lock().insert(token.clone(), UndoEntry { ops, snapshots, inverse, created: Instant::now() });
        Ok(ActionResult { affected, undo_token: Some(token) })
    }

    /// Reverts an action. Returns false when a move / delete already reached the server.
    pub fn undo(&self, token: &str) -> Result<bool> {
        let Some(entry) = self.undo.lock().remove(token) else { return Ok(false) };
        let op_ids: Vec<i64> = entry.ops.iter().map(|(_, id)| *id).collect();
        if entry.inverse {
            let current = self.db.snapshot(&entry.snapshots.iter().map(|s| s.id).collect::<Vec<_>>())?;
            self.db.restore(&entry.snapshots)?;
            let cancelled = self.db.cancel_ops(&op_ids)?;
            if cancelled < op_ids.len() {
                for (before, now) in entry.snapshots.iter().zip(current.iter()) {
                    let acc = self.db.message(before.id)?.summary.account_id;
                    if before.seen != now.seen {
                        self.db.enqueue_op(&acc, &OpKind::Flags { message_ids: vec![before.id], flag: "seen".into(), add: before.seen })?;
                    }
                    if before.flagged != now.flagged {
                        let op = OpKind::Flags { message_ids: vec![before.id], flag: "flagged".into(), add: before.flagged };
                        self.db.enqueue_op(&acc, &op)?;
                    }
                }
            }
        } else {
            if self.db.cancel_ops(&op_ids)? < op_ids.len() {
                return Ok(false);
            }
            self.db.restore(&entry.snapshots)?;
        }
        for (acc, _) in &entry.ops {
            self.wake(Some(acc));
        }
        self.changed(None);
        Ok(true)
    }

    fn target_folder(&self, acc: &Account, role: FolderRole) -> Result<Option<Folder>> {
        if let Some(f) = self.db.folder_by_role(&acc.id, role)? {
            return Ok(Some(f));
        }
        match (acc.kind, role) {
            (AccountKind::Pop3, r) => {
                let name = match r {
                    FolderRole::Archive => "归档",
                    FolderRole::Trash => "已删除",
                    FolderRole::Junk => "垃圾邮件",
                    FolderRole::Inbox => "收件箱",
                    FolderRole::Sent => "已发送",
                    FolderRole::Drafts => "草稿箱",
                    _ => return Ok(None),
                };
                let id = self.db.ensure_local_folder(&acc.id, r, name)?;
                Ok(Some(self.db.folder(id)?))
            }
            (AccountKind::Imap, FolderRole::Archive) => {
                // Gmail archives into All Mail; other servers get an "Archive" folder.
                if let Some(all) = self.db.folder_by_role(&acc.id, FolderRole::All)? {
                    return Ok(Some(all));
                }
                self.db.enqueue_op(&acc.id, &OpKind::CreateFolder { path: "Archive".into() })?;
                let id = self.db.upsert_folder(
                    &acc.id,
                    &crate::store::FolderSpec {
                        path: "Archive".into(),
                        name: "Archive".into(),
                        delimiter: None,
                        role: FolderRole::Archive,
                        selectable: true,
                    },
                )?;
                Ok(Some(self.db.folder(id)?))
            }
            _ => Ok(None),
        }
    }

    /// Returns the ids of the ops created (for undo).
    fn act_account(&self, acc: &Account, msgs: &[StoredMessage], action: &Action) -> Result<Vec<i64>> {
        let ids: Vec<MessageId> = msgs.iter().map(|m| m.summary.id).collect();
        let imap = acc.kind == AccountKind::Imap;
        let mut ops = Vec::new();
        let flag = |name: &str, add: bool, ops: &mut Vec<i64>| -> Result<()> {
            self.db.set_flag(&ids, name, add)?;
            if imap {
                ops.push(self.db.enqueue_op(&acc.id, &OpKind::Flags { message_ids: ids.clone(), flag: name.into(), add })?);
            }
            Ok(())
        };
        match action {
            Action::Read => flag("seen", true, &mut ops)?,
            Action::Unread => flag("seen", false, &mut ops)?,
            Action::Flag => flag("flagged", true, &mut ops)?,
            Action::Unflag => flag("flagged", false, &mut ops)?,
            Action::Pin | Action::Unpin => self.db.set_flag(&ids, "pinned", *action == Action::Pin)?,
            Action::Snooze { until } => self.db.snooze(&ids, Some(*until))?,
            Action::Unsnooze => self.db.snooze(&ids, None)?,
            Action::Category { category } => {
                for id in &ids {
                    self.db.set_category(*id, *category)?;
                }
            }
            Action::Label { add, remove } => {
                for m in msgs {
                    let mut labels = m.summary.labels.clone();
                    labels.retain(|l| !remove.contains(l));
                    for l in add {
                        if !labels.contains(l) {
                            labels.push(l.clone());
                        }
                    }
                    self.db.set_labels(m.summary.id, &labels)?;
                }
                if imap {
                    ops.push(self.db.enqueue_op(&acc.id, &OpKind::Labels { message_ids: ids.clone(), add: add.clone(), remove: remove.clone() })?);
                }
            }
            Action::Delete => ops.extend(self.delete_permanently(acc, msgs)?),
            Action::Trash => {
                let (in_trash, rest): (Vec<_>, Vec<_>) =
                    msgs.iter().cloned().partition(|m| matches!(m.folder_role, FolderRole::Trash | FolderRole::Junk));
                ops.extend(self.delete_permanently(acc, &in_trash)?);
                match self.target_folder(acc, FolderRole::Trash)? {
                    Some(t) => ops.extend(self.move_messages(acc, &rest, &t)?),
                    None => ops.extend(self.delete_permanently(acc, &rest)?),
                }
            }
            Action::Archive | Action::Spam | Action::NotSpam | Action::MoveToInbox | Action::Move { .. } => {
                let target = match action {
                    Action::Archive => self.target_folder(acc, FolderRole::Archive)?,
                    Action::Spam => self.target_folder(acc, FolderRole::Junk)?,
                    Action::NotSpam | Action::MoveToInbox => self.target_folder(acc, FolderRole::Inbox)?,
                    Action::Move { folder_id } => {
                        let f = self.db.folder(*folder_id)?;
                        if f.account_id != acc.id {
                            return Err(Error::Invalid("不能跨账户移动邮件".into()));
                        }
                        Some(f)
                    }
                    _ => None,
                };
                let target = target.ok_or_else(|| Error::NotFound("目标文件夹不存在".into()))?;
                if *action == Action::Spam {
                    for m in msgs {
                        if !m.summary.from.email.is_empty() {
                            let _ = self.db.set_trusted_images(&m.summary.from.email, false);
                        }
                    }
                }
                ops.extend(self.move_messages(acc, msgs, &target)?);
            }
        }
        Ok(ops)
    }

    fn move_messages(&self, acc: &Account, msgs: &[StoredMessage], target: &Folder) -> Result<Vec<i64>> {
        let mut ops = Vec::new();
        let mut by_folder: HashMap<FolderId, Vec<&StoredMessage>> = HashMap::new();
        for m in msgs.iter().filter(|m| m.summary.folder_id != target.id) {
            by_folder.entry(m.summary.folder_id).or_default().push(m);
        }
        for (from, list) in by_folder {
            let ids: Vec<MessageId> = list.iter().map(|m| m.summary.id).collect();
            let uids: Vec<u32> = list.iter().filter_map(|m| m.uid).collect();
            let server = acc.kind == AccountKind::Imap && !target.local && !list[0].folder_local;
            if server && !uids.is_empty() {
                ops.push(self.db.enqueue_op_at(
                    &acc.id,
                    &OpKind::Move { from, to: target.id, uids },
                    now() + UNDO_WINDOW,
                )?);
            }
            self.db.move_local(&ids, target.id, !server)?;
            if target.role != FolderRole::Inbox {
                self.db.snooze(&ids, None)?;
            }
        }
        Ok(ops)
    }

    fn delete_permanently(&self, acc: &Account, msgs: &[StoredMessage]) -> Result<Vec<i64>> {
        let mut ops = Vec::new();
        if msgs.is_empty() {
            return Ok(ops);
        }
        let mut by_folder: HashMap<FolderId, Vec<&StoredMessage>> = HashMap::new();
        for m in msgs {
            by_folder.entry(m.summary.folder_id).or_default().push(m);
        }
        for (folder, list) in by_folder {
            let ids: Vec<MessageId> = list.iter().map(|m| m.summary.id).collect();
            let uids: Vec<u32> = list.iter().filter_map(|m| m.uid).collect();
            match acc.kind {
                AccountKind::Imap if !list[0].folder_local && !uids.is_empty() => {
                    ops.push(self.db.enqueue_op_at(&acc.id, &OpKind::Expunge { folder, uids }, now() + UNDO_WINDOW)?);
                    self.db.set_flag(&ids, "hidden", true)?;
                }
                AccountKind::Pop3 => {
                    let uidls: Vec<String> = list.iter().filter_map(|m| m.remote_id.clone()).collect();
                    if acc.config.pop_delete_on_local_delete && !uidls.is_empty() {
                        ops.push(self.db.enqueue_op_at(&acc.id, &OpKind::PopDelete { uidls }, now() + UNDO_WINDOW)?);
                    }
                    self.db.set_flag(&ids, "hidden", true)?;
                }
                _ => self.db.delete_messages(&ids)?,
            }
        }
        Ok(ops)
    }

    // ---- folders -------------------------------------------------------------------------

    pub fn create_folder(&self, account_id: &str, name: &str, parent: Option<FolderId>) -> Result<Folder> {
        let acc = self.db.account(account_id)?;
        let (path, delimiter) = match parent {
            Some(p) => {
                let pf = self.db.folder(p)?;
                let d = pf.delimiter.clone().unwrap_or_else(|| "/".into());
                (format!("{}{}{}", pf.path, d, crate::imap::utf7::encode(name)), Some(d))
            }
            None => (crate::imap::utf7::encode(name), None),
        };
        let local = acc.kind != AccountKind::Imap;
        let path = if local { format!("local:{}", name) } else { path };
        let id = self.db.upsert_folder(
            account_id,
            &crate::store::FolderSpec { path: path.clone(), name: name.into(), delimiter, role: FolderRole::Custom, selectable: true },
        )?;
        if local {
            self.db.write(|c| {
                c.execute("UPDATE folders SET local = 1 WHERE id = ?", [id])?;
                Ok(())
            })?;
        } else {
            self.db.enqueue_op(account_id, &OpKind::CreateFolder { path })?;
            self.wake(Some(account_id));
        }
        self.events.emit(crate::events::Event::FoldersChanged { account_id: account_id.into() });
        self.db.folder(id)
    }

    pub fn rename_folder(&self, folder_id: FolderId, new_name: &str) -> Result<Folder> {
        let f = self.db.folder(folder_id)?;
        if f.role != FolderRole::Custom {
            return Err(Error::Invalid("系统文件夹不能重命名".into()));
        }
        let encoded = crate::imap::utf7::encode(new_name);
        let new_path = match (&f.delimiter, f.path.rfind(f.delimiter.as_deref().unwrap_or("\u{0}"))) {
            (Some(d), Some(pos)) if !f.local => format!("{}{}{}", &f.path[..pos], d, encoded),
            _ if f.local => format!("local:{new_name}"),
            _ => encoded,
        };
        if !f.local {
            self.db.enqueue_op(&f.account_id, &OpKind::RenameFolder { from: f.path.clone(), to: new_path.clone() })?;
            self.wake(Some(&f.account_id));
        }
        self.db.rename_folder_local(folder_id, &new_path, new_name)?;
        self.events.emit(crate::events::Event::FoldersChanged { account_id: f.account_id.clone() });
        self.db.folder(folder_id)
    }

    pub fn delete_folder(&self, folder_id: FolderId) -> Result<()> {
        let f = self.db.folder(folder_id)?;
        if f.role != FolderRole::Custom {
            return Err(Error::Invalid("系统文件夹不能删除".into()));
        }
        if !f.local {
            self.db.enqueue_op(&f.account_id, &OpKind::DeleteFolder { path: f.path.clone() })?;
            self.wake(Some(&f.account_id));
        }
        self.db.delete_folder(folder_id)?;
        self.events.emit(crate::events::Event::FoldersChanged { account_id: f.account_id.clone() });
        Ok(())
    }

    /// Marks every message of a mailbox view as read.
    pub async fn mark_all_read(&self, mailbox: &Mailbox) -> Result<ActionResult> {
        let mut ids = Vec::new();
        let mut before = None;
        loop {
            let page = self.db.list_messages(&crate::store::ListQuery {
                mailbox: mailbox.clone(),
                search: Some("is:unread".into()),
                before,
                limit: 1000,
                ..Default::default()
            })?;
            if page.is_empty() {
                break;
            }
            before = page.last().map(|m| (m.date, m.id));
            ids.extend(page.iter().map(|m| m.id));
            if page.len() < 1000 {
                break;
            }
        }
        self.act(&ids, Action::Read).await
    }
}

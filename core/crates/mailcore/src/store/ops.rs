use super::{Db, now};
use crate::error::Result;
use crate::model::{FolderId, MessageId};
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// A server-side change waiting to be applied by the account worker.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OpKind {
    /// Add or remove an IMAP flag (`\Seen`, `\Flagged`, `\Answered`, `$Forwarded`).
    Flags { message_ids: Vec<MessageId>, flag: String, add: bool },
    /// Move messages that were in `from` with `uids` to `to`.
    Move { from: FolderId, to: FolderId, uids: Vec<u32> },
    /// Permanently delete.
    Expunge { folder: FolderId, uids: Vec<u32> },
    /// Upload a message (draft, sent copy, import). `replace_uid` is expunged first.
    Append { folder: FolderId, blob: String, flags: Vec<String>, replace_uid: Option<u32> },
    /// Gmail labels.
    Labels { message_ids: Vec<MessageId>, add: Vec<String>, remove: Vec<String> },
    CreateFolder { path: String },
    RenameFolder { from: String, to: String },
    DeleteFolder { path: String },
    /// POP3: delete these UIDLs from the server.
    PopDelete { uidls: Vec<String> },
    /// Upload a draft to the Drafts folder, replacing older copies tagged with the same draft id.
    ReplaceDraft { draft_id: String, blob: String },
    /// Remove the server copies of a draft (after sending or discarding).
    DeleteDraft { draft_id: String },
}

impl OpKind {
    pub fn name(&self) -> &'static str {
        match self {
            OpKind::Flags { .. } => "flags",
            OpKind::Move { .. } => "move",
            OpKind::Expunge { .. } => "expunge",
            OpKind::Append { .. } => "append",
            OpKind::Labels { .. } => "labels",
            OpKind::CreateFolder { .. } => "create_folder",
            OpKind::RenameFolder { .. } => "rename_folder",
            OpKind::DeleteFolder { .. } => "delete_folder",
            OpKind::PopDelete { .. } => "pop_delete",
            OpKind::ReplaceDraft { .. } => "replace_draft",
            OpKind::DeleteDraft { .. } => "delete_draft",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Op {
    pub id: i64,
    pub account_id: String,
    pub kind: OpKind,
    pub attempts: i64,
}

impl Db {
    pub fn enqueue_op(&self, account_id: &str, kind: &OpKind) -> Result<i64> {
        self.enqueue_op_at(account_id, kind, 0)
    }

    /// Enqueues an op that only becomes due at `not_before` (used to keep a short undo window).
    pub fn enqueue_op_at(&self, account_id: &str, kind: &OpKind, not_before: i64) -> Result<i64> {
        let payload = serde_json::to_string(kind)?;
        self.write(|c| {
            c.execute(
                "INSERT INTO ops (account_id, kind, payload, next_try, created_at) VALUES (?, ?, ?, ?, ?)",
                params![account_id, kind.name(), payload, not_before, now()],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    /// Cancels ops that have not run yet (undo). Returns how many were removed.
    pub fn cancel_ops(&self, ids: &[i64]) -> Result<usize> {
        self.tx(|tx| {
            let mut n = 0;
            for id in ids {
                n += tx.execute("DELETE FROM ops WHERE id = ? AND attempts = 0", [id])?;
            }
            Ok(n)
        })
    }

    /// Earliest time an op of this account becomes due.
    pub fn next_op_time(&self, account_id: &str) -> Result<Option<i64>> {
        self.read(|c| Ok(c.query_row("SELECT MIN(next_try) FROM ops WHERE account_id = ?", [account_id], |r| r.get(0))?))
    }

    /// Ops ready to run for an account, oldest first.
    pub fn due_ops(&self, account_id: &str) -> Result<Vec<Op>> {
        let rows: Vec<(i64, String, i64)> = self.read(|c| {
            let mut st = c.prepare(
                "SELECT id, payload, attempts FROM ops WHERE account_id = ? AND next_try <= ? ORDER BY id",
            )?;
            let rows = st
                .query_map(params![account_id, now()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        Ok(rows
            .into_iter()
            .filter_map(|(id, payload, attempts)| {
                serde_json::from_str(&payload).ok().map(|kind| Op { id, account_id: account_id.into(), kind, attempts })
            })
            .collect())
    }

    pub fn pending_op_count(&self, account_id: &str) -> Result<i64> {
        self.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM ops WHERE account_id = ?", [account_id], |r| r.get(0))?))
    }

    pub fn finish_op(&self, id: i64) -> Result<()> {
        self.write(|c| {
            c.execute("DELETE FROM ops WHERE id = ?", [id])?;
            Ok(())
        })
    }

    /// Records a failure; the op is retried with exponential backoff and dropped after 20 attempts.
    pub fn fail_op(&self, id: i64, attempts: i64, error: &str) -> Result<()> {
        if attempts >= 20 {
            return self.finish_op(id);
        }
        let delay = (30i64 << attempts.min(10)).min(3600);
        self.write(|c| {
            c.execute(
                "UPDATE ops SET attempts = attempts + 1, next_try = ?, last_error = ? WHERE id = ?",
                params![now() + delay, error, id],
            )?;
            Ok(())
        })
    }

    /// Rewrites the payload of an op (e.g. after partially applying it).
    pub fn replace_op(&self, id: i64, kind: &OpKind) -> Result<()> {
        let payload = serde_json::to_string(kind)?;
        self.write(|c| {
            c.execute("UPDATE ops SET payload = ?, next_try = ? WHERE id = ?", params![payload, now() + 15, id])?;
            Ok(())
        })
    }
}

use super::Db;
use crate::error::{Error, Result};
use crate::model::{Folder, FolderId, FolderRole};
use rusqlite::{OptionalExtension, Row, params};

const FOLDER_SELECT: &str = "SELECT f.*,
    (SELECT COUNT(*) FROM messages m WHERE m.folder_id = f.id AND m.seen = 0 AND m.hidden = 0) AS unread,
    (SELECT COUNT(*) FROM messages m WHERE m.folder_id = f.id AND m.hidden = 0) AS total
    FROM folders f";

fn folder_from_row(r: &Row) -> rusqlite::Result<Folder> {
    Ok(Folder {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        path: r.get("path")?,
        name: r.get("name")?,
        delimiter: r.get("delimiter")?,
        role: FolderRole::parse(&r.get::<_, String>("role")?),
        unread: r.get("unread")?,
        total: r.get("total")?,
        selectable: r.get("selectable")?,
        local: r.get("local")?,
        uidvalidity: r.get("uidvalidity")?,
        uidnext: r.get("uidnext")?,
        highest_modseq: r.get::<_, Option<i64>>("highest_modseq")?.map(|v| v as u64),
        last_sync: r.get("last_sync")?,
    })
}

#[derive(Debug, Clone)]
pub struct FolderSpec {
    pub path: String,
    pub name: String,
    pub delimiter: Option<String>,
    pub role: FolderRole,
    pub selectable: bool,
}

impl Db {
    pub fn folders(&self, account_id: Option<&str>) -> Result<Vec<Folder>> {
        self.read(|c| {
            let sql = format!(
                "{FOLDER_SELECT} JOIN accounts a ON a.id = f.account_id
                 WHERE (?1 IS NULL OR f.account_id = ?1) ORDER BY a.sort_order, f.path"
            );
            let mut st = c.prepare(&sql)?;
            let mut rows = st.query_map([account_id], folder_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows.sort_by(|a, b| {
                (a.account_id == b.account_id)
                    .then(|| a.role.rank().cmp(&b.role.rank()).then(a.path.to_lowercase().cmp(&b.path.to_lowercase())))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            Ok(rows)
        })
    }

    pub fn folder(&self, id: FolderId) -> Result<Folder> {
        self.read(|c| {
            c.query_row(&format!("{FOLDER_SELECT} WHERE f.id = ?"), [id], folder_from_row)
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("folder {id}")))
        })
    }

    pub fn folder_by_role(&self, account_id: &str, role: FolderRole) -> Result<Option<Folder>> {
        self.read(|c| {
            Ok(c.query_row(
                &format!("{FOLDER_SELECT} WHERE f.account_id = ? AND f.role = ? ORDER BY f.local, f.id LIMIT 1"),
                params![account_id, role.as_str()],
                folder_from_row,
            )
            .optional()?)
        })
    }

    pub fn folder_by_path(&self, account_id: &str, path: &str) -> Result<Option<Folder>> {
        self.read(|c| {
            Ok(c.query_row(
                &format!("{FOLDER_SELECT} WHERE f.account_id = ? AND f.path = ?"),
                params![account_id, path],
                folder_from_row,
            )
            .optional()?)
        })
    }

    /// Creates or refreshes a server folder; returns its id.
    pub fn upsert_folder(&self, account_id: &str, spec: &FolderSpec) -> Result<FolderId> {
        self.write(|c| {
            c.execute(
                "INSERT INTO folders (account_id, path, name, delimiter, role, selectable)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(account_id, path) DO UPDATE SET name = excluded.name,
                   delimiter = excluded.delimiter, role = excluded.role, selectable = excluded.selectable",
                params![account_id, spec.path, spec.name, spec.delimiter, spec.role.as_str(), spec.selectable],
            )?;
            Ok(c.query_row(
                "SELECT id FROM folders WHERE account_id = ? AND path = ?",
                params![account_id, spec.path],
                |r| r.get(0),
            )?)
        })
    }

    /// Ensures a local-only folder (POP3 mailboxes, outbox) exists.
    pub fn ensure_local_folder(&self, account_id: &str, role: FolderRole, name: &str) -> Result<FolderId> {
        if let Some(f) = self.folder_by_role(account_id, role)? {
            return Ok(f.id);
        }
        let path = format!("local:{}", role.as_str());
        self.write(|c| {
            c.execute(
                "INSERT OR IGNORE INTO folders (account_id, path, name, role, local) VALUES (?, ?, ?, ?, 1)",
                params![account_id, path, name, role.as_str()],
            )?;
            Ok(c.query_row(
                "SELECT id FROM folders WHERE account_id = ? AND path = ?",
                params![account_id, path],
                |r| r.get(0),
            )?)
        })
    }

    pub fn set_folder_state(
        &self,
        id: FolderId,
        uidvalidity: Option<u32>,
        uidnext: Option<u32>,
        highest_modseq: Option<u64>,
    ) -> Result<()> {
        self.write(|c| {
            c.execute(
                "UPDATE folders SET uidvalidity = ?, uidnext = ?, highest_modseq = ?, last_sync = ? WHERE id = ?",
                params![uidvalidity, uidnext, highest_modseq.map(|v| v as i64), super::now(), id],
            )?;
            Ok(())
        })
    }

    pub fn set_folder_sync_enabled(&self, id: FolderId, enabled: bool) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE folders SET sync_enabled = ? WHERE id = ?", params![enabled, id])?;
            Ok(())
        })
    }

    pub fn folder_sync_enabled(&self, id: FolderId) -> Result<bool> {
        self.read(|c| Ok(c.query_row("SELECT sync_enabled FROM folders WHERE id = ?", [id], |r| r.get(0))?))
    }

    pub fn rename_folder_local(&self, id: FolderId, path: &str, name: &str) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE folders SET path = ?, name = ? WHERE id = ?", params![path, name, id])?;
            Ok(())
        })
    }

    pub fn delete_folder(&self, id: FolderId) -> Result<()> {
        self.tx(|tx| {
            tx.execute("DELETE FROM messages_fts WHERE rowid IN (SELECT id FROM messages WHERE folder_id = ?)", [id])?;
            tx.execute("DELETE FROM folders WHERE id = ?", [id])?;
            Ok(())
        })
    }

    /// Drops server folders that no longer exist.
    pub fn prune_folders(&self, account_id: &str, keep_paths: &[String]) -> Result<Vec<FolderId>> {
        let existing = self.folders(Some(account_id))?;
        let mut removed = Vec::new();
        for f in existing {
            if !f.local && !keep_paths.contains(&f.path) {
                self.delete_folder(f.id)?;
                removed.push(f.id);
            }
        }
        Ok(removed)
    }

    /// Removes all cached messages of a folder (UIDVALIDITY changed).
    pub fn clear_folder(&self, id: FolderId) -> Result<()> {
        self.tx(|tx| {
            tx.execute("DELETE FROM messages_fts WHERE rowid IN (SELECT id FROM messages WHERE folder_id = ?)", [id])?;
            tx.execute("DELETE FROM messages WHERE folder_id = ?", [id])?;
            Ok(())
        })
    }

    pub fn unread_counts(&self) -> Result<Vec<(String, i64)>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT a.id, (SELECT COUNT(*) FROM messages m JOIN folders f ON f.id = m.folder_id
                   WHERE m.account_id = a.id AND f.role = 'inbox' AND m.seen = 0 AND m.hidden = 0
                   AND (m.snoozed_until IS NULL)) FROM accounts a ORDER BY a.sort_order",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::store::test_db;

    #[test]
    fn folders_upsert_and_roles() {
        let (_d, db) = test_db();
        let a = db.insert_account(Account { email: "x@163.com".into(), ..Default::default() }).unwrap();
        let spec = FolderSpec {
            path: "INBOX".into(),
            name: "收件箱".into(),
            delimiter: Some("/".into()),
            role: FolderRole::Inbox,
            selectable: true,
        };
        let id1 = db.upsert_folder(&a.id, &spec).unwrap();
        let id2 = db.upsert_folder(&a.id, &spec).unwrap();
        assert_eq!(id1, id2);
        let sent = db
            .upsert_folder(&a.id, &FolderSpec { path: "&XfJT0ZAB-".into(), name: "已发送".into(), role: FolderRole::Sent, ..spec.clone() })
            .unwrap();
        assert_eq!(db.folder_by_role(&a.id, FolderRole::Sent).unwrap().unwrap().id, sent);
        let all = db.folders(Some(&a.id)).unwrap();
        assert_eq!(all[0].role, FolderRole::Inbox);
        let removed = db.prune_folders(&a.id, &["INBOX".to_string()]).unwrap();
        assert_eq!(removed, vec![sent]);
        let local = db.ensure_local_folder(&a.id, FolderRole::Outbox, "发件箱").unwrap();
        assert_eq!(db.ensure_local_folder(&a.id, FolderRole::Outbox, "发件箱").unwrap(), local);
        assert!(db.folder(local).unwrap().local);
    }
}

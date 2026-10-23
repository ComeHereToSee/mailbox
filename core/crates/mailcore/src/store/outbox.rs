use super::{Db, now};
use crate::error::{Error, Result};
use crate::model::{Draft, OutboxItem, OutboxStatus};
use rusqlite::{OptionalExtension, Row, params};

fn status_str(s: OutboxStatus) -> &'static str {
    match s {
        OutboxStatus::Queued => "queued",
        OutboxStatus::Sending => "sending",
        OutboxStatus::Sent => "sent",
        OutboxStatus::Failed => "failed",
        OutboxStatus::Cancelled => "cancelled",
    }
}

fn status_from(s: &str) -> OutboxStatus {
    match s {
        "sending" => OutboxStatus::Sending,
        "sent" => OutboxStatus::Sent,
        "failed" => OutboxStatus::Failed,
        "cancelled" => OutboxStatus::Cancelled,
        _ => OutboxStatus::Queued,
    }
}

fn item_from_row(r: &Row) -> rusqlite::Result<OutboxItem> {
    Ok(OutboxItem {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        subject: r.get("subject")?,
        to: serde_json::from_str(&r.get::<_, String>("to_json")?).unwrap_or_default(),
        send_at: r.get("send_at")?,
        status: status_from(&r.get::<_, String>("status")?),
        attempts: r.get("attempts")?,
        last_error: r.get("last_error")?,
        created_at: r.get("created_at")?,
    })
}

impl Db {
    pub fn queue_outgoing(&self, draft: &Draft, send_at: i64) -> Result<OutboxItem> {
        let id = super::new_id();
        let data = serde_json::to_string(draft)?;
        let to = serde_json::to_string(&draft.to)?;
        let t = now();
        self.write(|c| {
            c.execute(
                "INSERT INTO outbox (id, account_id, draft, subject, to_json, send_at, status, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)",
                params![id, draft.account_id, data, draft.subject, to, send_at, t],
            )?;
            Ok(())
        })?;
        self.outbox_item(&id)
    }

    pub fn outbox_item(&self, id: &str) -> Result<OutboxItem> {
        self.read(|c| {
            c.query_row("SELECT * FROM outbox WHERE id = ?", [id], item_from_row)
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("outbox {id}")))
        })
    }

    pub fn outbox_draft(&self, id: &str) -> Result<Draft> {
        let data: String = self.read(|c| {
            c.query_row("SELECT draft FROM outbox WHERE id = ?", [id], |r| r.get(0))
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("outbox {id}")))
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn outbox(&self) -> Result<Vec<OutboxItem>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT * FROM outbox WHERE status IN ('queued', 'sending', 'failed') ORDER BY send_at",
            )?;
            let rows = st.query_map([], item_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Queued items whose time has come.
    pub fn due_outgoing(&self, at: i64) -> Result<Vec<OutboxItem>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT * FROM outbox WHERE status = 'queued' AND send_at <= ? ORDER BY send_at")?;
            let rows = st.query_map([at], item_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn next_outgoing_time(&self) -> Result<Option<i64>> {
        self.read(|c| Ok(c.query_row("SELECT MIN(send_at) FROM outbox WHERE status = 'queued'", [], |r| r.get(0))?))
    }

    pub fn set_outbox_status(&self, id: &str, status: OutboxStatus, error: Option<&str>) -> Result<()> {
        self.write(|c| {
            c.execute(
                "UPDATE outbox SET status = ?, last_error = ?, attempts = attempts + CASE WHEN ? = 'failed' THEN 1 ELSE 0 END
                 WHERE id = ?",
                params![status_str(status), error, status_str(status), id],
            )?;
            Ok(())
        })
    }

    /// Re-queues a failed item for a retry at `at`.
    pub fn retry_outgoing(&self, id: &str, at: i64) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE outbox SET status = 'queued', send_at = ? WHERE id = ?", params![at, id])?;
            Ok(())
        })
    }

    /// Cancels a queued send (undo send). Returns the draft so the composer can reopen it.
    pub fn cancel_outgoing(&self, id: &str) -> Result<Option<Draft>> {
        let changed = self.write(|c| {
            Ok(c.execute("UPDATE outbox SET status = 'cancelled' WHERE id = ? AND status = 'queued'", [id])?)
        })?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(self.outbox_draft(id)?))
    }

    pub fn purge_outbox(&self, older_than: i64) -> Result<()> {
        self.write(|c| {
            c.execute("DELETE FROM outbox WHERE status IN ('sent', 'cancelled') AND created_at < ?", [older_than])?;
            Ok(())
        })
    }

    pub fn save_draft(&self, draft: &Draft) -> Result<()> {
        let data = serde_json::to_string(draft)?;
        self.write(|c| {
            c.execute(
                "INSERT INTO drafts (id, account_id, data, updated_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET account_id = excluded.account_id, data = excluded.data, updated_at = excluded.updated_at",
                params![draft.id, draft.account_id, data, now()],
            )?;
            Ok(())
        })
    }

    pub fn draft(&self, id: &str) -> Result<Option<(Draft, Option<u32>)>> {
        let row: Option<(String, Option<u32>)> = self.read(|c| {
            Ok(c.query_row("SELECT data, server_uid FROM drafts WHERE id = ?", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?)
        })?;
        match row {
            Some((d, uid)) => Ok(Some((serde_json::from_str(&d)?, uid))),
            None => Ok(None),
        }
    }

    pub fn drafts(&self) -> Result<Vec<Draft>> {
        let rows: Vec<String> = self.read(|c| {
            let mut st = c.prepare("SELECT data FROM drafts ORDER BY updated_at DESC")?;
            let rows = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        Ok(rows.iter().filter_map(|d| serde_json::from_str(d).ok()).collect())
    }

    pub fn set_draft_server_uid(&self, id: &str, uid: Option<u32>) -> Result<()> {
        self.write(|c| {
            c.execute("UPDATE drafts SET server_uid = ? WHERE id = ?", params![uid, id])?;
            Ok(())
        })
    }

    pub fn delete_draft(&self, id: &str) -> Result<()> {
        self.write(|c| {
            c.execute("DELETE FROM drafts WHERE id = ?", [id])?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::*;
    use crate::store::test_db;

    #[test]
    fn outbox_undo() {
        let (_d, db) = test_db();
        let a = db.insert_account(Account { email: "me@x.com".into(), ..Default::default() }).unwrap();
        let d = Draft { id: "d1".into(), account_id: a.id.clone(), subject: "Hi".into(), ..Default::default() };
        let item = db.queue_outgoing(&d, 100).unwrap();
        assert!(db.due_outgoing(50).unwrap().is_empty());
        assert_eq!(db.due_outgoing(100).unwrap().len(), 1);
        let back = db.cancel_outgoing(&item.id).unwrap().unwrap();
        assert_eq!(back.subject, "Hi");
        assert!(db.cancel_outgoing(&item.id).unwrap().is_none());
        assert!(db.due_outgoing(1000).unwrap().is_empty());
        db.save_draft(&d).unwrap();
        db.set_draft_server_uid("d1", Some(9)).unwrap();
        assert_eq!(db.draft("d1").unwrap().unwrap().1, Some(9));
    }
}

use super::{Db, new_id, now};
use crate::error::{Error, Result};
use crate::model::{Account, AccountConfig, AccountKind, Identity};
use rusqlite::{OptionalExtension, Row, params};

fn kind_from(s: &str) -> AccountKind {
    match s {
        "pop3" => AccountKind::Pop3,
        "graph" => AccountKind::Graph,
        "jmap" => AccountKind::Jmap,
        "web" => AccountKind::Web,
        _ => AccountKind::Imap,
    }
}

fn account_from_row(r: &Row) -> rusqlite::Result<Account> {
    let config: String = r.get("config")?;
    Ok(Account {
        id: r.get("id")?,
        kind: kind_from(&r.get::<_, String>("kind")?),
        email: r.get("email")?,
        name: r.get("name")?,
        label: r.get("label")?,
        color: r.get("color")?,
        provider: r.get("provider")?,
        config: serde_json::from_str::<AccountConfig>(&config).unwrap_or_default(),
        enabled: r.get("enabled")?,
        sort_order: r.get("sort_order")?,
        created_at: r.get("created_at")?,
    })
}

fn identity_from_row(r: &Row) -> rusqlite::Result<Identity> {
    Ok(Identity {
        id: r.get("id")?,
        account_id: r.get("account_id")?,
        name: r.get("name")?,
        email: r.get("email")?,
        reply_to: r.get("reply_to")?,
        signature_html: r.get("signature_html")?,
        is_default: r.get("is_default")?,
    })
}

impl Db {
    pub fn accounts(&self) -> Result<Vec<Account>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT * FROM accounts ORDER BY sort_order, created_at")?;
            let rows = st.query_map([], account_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn account(&self, id: &str) -> Result<Account> {
        self.read(|c| {
            c.query_row("SELECT * FROM accounts WHERE id = ?", [id], account_from_row)
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("account {id}")))
        })
    }

    /// Inserts a new account and its default identity. Fills id / created_at when empty.
    pub fn insert_account(&self, mut a: Account) -> Result<Account> {
        if a.id.is_empty() {
            a.id = new_id();
        }
        a.created_at = now();
        if a.label.is_empty() {
            a.label = a.email.clone();
        }
        let config = serde_json::to_string(&a.config)?;
        self.tx(|tx| {
            let order: i64 =
                tx.query_row("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM accounts", [], |r| r.get(0))?;
            a.sort_order = order;
            tx.execute(
                "INSERT INTO accounts (id, kind, email, name, label, color, provider, config, enabled, sort_order, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![a.id, a.kind.as_str(), a.email, a.name, a.label, a.color, a.provider, config, a.enabled, a.sort_order, a.created_at],
            )?;
            tx.execute(
                "INSERT INTO identities (id, account_id, name, email, is_default) VALUES (?, ?, ?, ?, 1)",
                params![new_id(), a.id, a.name, a.email],
            )?;
            Ok(())
        })?;
        Ok(a)
    }

    pub fn update_account(&self, a: &Account) -> Result<()> {
        let config = serde_json::to_string(&a.config)?;
        let n = self.write(|c| {
            Ok(c.execute(
                "UPDATE accounts SET email = ?, name = ?, label = ?, color = ?, provider = ?, config = ?, enabled = ?, sort_order = ?
                 WHERE id = ?",
                params![a.email, a.name, a.label, a.color, a.provider, config, a.enabled, a.sort_order, a.id],
            )?)
        })?;
        if n == 0 {
            return Err(Error::NotFound(format!("account {}", a.id)));
        }
        Ok(())
    }

    pub fn delete_account(&self, id: &str) -> Result<()> {
        self.tx(|tx| {
            tx.execute(
                "DELETE FROM messages_fts WHERE rowid IN (SELECT id FROM messages WHERE account_id = ?)",
                [id],
            )?;
            tx.execute("DELETE FROM accounts WHERE id = ?", [id])?;
            Ok(())
        })
    }

    pub fn identities(&self, account_id: Option<&str>) -> Result<Vec<Identity>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT i.* FROM identities i JOIN accounts a ON a.id = i.account_id
                 WHERE (?1 IS NULL OR i.account_id = ?1) ORDER BY a.sort_order, i.is_default DESC, i.email",
            )?;
            let rows = st.query_map([account_id], identity_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn identity(&self, id: &str) -> Result<Identity> {
        self.read(|c| {
            c.query_row("SELECT * FROM identities WHERE id = ?", [id], identity_from_row)
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("identity {id}")))
        })
    }

    pub fn default_identity(&self, account_id: &str) -> Result<Identity> {
        self.read(|c| {
            c.query_row(
                "SELECT * FROM identities WHERE account_id = ? ORDER BY is_default DESC LIMIT 1",
                [account_id],
                identity_from_row,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("identity for {account_id}")))
        })
    }

    pub fn save_identity(&self, mut i: Identity) -> Result<Identity> {
        if i.id.is_empty() {
            i.id = new_id();
        }
        self.tx(|tx| {
            if i.is_default {
                tx.execute("UPDATE identities SET is_default = 0 WHERE account_id = ?", [&i.account_id])?;
            }
            tx.execute(
                "INSERT INTO identities (id, account_id, name, email, reply_to, signature_html, is_default)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, email = excluded.email,
                   reply_to = excluded.reply_to, signature_html = excluded.signature_html, is_default = excluded.is_default",
                params![i.id, i.account_id, i.name, i.email, i.reply_to, i.signature_html, i.is_default],
            )?;
            Ok(())
        })?;
        Ok(i)
    }

    pub fn delete_identity(&self, id: &str) -> Result<()> {
        self.write(|c| {
            c.execute("DELETE FROM identities WHERE id = ?", [id])?;
            Ok(())
        })
    }

    /// All addresses that belong to the user, used to tell "me" apart in threads and RSVPs.
    pub fn own_addresses(&self) -> Result<Vec<String>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT lower(email) FROM identities UNION SELECT lower(email) FROM accounts")?;
            let rows = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(rows)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::*;
    use crate::store::test_db;

    #[test]
    fn account_roundtrip() {
        let (_d, db) = test_db();
        let a = db
            .insert_account(Account {
                email: "a@qq.com".into(),
                name: "张三".into(),
                kind: AccountKind::Imap,
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(a.label, "a@qq.com");
        let mut got = db.account(&a.id).unwrap();
        assert_eq!(got.name, "张三");
        got.label = "QQ".into();
        db.update_account(&got).unwrap();
        assert_eq!(db.accounts().unwrap()[0].label, "QQ");
        let ids = db.identities(Some(&a.id)).unwrap();
        assert_eq!(ids.len(), 1);
        assert!(ids[0].is_default);
        db.delete_account(&a.id).unwrap();
        assert!(db.accounts().unwrap().is_empty());
        assert!(db.identities(None).unwrap().is_empty());
    }
}

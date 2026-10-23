use super::{Db, now};
use crate::error::Result;
use crate::model::{Contact, EmailAddress};
use rusqlite::{OptionalExtension, params};

impl Db {
    /// Remembers addresses for autocomplete. `weight` is higher for people we write to.
    pub fn record_contacts(&self, addrs: &[EmailAddress], weight: i64) -> Result<()> {
        let t = now();
        self.tx(|tx| {
            for a in addrs {
                let email = a.email.trim().to_lowercase();
                if email.is_empty() || !email.contains('@') {
                    continue;
                }
                tx.execute(
                    "INSERT INTO contacts (email, name, use_count, last_used) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(email) DO UPDATE SET use_count = use_count + ?3, last_used = MAX(last_used, ?4),
                       name = COALESCE(?2, name)",
                    params![email, a.name, weight, t],
                )?;
            }
            Ok(())
        })
    }

    pub fn search_contacts(&self, q: &str, limit: i64) -> Result<Vec<Contact>> {
        let like = format!("%{}%", q.trim());
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT email, name, use_count, last_used, vip FROM contacts
                 WHERE email LIKE ?1 OR name LIKE ?1
                 ORDER BY vip DESC, (email LIKE ?2) DESC, use_count DESC, last_used DESC LIMIT ?3",
            )?;
            let rows = st
                .query_map(params![like, format!("{}%", q.trim()), limit], |r| {
                    Ok(Contact {
                        email: r.get(0)?,
                        name: r.get(1)?,
                        use_count: r.get(2)?,
                        last_used: r.get(3)?,
                        vip: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn set_vip(&self, email: &str, vip: bool) -> Result<()> {
        self.write(|c| {
            c.execute(
                "INSERT INTO contacts (email, vip) VALUES (lower(?1), ?2) ON CONFLICT(email) DO UPDATE SET vip = ?2",
                params![email.trim(), vip],
            )?;
            Ok(())
        })
    }

    pub fn is_vip(&self, email: &str) -> Result<bool> {
        self.read(|c| {
            Ok(c.query_row("SELECT vip FROM contacts WHERE email = ?", [email.trim()], |r| r.get(0))
                .optional()?
                .unwrap_or(false))
        })
    }

    pub fn vips(&self) -> Result<Vec<String>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT email FROM contacts WHERE vip = 1 ORDER BY email")?;
            let rows = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn set_trusted_images(&self, email: &str, trusted: bool) -> Result<()> {
        self.write(|c| {
            c.execute(
                "INSERT INTO contacts (email, trusted_images) VALUES (lower(?1), ?2)
                 ON CONFLICT(email) DO UPDATE SET trusted_images = ?2",
                params![email.trim(), trusted],
            )?;
            Ok(())
        })
    }

    pub fn trusts_images(&self, email: &str) -> Result<bool> {
        self.read(|c| {
            Ok(c.query_row("SELECT trusted_images FROM contacts WHERE email = ?", [email.trim()], |r| r.get(0))
                .optional()?
                .unwrap_or(false))
        })
    }

    pub fn is_known_contact(&self, email: &str) -> Result<bool> {
        self.read(|c| {
            Ok(c.query_row("SELECT use_count > 0 FROM contacts WHERE email = ?", [email.trim()], |r| r.get(0))
                .optional()?
                .unwrap_or(false))
        })
    }

    /// Blocks an address or a whole domain (`@spam.com`).
    pub fn block(&self, pattern: &str) -> Result<()> {
        self.write(|c| {
            c.execute("INSERT OR IGNORE INTO blocked (pattern, created_at) VALUES (lower(?), ?)", params![pattern.trim(), now()])?;
            Ok(())
        })
    }

    pub fn unblock(&self, pattern: &str) -> Result<()> {
        self.write(|c| {
            c.execute("DELETE FROM blocked WHERE pattern = ?", [pattern.trim()])?;
            Ok(())
        })
    }

    pub fn blocked(&self) -> Result<Vec<String>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT pattern FROM blocked ORDER BY pattern")?;
            let rows = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn is_blocked(&self, email: &str) -> Result<bool> {
        let email = email.trim().to_lowercase();
        let domain = email.rsplit_once('@').map(|(_, d)| format!("@{d}")).unwrap_or_default();
        self.read(|c| {
            Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM blocked WHERE pattern = ? OR pattern = ?)",
                params![email, domain],
                |r| r.get(0),
            )?)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::model::EmailAddress;
    use crate::store::test_db;

    #[test]
    fn contacts_and_blocking() {
        let (_d, db) = test_db();
        db.record_contacts(&[EmailAddress::new(Some("王五"), "WangWu@corp.cn")], 3).unwrap();
        db.record_contacts(&[EmailAddress::new(None, "wangwu@corp.cn")], 1).unwrap();
        let found = db.search_contacts("王", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].use_count, 4);
        assert_eq!(found[0].name.as_deref(), Some("王五"));
        db.set_vip("wangwu@corp.cn", true).unwrap();
        assert!(db.is_vip("wangwu@corp.cn").unwrap());
        db.block("@spam.com").unwrap();
        assert!(db.is_blocked("Bad@Spam.com").unwrap());
        assert!(!db.is_blocked("ok@corp.cn").unwrap());
    }
}

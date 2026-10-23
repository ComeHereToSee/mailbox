use super::Db;
use crate::error::Result;
use rusqlite::{OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};

/// Small JSON document store for rules, templates, smart folders, forwarders and settings.
impl Db {
    pub fn kv_get<T: DeserializeOwned>(&self, space: &str, id: &str) -> Result<Option<T>> {
        let data: Option<String> = self.read(|c| {
            Ok(c.query_row("SELECT data FROM kv WHERE space = ? AND id = ?", params![space, id], |r| r.get(0))
                .optional()?)
        })?;
        Ok(match data {
            Some(d) => Some(serde_json::from_str(&d)?),
            None => None,
        })
    }

    pub fn kv_list<T: DeserializeOwned>(&self, space: &str) -> Result<Vec<T>> {
        let rows: Vec<String> = self.read(|c| {
            let mut st = c.prepare("SELECT data FROM kv WHERE space = ? ORDER BY sort, id")?;
            let rows = st.query_map([space], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })?;
        Ok(rows.iter().filter_map(|d| serde_json::from_str(d).ok()).collect())
    }

    pub fn kv_put<T: Serialize>(&self, space: &str, id: &str, value: &T, sort: i64) -> Result<()> {
        let data = serde_json::to_string(value)?;
        self.write(|c| {
            c.execute(
                "INSERT INTO kv (space, id, data, sort) VALUES (?, ?, ?, ?)
                 ON CONFLICT(space, id) DO UPDATE SET data = excluded.data, sort = excluded.sort",
                params![space, id, data, sort],
            )?;
            Ok(())
        })
    }

    pub fn kv_delete(&self, space: &str, id: &str) -> Result<bool> {
        self.write(|c| Ok(c.execute("DELETE FROM kv WHERE space = ? AND id = ?", params![space, id])? > 0))
    }

    pub fn settings(&self) -> Result<crate::model::Settings> {
        Ok(self.kv_get("settings", "app")?.unwrap_or_default())
    }

    pub fn save_settings(&self, s: &crate::model::Settings) -> Result<()> {
        self.kv_put("settings", "app", s, 0)
    }
}

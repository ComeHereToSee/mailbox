//! SQLite persistence. One writer connection plus a small pool of readers (WAL mode).

mod accounts;
mod contacts;
mod folders;
mod kv;
mod messages;
mod ops;
mod outbox;

pub use folders::FolderSpec;
pub use messages::{ListQuery, NewMessage, StoredMessage};
pub use ops::{Op, OpKind};

use crate::error::Result;
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

const MIGRATIONS: &[&str] = &[include_str!("schema.sql")];

pub struct Db {
    path: PathBuf,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
}

fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(())
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Db> {
        let path = path.as_ref().to_path_buf();
        let mut conn = Connection::open(&path)?;
        configure(&conn)?;
        migrate(&mut conn)?;
        crate::paths::restrict(&path)?;
        Ok(Db { path, writer: Mutex::new(conn), readers: Mutex::new(Vec::new()) })
    }

    /// Runs `f` on the writer connection.
    pub fn write<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut conn = self.writer.lock();
        f(&mut conn)
    }

    /// Runs `f` inside a transaction on the writer connection.
    pub fn tx<T>(&self, f: impl FnOnce(&rusqlite::Transaction) -> Result<T>) -> Result<T> {
        let mut conn = self.writer.lock();
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Runs `f` on a pooled read-only connection.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = match self.readers.lock().pop() {
            Some(c) => c,
            None => {
                let c = Connection::open_with_flags(
                    &self.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                c.busy_timeout(std::time::Duration::from_secs(10))?;
                c
            }
        };
        let out = f(&conn);
        let mut pool = self.readers.lock();
        if pool.len() < 4 {
            pool.push(conn);
        }
        out
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}

#[cfg(test)]
pub(crate) fn test_db() -> (tempfile_dir::TempDir, Db) {
    let dir = tempfile_dir::TempDir::new();
    let db = Db::open(dir.path().join("t.db")).unwrap();
    (dir, db)
}

#[cfg(test)]
pub(crate) mod tempfile_dir {
    use std::path::{Path, PathBuf};

    /// Minimal temp dir helper so tests need no extra crate.
    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> TempDir {
            let p = std::env::temp_dir().join(format!("mailcore-test-{}", super::new_id()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

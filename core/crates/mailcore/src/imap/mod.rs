//! IMAP client built on `async-imap`: connect / STARTTLS / login (password or XOAUTH2),
//! capability detection, folder listing with role detection and the commands the sync
//! engine needs.

pub mod utf7;

use crate::error::{Error, Result};
use crate::model::{Flags, FolderRole, Security, ServerConfig};
use crate::net::{self, MailStream};
use async_imap::types::{Flag, NameAttribute};
use async_imap::{Authenticator, Client, Session};
use futures::TryStreamExt;
use std::collections::HashSet;
use std::time::Duration;

pub type ImapSession = Session<MailStream>;

const CMD_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Default)]
pub struct Caps {
    pub idle: bool,
    pub condstore: bool,
    pub move_: bool,
    pub uidplus: bool,
    pub gmail: bool,
    pub id: bool,
    pub special_use: bool,
}

pub enum ImapAuth {
    Password(String),
    OAuth2(String),
}

struct XOAuth2 {
    payload: String,
    sent: bool,
}

impl Authenticator for XOAuth2 {
    type Response = String;
    fn process(&mut self, _challenge: &[u8]) -> String {
        if self.sent {
            // Error challenge: an empty response makes the server finish with NO.
            String::new()
        } else {
            self.sent = true;
            self.payload.clone()
        }
    }
}

pub fn xoauth2_payload(user: &str, token: &str) -> String {
    format!("user={user}\x01auth=Bearer {token}\x01\x01")
}

fn auth_error(e: async_imap::error::Error) -> Error {
    match e {
        async_imap::error::Error::No(msg) | async_imap::error::Error::Bad(msg) => Error::Auth(msg),
        other => Error::Imap(other.to_string()),
    }
}

async fn timed<T>(fut: impl std::future::Future<Output = std::result::Result<T, async_imap::error::Error>>) -> Result<T> {
    match tokio::time::timeout(CMD_TIMEOUT, fut).await {
        Ok(r) => r.map_err(Error::from),
        Err(_) => Err(Error::Net("IMAP 命令超时".into())),
    }
}

pub struct ImapConn {
    pub session: ImapSession,
    pub caps: Caps,
    pub selected: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RemoteFolder {
    pub path: String,
    pub name: String,
    pub delimiter: Option<String>,
    pub role: FolderRole,
    pub selectable: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SelectInfo {
    pub exists: u32,
    pub uidvalidity: Option<u32>,
    pub uidnext: Option<u32>,
    pub highest_modseq: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct FetchedMessage {
    pub uid: u32,
    pub flags: Flags,
    pub labels: Vec<String>,
    pub size: u32,
    pub internal_date: Option<i64>,
    pub modseq: Option<u64>,
    pub header: Option<Vec<u8>>,
    pub body: Option<Vec<u8>>,
}

fn convert_flags<'a>(flags: impl Iterator<Item = Flag<'a>>) -> Flags {
    let mut f = Flags::default();
    for flag in flags {
        match flag {
            Flag::Seen => f.seen = true,
            Flag::Flagged => f.flagged = true,
            Flag::Answered => f.answered = true,
            Flag::Draft => f.draft = true,
            Flag::Custom(c) if c.eq_ignore_ascii_case("$Forwarded") => f.forwarded = true,
            _ => {}
        }
    }
    f
}

fn convert_fetch(f: &async_imap::types::Fetch) -> Option<FetchedMessage> {
    Some(FetchedMessage {
        uid: f.uid?,
        flags: convert_flags(f.flags()),
        labels: f.gmail_labels().map(|l| l.iter().map(|s| s.to_string()).collect()).unwrap_or_default(),
        size: f.size.unwrap_or(0),
        internal_date: f.internal_date().map(|d| d.timestamp()),
        modseq: f.modseq,
        header: f.header().map(|h| h.to_vec()),
        body: f.body().map(|b| b.to_vec()),
    })
}

/// Compresses UIDs into an IMAP sequence set: `1:5,7,9:12`.
pub fn uid_set(uids: &[u32]) -> String {
    let mut v: Vec<u32> = uids.to_vec();
    v.sort_unstable();
    v.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let start = v[i];
        let mut end = start;
        while i + 1 < v.len() && v[i + 1] == end + 1 {
            i += 1;
            end = v[i];
        }
        out.push(if start == end { start.to_string() } else { format!("{start}:{end}") });
        i += 1;
    }
    out.join(",")
}

pub fn flag_name(flag: &str) -> &str {
    match flag {
        "seen" => "\\Seen",
        "flagged" => "\\Flagged",
        "answered" => "\\Answered",
        "draft" => "\\Draft",
        "deleted" => "\\Deleted",
        "forwarded" => "$Forwarded",
        other => other,
    }
}

/// Detects a folder role from SPECIAL-USE attributes or well-known names (incl. Chinese ones).
pub fn detect_role(path: &str, decoded: &str, attrs: &[NameAttribute<'_>]) -> FolderRole {
    if path.eq_ignore_ascii_case("INBOX") {
        return FolderRole::Inbox;
    }
    for a in attrs {
        let role = match a {
            NameAttribute::All => FolderRole::All,
            NameAttribute::Archive => FolderRole::Archive,
            NameAttribute::Drafts => FolderRole::Drafts,
            NameAttribute::Flagged => FolderRole::Flagged,
            NameAttribute::Junk => FolderRole::Junk,
            NameAttribute::Sent => FolderRole::Sent,
            NameAttribute::Trash => FolderRole::Trash,
            NameAttribute::Extension(s) => match s.to_ascii_lowercase().as_str() {
                "\\important" => FolderRole::Important,
                "\\spam" => FolderRole::Junk,
                "\\starred" => FolderRole::Flagged,
                "\\allmail" => FolderRole::All,
                "\\inbox" => FolderRole::Inbox,
                _ => continue,
            },
            _ => continue,
        };
        return role;
    }
    role_from_name(decoded)
}

pub fn role_from_name(decoded: &str) -> FolderRole {
    let leaf = decoded.rsplit(['/', '.']).next().unwrap_or(decoded).trim().to_lowercase();
    match leaf.as_str() {
        "sent" | "sent items" | "sent messages" | "sent mail" | "已发送" | "已发送邮件" | "已发邮件" | "发件箱" => FolderRole::Sent,
        "drafts" | "draft" | "草稿箱" | "草稿" | "草稿夹" => FolderRole::Drafts,
        "trash" | "deleted" | "deleted items" | "deleted messages" | "bin" | "已删除" | "已删除邮件" | "废件箱" | "回收站" => {
            FolderRole::Trash
        }
        "junk" | "spam" | "junk e-mail" | "junk email" | "bulk mail" | "垃圾邮件" | "垃圾箱" => FolderRole::Junk,
        "archive" | "archives" | "归档" | "存档" | "已归档" => FolderRole::Archive,
        "all mail" | "所有邮件" => FolderRole::All,
        "starred" | "已加星标" => FolderRole::Flagged,
        "important" | "重要" => FolderRole::Important,
        _ => FolderRole::Custom,
    }
}

impl ImapConn {
    pub async fn connect(server: &ServerConfig, user: &str, auth: &ImapAuth, send_id: bool) -> Result<ImapConn> {
        let stream = net::connect(server).await?;
        let mut client = Client::new(stream);
        let greeting = tokio::time::timeout(net::CONNECT_TIMEOUT, client.read_response())
            .await
            .map_err(|_| Error::Net("等待 IMAP 欢迎信息超时".into()))??;
        if greeting.is_none() {
            return Err(Error::Net("服务器关闭了连接".into()));
        }
        if server.security == Security::StartTls {
            timed(client.run_command_and_check_ok("STARTTLS", None)).await?;
            let tcp = client.into_inner().into_plain()?;
            let tls = net::tls_wrap(tcp, &server.host, server.accept_invalid_certs).await?;
            client = Client::new(MailStream::Tls(Box::new(tls)));
        }
        let login = async {
            match auth {
                ImapAuth::Password(p) => client.login(user, p).await.map_err(|(e, _)| auth_error(e)),
                ImapAuth::OAuth2(token) => client
                    .authenticate("XOAUTH2", XOAuth2 { payload: xoauth2_payload(user, token), sent: false })
                    .await
                    .map_err(|(e, _)| auth_error(e)),
            }
        };
        let mut session = tokio::time::timeout(CMD_TIMEOUT, login)
            .await
            .map_err(|_| Error::Net("IMAP 登录超时".into()))??;
        let caps_raw = timed(session.capabilities()).await?;
        let caps = Caps {
            idle: caps_raw.has_str("IDLE"),
            condstore: caps_raw.has_str("CONDSTORE") || caps_raw.has_str("QRESYNC"),
            move_: caps_raw.has_str("MOVE"),
            uidplus: caps_raw.has_str("UIDPLUS"),
            gmail: caps_raw.has_str("X-GM-EXT-1"),
            id: caps_raw.has_str("ID"),
            special_use: caps_raw.has_str("SPECIAL-USE"),
        };
        // NetEase (163/126/yeah) rejects SELECT with "Unsafe Login" unless the client identifies itself.
        if send_id {
            let ident = [
                ("name", Some("Mailbox")),
                ("version", Some(env!("CARGO_PKG_VERSION"))),
                ("vendor", Some("ComeHereToSee")),
                ("os", Some("macOS")),
                ("support-email", Some("mailbox@comeheretosee.local")),
            ];
            let _ = timed(session.id(ident)).await;
        }
        Ok(ImapConn { session, caps, selected: None })
    }

    pub async fn logout(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.session.logout()).await;
    }

    pub async fn noop(&mut self) -> Result<()> {
        timed(self.session.noop()).await
    }

    pub async fn list_folders(&mut self) -> Result<Vec<RemoteFolder>> {
        let names: Vec<async_imap::types::Name> = timed(async {
            let stream = self.session.list(Some(""), Some("*")).await?;
            stream.try_collect().await
        })
        .await?;
        let mut out = Vec::new();
        for n in &names {
            let path = n.name().to_string();
            let decoded = utf7::decode(&path);
            let delimiter = n.delimiter().map(String::from);
            let leaf = match &delimiter {
                Some(d) if !d.is_empty() => decoded.rsplit(d.as_str()).next().unwrap_or(&decoded).to_string(),
                _ => decoded.clone(),
            };
            let attrs = n.attributes();
            let selectable = !attrs.iter().any(|a| matches!(a, NameAttribute::NoSelect))
                && !attrs.iter().any(|a| matches!(a, NameAttribute::Extension(s) if s.eq_ignore_ascii_case("\\NonExistent")));
            let role = detect_role(&path, &decoded, attrs);
            let name = if role == FolderRole::Inbox { "INBOX".to_string() } else { leaf };
            out.push(RemoteFolder { path, name, delimiter, role, selectable });
        }
        // Only one folder per special role; the first one (server order) wins.
        let mut seen = HashSet::new();
        for f in out.iter_mut() {
            if f.role != FolderRole::Custom && !seen.insert(f.role) {
                f.role = FolderRole::Custom;
            }
        }
        Ok(out)
    }

    pub async fn select(&mut self, path: &str) -> Result<SelectInfo> {
        let mbox = if self.caps.condstore {
            timed(self.session.select_condstore(path)).await?
        } else {
            timed(self.session.select(path)).await?
        };
        self.selected = Some(path.to_string());
        Ok(SelectInfo {
            exists: mbox.exists,
            uidvalidity: mbox.uid_validity,
            uidnext: mbox.uid_next,
            highest_modseq: mbox.highest_modseq,
        })
    }

    async fn ensure_selected(&mut self, path: &str) -> Result<()> {
        if self.selected.as_deref() != Some(path) {
            self.select(path).await?;
        }
        Ok(())
    }

    pub async fn uid_search(&mut self, path: &str, query: &str) -> Result<Vec<u32>> {
        self.ensure_selected(path).await?;
        let set = timed(self.session.uid_search(query)).await?;
        let mut v: Vec<u32> = set.into_iter().collect();
        v.sort_unstable();
        Ok(v)
    }

    async fn uid_fetch(&mut self, path: &str, set: &str, query: &str) -> Result<Vec<FetchedMessage>> {
        self.ensure_selected(path).await?;
        let fetches: Vec<async_imap::types::Fetch> = timed(async {
            let stream = self.session.uid_fetch(set, query).await?;
            stream.try_collect().await
        })
        .await?;
        Ok(fetches.iter().filter_map(convert_fetch).collect())
    }

    /// Headers + flags of the given UIDs (or a range like `100:*`).
    pub async fn fetch_headers(&mut self, path: &str, set: &str) -> Result<Vec<FetchedMessage>> {
        let gm = if self.caps.gmail { " X-GM-LABELS" } else { "" };
        let ms = if self.caps.condstore { " MODSEQ" } else { "" };
        let query = format!("(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER]{gm}{ms})");
        self.uid_fetch(path, set, &query).await
    }

    pub async fn fetch_flags(&mut self, path: &str, set: &str, changed_since: Option<u64>) -> Result<Vec<FetchedMessage>> {
        let gm = if self.caps.gmail { " X-GM-LABELS" } else { "" };
        let query = match (changed_since, self.caps.condstore) {
            (Some(ms), true) => format!("(UID FLAGS{gm} MODSEQ) (CHANGEDSINCE {ms})"),
            _ => format!("(UID FLAGS{gm})"),
        };
        self.uid_fetch(path, set, &query).await
    }

    pub async fn fetch_bodies(&mut self, path: &str, uids: &[u32]) -> Result<Vec<FetchedMessage>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        self.uid_fetch(path, &uid_set(uids), "(UID FLAGS BODY.PEEK[])").await
    }

    pub async fn store_flag(&mut self, path: &str, uids: &[u32], flag: &str, add: bool) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        self.ensure_selected(path).await?;
        let op = if add { "+FLAGS.SILENT" } else { "-FLAGS.SILENT" };
        let query = format!("{op} ({})", flag_name(flag));
        for chunk in uids.chunks(500) {
            let set = uid_set(chunk);
            timed(async {
                let stream = self.session.uid_store(&set, &query).await?;
                let _: Vec<_> = stream.try_collect().await?;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    pub async fn store_labels(&mut self, path: &str, uids: &[u32], labels: &[String], add: bool) -> Result<()> {
        if uids.is_empty() || labels.is_empty() {
            return Ok(());
        }
        self.ensure_selected(path).await?;
        let quoted: Vec<String> = labels.iter().map(|l| format!("\"{}\"", utf7::encode(l).replace('"', "\\\""))).collect();
        let op = if add { "+X-GM-LABELS.SILENT" } else { "-X-GM-LABELS.SILENT" };
        let query = format!("{op} ({})", quoted.join(" "));
        let set = uid_set(uids);
        timed(async {
            let stream = self.session.uid_store(&set, &query).await?;
            let _: Vec<_> = stream.try_collect().await?;
            Ok(())
        })
        .await
    }

    pub async fn move_uids(&mut self, from: &str, uids: &[u32], to: &str) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        self.ensure_selected(from).await?;
        for chunk in uids.chunks(500) {
            let set = uid_set(chunk);
            if self.caps.move_ {
                timed(self.session.uid_mv(&set, to)).await?;
            } else {
                timed(self.session.uid_copy(&set, to)).await?;
                self.store_flag(from, chunk, "deleted", true).await?;
                self.expunge_set(&set).await?;
            }
        }
        Ok(())
    }

    async fn expunge_set(&mut self, set: &str) -> Result<()> {
        if self.caps.uidplus {
            timed(async {
                let stream = self.session.uid_expunge(set).await?;
                let _: Vec<_> = stream.try_collect().await?;
                Ok(())
            })
            .await
        } else {
            timed(async {
                let stream = self.session.expunge().await?;
                let _: Vec<_> = stream.try_collect().await?;
                Ok(())
            })
            .await
        }
    }

    pub async fn expunge_uids(&mut self, path: &str, uids: &[u32]) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        self.store_flag(path, uids, "deleted", true).await?;
        for chunk in uids.chunks(500) {
            self.expunge_set(&uid_set(chunk)).await?;
        }
        Ok(())
    }

    pub async fn append(&mut self, path: &str, flags: &[String], raw: &[u8]) -> Result<()> {
        let flag_str = if flags.is_empty() {
            None
        } else {
            Some(format!("({})", flags.iter().map(|f| flag_name(f).to_string()).collect::<Vec<_>>().join(" ")))
        };
        timed(self.session.append(path, flag_str.as_deref(), None, raw)).await?;
        if self.selected.as_deref() == Some(path) {
            self.selected = None;
        }
        Ok(())
    }

    pub async fn create_folder(&mut self, path: &str) -> Result<()> {
        timed(self.session.create(path)).await?;
        let _ = timed(self.session.subscribe(path)).await;
        Ok(())
    }

    pub async fn rename_folder(&mut self, from: &str, to: &str) -> Result<()> {
        if self.selected.as_deref() == Some(from) {
            let _ = timed(self.session.close()).await;
            self.selected = None;
        }
        timed(self.session.rename(from, to)).await
    }

    pub async fn delete_folder(&mut self, path: &str) -> Result<()> {
        if self.selected.as_deref() == Some(path) {
            let _ = timed(self.session.close()).await;
            self.selected = None;
        }
        timed(self.session.delete(path)).await
    }

    /// Runs a server-side search (`TEXT "..."` / Gmail `X-GM-RAW`).
    pub async fn server_search(&mut self, path: &str, text: &str) -> Result<Vec<u32>> {
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        let query = if self.caps.gmail {
            format!("X-GM-RAW \"{escaped}\"")
        } else if text.is_ascii() {
            format!("TEXT \"{escaped}\"")
        } else {
            format!("CHARSET UTF-8 TEXT \"{escaped}\"")
        };
        self.uid_search(path, &query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_sets() {
        assert_eq!(uid_set(&[1, 2, 3, 5, 7, 8, 9, 20]), "1:3,5,7:9,20");
        assert_eq!(uid_set(&[4]), "4");
        assert_eq!(uid_set(&[3, 1, 2, 2]), "1:3");
    }

    #[test]
    fn roles_from_names() {
        assert_eq!(role_from_name("已发送"), FolderRole::Sent);
        assert_eq!(role_from_name("Sent Messages"), FolderRole::Sent);
        assert_eq!(role_from_name("[Gmail]/Sent Mail"), FolderRole::Sent);
        assert_eq!(role_from_name("Deleted Messages"), FolderRole::Trash);
        assert_eq!(role_from_name("垃圾邮件"), FolderRole::Junk);
        assert_eq!(role_from_name("Projects"), FolderRole::Custom);
    }
}

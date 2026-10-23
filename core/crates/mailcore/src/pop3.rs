//! POP3 client: RFC 1939 commands, RFC 2449 CAPA / response codes, RFC 2595 STLS and
//! SASL login (AUTH PLAIN / XOAUTH2, RFC 5034).
//!
//! Everything is byte oriented: message data is returned exactly as the server sent it
//! (CRLF line endings preserved) apart from removing the byte-stuffing of lines that start
//! with `.`, so messages in any charset (GBK, Big5, ...) survive untouched.
//!
//! Each network read and write has its own inactivity timeout, so a large `RETR` keeps
//! going as long as data keeps arriving, while a stalled server fails within a minute.

use crate::error::{Error, Result};
use crate::model::{Security, ServerConfig};
use crate::net::{self, MailStream};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum time to wait for any single read or write to make progress.
pub const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// Status lines are short (RFC 2449 says 512 octets); anything far longer is a broken server.
const MAX_STATUS_LINE: usize = 64 * 1024;

#[derive(Clone)]
pub enum Pop3Auth {
    Password(String),
    /// OAuth2 access token, sent with `AUTH XOAUTH2`.
    OAuth2(String),
}

impl std::fmt::Debug for Pop3Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pop3Auth::Password(_) => f.write_str("Password(***)"),
            Pop3Auth::OAuth2(_) => f.write_str("OAuth2(***)"),
        }
    }
}

/// A server reply line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reply {
    Ok(String),
    Err(String),
    /// SASL continuation (`+ <base64>`).
    Cont(String),
}

/// Decodes server text: UTF-8 if valid, otherwise GB18030 (Chinese servers often reply in GBK).
fn decode_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => encoding_rs::GB18030.decode_without_bom_handling(bytes).0.into_owned(),
    }
}

fn trim_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn parse_reply(line: &[u8]) -> Result<Reply> {
    let line = trim_eol(line);
    let rest_text = |n: usize| decode_text(&line[n..]).trim().to_string();
    if line.len() >= 3 && line[..3].eq_ignore_ascii_case(b"+OK") {
        Ok(Reply::Ok(rest_text(3)))
    } else if line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"-ERR") {
        Ok(Reply::Err(rest_text(4)))
    } else if line.first() == Some(&b'+') {
        Ok(Reply::Cont(rest_text(1)))
    } else {
        Err(Error::Pop3(format!("无法识别的服务器响应: {}", decode_text(line).trim())))
    }
}

/// Extracts an RFC 2449 response code: `[IN-USE] mailbox locked` -> `IN-USE`.
fn response_code(msg: &str) -> Option<&str> {
    let rest = msg.strip_prefix('[')?;
    let end = rest.find(']')?;
    Some(&rest[..end])
}

/// Maps a `-ERR` received while logging in. Temporary conditions (mailbox locked, login
/// throttled, server busy) are not credential problems, so they are not reported as `Auth`
/// (which would stop automatic retries).
fn login_error(msg: &str) -> Error {
    let code = response_code(msg).unwrap_or("").to_ascii_uppercase();
    if code == "IN-USE" {
        Error::Pop3(format!("邮箱正被其他客户端占用，请稍后再试: {msg}"))
    } else if code == "LOGIN-DELAY" {
        Error::Pop3(format!("登录过于频繁，请稍后再试: {msg}"))
    } else if code.starts_with("SYS/TEMP") {
        Error::Pop3(format!("服务器暂时不可用: {msg}"))
    } else {
        Error::Auth(format!("POP3 登录失败: {msg}"))
    }
}

fn unexpected(what: &str, reply: &Reply) -> Error {
    Error::Pop3(format!("{what} 收到意外响应: {reply:?}"))
}

/// Rejects strings that would break the line-based protocol (command injection).
fn check_arg(value: &str, what: &str) -> Result<()> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(Error::Invalid(format!("{what}包含非法字符")));
    }
    Ok(())
}

fn parse_num<T: std::str::FromStr>(tok: Option<&str>, line: &str, what: &str) -> Result<T> {
    tok.and_then(|t| t.parse().ok()).ok_or_else(|| Error::Pop3(format!("无法解析 {what} 响应: {line}")))
}

/// Parses `+OK <count> <octets>` (STAT) or `<msg> <octets>` (LIST) style pairs.
fn parse_pair(line: &str, what: &str) -> Result<(u32, u64)> {
    let mut it = line.split_ascii_whitespace();
    let a = parse_num(it.next(), line, what)?;
    let b = parse_num(it.next(), line, what)?;
    Ok((a, b))
}

fn parse_uidl_line(line: &str) -> Result<(u32, String)> {
    let mut it = line.split_ascii_whitespace();
    let n = parse_num(it.next(), line, "UIDL")?;
    let uid = it.next().ok_or_else(|| Error::Pop3(format!("无法解析 UIDL 响应: {line}")))?;
    Ok((n, uid.to_string()))
}

/// Splits a multi-line text response into non-empty lines.
fn text_lines(data: &[u8]) -> Vec<String> {
    data.split(|&b| b == b'\n').map(|l| decode_text(trim_eol(l)).trim().to_string()).filter(|l| !l.is_empty()).collect()
}

fn verb(cmd: &str) -> &str {
    cmd.split(' ').next().unwrap_or(cmd)
}

pub struct Pop3Conn {
    stream: BufReader<MailStream>,
    greeting: String,
    caps: Vec<String>,
}

impl Pop3Conn {
    /// Connects (TLS / STLS / plain per `server.security`), reads the greeting and logs in.
    ///
    /// The login name is `server.username` when set, otherwise `user`.
    /// Password auth uses USER/PASS and falls back to `AUTH PLAIN` when the server rejects
    /// USER (or does not advertise it but offers SASL PLAIN). OAuth2 uses `AUTH XOAUTH2`.
    pub async fn connect(server: &ServerConfig, user: &str, auth: &Pop3Auth) -> Result<Pop3Conn> {
        let login = server.username.as_deref().map(str::trim).filter(|u| !u.is_empty()).unwrap_or(user);
        check_arg(login, "用户名")?;
        if let Pop3Auth::Password(password) = auth {
            check_arg(password, "密码")?;
        }
        let stream = net::connect(server).await?;
        let mut conn = Pop3Conn { stream: BufReader::new(stream), greeting: String::new(), caps: Vec::new() };
        conn.greeting = match tokio::time::timeout(net::CONNECT_TIMEOUT, conn.read_reply()).await {
            Err(_) => return Err(Error::Net(format!("等待 POP3 欢迎信息超时 ({}:{})", server.host, server.port))),
            Ok(Err(e)) => return Err(e),
            Ok(Ok(Reply::Ok(text))) => text,
            Ok(Ok(Reply::Err(msg))) => return Err(Error::Pop3(format!("服务器拒绝连接: {msg}"))),
            Ok(Ok(other)) => return Err(unexpected("欢迎信息", &other)),
        };
        if server.security == Security::StartTls {
            conn = conn.starttls(&server.host, server.accept_invalid_certs).await?;
        }
        // Capabilities from before STLS must not be trusted (RFC 2595), so fetch them here.
        conn.capa().await?;
        conn.login(login, auth).await?;
        Ok(conn)
    }

    /// The text after `+OK` in the server greeting.
    pub fn greeting(&self) -> &str {
        &self.greeting
    }

    /// Capabilities from the last [`capa`](Self::capa) call (made automatically before login).
    pub fn cached_caps(&self) -> &[String] {
        &self.caps
    }

    /// Whether the last CAPA listed `name` (case-insensitive, first token, e.g. `UIDL`, `TOP`).
    pub fn has_cap(&self, name: &str) -> bool {
        self.caps.iter().any(|c| c.split_ascii_whitespace().next().is_some_and(|t| t.eq_ignore_ascii_case(name)))
    }

    /// SASL mechanisms advertised in the `SASL` capability.
    pub fn sasl_mechanisms(&self) -> Vec<String> {
        self.caps
            .iter()
            .find_map(|c| {
                let mut it = c.split_ascii_whitespace();
                it.next().filter(|t| t.eq_ignore_ascii_case("SASL")).map(|_| it.map(str::to_ascii_uppercase).collect())
            })
            .unwrap_or_default()
    }

    pub fn is_tls(&self) -> bool {
        matches!(self.stream.get_ref(), MailStream::Tls(_))
    }

    // ---- low level I/O -------------------------------------------------------------

    async fn send(&mut self, line: &str) -> Result<()> {
        let mut data = Vec::with_capacity(line.len() + 2);
        data.extend_from_slice(line.as_bytes());
        data.extend_from_slice(b"\r\n");
        let stream = self.stream.get_mut();
        let write = async {
            stream.write_all(&data).await?;
            stream.flush().await
        };
        tokio::time::timeout(IO_TIMEOUT, write)
            .await
            .map_err(|_| Error::Net("POP3 发送命令超时".into()))?
            .map_err(|e| Error::Net(format!("POP3 发送命令失败: {e}")))
    }

    /// Appends one line (including its line ending) to `out`. Each network read has its own
    /// timeout, so long lines / slow transfers only fail when the server stops sending.
    async fn read_line_into(&mut self, out: &mut Vec<u8>, max: usize) -> Result<()> {
        let start = out.len();
        loop {
            let buf = tokio::time::timeout(IO_TIMEOUT, self.stream.fill_buf())
                .await
                .map_err(|_| Error::Net("POP3 服务器响应超时".into()))?
                .map_err(|e| Error::Net(format!("POP3 读取失败: {e}")))?;
            if buf.is_empty() {
                return Err(Error::Net("POP3 服务器关闭了连接".into()));
            }
            let (used, done) = match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (i + 1, true),
                None => (buf.len(), false),
            };
            out.extend_from_slice(&buf[..used]);
            self.stream.consume(used);
            if done {
                return Ok(());
            }
            if out.len() - start > max {
                return Err(Error::Pop3("服务器响应行过长".into()));
            }
        }
    }

    async fn read_reply(&mut self) -> Result<Reply> {
        let mut line = Vec::new();
        self.read_line_into(&mut line, MAX_STATUS_LINE).await?;
        parse_reply(&line)
    }

    /// Reads the body of a multi-line response up to the `.` terminator, removing byte
    /// stuffing. Line endings are kept exactly as received.
    async fn read_multiline(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let start = out.len();
            self.read_line_into(&mut out, usize::MAX).await?;
            let line = &out[start..];
            if line == b".\r\n" || line == b".\n" {
                out.truncate(start);
                return Ok(out);
            }
            if line.first() == Some(&b'.') {
                out.remove(start);
            }
        }
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply> {
        self.send(cmd).await?;
        self.read_reply().await
    }

    /// Sends a command that must answer `+OK`; returns the text after it.
    async fn simple(&mut self, cmd: &str) -> Result<String> {
        match self.command(cmd).await? {
            Reply::Ok(text) => Ok(text),
            Reply::Err(msg) => Err(Error::Pop3(format!("{} 命令失败: {msg}", verb(cmd)))),
            other => Err(unexpected(verb(cmd), &other)),
        }
    }

    /// Sends a command with a multi-line answer and returns the (unstuffed) data.
    async fn multi(&mut self, cmd: &str) -> Result<Vec<u8>> {
        self.simple(cmd).await?;
        self.read_multiline().await
    }

    // ---- session setup -------------------------------------------------------------

    async fn starttls(mut self, host: &str, accept_invalid: bool) -> Result<Pop3Conn> {
        match self.command("STLS").await? {
            Reply::Ok(_) => {}
            Reply::Err(msg) => return Err(Error::Pop3(format!("服务器不支持 STLS 加密: {msg}"))),
            other => return Err(unexpected("STLS", &other)),
        }
        // Anything the server sent after its +OK would be injected into the TLS session.
        if !self.stream.buffer().is_empty() {
            return Err(Error::Net("STLS 响应后收到意外数据，已中止连接".into()));
        }
        let tcp = self.stream.into_inner().into_plain()?;
        let tls = net::tls_wrap(tcp, host, accept_invalid).await?;
        Ok(Pop3Conn {
            stream: BufReader::new(MailStream::Tls(Box::new(tls))),
            greeting: self.greeting,
            caps: Vec::new(),
        })
    }

    /// Logs in; `login` and the password were checked by [`check_arg`] in `connect`.
    async fn login(&mut self, login: &str, auth: &Pop3Auth) -> Result<()> {
        match auth {
            Pop3Auth::Password(password) => {
                let sasl_plain = self.sasl_mechanisms().iter().any(|m| m == "PLAIN");
                let skip_user = !self.caps.is_empty() && !self.has_cap("USER") && sasl_plain;
                let mut user_err = None;
                if !skip_user {
                    match self.command(&format!("USER {login}")).await? {
                        Reply::Ok(_) => {
                            return match self.command(&format!("PASS {password}")).await? {
                                Reply::Ok(_) => Ok(()),
                                Reply::Err(msg) => Err(login_error(&msg)),
                                other => Err(unexpected("PASS", &other)),
                            };
                        }
                        Reply::Err(msg) => user_err = Some(msg),
                        other => return Err(unexpected("USER", &other)),
                    }
                }
                let payload = B64.encode(format!("\0{login}\0{password}"));
                match (self.sasl("PLAIN", &payload).await, user_err) {
                    (Err(Error::Auth(msg)), Some(user_msg)) => {
                        Err(Error::Auth(format!("{msg}（USER 命令被拒绝: {user_msg}）")))
                    }
                    (r, _) => r,
                }
            }
            Pop3Auth::OAuth2(token) => {
                let payload = B64.encode(crate::imap::xoauth2_payload(login, token));
                self.sasl("XOAUTH2", &payload).await
            }
        }
    }

    /// RFC 5034 exchange: `AUTH <mech>`, wait for `+`, send the base64 response.
    async fn sasl(&mut self, mech: &str, payload: &str) -> Result<()> {
        match self.command(&format!("AUTH {mech}")).await? {
            Reply::Cont(_) => {}
            Reply::Ok(_) => return Ok(()),
            Reply::Err(msg) => return Err(login_error(&msg)),
        }
        self.send(payload).await?;
        match self.read_reply().await? {
            Reply::Ok(_) => Ok(()),
            Reply::Err(msg) => Err(login_error(&msg)),
            Reply::Cont(challenge) => {
                // XOAUTH2 failure: `+ <base64 JSON error>`; an empty response makes the server
                // finish with -ERR. For other mechanisms `*` cancels the exchange.
                let detail = B64
                    .decode(challenge.trim())
                    .ok()
                    .map(|b| decode_text(&b))
                    .filter(|s| !s.is_empty())
                    .unwrap_or(challenge);
                self.send(if mech == "XOAUTH2" { "" } else { "*" }).await?;
                let final_msg = match self.read_reply().await {
                    Ok(Reply::Err(m)) if !m.is_empty() => m,
                    _ => "认证被拒绝".to_string(),
                };
                Err(Error::Auth(format!("POP3 登录失败: {final_msg} ({detail})")))
            }
        }
    }

    // ---- commands ------------------------------------------------------------------

    /// `CAPA` (RFC 2449). A server without CAPA support yields an empty list.
    pub async fn capa(&mut self) -> Result<Vec<String>> {
        let caps = match self.command("CAPA").await? {
            Reply::Ok(_) => text_lines(&self.read_multiline().await?),
            Reply::Err(_) => Vec::new(),
            other => return Err(unexpected("CAPA", &other)),
        };
        self.caps = caps.clone();
        Ok(caps)
    }

    /// `STAT`: (message count, total octets).
    pub async fn stat(&mut self) -> Result<(u32, u64)> {
        let text = self.simple("STAT").await?;
        parse_pair(&text, "STAT")
    }

    /// `LIST`: (message number, octets) for every message.
    pub async fn list(&mut self) -> Result<Vec<(u32, u64)>> {
        let data = self.multi("LIST").await?;
        text_lines(&data).iter().map(|l| parse_pair(l, "LIST")).collect()
    }

    /// `LIST <msg>`: size of one message.
    pub async fn list_one(&mut self, msg: u32) -> Result<u64> {
        let text = self.simple(&format!("LIST {msg}")).await?;
        Ok(parse_pair(&text, "LIST")?.1)
    }

    /// `UIDL`: (message number, unique id) for every message.
    pub async fn uidl(&mut self) -> Result<Vec<(u32, String)>> {
        let data = self.multi("UIDL").await?;
        text_lines(&data).iter().map(|l| parse_uidl_line(l)).collect()
    }

    /// `UIDL <msg>`: unique id of one message.
    pub async fn uidl_one(&mut self, msg: u32) -> Result<String> {
        let text = self.simple(&format!("UIDL {msg}")).await?;
        Ok(parse_uidl_line(&text)?.1)
    }

    /// `RETR`: the full raw message (dot-unstuffed, line endings as sent by the server).
    pub async fn retr(&mut self, msg: u32) -> Result<Vec<u8>> {
        self.multi(&format!("RETR {msg}")).await
    }

    /// `TOP`: the header plus the first `lines` body lines.
    pub async fn top(&mut self, msg: u32, lines: u32) -> Result<Vec<u8>> {
        self.multi(&format!("TOP {msg} {lines}")).await
    }

    /// `DELE`: marks a message deleted; it is removed when [`quit`](Self::quit) succeeds.
    pub async fn dele(&mut self, msg: u32) -> Result<()> {
        self.simple(&format!("DELE {msg}")).await.map(|_| ())
    }

    /// `RSET`: unmarks all messages marked deleted in this session.
    pub async fn rset(&mut self) -> Result<()> {
        self.simple("RSET").await.map(|_| ())
    }

    pub async fn noop(&mut self) -> Result<()> {
        self.simple("NOOP").await.map(|_| ())
    }

    /// `QUIT`: ends the session and commits deletions. Dropping the connection without
    /// calling this leaves every message on the server.
    pub async fn quit(mut self) -> Result<()> {
        let reply = self.command("QUIT").await;
        let _ = tokio::time::timeout(Duration::from_secs(5), self.stream.get_mut().shutdown()).await;
        match reply? {
            Reply::Ok(_) => Ok(()),
            Reply::Err(msg) => Err(Error::Pop3(format!("QUIT 失败，删除可能未生效: {msg}"))),
            other => Err(unexpected("QUIT", &other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// One scripted exchange: the line the client must send and the canned response.
    type Step = (String, Vec<u8>);

    fn step(cmd: impl Into<String>, response: impl AsRef<[u8]>) -> Step {
        (cmd.into(), response.as_ref().to_vec())
    }

    /// Starts a fake POP3 server that sends `greeting`, then for each step reads one command
    /// line and writes the canned response. Returns the commands it received.
    async fn fake_server(greeting: &'static str, script: Vec<Step>) -> (ServerConfig, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = BufReader::new(sock);
            sock.get_mut().write_all(greeting.as_bytes()).await.unwrap();
            let mut received = Vec::new();
            for (_, response) in script {
                let mut line = Vec::new();
                if sock.read_until(b'\n', &mut line).await.unwrap() == 0 {
                    break;
                }
                received.push(String::from_utf8(trim_eol(&line).to_vec()).unwrap());
                sock.get_mut().write_all(&response).await.unwrap();
            }
            // Keep the socket open until the client hangs up.
            let mut rest = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), sock.read_to_end(&mut rest)).await;
            received
        });
        let server = ServerConfig {
            host: "127.0.0.1".into(),
            port,
            security: Security::None,
            username: None,
            accept_invalid_certs: false,
        };
        (server, handle)
    }

    fn expected(script: &[Step]) -> Vec<String> {
        script.iter().map(|(cmd, _)| cmd.clone()).collect()
    }

    const GREETING: &str = "+OK POP3 ready <1896.697170952@test>\r\n";

    fn capa(lines: &str) -> Step {
        step("CAPA", format!("+OK Capability list follows\r\n{lines}.\r\n"))
    }

    fn login_steps() -> Vec<Step> {
        vec![
            capa("TOP\r\nUSER\r\nUIDL\r\nSASL PLAIN\r\n"),
            step("USER alice", "+OK\r\n"),
            step("PASS secret", "+OK Logged in.\r\n"),
        ]
    }

    fn pw() -> Pop3Auth {
        Pop3Auth::Password("secret".into())
    }

    #[test]
    fn reply_parsing() {
        assert_eq!(parse_reply(b"+OK 2 320\r\n").unwrap(), Reply::Ok("2 320".into()));
        assert_eq!(parse_reply(b"+OK\r\n").unwrap(), Reply::Ok(String::new()));
        assert_eq!(parse_reply(b"-ERR [AUTH] bad\r\n").unwrap(), Reply::Err("[AUTH] bad".into()));
        assert_eq!(parse_reply(b"+ \r\n").unwrap(), Reply::Cont(String::new()));
        assert_eq!(parse_reply(b"+ eyJ9\n").unwrap(), Reply::Cont("eyJ9".into()));
        assert!(parse_reply(b"* OK imap?\r\n").is_err());
        // GBK error text from Chinese servers.
        let mut gbk = b"-ERR ".to_vec();
        gbk.extend_from_slice(&[0xC3, 0xDC, 0xC2, 0xEB, 0xB4, 0xED, 0xCE, 0xF3]); // 密码错误
        assert_eq!(parse_reply(&gbk).unwrap(), Reply::Err("密码错误".into()));
        assert_eq!(response_code("[IN-USE] locked"), Some("IN-USE"));
        assert_eq!(response_code("no code"), None);
        assert!(login_error("[AUTH] Authentication failed.").is_auth());
        assert!(login_error("Invalid password").is_auth());
        assert!(!login_error("[IN-USE] Mailbox locked").is_auth());
        assert!(!login_error("[SYS/TEMP] try later").is_auth());
        assert!(parse_pair("1 abc", "LIST").is_err());
        assert_eq!(parse_uidl_line("3 a-b:c").unwrap(), (3, "a-b:c".to_string()));
    }

    #[tokio::test]
    async fn retr_unstuffs_dots_and_is_binary_safe() {
        let mut body = b"+OK 120 octets\r\nSubject: =?GBK?B?suLK1A==?=\r\n\r\n".to_vec();
        body.extend_from_slice(b"..leading dot\r\n");
        body.extend_from_slice(b"..\r\n"); // a lone "." line inside the message
        body.extend_from_slice(b"...\r\n");
        body.extend_from_slice(&[0xC4, 0xE3, 0xBA, 0xC3, b'\r', b'\n']); // 你好 in GBK
        body.extend_from_slice(b"middle . dot stays\r\n");
        body.extend_from_slice(b".\r\n");
        let mut script = login_steps();
        script.push(step("RETR 1", body));
        script.push(step("TOP 1 0", "+OK\r\nSubject: x\r\n\r\n.\r\n"));
        script.push(step("QUIT", "+OK Bye\r\n"));
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;

        let mut c = Pop3Conn::connect(&server, "alice", &pw()).await.unwrap();
        assert!(c.greeting().starts_with("POP3 ready"));
        assert!(c.has_cap("uidl") && c.has_cap("TOP") && !c.has_cap("STLS"));
        assert_eq!(c.sasl_mechanisms(), vec!["PLAIN".to_string()]);
        assert!(!c.is_tls());
        let msg = c.retr(1).await.unwrap();
        let mut expect = b"Subject: =?GBK?B?suLK1A==?=\r\n\r\n.leading dot\r\n.\r\n..\r\n".to_vec();
        expect.extend_from_slice(&[0xC4, 0xE3, 0xBA, 0xC3, b'\r', b'\n']);
        expect.extend_from_slice(b"middle . dot stays\r\n");
        assert_eq!(msg, expect);
        assert_eq!(c.top(1, 0).await.unwrap(), b"Subject: x\r\n\r\n");
        c.quit().await.unwrap();
        assert_eq!(handle.await.unwrap(), want);
    }

    #[tokio::test]
    async fn stat_list_uidl_dele() {
        let mut script = login_steps();
        script.extend([
            step("STAT", "+OK 2 320\r\n"),
            step("LIST", "+OK 2 messages (320 octets)\r\n1 120\r\n2 200\r\n.\r\n"),
            step("UIDL", "+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n.\r\n"),
            step("LIST 2", "+OK 2 200\r\n"),
            step("UIDL 1", "+OK 1 whqtswO00WBw418f9t5JxYwZ\r\n"),
            step("LIST", "+OK\r\n.\r\n"),
            step("RETR 9", "-ERR no such message\r\n"),
            step("DELE 1", "+OK message 1 deleted\r\n"),
            step("RSET", "+OK\r\n"),
            step("NOOP", "+OK\r\n"),
            step("QUIT", "+OK dewey POP3 server signing off (1 message left)\r\n"),
        ]);
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;

        let mut c = Pop3Conn::connect(&server, "alice", &pw()).await.unwrap();
        assert_eq!(c.stat().await.unwrap(), (2, 320));
        assert_eq!(c.list().await.unwrap(), vec![(1, 120), (2, 200)]);
        assert_eq!(
            c.uidl().await.unwrap(),
            vec![(1, "whqtswO00WBw418f9t5JxYwZ".to_string()), (2, "QhdPYR:00WBw1Ph7x7".to_string())]
        );
        assert_eq!(c.list_one(2).await.unwrap(), 200);
        assert_eq!(c.uidl_one(1).await.unwrap(), "whqtswO00WBw418f9t5JxYwZ");
        assert!(c.list().await.unwrap().is_empty());
        let err = c.retr(9).await.unwrap_err();
        assert!(matches!(&err, Error::Pop3(m) if m.contains("no such message")), "{err}");
        c.dele(1).await.unwrap();
        c.rset().await.unwrap();
        c.noop().await.unwrap();
        c.quit().await.unwrap();
        assert_eq!(handle.await.unwrap(), want);
    }

    #[tokio::test]
    async fn pass_rejected_is_auth_error() {
        let script = vec![
            capa("USER\r\n"),
            step("USER alice", "+OK\r\n"),
            step("PASS wrong", "-ERR [AUTH] Authentication failed.\r\n"),
        ];
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;
        let err = Pop3Conn::connect(&server, "alice", &Pop3Auth::Password("wrong".into())).await.err().unwrap();
        assert!(matches!(&err, Error::Auth(m) if m.contains("Authentication failed")), "{err}");
        assert!(err.is_auth());
        assert_eq!(handle.await.unwrap(), want);
    }

    #[tokio::test]
    async fn mailbox_in_use_is_not_auth_error() {
        let script = vec![
            capa("USER\r\nRESP-CODES\r\n"),
            step("USER alice", "+OK\r\n"),
            step("PASS secret", "-ERR [IN-USE] Mailbox is locked\r\n"),
        ];
        let (server, _handle) = fake_server(GREETING, script).await;
        let err = Pop3Conn::connect(&server, "alice", &pw()).await.err().unwrap();
        assert!(matches!(&err, Error::Pop3(m) if m.contains("Mailbox is locked")), "{err}");
    }

    #[tokio::test]
    async fn user_rejected_falls_back_to_auth_plain() {
        let script = vec![
            // A server without CAPA support.
            step("CAPA", "-ERR unknown command\r\n"),
            step("USER alice@corp.cn", "-ERR USER command disabled\r\n"),
            step("AUTH PLAIN", "+ \r\n"),
            step(B64.encode("\0alice@corp.cn\0secret"), "+OK Logged in\r\n"),
            step("STAT", "+OK 0 0\r\n"),
            step("QUIT", "+OK\r\n"),
        ];
        let want = expected(&script);
        let (mut server, handle) = fake_server(GREETING, script).await;
        // `server.username` wins over the account address.
        server.username = Some("alice@corp.cn".into());
        let mut c = Pop3Conn::connect(&server, "ignored@example.com", &pw()).await.unwrap();
        assert!(c.cached_caps().is_empty());
        assert_eq!(c.stat().await.unwrap(), (0, 0));
        c.quit().await.unwrap();
        assert_eq!(handle.await.unwrap(), want);
    }

    #[tokio::test]
    async fn auth_plain_failure_after_user_rejected_is_auth_error() {
        let script = vec![
            capa("USER\r\nSASL PLAIN\r\n"),
            step("USER alice", "-ERR [AUTH] Plaintext authentication disallowed\r\n"),
            step("AUTH PLAIN", "+\r\n"),
            step(B64.encode("\0alice\0secret"), "-ERR [AUTH] Authentication failed.\r\n"),
        ];
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;
        let err = Pop3Conn::connect(&server, "alice", &pw()).await.err().unwrap();
        assert!(
            matches!(&err, Error::Auth(m) if m.contains("Authentication failed") && m.contains("Plaintext authentication disallowed")),
            "{err}"
        );
        assert_eq!(handle.await.unwrap(), want);
    }

    #[tokio::test]
    async fn auth_plain_used_directly_when_user_not_advertised() {
        let script = vec![
            capa("SASL PLAIN XOAUTH2\r\nUIDL\r\n"),
            step("AUTH PLAIN", "+\r\n"),
            step(B64.encode("\0alice\0secret"), "+OK\r\n"),
            step("QUIT", "+OK\r\n"),
        ];
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;
        let c = Pop3Conn::connect(&server, "alice", &pw()).await.unwrap();
        assert_eq!(c.sasl_mechanisms(), vec!["PLAIN".to_string(), "XOAUTH2".to_string()]);
        c.quit().await.unwrap();
        assert_eq!(handle.await.unwrap(), want);
    }

    #[tokio::test]
    async fn xoauth2_success_and_error_challenge() {
        let payload = B64.encode("user=alice@gmail.com\x01auth=Bearer tok\x01\x01");
        let oauth = Pop3Auth::OAuth2("tok".into());
        let script = vec![
            capa("SASL XOAUTH2\r\nUSER\r\n"),
            step("AUTH XOAUTH2", "+\r\n"),
            step(payload.clone(), "+OK Welcome\r\n"),
            step("QUIT", "+OK\r\n"),
        ];
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;
        let c = Pop3Conn::connect(&server, "alice@gmail.com", &oauth).await.unwrap();
        c.quit().await.unwrap();
        assert_eq!(handle.await.unwrap(), want);

        let json = r#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#;
        let script = vec![
            capa("SASL XOAUTH2\r\nUSER\r\n"),
            step("AUTH XOAUTH2", "+ \r\n"),
            step(payload, format!("+ {}\r\n", B64.encode(json))),
            // The client answers the error challenge with an empty line.
            step("", "-ERR [AUTH] Invalid credentials\r\n"),
        ];
        let want = expected(&script);
        let (server, handle) = fake_server(GREETING, script).await;
        let err = Pop3Conn::connect(&server, "alice@gmail.com", &oauth).await.err().unwrap();
        assert!(matches!(&err, Error::Auth(m) if m.contains("Invalid credentials") && m.contains("401")), "{err}");
        assert_eq!(handle.await.unwrap(), want);

        // Mechanism not supported by the server.
        let script = vec![capa("USER\r\n"), step("AUTH XOAUTH2", "-ERR Unsupported authentication mechanism.\r\n")];
        let (server, _handle) = fake_server(GREETING, script).await;
        let err = Pop3Conn::connect(&server, "alice@gmail.com", &oauth).await.err().unwrap();
        assert!(matches!(&err, Error::Auth(m) if m.contains("Unsupported")), "{err}");
    }

    #[tokio::test]
    async fn rejects_bad_greeting_and_injection() {
        let (server, _h) = fake_server("-ERR too many connections\r\n", vec![]).await;
        let err = Pop3Conn::connect(&server, "alice", &pw()).await.err().unwrap();
        assert!(matches!(&err, Error::Pop3(m) if m.contains("too many connections")), "{err}");

        // Rejected before any connection is attempted.
        let server = ServerConfig { host: "127.0.0.1".into(), port: 1, ..Default::default() };
        let err = Pop3Conn::connect(&server, "alice\r\nDELE 1", &pw()).await.err().unwrap();
        assert!(matches!(err, Error::Invalid(_)), "{err}");
        let err = Pop3Conn::connect(&server, "alice", &Pop3Auth::Password("x\r\nQUIT".into())).await.err().unwrap();
        assert!(matches!(err, Error::Invalid(_)), "{err}");
    }

    #[tokio::test]
    async fn connection_drop_mid_response_is_net_error() {
        let mut script = login_steps();
        script.push(step("RETR 1", "+OK\r\nSubject: cut off\r\n"));
        let (server, handle) = fake_server(GREETING, script).await;
        let mut c = Pop3Conn::connect(&server, "alice", &pw()).await.unwrap();
        let retr = c.retr(1);
        tokio::pin!(retr);
        tokio::select! {
            _ = &mut retr => panic!("RETR must not complete without the terminator"),
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        // Kill the fake server; its socket closes mid-response.
        handle.abort();
        let err = retr.await.unwrap_err();
        assert!(matches!(err, Error::Net(_)), "{err}");
    }
}

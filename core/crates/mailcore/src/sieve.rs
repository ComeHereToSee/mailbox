//! Server-side filtering: a ManageSieve client (RFC 5804) and a generator that turns
//! local rules into a Sieve script (RFC 5228 + fileinto, imap4flags, copy, body, regex).

use crate::error::{Error, Result};
use crate::model::{Rule, RuleAction, RuleCondition, Security, ServerConfig};
use crate::net::{self, MailStream};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub const DEFAULT_PORT: u16 = 4190;
pub const SCRIPT_NAME: &str = "mailbox";
const TIMEOUT: Duration = Duration::from_secs(30);

pub enum SieveAuth {
    Password(String),
    OAuth2(String),
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SieveScript {
    pub name: String,
    pub active: bool,
}

pub struct SieveConn {
    stream: BufReader<MailStream>,
    pub capabilities: Vec<(String, String)>,
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The response of a command: OK / NO / BYE plus any data lines before it.
struct Reply {
    ok: bool,
    text: String,
    data: Vec<String>,
}

impl SieveConn {
    pub async fn connect(server: &ServerConfig, user: &str, auth: &SieveAuth) -> Result<SieveConn> {
        let stream = net::connect(server).await?;
        let mut conn = SieveConn { stream: BufReader::new(stream), capabilities: Vec::new() };
        let greeting = conn.read_reply().await?;
        conn.capabilities = parse_caps(&greeting.data);
        if server.security == Security::StartTls {
            conn.command("STARTTLS").await?;
            let plain = conn.stream.into_inner().into_plain()?;
            let tls = net::tls_wrap(plain, &server.host, server.accept_invalid_certs).await?;
            conn = SieveConn { stream: BufReader::new(MailStream::Tls(Box::new(tls))), capabilities: Vec::new() };
            // The server re-announces its capabilities after STARTTLS.
            let caps = conn.read_reply().await?;
            conn.capabilities = parse_caps(&caps.data);
        }
        let login = server.username.clone().filter(|u| !u.is_empty()).unwrap_or_else(|| user.to_string());
        let (mech, payload) = match auth {
            SieveAuth::Password(p) => ("PLAIN", B64.encode(format!("\0{login}\0{p}"))),
            SieveAuth::OAuth2(t) => ("XOAUTH2", B64.encode(crate::imap::xoauth2_payload(&login, t))),
        };
        let r = conn.send(&format!("AUTHENTICATE \"{mech}\" \"{payload}\"")).await?;
        if !r.ok {
            return Err(Error::Auth(format!("ManageSieve 登录失败: {}", r.text)));
        }
        Ok(conn)
    }

    pub fn has_extension(&self, ext: &str) -> bool {
        self.capabilities
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("SIEVE") && v.split_whitespace().any(|e| e.eq_ignore_ascii_case(ext)))
    }

    async fn write(&mut self, data: &[u8]) -> Result<()> {
        tokio::time::timeout(TIMEOUT, async {
            self.stream.get_mut().write_all(data).await?;
            self.stream.get_mut().flush().await
        })
        .await
        .map_err(|_| Error::Net("ManageSieve 超时".into()))?
        .map_err(|e| Error::Net(e.to_string()))
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        let n = tokio::time::timeout(TIMEOUT, self.stream.read_until(b'\n', &mut buf))
            .await
            .map_err(|_| Error::Net("ManageSieve 超时".into()))?
            .map_err(|e| Error::Net(e.to_string()))?;
        if n == 0 {
            return Err(Error::Net("ManageSieve 连接已断开".into()));
        }
        Ok(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string())
    }

    /// Reads data lines (resolving `{n}` literals) until OK / NO / BYE.
    async fn read_reply(&mut self) -> Result<Reply> {
        let mut data = Vec::new();
        loop {
            let mut line = self.read_line().await?;
            // A trailing literal: `"name" {123}` followed by 123 bytes.
            while let Some(len) = literal_len(&line) {
                let mut lit = vec![0u8; len];
                tokio::time::timeout(TIMEOUT, self.stream.read_exact(&mut lit))
                    .await
                    .map_err(|_| Error::Net("ManageSieve 超时".into()))?
                    .map_err(|e| Error::Net(e.to_string()))?;
                let cut = line.rfind('{').unwrap_or(line.len());
                line.truncate(cut);
                line.push_str(&String::from_utf8_lossy(&lit));
                let rest = self.read_line().await?;
                line.push_str(&rest);
            }
            let upper = line.to_ascii_uppercase();
            for (prefix, ok) in [("OK", true), ("NO", false), ("BYE", false)] {
                if upper == prefix || upper.starts_with(&format!("{prefix} ")) {
                    let text = line[prefix.len()..].trim().trim_matches('"').to_string();
                    return Ok(Reply { ok, text, data });
                }
            }
            data.push(line);
        }
    }

    async fn send(&mut self, cmd: &str) -> Result<Reply> {
        self.write(format!("{cmd}\r\n").as_bytes()).await?;
        self.read_reply().await
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply> {
        let r = self.send(cmd).await?;
        if !r.ok {
            return Err(Error::Other(format!("ManageSieve {cmd}: {}", r.text)));
        }
        Ok(r)
    }

    pub async fn list(&mut self) -> Result<Vec<SieveScript>> {
        let r = self.command("LISTSCRIPTS").await?;
        Ok(r.data
            .iter()
            .filter_map(|l| {
                let name = l.split('"').nth(1)?.to_string();
                Some(SieveScript { name, active: l.to_ascii_uppercase().ends_with("ACTIVE") })
            })
            .collect())
    }

    pub async fn get(&mut self, name: &str) -> Result<String> {
        let r = self.command(&format!("GETSCRIPT {}", quote(name))).await?;
        Ok(r.data.join("\r\n"))
    }

    /// Checks the script on the server (syntax / unsupported extensions).
    pub async fn check(&mut self, script: &str) -> Result<()> {
        let r = self.put_literal("CHECKSCRIPT", None, script).await?;
        if r.ok { Ok(()) } else { Err(Error::Invalid(format!("Sieve 脚本有误: {}", r.text))) }
    }

    pub async fn put(&mut self, name: &str, script: &str) -> Result<()> {
        let r = self.put_literal("PUTSCRIPT", Some(name), script).await?;
        if r.ok { Ok(()) } else { Err(Error::Invalid(format!("上传 Sieve 脚本失败: {}", r.text))) }
    }

    async fn put_literal(&mut self, cmd: &str, name: Option<&str>, script: &str) -> Result<Reply> {
        let script = script.replace("\r\n", "\n").replace('\n', "\r\n");
        let head = match name {
            Some(n) => format!("{cmd} {} {{{}+}}\r\n", quote(n), script.len()),
            None => format!("{cmd} {{{}+}}\r\n", script.len()),
        };
        self.write(head.as_bytes()).await?;
        self.write(script.as_bytes()).await?;
        self.write(b"\r\n").await?;
        self.read_reply().await
    }

    pub async fn activate(&mut self, name: &str) -> Result<()> {
        self.command(&format!("SETACTIVE {}", quote(name))).await.map(|_| ())
    }

    pub async fn delete(&mut self, name: &str) -> Result<()> {
        self.command(&format!("DELETESCRIPT {}", quote(name))).await.map(|_| ())
    }

    pub async fn logout(mut self) {
        let _ = self.send("LOGOUT").await;
    }
}

fn literal_len(line: &str) -> Option<usize> {
    let t = line.trim_end();
    if !t.ends_with('}') {
        return None;
    }
    let open = t.rfind('{')?;
    t[open + 1..t.len() - 1].trim_end_matches('+').parse().ok()
}

fn parse_caps(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|l| {
            let mut parts = l.split('"').filter(|p| !p.trim().is_empty());
            let k = parts.next()?.to_string();
            let v = parts.next().unwrap_or("").to_string();
            Some((k, v))
        })
        .collect()
}

// ---- rules → Sieve ------------------------------------------------------------------------

fn sieve_str(s: &str) -> String {
    quote(s)
}

fn condition(c: &RuleCondition, needs: &mut Vec<&'static str>) -> Option<String> {
    let (match_type, value) = match c.op.as_str() {
        "contains" | "not_contains" => (":contains", c.value.clone()),
        "equals" => (":is", c.value.clone()),
        "starts_with" => (":matches", format!("{}*", c.value.replace('*', "\\\\*").replace('?', "\\\\?"))),
        "ends_with" => (":matches", format!("*{}", c.value.replace('*', "\\\\*").replace('?', "\\\\?"))),
        "regex" => {
            needs.push("regex");
            (":regex", c.value.clone())
        }
        "exists" => ("", String::new()),
        _ => return None,
    };
    let headers = match c.field.as_str() {
        "from" => "\"from\"".to_string(),
        "to" => "\"to\"".to_string(),
        "cc" => "\"cc\"".to_string(),
        "recipients" => "[\"to\", \"cc\"]".to_string(),
        "subject" => "\"subject\"".to_string(),
        "list_id" => "\"list-id\"".to_string(),
        f if f.starts_with("header:") => sieve_str(&f[7..]),
        "body" => {
            needs.push("body");
            let test = format!("body :text {match_type} {}", sieve_str(&value));
            return Some(if c.op == "not_contains" { format!("not {test}") } else { test });
        }
        "has_attachment" => {
            let test = "header :contains \"content-type\" \"multipart/mixed\"".to_string();
            return Some(if c.value == "false" { format!("not {test}") } else { test });
        }
        _ => return None,
    };
    let test = if c.op == "exists" {
        format!("exists {headers}")
    } else {
        let kind = if matches!(c.field.as_str(), "from" | "to" | "cc" | "recipients") { "address" } else { "header" };
        format!("{kind} {match_type} {headers} {}", sieve_str(&value))
    };
    Some(if c.op == "not_contains" { format!("not {test}") } else { test })
}

fn action(a: &RuleAction, folder_for: &dyn Fn(&str) -> Option<String>, needs: &mut Vec<&'static str>) -> Option<String> {
    match a.kind.as_str() {
        "move" => {
            needs.push("fileinto");
            Some(format!("fileinto {};", sieve_str(&folder_for(&a.value).unwrap_or_else(|| a.value.clone()))))
        }
        "archive" => {
            needs.push("fileinto");
            Some(format!("fileinto {};", sieve_str(&folder_for("archive").unwrap_or_else(|| "Archive".into()))))
        }
        "trash" => {
            needs.push("fileinto");
            Some(format!("fileinto {};", sieve_str(&folder_for("trash").unwrap_or_else(|| "Trash".into()))))
        }
        "mark_read" => {
            needs.push("imap4flags");
            Some("addflag \"\\\\Seen\";".into())
        }
        "flag" => {
            needs.push("imap4flags");
            Some("addflag \"\\\\Flagged\";".into())
        }
        "forward" => {
            needs.push("copy");
            let lines: Vec<String> = a
                .value
                .split([',', ';'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|t| format!("redirect :copy {};", sieve_str(t)))
                .collect();
            if lines.is_empty() { None } else { Some(lines.join("\n    ")) }
        }
        "stop" => Some("stop;".into()),
        // Local-only actions (labels, categories, VIP, notifications) have no Sieve equivalent.
        _ => None,
    }
}

/// Builds a Sieve script from the rules that apply to one account. `folder_for` maps a
/// role or folder name to the server folder path. Rules without server-side actions are skipped.
pub fn rules_to_sieve(rules: &[Rule], account_id: &str, folder_for: &dyn Fn(&str) -> Option<String>) -> String {
    let mut needs: Vec<&'static str> = Vec::new();
    let mut blocks = Vec::new();
    for r in rules {
        if !r.enabled || r.account_id.as_deref().is_some_and(|a| !a.is_empty() && a != account_id) {
            continue;
        }
        let tests: Vec<String> = r.conditions.iter().filter_map(|c| condition(c, &mut needs)).collect();
        if tests.is_empty() || tests.len() != r.conditions.len() {
            continue;
        }
        let actions: Vec<String> = r.actions.iter().filter_map(|a| action(a, folder_for, &mut needs)).collect();
        if actions.iter().all(|a| a == "stop;") {
            continue;
        }
        let test = if tests.len() == 1 {
            tests[0].clone()
        } else {
            format!("{} ({})", if r.match_all { "allof" } else { "anyof" }, tests.join(", "))
        };
        blocks.push(format!("# {}\nif {test} {{\n    {}\n}}", r.name.replace('\n', " "), actions.join("\n    ")));
    }
    needs.sort_unstable();
    needs.dedup();
    let mut out = String::from("# 由 Mailbox 根据本地规则生成，请在 Mailbox 中修改规则\n");
    if !needs.is_empty() {
        out.push_str(&format!("require [{}];\n", needs.iter().map(|n| sieve_str(n)).collect::<Vec<_>>().join(", ")));
    }
    out.push('\n');
    out.push_str(&blocks.join("\n\n"));
    out.push('\n');
    out
}

/// ManageSieve server for an account: explicit config, else the IMAP host on port 4190.
pub fn server_for(imap: &ServerConfig) -> ServerConfig {
    ServerConfig {
        host: imap.host.clone(),
        port: DEFAULT_PORT,
        security: if imap.security == Security::None { Security::None } else { Security::StartTls },
        username: imap.username.clone(),
        accept_invalid_certs: imap.accept_invalid_certs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_script() {
        let rules = vec![
            Rule {
                name: "账单".into(),
                enabled: true,
                match_all: true,
                conditions: vec![
                    RuleCondition { field: "from".into(), op: "ends_with".into(), value: "@alipay.com".into() },
                    RuleCondition { field: "subject".into(), op: "contains".into(), value: "账单".into() },
                ],
                actions: vec![
                    RuleAction { kind: "move".into(), value: "账单".into() },
                    RuleAction { kind: "mark_read".into(), value: String::new() },
                    RuleAction { kind: "category".into(), value: "updates".into() },
                ],
                ..Default::default()
            },
            Rule {
                name: "label only".into(),
                enabled: true,
                conditions: vec![RuleCondition { field: "subject".into(), op: "contains".into(), value: "x".into() }],
                actions: vec![RuleAction { kind: "label".into(), value: "x".into() }],
                ..Default::default()
            },
            Rule {
                name: "other account".into(),
                enabled: true,
                account_id: Some("b".into()),
                conditions: vec![RuleCondition { field: "subject".into(), op: "contains".into(), value: "y".into() }],
                actions: vec![RuleAction { kind: "trash".into(), value: String::new() }],
                ..Default::default()
            },
        ];
        let s = rules_to_sieve(&rules, "a", &|n| if n == "账单" { Some("&jSZTVQ-".into()) } else { None });
        assert!(s.contains("require [\"fileinto\", \"imap4flags\"];"), "{s}");
        assert!(s.contains("allof (address :matches \"from\" \"*@alipay.com\", header :contains \"subject\" \"账单\")"), "{s}");
        assert!(s.contains("fileinto \"&jSZTVQ-\";"));
        assert!(s.contains("addflag \"\\\\Seen\";"));
        assert!(!s.contains("label only"));
        assert!(!s.contains("other account"));
    }

    #[test]
    fn parses_literal_length() {
        assert_eq!(literal_len("\"mailbox\" {42}"), Some(42));
        assert_eq!(literal_len("{7+}"), Some(7));
        assert_eq!(literal_len("OK"), None);
    }
}

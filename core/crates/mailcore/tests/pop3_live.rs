//! POP3 against the local Dovecot from `scripts/test-env/start.sh`.
//! Uses bob's mailbox so it never interferes with the IMAP tests (alice).

mod common;

use mailcore::Error;
use mailcore::imap::{ImapAuth, ImapConn};
use mailcore::model::Security;
use mailcore::pop3::{Pop3Auth, Pop3Conn};

const USER: &str = "bob@test.local";

fn password() -> Pop3Auth {
    Pop3Auth::Password("secret".into())
}

/// A message whose body exercises byte-stuffing: lines starting with "." and a lone ".".
fn message(mid: &str) -> Vec<u8> {
    format!(
        "From: =?UTF-8?B?5byg5LiJ?= <zhangsan@corp.cn>\r\nTo: {USER}\r\nSubject: POP3 {mid}\r\n\
         Message-ID: <{mid}>\r\nDate: Thu, 22 Oct 2026 10:00:00 +0800\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n\
         第一行\r\n.starts with a dot\r\n..two dots\r\n.\r\nlast line\r\n"
    )
    .into_bytes()
}

async fn append(raw: &[u8]) {
    let mut imap = ImapConn::connect(&common::imap(Security::Tls), USER, &ImapAuth::Password("secret".into()), true)
        .await
        .unwrap();
    imap.append("INBOX", &[], raw).await.unwrap();
    imap.logout().await;
}

/// Finds the message with `mid` by looking at headers (newest first).
async fn find(c: &mut Pop3Conn, mid: &str) -> Option<u32> {
    let needle = format!("Message-ID: <{mid}>");
    let list = c.list().await.unwrap();
    for &(n, _) in list.iter().rev() {
        let head = c.top(n, 0).await.unwrap();
        if String::from_utf8_lossy(&head).contains(&needle) {
            return Some(n);
        }
    }
    None
}

#[tokio::test]
async fn pop3_stat_list_uidl_retr_top_dele() {
    if !common::servers_available() {
        return;
    }
    mailcore::net::install_crypto_provider();
    for sec in [Security::Tls, Security::StartTls, Security::None] {
        let mid = format!("{}@test", common::unique("pop3"));
        let raw = message(&mid);
        append(&raw).await;

        let mut c = Pop3Conn::connect(&common::pop3(sec), USER, &password()).await.unwrap();
        assert_eq!(c.is_tls(), sec != Security::None, "{sec:?}");
        let caps = c.capa().await.unwrap();
        assert!(c.has_cap("UIDL") && c.has_cap("TOP"), "{sec:?}: {caps:?}");
        assert!(!c.has_cap("STLS") || sec == Security::None, "STLS must not be offered inside TLS: {caps:?}");

        let (count, octets) = c.stat().await.unwrap();
        let list = c.list().await.unwrap();
        let uidl = c.uidl().await.unwrap();
        assert!(count >= 1);
        assert_eq!(list.len(), count as usize);
        assert_eq!(uidl.len(), count as usize);
        assert_eq!(list.iter().map(|&(_, s)| s).sum::<u64>(), octets);
        assert!(list.iter().zip(&uidl).all(|(l, u)| l.0 == u.0));

        let n = find(&mut c, &mid).await.expect("appended message visible over POP3");
        let uid = c.uidl_one(n).await.unwrap();
        assert!(uidl.contains(&(n, uid.clone())));
        assert_eq!(c.list_one(n).await.unwrap(), raw.len() as u64);

        // RETR returns the exact bytes that were appended (dots unstuffed, CRLF kept).
        let got = c.retr(n).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&raw), "{sec:?}");
        assert_eq!(got, raw);

        let head = c.top(n, 0).await.unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert!(String::from_utf8_lossy(&head).contains(&format!("Subject: POP3 {mid}")));
        assert!(!String::from_utf8_lossy(&head).contains("第一行"));
        let top2 = c.top(n, 2).await.unwrap();
        assert!(top2.starts_with(&head));
        assert_eq!(&top2[head.len()..], "第一行\r\n.starts with a dot\r\n".as_bytes());

        c.noop().await.unwrap();

        // DELE + RSET keeps the message.
        c.dele(n).await.unwrap();
        assert!(c.retr(n).await.is_err(), "deleted message must not be retrievable");
        c.rset().await.unwrap();
        c.quit().await.unwrap();

        // Dropping the connection without QUIT does not commit deletions.
        let mut c = Pop3Conn::connect(&common::pop3(sec), USER, &password()).await.unwrap();
        let n = find(&mut c, &mid).await.expect("message survives RSET");
        c.dele(n).await.unwrap();
        drop(c);

        // DELE + QUIT removes it.
        let mut c = Pop3Conn::connect(&common::pop3(sec), USER, &password()).await.unwrap();
        let n = find(&mut c, &mid).await.expect("message survives a dropped session");
        assert_eq!(c.uidl_one(n).await.unwrap(), uid);
        c.dele(n).await.unwrap();
        c.quit().await.unwrap();

        let mut c = Pop3Conn::connect(&common::pop3(sec), USER, &password()).await.unwrap();
        let uidl = c.uidl().await.unwrap();
        assert!(!uidl.iter().any(|(_, u)| *u == uid), "{sec:?}: message still on server after DELE + QUIT");
        assert!(find(&mut c, &mid).await.is_none());
        c.quit().await.unwrap();
    }
}

#[tokio::test]
async fn pop3_login_failures() {
    if !common::servers_available() {
        return;
    }
    mailcore::net::install_crypto_provider();
    let err = Pop3Conn::connect(&common::pop3(Security::Tls), USER, &Pop3Auth::Password("wrong".into()))
        .await
        .err()
        .expect("wrong password must fail");
    assert!(matches!(&err, Error::Auth(m) if m.contains("POP3 登录失败")), "{err}");

    // `server.username` overrides the account address.
    let mut server = common::pop3(Security::StartTls);
    server.username = Some("nobody@test.local".into());
    let err = Pop3Conn::connect(&server, USER, &password()).await.err().expect("unknown user must fail");
    assert!(err.is_auth(), "{err}");

    // The test Dovecot has no XOAUTH2 mechanism.
    let err = Pop3Conn::connect(&common::pop3(Security::Tls), USER, &Pop3Auth::OAuth2("token".into()))
        .await
        .err()
        .expect("XOAUTH2 must fail");
    assert!(err.is_auth(), "{err}");
}

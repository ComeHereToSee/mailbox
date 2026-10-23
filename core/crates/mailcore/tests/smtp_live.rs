mod common;

use mailcore::imap::{ImapAuth, ImapConn};
use mailcore::mime::build::{Outgoing, build, new_message_id};
use mailcore::model::{EmailAddress, Security, ServerConfig};
use mailcore::smtp::{self, SmtpAuth};

#[tokio::test]
async fn smtp_send_reaches_mailbox() {
    if !common::servers_available() {
        return;
    }
    mailcore::net::install_crypto_provider();
    let server = common::smtp();
    smtp::test(&server, "alice", &SmtpAuth::Password("secret".into())).await.unwrap();
    // GreenMail accepts any SMTP password, so wrong-password handling is covered by the IMAP tests.

    let subject = common::unique("发送测试");
    let out = Outgoing {
        from: EmailAddress::new(Some("Alice 爱丽丝"), "alice@test.local"),
        to: vec![EmailAddress::new(Some("Bob"), "bob@test.local")],
        subject: subject.clone(),
        html: Some("<p>你好 <b>Bob</b></p>".into()),
        text: "你好 Bob".into(),
        message_id: new_message_id("alice@test.local"),
        date: chrono::Utc::now().timestamp(),
        ..Default::default()
    };
    let raw = build(&out, false).unwrap();
    smtp::send(&server, "alice", &SmtpAuth::Password("secret".into()), "alice@test.local", &["bob@test.local".into()], &raw)
        .await
        .unwrap();

    let gm_imap = ServerConfig { host: "127.0.0.1".into(), port: 3143, security: Security::None, username: None, accept_invalid_certs: true };
    let mut c = ImapConn::connect(&gm_imap, "bob", &ImapAuth::Password("secret".into()), false).await.unwrap();
    let mut found = Vec::new();
    for _ in 0..20 {
        found = c.uid_search("INBOX", "ALL").await.unwrap();
        let heads = c.fetch_headers("INBOX", &mailcore::imap::uid_set(&found)).await.unwrap_or_default();
        if heads.iter().any(|h| mailcore::mime::parse_headers(h.header.as_deref().unwrap_or_default()).subject == subject) {
            c.logout().await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("sent message not delivered ({} messages in inbox)", found.len());
}

//! POP3 account through the engine: import, new-mail notification, local folders.
mod common;

use mailcore::engine::NewAccount;
use mailcore::events::Event;
use mailcore::imap::{ImapAuth, ImapConn};
use mailcore::model::*;
use mailcore::store::ListQuery;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pop3_account_end_to_end() {
    if !common::servers_available() {
        return;
    }
    unsafe { std::env::set_var("MAILBOX_KEY_FILE", "1") };
    let dir = std::env::temp_dir().join(common::unique("pop-engine"));
    let e = mailcore::Engine::open(&dir).unwrap();
    e.start();
    let mut events = e.events.subscribe();

    let mut imap = ImapConn::connect(&common::imap(Security::Tls), "bob@test.local", &ImapAuth::Password("secret".into()), false)
        .await
        .unwrap();
    let first = common::unique("POP首封");
    imap.append("INBOX", &[], &common::sample_message(&first, &format!("{first}@t"))).await.unwrap();

    let mut smtp = common::smtp();
    smtp.username = Some("bob".into());
    let acc = e
        .add_account(NewAccount {
            kind: AccountKind::Pop3,
            email: "bob@test.local".into(),
            name: "Bob".into(),
            label: "POP测试".into(),
            config: AccountConfig { pop3: Some(common::pop3(Security::Tls)), smtp: Some(smtp), poll_interval_secs: 60, ..Default::default() },
            password: Some("secret".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let found = |subject: &str| {
        e.db.list_messages(&ListQuery { account_id: Some(acc.id.clone()), limit: 500, ..Default::default() })
            .unwrap()
            .into_iter()
            .find(|m| m.subject == subject)
    };
    let mut ok = false;
    for _ in 0..80 {
        if found(&first).is_some() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ok, "initial POP3 import missing");
    let folders = e.db.folders(Some(&acc.id)).unwrap();
    assert!(folders.iter().all(|f| f.local));
    assert!(folders.iter().any(|f| f.role == FolderRole::Sent));

    // A second message arrives; waking the worker downloads it and announces it.
    let second = common::unique("POP新邮件");
    imap.append("INBOX", &[], &common::sample_message(&second, &format!("{second}@t"))).await.unwrap();
    e.wake(Some(&acc.id));
    let got = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Event::NewMail { message, account_label, .. }) = events.recv().await {
                if message.subject == second {
                    return account_label;
                }
            }
        }
    })
    .await
    .expect("no NewMail for POP3");
    assert_eq!(got, "POP测试");
    let m = found(&second).unwrap();
    let d = e.message_detail(m.id).await.unwrap();
    assert!(d.body_loaded && d.text.unwrap_or_default().contains("测试邮件"));

    // Local archive works for POP3 (no server folders).
    e.act(&[m.id], mailcore::engine::Action::Archive).await.unwrap();
    let archive = e.db.folder_by_role(&acc.id, FolderRole::Archive).unwrap().unwrap();
    assert!(archive.local);
    assert_eq!(e.db.message(m.id).unwrap().summary.folder_id, archive.id);

    imap.logout().await;
    e.delete_account(&acc.id).await.unwrap();
    e.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

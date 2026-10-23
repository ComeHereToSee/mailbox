//! End-to-end engine test against Dovecot (IMAP) + GreenMail (SMTP).
mod common;

use mailcore::engine::{Action, NewAccount};
use mailcore::events::Event;
use mailcore::imap::{ImapAuth, ImapConn};
use mailcore::model::*;
use mailcore::store::ListQuery;
use std::time::Duration;

async fn wait_until<F: FnMut() -> bool>(secs: u64, mut f: F) -> bool {
    for _ in 0..secs * 4 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn server_uids(path: &str, mid: &str) -> Vec<u32> {
    let mut c = ImapConn::connect(&common::imap(Security::Tls), "alice@test.local", &ImapAuth::Password("secret".into()), false)
        .await
        .unwrap();
    let uids = c.uid_search(path, &format!("HEADER Message-ID \"{mid}\"")).await.unwrap();
    c.logout().await;
    uids
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_end_to_end() {
    if !common::servers_available() {
        return;
    }
    unsafe { std::env::set_var("MAILBOX_KEY_FILE", "1") };
    let dir = std::env::temp_dir().join(common::unique("engine"));
    let e = mailcore::Engine::open(&dir).unwrap();
    e.start();
    let mut events = e.events.subscribe();

    // Seed the inbox before the account exists (initial sync must not notify).
    let mut seed = ImapConn::connect(&common::imap(Security::Tls), "alice@test.local", &ImapAuth::Password("secret".into()), false)
        .await
        .unwrap();
    let old_mid = format!("{}@test", common::unique("old"));
    seed.append("INBOX", &[], &common::sample_message("旧邮件", &old_mid)).await.unwrap();

    let mut smtp = common::smtp();
    smtp.username = Some("alice".into());
    let acc = e
        .add_account(NewAccount {
            kind: AccountKind::Imap,
            email: "alice@test.local".into(),
            name: "Alice".into(),
            label: "测试".into(),
            config: AccountConfig {
                imap: Some(common::imap(Security::Tls)),
                smtp: Some(smtp),
                poll_interval_secs: 60,
                ..Default::default()
            },
            password: Some("secret".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(e.add_account(NewAccount { email: "alice@test.local".into(), ..Default::default() }).await.is_err());

    assert!(
        wait_until(30, || {
            e.db.list_messages(&ListQuery { account_id: Some(acc.id.clone()), limit: 1000, ..Default::default() })
                .unwrap()
                .iter()
                .any(|m| m.subject == "旧邮件")
        })
        .await,
        "initial sync did not bring the seeded message"
    );
    let folders = e.db.folders(Some(&acc.id)).unwrap();
    for role in [FolderRole::Inbox, FolderRole::Sent, FolderRole::Trash, FolderRole::Archive, FolderRole::Drafts] {
        assert!(folders.iter().any(|f| f.role == role), "missing {role:?}");
    }

    // New mail while running → IDLE → NewMail event with the account label.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let subject = common::unique("新邮件");
    let mid = format!("{subject}@test");
    seed.append("INBOX", &[], &common::sample_message(&subject, &mid)).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if let Ok(Event::NewMail { message, account_label, notify, .. }) = events.recv().await {
                if message.subject == subject {
                    return (message, account_label, notify);
                }
            }
        }
    })
    .await
    .expect("no NewMail event");
    assert_eq!(got.1, "测试");
    assert!(got.2, "should notify");
    assert!(!got.0.snippet.is_empty(), "new mail should carry a snippet");
    let id = got.0.id;

    // Detail + search.
    let d = e.message_detail(id).await.unwrap();
    assert!(d.body_loaded);
    assert!(d.text.unwrap_or_default().contains("测试邮件"));
    let found = e.db.list_messages(&ListQuery { search: Some("测试邮件".into()), ..Default::default() }).unwrap();
    assert!(found.iter().any(|m| m.id == id));

    // Read flag reaches the server.
    e.act(&[id], Action::Read).await.unwrap();
    let ok = {
        let mut ok = false;
        for _ in 0..40 {
            let mut c = ImapConn::connect(&common::imap(Security::Tls), "alice@test.local", &ImapAuth::Password("secret".into()), false)
                .await
                .unwrap();
            let uids = c.uid_search("INBOX", &format!("HEADER Message-ID \"{mid}\" SEEN")).await.unwrap();
            c.logout().await;
            if !uids.is_empty() {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        ok
    };
    assert!(ok, "\\Seen not stored on server");

    // Trash + undo keeps it in the inbox.
    let r = e.act(&[id], Action::Trash).await.unwrap();
    assert!(e.db.list_messages(&ListQuery::default()).unwrap().iter().all(|m| m.id != id));
    assert!(e.undo(r.undo_token.as_deref().unwrap()).unwrap());
    assert!(e.db.list_messages(&ListQuery::default()).unwrap().iter().any(|m| m.id == id));

    // Archive goes through after the undo window.
    e.act(&[id], Action::Archive).await.unwrap();
    let mut archived = false;
    for _ in 0..60 {
        if !server_uids("Archive", &mid).await.is_empty() && server_uids("INBOX", &mid).await.is_empty() {
            archived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(archived, "archive did not reach the server");
    let archive = e.db.folder_by_role(&acc.id, FolderRole::Archive).unwrap().unwrap();
    assert!(
        wait_until(30, || e.db.message(id).map(|m| m.summary.folder_id == archive.id && m.uid.is_some()).unwrap_or(false)).await,
        "moved message did not adopt its new UID"
    );

    // Reply draft + send.
    let draft = e.reply_draft(id, ComposeMode::Reply).await.unwrap();
    assert_eq!(draft.to[0].email, "zhangsan@corp.cn");
    assert!(draft.subject.starts_with("Re: "));
    let mut out = Draft {
        account_id: acc.id.clone(),
        to: vec![EmailAddress::new(Some("Bob"), "bob@test.local")],
        subject: common::unique("引擎发送"),
        html: "<p>你好 <img src=\"data:image/png;base64,iVBORw0KGgo=\"></p>".into(),
        ..Default::default()
    };
    out.id = String::new();
    let item = e.send_draft(out.clone(), Some(0)).unwrap();
    let sent = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Event::Outbox { id, status, error }) = events.recv().await {
                if id == item.id && matches!(status, OutboxStatus::Sent | OutboxStatus::Failed) {
                    return (status, error);
                }
            }
        }
    })
    .await
    .expect("no outbox event");
    assert_eq!(sent.0, OutboxStatus::Sent, "{:?}", sent.1);
    let sent_folder = e.db.folder_by_role(&acc.id, FolderRole::Sent).unwrap().unwrap();
    assert!(
        wait_until(40, || {
            e.db.list_messages(&ListQuery { mailbox: Mailbox::Folder(sent_folder.id), limit: 200, ..Default::default() })
                .unwrap()
                .iter()
                .any(|m| m.subject == out.subject)
        })
        .await,
        "sent copy missing from Sent"
    );
    assert!(e.db.search_contacts("bob", 5).unwrap().iter().any(|c| c.email == "bob@test.local"));

    // Undo send.
    let item = e.send_draft(Draft { subject: "不要发".into(), ..out.clone() }, None).unwrap();
    let back = e.cancel_send(&item.id).unwrap().expect("undo send");
    assert_eq!(back.subject, "不要发");

    seed.logout().await;
    e.delete_account(&acc.id).await.unwrap();
    e.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

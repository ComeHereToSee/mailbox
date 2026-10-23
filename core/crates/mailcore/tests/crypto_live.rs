//! Signed + encrypted mail through the whole engine: key store, send (GreenMail), Sent copy
//! (Dovecot), then decrypt and verify on display.
mod common;

use mailcore::engine::{KeyImport, NewAccount};
use mailcore::events::Event;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_and_encrypted_round_trip() {
    if !common::servers_available() {
        return;
    }
    unsafe { std::env::set_var("MAILBOX_KEY_FILE", "1") };
    let dir = std::env::temp_dir().join(common::unique("crypto"));
    let e = mailcore::Engine::open(&dir).unwrap();
    e.start();
    let mut events = e.events.subscribe();

    // Key store: generate, export, re-import the public half (must keep the secret key).
    let alice = e.generate_key("Alice", "alice@test.local", Some("口令")).unwrap();
    let bob = e.generate_key("Bob", "bob@test.local", None).unwrap();
    assert!(alice.has_secret && bob.has_secret);
    let bob_pub = e.export_key(&bob.id, false).unwrap();
    assert!(bob_pub.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    let again = e.import_key(KeyImport { text: Some(bob_pub), ..Default::default() }).unwrap();
    assert!(again.has_secret, "re-importing a public key dropped the secret key");
    assert_eq!(e.list_keys().len(), 2);
    let (have, missing) = e.recipient_keys(&["Bob <bob@test.local>".into(), "carol@test.local".into()]);
    assert_eq!(have.len(), 1);
    assert_eq!(missing, vec!["carol@test.local".to_string()]);

    let mut smtp = common::smtp();
    smtp.username = Some("alice".into());
    let acc = e
        .add_account(NewAccount {
            kind: AccountKind::Imap,
            email: "alice@test.local".into(),
            name: "Alice".into(),
            label: "加密".into(),
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
    assert!(
        wait_until(30, || e.db.folder_by_role(&acc.id, FolderRole::Sent).ok().flatten().is_some()).await,
        "folders not synced"
    );

    // Encrypting to someone without a key is refused before anything is queued.
    let mut d = Draft {
        account_id: acc.id.clone(),
        to: vec![EmailAddress::new(Some("Carol"), "carol@test.local")],
        subject: common::unique("加密"),
        html: "<p>机密内容：项目代号 蓝鲸</p>".into(),
        sign: true,
        encrypt: true,
        ..Default::default()
    };
    let err = e.send_draft(d.clone(), Some(0)).unwrap_err().to_string();
    assert!(err.contains("carol@test.local"), "{err}");

    d.to = vec![EmailAddress::new(Some("Bob"), "bob@test.local")];
    let item = e.send_draft(d.clone(), Some(0)).unwrap();
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
    let mut id = None;
    assert!(
        wait_until(40, || {
            id = e
                .db
                .list_messages(&ListQuery { mailbox: Mailbox::Folder(sent_folder.id), limit: 200, ..Default::default() })
                .unwrap()
                .into_iter()
                .find(|m| m.subject == d.subject)
                .map(|m| m.id);
            id.is_some()
        })
        .await,
        "sent copy missing from Sent"
    );
    let id = id.unwrap();

    // What went to the server is really encrypted …
    let raw = String::from_utf8_lossy(&e.raw_message(id).await.unwrap()).to_string();
    assert!(raw.contains("multipart/encrypted"), "{raw}");
    assert!(!raw.contains("蓝鲸"));

    // … and reads back decrypted with a valid signature (encrypted to the sender too).
    let detail = e.message_detail(id).await.unwrap();
    assert!(detail.encrypted && detail.decrypted, "{:?}", detail.decrypt_error);
    let sig = detail.signature.expect("signature status");
    assert!(sig.valid, "{}", sig.message);
    assert_eq!(sig.kind, "pgp");
    assert!(detail.text.unwrap_or_default().contains("蓝鲸"));
    assert!(detail.html.unwrap_or_default().contains("蓝鲸"));

    // Deleting a key removes it and its passphrase.
    e.delete_key(&bob.id).unwrap();
    assert_eq!(e.list_keys().len(), 1);

    e.delete_account(&acc.id).await.unwrap();
    e.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

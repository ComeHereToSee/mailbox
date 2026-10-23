mod common;

use mailcore::imap::{ImapAuth, ImapConn};
use mailcore::model::{FolderRole, Security};

#[tokio::test]
async fn imap_connect_list_append_flags_move() {
    if !common::servers_available() {
        return;
    }
    mailcore::net::install_crypto_provider();
    for sec in [Security::Tls, Security::StartTls] {
        let mut c = ImapConn::connect(&common::imap(sec), "alice@test.local", &ImapAuth::Password("secret".into()), true)
            .await
            .unwrap();
        assert!(c.caps.idle && c.caps.move_ && c.caps.condstore);
        let folders = c.list_folders().await.unwrap();
        let roles: Vec<_> = folders.iter().map(|f| f.role).collect();
        for r in [FolderRole::Inbox, FolderRole::Sent, FolderRole::Drafts, FolderRole::Trash, FolderRole::Junk, FolderRole::Archive] {
            assert!(roles.contains(&r), "missing {r:?}");
        }
        c.logout().await;
    }

    let bad = ImapConn::connect(&common::imap(Security::Tls), "alice@test.local", &ImapAuth::Password("nope".into()), true).await;
    assert!(matches!(bad, Err(ref e) if e.is_auth()), "wrong password must be an auth error");

    let mut c = ImapConn::connect(&common::imap(Security::Tls), "alice@test.local", &ImapAuth::Password("secret".into()), true)
        .await
        .unwrap();
    let subject = common::unique("smoke");
    let mid = format!("{subject}@test");
    c.append("INBOX", &[], &common::sample_message(&subject, &mid)).await.unwrap();
    let info = c.select("INBOX").await.unwrap();
    assert!(info.exists > 0 && info.uidvalidity.is_some() && info.highest_modseq.is_some());
    let uids = c.uid_search("INBOX", &format!("HEADER Message-ID \"{mid}\"")).await.unwrap();
    assert_eq!(uids.len(), 1);
    let fetched = c.fetch_headers("INBOX", &uids[0].to_string()).await.unwrap();
    assert_eq!(fetched.len(), 1);
    assert!(!fetched[0].flags.seen);
    assert!(String::from_utf8_lossy(fetched[0].header.as_ref().unwrap()).contains(&subject));
    c.store_flag("INBOX", &uids, "seen", true).await.unwrap();
    let flags = c.fetch_flags("INBOX", &uids[0].to_string(), None).await.unwrap();
    assert!(flags[0].flags.seen);
    let body = c.fetch_bodies("INBOX", &uids).await.unwrap();
    assert!(body[0].body.as_ref().unwrap().len() > 100);
    c.move_uids("INBOX", &uids, "Archive").await.unwrap();
    assert!(c.uid_search("INBOX", &format!("HEADER Message-ID \"{mid}\"")).await.unwrap().is_empty());
    let moved = c.uid_search("Archive", &format!("HEADER Message-ID \"{mid}\"")).await.unwrap();
    assert_eq!(moved.len(), 1);
    c.expunge_uids("Archive", &moved).await.unwrap();
    assert!(c.uid_search("Archive", &format!("HEADER Message-ID \"{mid}\"")).await.unwrap().is_empty());
    let name = common::unique("项目");
    c.create_folder(&mailcore::imap::utf7::encode(&name)).await.unwrap();
    let folders = c.list_folders().await.unwrap();
    assert!(folders.iter().any(|f| f.name == name));
    c.delete_folder(&mailcore::imap::utf7::encode(&name)).await.unwrap();
    c.logout().await;
}

mod common;

use mailcore::model::{Rule, RuleAction, RuleCondition, Security, ServerConfig};
use mailcore::sieve::{SieveAuth, SieveConn, rules_to_sieve};

#[tokio::test]
async fn managesieve_roundtrip() {
    if !common::servers_available() {
        return;
    }
    mailcore::net::install_crypto_provider();
    let server = ServerConfig { host: "127.0.0.1".into(), port: 14190, security: Security::StartTls, username: None, accept_invalid_certs: true };
    let bad = SieveConn::connect(&server, "alice@test.local", &SieveAuth::Password("nope".into())).await;
    assert!(matches!(bad, Err(ref e) if e.is_auth()));
    let mut c = SieveConn::connect(&server, "alice@test.local", &SieveAuth::Password("secret".into())).await.unwrap();
    assert!(c.has_extension("fileinto") && c.has_extension("imap4flags"));
    let rules = vec![Rule {
        name: "通知归档".into(),
        enabled: true,
        match_all: false,
        conditions: vec![
            RuleCondition { field: "from".into(), op: "contains".into(), value: "noreply".into() },
            RuleCondition { field: "subject".into(), op: "regex".into(), value: "^\\[CI\\]".into() },
        ],
        actions: vec![
            RuleAction { kind: "move".into(), value: "Archive".into() },
            RuleAction { kind: "mark_read".into(), value: String::new() },
            RuleAction { kind: "forward".into(), value: "bob@test.local".into() },
        ],
        ..Default::default()
    }];
    let script = rules_to_sieve(&rules, "a", &|_| None);
    c.check(&script).await.unwrap();
    assert!(c.check("if foo { bar; }").await.is_err());
    c.put("mailbox-test", &script).await.unwrap();
    c.activate("mailbox-test").await.unwrap();
    let list = c.list().await.unwrap();
    assert!(list.iter().any(|s| s.name == "mailbox-test" && s.active), "{list:?}");
    let got = c.get("mailbox-test").await.unwrap();
    assert_eq!(got.replace("\r\n", "\n").trim(), script.trim());
    c.activate("").await.unwrap();
    c.delete("mailbox-test").await.unwrap();
    assert!(!c.list().await.unwrap().iter().any(|s| s.name == "mailbox-test"));
    c.logout().await;
}

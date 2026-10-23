//! Helpers for integration tests that need the servers from `scripts/test-env/start.sh`.
#![allow(dead_code)]

use mailcore::model::{Security, ServerConfig};

pub fn servers_available() -> bool {
    if std::env::var("MAILBOX_TEST_SERVERS").is_err() {
        eprintln!("skipping: set MAILBOX_TEST_SERVERS=1 and run scripts/test-env/start.sh");
        return false;
    }
    true
}

pub fn imap(security: Security) -> ServerConfig {
    let port = match security {
        Security::Tls => 11993,
        _ => 11143,
    };
    ServerConfig { host: "127.0.0.1".into(), port, security, username: None, accept_invalid_certs: true }
}

pub fn pop3(security: Security) -> ServerConfig {
    let port = match security {
        Security::Tls => 11995,
        _ => 11110,
    };
    ServerConfig { host: "127.0.0.1".into(), port, security, username: None, accept_invalid_certs: true }
}

pub fn smtp() -> ServerConfig {
    ServerConfig { host: "127.0.0.1".into(), port: 3025, security: Security::None, username: Some("alice".into()), accept_invalid_certs: true }
}

pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

pub fn sample_message(subject: &str, mid: &str) -> Vec<u8> {
    format!(
        "From: =?UTF-8?B?5byg5LiJ?= <zhangsan@corp.cn>\r\nTo: alice@test.local\r\nSubject: {subject}\r\n\
         Message-ID: <{mid}>\r\nDate: Thu, 22 Oct 2026 10:00:00 +0800\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n你好，这是一封测试邮件。\r\n"
    )
    .into_bytes()
}

//! HTTP API tests against an in-process engine with demo data (no mail servers needed).

use futures::StreamExt;
use mailcore::{Engine, api};
use serde_json::{Value, json};

struct Ctx {
    base: String,
    token: String,
    http: reqwest::Client,
    _engine: Engine,
    dir: std::path::PathBuf,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Ctx {
    async fn get(&self, path: &str) -> Value {
        let r = self.http.get(format!("{}{path}", self.base)).bearer_auth(&self.token).send().await.unwrap();
        assert!(r.status().is_success(), "GET {path}: {}", r.status());
        r.json().await.unwrap()
    }
    async fn post(&self, path: &str, body: Value) -> Value {
        let r = self.http.post(format!("{}{path}", self.base)).bearer_auth(&self.token).json(&body).send().await.unwrap();
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        assert!(status.is_success(), "POST {path}: {status} {v}");
        v
    }
}

async fn setup() -> Ctx {
    unsafe { std::env::set_var("MAILBOX_KEY_FILE", "1") };
    let dir = std::env::temp_dir().join(format!("mailbox-api-{}", uuid::Uuid::new_v4().simple()));
    let engine = Engine::open(&dir).unwrap();
    let h = api::serve(engine.clone(), Some(0)).await.unwrap();
    engine.start();
    let info: api::DaemonInfo = serde_json::from_slice(&std::fs::read(dir.join("daemon.json")).unwrap()).unwrap();
    assert_eq!(info.port, h.port);
    Ctx { base: format!("http://127.0.0.1:{}", h.port), token: h.token, http: reqwest::Client::new(), _engine: engine, dir }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_flow() {
    let c = setup().await;

    // Auth and host checks.
    let r = c.http.get(format!("{}/v1/status", c.base)).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.http.get(format!("{}/v1/status", c.base)).bearer_auth(&c.token).header("Host", "evil.com").send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(c.http.get(format!("{}/health", c.base)).send().await.unwrap().text().await.unwrap(), "ok");

    // Events over WebSocket.
    let ws_url = format!("ws://127.0.0.1:{}/v1/events?token={}", c.base.rsplit(':').next().unwrap(), c.token);
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let hello = ws.next().await.unwrap().unwrap();
    assert!(hello.to_text().unwrap().contains("hello"));

    let demo = c.post("/v1/demo", json!({})).await;
    assert_eq!(demo["account"].as_array().unwrap().len(), 2);
    let mut saw_accounts_changed = false;
    for _ in 0..20 {
        let Ok(Some(Ok(m))) = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await else { break };
        if m.to_text().unwrap_or("").contains("accounts_changed") {
            saw_accounts_changed = true;
            break;
        }
    }
    assert!(saw_accounts_changed);

    let accounts = c.get("/v1/accounts").await;
    assert_eq!(accounts.as_array().unwrap().len(), 2);
    let status = c.get("/v1/status").await;
    assert!(status["unread_total"].as_i64().unwrap() >= 4);

    let list = c.get("/v1/messages?mailbox=unified:inbox&threads=false").await;
    let msgs = list["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 10);
    let first = &msgs[0];
    assert!(first["subject"].as_str().is_some() && first["snippet"].as_str().unwrap().len() > 3);

    let found = c.get(&format!("/v1/messages?q={}", urlencode("纪要"))).await;
    assert_eq!(found["messages"].as_array().unwrap().len(), 1);
    let id = found["messages"][0]["id"].as_i64().unwrap();

    let detail = c.get(&format!("/v1/messages/{id}")).await;
    assert!(detail["html"].as_str().unwrap().contains("周五前"));
    assert_eq!(detail["attachments"].as_array().unwrap().len(), 1);
    assert!(detail["summary"].is_null(), "summary must be flattened");
    assert!(detail["is_vip"].as_bool().unwrap());

    let att = c.http.get(format!("{}/v1/messages/{id}/attachments/{}", c.base, detail["attachments"][0]["id"])).bearer_auth(&c.token).send().await.unwrap();
    assert!(att.headers()["content-disposition"].to_str().unwrap().contains("filename*=UTF-8''"));
    assert_eq!(att.bytes().await.unwrap().as_ref(), b"demo");

    // Actions + undo.
    let r = c.post("/v1/messages/actions", json!({"ids": [id], "action": "archive"})).await;
    let token = r["undo_token"].as_str().unwrap().to_string();
    let inbox = c.get("/v1/messages?mailbox=unified:inbox").await;
    assert!(inbox["messages"].as_array().unwrap().iter().all(|m| m["id"].as_i64() != Some(id)));
    assert_eq!(c.post("/v1/undo", json!({"token": token})).await["ok"], true);
    c.post("/v1/messages/actions", json!({"ids": [id], "action": "snooze", "until": 4102444800i64})).await;
    let snoozed = c.get("/v1/messages?mailbox=snoozed").await;
    assert_eq!(snoozed["messages"].as_array().unwrap().len(), 1);

    let counts = c.get("/v1/counts?mailboxes=unified:inbox,starred,category:promotions").await;
    assert!(counts["unified:inbox"]["unread"].as_i64().unwrap() >= 3);
    assert!(counts["category:promotions"]["total"].as_i64().unwrap() >= 1);

    // Reply template.
    let other = msgs.iter().find(|m| m["subject"].as_str().unwrap().contains("接口文档")).unwrap();
    let draft = c.get(&format!("/v1/messages/{}/reply?mode=reply_all", other["id"])).await;
    assert_eq!(draft["to"][0]["email"], "lisi@corp-demo.cn");
    assert!(draft["html"].as_str().unwrap().contains("写道"));

    // Settings / rules / templates.
    let mut s = c.get("/v1/settings").await;
    s["undo_send_secs"] = json!(10);
    let r = c.http.put(format!("{}/v1/settings", c.base)).bearer_auth(&c.token).json(&s).send().await.unwrap();
    assert!(r.status().is_success());
    assert_eq!(c.get("/v1/settings").await["undo_send_secs"], 10);
    let rule = c
        .post(
            "/v1/rules",
            json!({"name": "账单归档", "enabled": true, "match_all": true,
                   "conditions": [{"field": "subject", "op": "contains", "value": "账单"}],
                   "actions": [{"kind": "archive"}]}),
        )
        .await;
    let rid = rule["id"].as_str().unwrap();
    assert_eq!(c.post(&format!("/v1/rules/{rid}/run"), json!({})).await["affected"], 1);
    c.post("/v1/templates", json!({"name": "收到", "html": "<p>收到，谢谢！</p>"})).await;
    assert_eq!(c.get("/v1/templates").await.as_array().unwrap().len(), 1);

    let menu = c.get("/v1/menu").await;
    assert!(!menu["items"].as_array().unwrap().is_empty());
    assert!(menu["items"][0]["account_label"].as_str().is_some());

    let contacts = c.get(&format!("/v1/contacts?q={}", urlencode("李"))).await;
    assert_eq!(contacts[0]["email"], "lisi@corp-demo.cn");

    // Errors are JSON with a code.
    let r = c.http.get(format!("{}/v1/messages/999999", c.base)).bearer_auth(&c.token).send().await.unwrap();
    assert_eq!(r.status(), 404);
    assert_eq!(r.json::<Value>().await.unwrap()["code"], "not_found");
}

fn urlencode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

//! Demo data so the UI can be explored (and screenshotted on CI) without real accounts.

use super::{Engine, detail};
use crate::error::Result;
use crate::mime::build::{self, OutAttachment, Outgoing};
use crate::model::*;
use crate::store::{FolderSpec, NewMessage, now};

struct Sample {
    from: (&'static str, &'static str),
    subject: &'static str,
    html: &'static str,
    hours_ago: i64,
    seen: bool,
    flagged: bool,
    category: Category,
    attachment: Option<&'static str>,
}

const QQ: &[Sample] = &[
    Sample { from: ("王经理", "wang@corp-demo.cn"), subject: "Q4 产品规划评审会议纪要", html: "<p>各位好，</p><p>附件是今天评审会的纪要，请在<b>周五前</b>确认各自负责的事项。</p><ul><li>移动端改版：张三</li><li>支付接入：李四</li></ul><p>谢谢！</p>", hours_ago: 1, seen: false, flagged: true, category: Category::Primary, attachment: Some("会议纪要.pdf") },
    Sample { from: ("李四", "lisi@corp-demo.cn"), subject: "回复：接口文档更新", html: "<p>已更新到 v2.3，主要改动在鉴权部分，详见文档第 4 节。</p>", hours_ago: 3, seen: false, flagged: false, category: Category::Primary, attachment: None },
    Sample { from: ("支付宝", "service@alipay-demo.com"), subject: "您的 10 月账单已出", html: "<p>尊敬的用户，您 10 月共消费 ¥3,280.50，请于 11 月 9 日前还款。</p>", hours_ago: 5, seen: true, flagged: false, category: Category::Updates, attachment: None },
    Sample { from: ("京东", "newsletter@jd-demo.com"), subject: "双十一预售开启，爆款低至 5 折", html: "<h2 style=\"color:#e1251b\">双十一狂欢</h2><p>数码、家电、美妆全场满减，限时抢购！</p>", hours_ago: 8, seen: false, flagged: false, category: Category::Promotions, attachment: None },
    Sample { from: ("张三", "zhangsan@friend-demo.cn"), subject: "周末爬山？", html: "<p>周六早上 8 点西山门口集合，记得带水 ⛰️</p>", hours_ago: 26, seen: true, flagged: false, category: Category::Primary, attachment: None },
    Sample { from: ("微博", "notice@weibo-demo.com"), subject: "你关注的人发布了新微博", html: "<p>你有 12 条新动态，快来看看吧。</p>", hours_ago: 30, seen: true, flagged: false, category: Category::Social, attachment: None },
];

const GMAIL: &[Sample] = &[
    Sample { from: ("GitHub", "noreply@github-demo.com"), subject: "[mailbox] Pull request merged: Add IMAP IDLE support", html: "<p><b>#42</b> was merged into <code>main</code>.</p>", hours_ago: 2, seen: false, flagged: false, category: Category::Updates, attachment: None },
    Sample { from: ("Emily Chen", "emily@design-demo.io"), subject: "Updated mockups for the inbox view", html: "<p>Hi! I've attached the latest mockups. Let me know what you think about the new sidebar.</p><p>— Emily</p>", hours_ago: 4, seen: false, flagged: true, category: Category::Primary, attachment: Some("inbox-mockup.png") },
    Sample { from: ("Google Calendar", "calendar-notification@google-demo.com"), subject: "Invitation: Weekly sync @ Mon 10:00", html: "<p>You have been invited to <b>Weekly sync</b>.</p>", hours_ago: 20, seen: true, flagged: false, category: Category::Updates, attachment: None },
    Sample { from: ("Rust Weekly", "hello@rust-weekly-demo.org"), subject: "This Week in Rust 571", html: "<p>Hello and welcome to another issue of This Week in Rust!</p>", hours_ago: 50, seen: true, flagged: false, category: Category::Forums, attachment: None },
];

impl Engine {
    /// Creates two demo accounts with sample folders and messages. Returns their ids.
    pub fn seed_demo(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for (email, name, label, color, samples) in [
            ("me@qq-demo.com", "我", "QQ·工作", "#12B7F5", QQ),
            ("me@gmail-demo.com", "Me", "Gmail", "#E5484D", GMAIL),
        ] {
            if let Some(a) = self.db.accounts()?.into_iter().find(|a| a.email == email) {
                ids.push(a.id);
                continue;
            }
            let acc = self.db.insert_account(Account {
                kind: AccountKind::Imap,
                email: email.into(),
                name: name.into(),
                label: label.into(),
                color: color.into(),
                provider: Some("demo".into()),
                enabled: true,
                ..Default::default()
            })?;
            let mut folders = std::collections::HashMap::new();
            for (path, role) in [
                ("INBOX", FolderRole::Inbox),
                ("Sent", FolderRole::Sent),
                ("Drafts", FolderRole::Drafts),
                ("Archive", FolderRole::Archive),
                ("Trash", FolderRole::Trash),
                ("Junk", FolderRole::Junk),
                ("项目", FolderRole::Custom),
            ] {
                let id = self.db.upsert_folder(
                    &acc.id,
                    &FolderSpec { path: path.into(), name: path.into(), delimiter: Some("/".into()), role, selectable: true },
                )?;
                self.db.set_folder_state(id, Some(1), None, None)?;
                folders.insert(role, id);
            }
            for (i, s) in samples.iter().enumerate() {
                let date = now() - s.hours_ago * 3600;
                let attachments = s
                    .attachment
                    .map(|n| vec![OutAttachment { filename: n.into(), mime: build::guess_mime(n).into(), data: b"demo".to_vec(), content_id: None }])
                    .unwrap_or_default();
                let o = Outgoing {
                    from: EmailAddress::new(Some(s.from.0), s.from.1),
                    to: vec![EmailAddress::new(Some(name), email)],
                    subject: s.subject.into(),
                    html: Some(s.html.into()),
                    text: crate::html::html_to_text(s.html),
                    attachments,
                    message_id: format!("demo-{i}-{}", build::new_message_id(email)),
                    date,
                    ..Default::default()
                };
                let raw = build::build(&o, false)?;
                let (h, _) = crate::mime::parse_full(&raw);
                let nm = NewMessage {
                    account_id: acc.id.clone(),
                    folder_id: folders[&FolderRole::Inbox],
                    uid: Some(i as u32 + 1),
                    message_id: h.message_id.clone(),
                    subject: h.subject.clone(),
                    from: h.from.clone(),
                    to: h.to.clone(),
                    date,
                    size: raw.len() as i64,
                    flags: Flags { seen: s.seen, flagged: s.flagged, ..Default::default() },
                    category: s.category,
                    has_attachments: s.attachment.is_some(),
                    ..Default::default()
                };
                let (id, _) = self.db.insert_message(&nm)?;
                detail::store_body(self, id, &raw)?;
            }
            if label == "QQ·工作" {
                self.db.set_vip("wang@corp-demo.cn", true)?;
                self.db.record_contacts(&[EmailAddress::new(Some("李四"), "lisi@corp-demo.cn")], 3)?;
            }
            self.set_status(&acc.id, SyncState::Idle, None);
            ids.push(acc.id);
        }
        self.events.emit(crate::events::Event::AccountsChanged);
        self.changed(None);
        Ok(ids)
    }
}

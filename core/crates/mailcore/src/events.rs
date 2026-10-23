use crate::model::{AccountStatus, MessageSummary, OutboxStatus};
use serde::Serialize;
use tokio::sync::broadcast;

/// Pushed to the app over the WebSocket and to the helper through the FFI callback.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A new message arrived. `notify` tells whether a system notification should be shown.
    NewMail {
        account_id: String,
        account_label: String,
        account_color: String,
        message: MessageSummary,
        notify: bool,
        sound: bool,
    },
    /// Message list contents changed (flags, new mail, moves).
    MessagesChanged { account_id: Option<String> },
    FoldersChanged { account_id: String },
    AccountStatus { status: AccountStatus },
    AccountsChanged,
    Outbox { id: String, status: OutboxStatus, error: Option<String> },
    OAuth { state: String, ok: bool, email: Option<String>, error: Option<String> },
    UnreadCounts { total: i64, accounts: Vec<(String, i64)> },
    SettingsChanged,
    /// A snoozed message came back to the inbox.
    Snoozed { message_id: i64 },
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(512);
        EventBus { tx }
    }
}

impl EventBus {
    pub fn emit(&self, e: Event) {
        let _ = self.tx.send(e);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

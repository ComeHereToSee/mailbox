//! Mailbox core: account sync (IMAP / POP3 / SMTP), local store, search and the
//! local HTTP API used by the macOS app.

pub mod autoconfig;
pub mod error;
pub mod imap;
pub mod events;
pub mod forward;
pub mod ics;
pub mod model;
pub mod net;
pub mod paths;
pub mod pop3;
pub mod search;
pub mod secrets;
pub mod store;

pub use error::{Error, Result};

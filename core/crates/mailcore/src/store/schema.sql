CREATE TABLE accounts (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    email       TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    label       TEXT NOT NULL DEFAULT '',
    color       TEXT NOT NULL DEFAULT '',
    provider    TEXT,
    config      TEXT NOT NULL DEFAULT '{}',
    enabled     INTEGER NOT NULL DEFAULT 1,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE identities (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name            TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL,
    reply_to        TEXT,
    signature_html  TEXT NOT NULL DEFAULT '',
    is_default      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE folders (
    id              INTEGER PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    name            TEXT NOT NULL,
    delimiter       TEXT,
    role            TEXT NOT NULL DEFAULT 'custom',
    selectable      INTEGER NOT NULL DEFAULT 1,
    local           INTEGER NOT NULL DEFAULT 0,
    sync_enabled    INTEGER NOT NULL DEFAULT 1,
    uidvalidity     INTEGER,
    uidnext         INTEGER,
    highest_modseq  INTEGER,
    last_sync       INTEGER,
    UNIQUE (account_id, path)
);

CREATE TABLE messages (
    id              INTEGER PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id       INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    uid             INTEGER,
    remote_id       TEXT,
    message_id      TEXT,
    in_reply_to     TEXT,
    refs            TEXT NOT NULL DEFAULT '',
    thread_id       TEXT NOT NULL,
    subject         TEXT NOT NULL DEFAULT '',
    from_name       TEXT,
    from_email      TEXT NOT NULL DEFAULT '',
    to_json         TEXT NOT NULL DEFAULT '[]',
    cc_json         TEXT NOT NULL DEFAULT '[]',
    bcc_json        TEXT NOT NULL DEFAULT '[]',
    reply_to_json   TEXT NOT NULL DEFAULT '[]',
    date            INTEGER NOT NULL,
    sort_date       INTEGER NOT NULL,
    size            INTEGER NOT NULL DEFAULT 0,
    seen            INTEGER NOT NULL DEFAULT 0,
    flagged         INTEGER NOT NULL DEFAULT 0,
    answered        INTEGER NOT NULL DEFAULT 0,
    forwarded       INTEGER NOT NULL DEFAULT 0,
    draft           INTEGER NOT NULL DEFAULT 0,
    labels          TEXT NOT NULL DEFAULT '[]',
    has_attachments INTEGER NOT NULL DEFAULT 0,
    snippet         TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT 'primary',
    list_id         TEXT,
    unsubscribe     TEXT,
    blob            TEXT,
    pinned          INTEGER NOT NULL DEFAULT 0,
    snoozed_until   INTEGER,
    hidden          INTEGER NOT NULL DEFAULT 0,
    modseq          INTEGER,
    created_at      INTEGER NOT NULL
);

CREATE UNIQUE INDEX messages_folder_uid ON messages(folder_id, uid) WHERE uid IS NOT NULL;
CREATE INDEX messages_folder_sort ON messages(folder_id, sort_date DESC);
CREATE INDEX messages_account_sort ON messages(account_id, sort_date DESC);
CREATE INDEX messages_thread ON messages(thread_id);
CREATE INDEX messages_msgid ON messages(account_id, message_id);
CREATE INDEX messages_snoozed ON messages(snoozed_until) WHERE snoozed_until IS NOT NULL;
CREATE INDEX messages_remote ON messages(folder_id, remote_id) WHERE remote_id IS NOT NULL;
CREATE INDEX messages_from ON messages(from_email);
CREATE INDEX messages_irt ON messages(account_id, in_reply_to);

CREATE VIRTUAL TABLE messages_fts USING fts5(
    subject, addresses, body, attachments,
    content = '', contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE attachments (
    id          INTEGER PRIMARY KEY,
    message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_index  INTEGER NOT NULL,
    filename    TEXT NOT NULL DEFAULT '',
    mime_type   TEXT NOT NULL DEFAULT 'application/octet-stream',
    size        INTEGER NOT NULL DEFAULT 0,
    content_id  TEXT,
    inline      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX attachments_message ON attachments(message_id);

CREATE TABLE contacts (
    email           TEXT PRIMARY KEY COLLATE NOCASE,
    name            TEXT,
    use_count       INTEGER NOT NULL DEFAULT 0,
    last_used       INTEGER NOT NULL DEFAULT 0,
    vip             INTEGER NOT NULL DEFAULT 0,
    trusted_images  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE blocked (
    pattern     TEXT PRIMARY KEY COLLATE NOCASE,
    created_at  INTEGER NOT NULL
);

CREATE TABLE ops (
    id          INTEGER PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_try    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  INTEGER NOT NULL
);

CREATE TABLE outbox (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    draft       TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    to_json     TEXT NOT NULL DEFAULT '[]',
    send_at     INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued',
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  INTEGER NOT NULL
);

CREATE TABLE drafts (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    data        TEXT NOT NULL,
    server_uid  INTEGER,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE kv (
    space   TEXT NOT NULL,
    id      TEXT NOT NULL,
    data    TEXT NOT NULL,
    sort    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (space, id)
);

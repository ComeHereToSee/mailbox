# Mailbox 本地 API

引擎（`mailcore`）运行在 Mailbox Helper 进程里（或开发时的 `mailboxd`），监听 `127.0.0.1:47920`（被占用时随机端口）。
主程序、菜单栏、分享扩展都通过它访问数据。

- 连接信息：`~/Library/Application Support/Mailbox/daemon.json` → `{ "port", "token", "pid", "version" }`（仅本人可读，每次启动重新生成 token）
- 认证：`Authorization: Bearer <token>`，或查询参数 `?token=`（WebSocket / 图片）
- `Host` 必须是 `127.0.0.1:<port>` / `localhost:<port>`（防 DNS rebinding）
- 错误：HTTP 4xx/5xx + `{ "error": "中文说明", "code": "not_found|invalid|auth|network|imap|smtp|pop3|oauth|db|io|other" }`
  - 邮箱账号认证失败返回 **422**（`code: "auth"`），401 只表示 API token 无效
- 所有 JSON 字段为 `snake_case`，与 `core/crates/mailcore/src/model.rs` 一一对应

## 事件流

`GET /v1/events`（WebSocket，文本帧 JSON，按 `type` 区分）：

| type | 字段 |
|---|---|
| `hello` | `version` |
| `new_mail` | `account_id`, `account_label`, `account_color`, `message` (MessageSummary), `notify`, `sound` |
| `messages_changed` | `account_id?` |
| `folders_changed` | `account_id` |
| `account_status` | `status` (AccountStatus) |
| `accounts_changed` | — |
| `outbox` | `id`, `status` (queued/sending/sent/failed/cancelled), `error?` |
| `o_auth` | `state`, `ok`, `email?`, `error?` |
| `unread_counts` | `total`, `accounts`: `[[account_id, n]]` |
| `settings_changed` | — |
| `snoozed` | `message_id`（稍后提醒到期回到收件箱） |
| `resync` | 客户端落后太多，应整体刷新 |

## 接口

### 状态 / 账户
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/status` | `{version, accounts: [AccountStatus], unread_total, outbox}` |
| GET | `/v1/presets` | 内置邮箱服务商预设 `[Provider]` |
| POST | `/v1/autoconfig` | `{email}` → `Discovery`（预设 / MX / ISPDB / SRV / 猜测） |
| GET / POST | `/v1/accounts` | 列表 / 添加（`NewAccount`，默认先测试连接） |
| POST | `/v1/accounts/test` | `NewAccount` → `TestReport {ok, incoming, smtp}` |
| POST | `/v1/accounts/order` | `{ids}` 调整顺序 |
| GET / PUT / DELETE | `/v1/accounts/{id}` | PUT 体：`{account, password?, smtp_password?}` |
| POST | `/v1/accounts/{id}/sync` | 立即同步；`POST /v1/sync` 同步全部 |
| POST | `/v1/accounts/{id}/reauth` | `{oauth_state}` 重新授权 |
| GET / POST | `/v1/identities?account=` | 发件身份（含签名），POST 新建或更新 |
| DELETE | `/v1/identities/{id}` | |

`NewAccount`：`{kind: imap|pop3|web, email, name, label, color, provider, config: AccountConfig, password?, smtp_password?, oauth_state?, skip_test}`

### OAuth（Gmail / Outlook）
1. `POST /v1/oauth/start {provider: "google"|"microsoft", login_hint?}` → `{url, state}`
2. 用默认浏览器打开 `url`；用户登录后浏览器回调 `GET /oauth/callback`（无需 token）
3. 等待 `o_auth` 事件，或轮询 `GET /v1/oauth/{state}` → `{pending, done, email}`
4. `POST /v1/accounts` 时带上 `oauth_state` 与 `config.auth = "oauth2"`

### 文件夹
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/folders?account=` | `[Folder]`（含 unread / total / role） |
| POST | `/v1/folders` | `{account_id, name, parent_id?}` |
| PATCH | `/v1/folders/{id}` | `{name?, sync_enabled?}` |
| DELETE | `/v1/folders/{id}` | 仅自定义文件夹 |
| POST | `/v1/folders/{id}/sync` | 打开文件夹时请求优先同步 |

### 邮件
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/messages` | `mailbox`, `q`, `threads`, `before_date`, `before_id`, `limit`, `account` → `{messages, cursor}` |
| GET | `/v1/counts?mailboxes=a,b` | `{mailbox: {unread, total}}` |
| GET | `/v1/messages/{id}` | `MessageDetail`；`?open=1` 同时按设置标为已读 |
| GET | `/v1/messages/{id}/thread` | 会话中所有邮件 `[MessageDetail]` |
| GET | `/v1/messages/{id}/raw` | 原始邮件（message/rfc822） |
| GET | `/v1/messages/{id}/attachments/{aid}` | 附件内容 |
| POST | `/v1/messages/{id}/attachments/{aid}/file` | 落盘到缓存并返回 `{path}`（Quick Look / 拖出） |
| GET | `/v1/messages/{id}/cid/{cid}` | 内嵌图片（`mailbox-cid://` 方案处理器使用） |
| POST | `/v1/messages/actions` | `{ids, action, ...}` → `{affected, undo_token}` |
| POST | `/v1/messages/mark-all-read` | `{mailbox}` |
| POST | `/v1/undo` | `{token}` → `{ok}` |
| GET | `/v1/messages/{id}/reply?mode=` | `reply|reply_all|forward|forward_as_attachment` → `Draft` |
| GET | `/v1/messages/{id}/edit-draft` | 草稿箱中的邮件 → `Draft` |
| POST | `/v1/messages/{id}/rsvp` | `{partstat: ACCEPTED|TENTATIVE|DECLINED}` |
| POST | `/v1/messages/{id}/unsubscribe` | `{result: done, method}` 或 `{result: open_url, url}` |
| POST | `/v1/messages/{id}/read-receipt` | 发送已读回执 |
| POST | `/v1/messages/{id}/trust-images` | `{trusted}` 信任发件人的远程图片 |
| POST | `/v1/search/server` | `{account_id, folder_id?, q}` 服务器端搜索 |

`mailbox` 取值：`unified:<role>`、`account:<id>:<role>`、`folder:<id>`、`starred`、`unread`、`snoozed`、`pinned`、`attachments`、`vip`、`category:<primary|social|promotions|updates|forums>`、`label:<account>:<name>`、`smart:<id>`、`all`。

`action` 取值：`read` `unread` `flag` `unflag` `archive` `trash` `delete`（永久） `spam` `not_spam` `move_to_inbox` `move {folder_id}` `label {add, remove}` `snooze {until}` `unsnooze` `pin` `unpin` `category {category}`。

搜索语法（`q`）：自由文本（中文按双字切分）+ `from:` `to:` `cc:` `subject:` `body:` `filename:` `has:attachment` `is:unread|read|starred|pinned|snoozed|vip|answered` `in:inbox|sent|…|文件夹名` `label:` `account:` `category:` `before:2026-01-31` `after:` `older_than:7d` `newer_than:2w` `larger:5M` `smaller:`，前缀 `-` 取反，引号包含空格。

### 写信 / 发件箱
| 方法 | 路径 | 说明 |
|---|---|---|
| GET / POST | `/v1/drafts` | POST 保存草稿（`?sync=1` 同时上传到服务器草稿箱） |
| GET / DELETE | `/v1/drafts/{id}` | |
| POST | `/v1/send` | `{draft, send_at?}`；不带 `send_at` 时按“撤销发送”延迟发送 |
| GET | `/v1/outbox` | 待发送 / 失败 |
| POST | `/v1/outbox/{id}/cancel` | 撤销发送 → `{draft}` |
| POST | `/v1/outbox/{id}/retry` | 重试 |
| POST | `/v1/calendar/invite` | 生成会议邀请 `{uid, ics}` |

`Draft.attachments[]`：`{path}`（本地文件）或 `{message_id, attachment_id}`（转发原邮件附件）；HTML 中的 `data:` 图片会自动转成内嵌图片。

### 联系人 / 规则 / 其他
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/contacts?q=&limit=` | 收件人自动补全 |
| POST | `/v1/contacts/vip` | `{email, vip}`；`GET /v1/vips` |
| GET / POST / DELETE | `/v1/blocked` | `{pattern}`（地址或 `@域名`） |
| GET / POST | `/v1/rules` | `Rule`；`DELETE /v1/rules/{id}`；`POST /v1/rules/{id}/run` 对现有收件箱执行 |
| GET / POST | `/v1/templates` | 模板 / 快捷短语；`DELETE /v1/templates/{id}` |
| GET / POST | `/v1/smart-folders` | 智能文件夹（保存的搜索） |
| GET / POST | `/v1/forwarders` | 通知转发（Bark / Server酱 / 企业微信 …）；`POST /v1/forwarders/test` |
| GET / PUT | `/v1/settings` | `Settings` |
| POST | `/v1/notifications/pause` | `{minutes}`（0 = 恢复） |
| GET | `/v1/menu?limit=` | 菜单栏迷你收件箱 `{unread, items: [{message, account_label, account_color}], settings}` |
| POST | `/v1/import` | `{folder_id, path}`（.mbox / .eml / 目录） |
| POST | `/v1/export` | `{ids? \| folder_id?, path, format: mbox|eml}` |
| POST | `/v1/demo` | 生成演示数据 |

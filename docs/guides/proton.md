# ProtonMail

ProtonMail 是端到端加密邮箱，不直接提供 IMAP。需要先在本机运行官方的 **Proton Mail Bridge**（仅付费套餐可用）。

1. 安装并打开 Proton Mail Bridge：<https://proton.me/mail/bridge>，用 Proton 账户登录。
2. 在 Bridge 中点开账户，复制它显示的 **IMAP / SMTP 用户名和密码**。注意这不是 Proton 登录密码。
3. 在 Mailbox 中选择 ProtonMail：
   - 地址填你的 Proton 邮箱；
   - 密码填 Bridge 里的那个密码；
   - 用户名不同的话，在“高级”中改为手动配置。

默认服务器：IMAP `127.0.0.1:1143`（STARTTLS），SMTP `127.0.0.1:1025`（STARTTLS）。Bridge 使用自签名证书，预设已经打开“允许自签名证书”。

Bridge 需要保持运行。可以把它和 Mailbox 都设为登录时启动。

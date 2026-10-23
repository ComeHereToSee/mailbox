# QQ 邮箱 / Foxmail / 腾讯企业邮

QQ 邮箱不能用 QQ 密码登录第三方客户端，需要开启 IMAP/SMTP 服务，然后用**授权码**登录。

## 获取授权码

1. 在 Mailbox 中选择“QQ 邮箱”，点 **在内置浏览器中打开网页版**（也可以用自己的浏览器打开 <https://wx.mail.qq.com/>）。
2. 登录后进入 **设置 → 账号与安全 → 安全设置**。
3. 找到 **POP3/IMAP/SMTP/Exchange/CardDAV 服务**，开启 **IMAP/SMTP 服务**，按提示用手机验证。
4. 页面会显示一个 16 位**授权码**，复制它。
5. 回到 Mailbox，把授权码粘贴到“授权码”一栏（空格会自动去掉），点 **测试并添加**。

## 服务器（自动填写，一般不用改）

| 协议 | 服务器 | 端口 | 加密 |
|---|---|---|---|
| IMAP | imap.qq.com | 993 | SSL/TLS |
| POP3 | pop.qq.com | 995 | SSL/TLS |
| SMTP | smtp.qq.com | 465 | SSL/TLS |

- foxmail.com 邮箱使用同一套服务器。
- **腾讯企业邮**（exmail.qq.com）的服务器是 imap / pop / smtp.exmail.qq.com。它的授权方式由企业管理员设置：可能要求“客户端专用密码”，也可能直接用邮箱密码。

## 常见问题

- **“Login fail. Account is abnormal, service is not open…”**：IMAP 服务没有开启，或者用了 QQ 密码。请重新生成授权码。
- **改了 QQ 密码以后无法收信**：授权码会失效，生成新的授权码后，到 设置 → 账户 中更新。
- **只看到最近的邮件**：默认只缓存最近 90 天。可以在 设置 → 账户 → 本地缓存 中改成“全部”。

# Outlook / Hotmail / Live / Office 365

微软已经停用 Outlook.com 的密码登录，只能用 **OAuth** 浏览器登录。你需要在 Microsoft Entra 注册一个免费的应用，这是一次性操作。

## 注册应用

1. 打开 <https://entra.microsoft.com/>（或 Azure Portal），进入 **应用注册 → 新注册**。
2. 名称填 “Mailbox”。受支持的账户类型选择 **任何组织目录中的账户和个人 Microsoft 账户**。
3. 重定向 URI：平台选 **公共客户端/本机（移动和桌面）**，填 `http://localhost/oauth/callback`。
4. 注册完成后，复制概览页里的 **应用程序（客户端）ID**。
5. **API 权限 → 添加权限 → API 我的组织使用 / Microsoft Graph**，添加这些委托权限：
   - `IMAP.AccessAsUser.All`
   - `SMTP.Send`
   - `POP.AccessAsUser.All`
   - `offline_access`
   - `openid`、`email`
6. **身份验证** 页面：打开 **允许公共客户端流**。
7. 在 Mailbox 的 设置 → 高级 → OAuth 中，填写 Microsoft 应用程序 ID。
8. 添加账户时选择 Outlook → **在浏览器中登录**。

## 服务器

| | 服务器 | 端口 |
|---|---|---|
| IMAP | outlook.office365.com | 993 SSL/TLS |
| POP3 | outlook.office365.com | 995 SSL/TLS |
| SMTP（个人账户） | smtp-mail.outlook.com | 587 STARTTLS |
| SMTP（Office 365） | smtp.office365.com | 587 STARTTLS |

## 企业 / 学校账户

如果组织禁止用户授权第三方应用，需要管理员同意，或由管理员在租户里注册这个应用。部分组织还会关闭 IMAP，这种情况请联系 IT 管理员。

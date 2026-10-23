# 推送到手机 / 微信 / 群聊

Mailbox 在 Mac 上用系统通知提醒新邮件。如果还想推送到手机或聊天工具：

1. 打开 设置 → 推送转发 → **添加推送**，选择一种渠道并填写参数。
2. 点 **测试**，确认能收到推送。
3. 推送和系统通知遵循同一套规则：免打扰、仅 VIP、分类过滤都会生效。

推送内容只有：账户名、发件人、主题和一句摘要，不含正文和附件。

| 渠道 | 需要填写 | 获取方式 |
|---|---|---|
| **Bark**（iPhone，走苹果推送 APNs） | Device Key | App Store 安装 Bark，复制首页 URL 中的 key |
| **Server酱**（推送到个人微信） | SendKey | <https://sct.ftqq.com/> 微信扫码登录 |
| **PushPlus**（推送到微信） | Token | <https://www.pushplus.plus/> |
| **企业微信群机器人** | Webhook 地址 | 群设置 → 群机器人 → 添加 |
| **飞书机器人** | Webhook 地址，可选签名密钥 | 群设置 → 群机器人 → 自定义机器人 |
| **钉钉机器人** | Webhook 地址，可选加签密钥 / 关键词 | 群设置 → 机器人 → 自定义 |
| **Telegram** | Bot Token、Chat ID | @BotFather 创建机器人 |
| **ntfy** | Topic | <https://ntfy.sh/> 或自建 |
| **Webhook** | URL | 会 POST 一段 JSON：`{account_label, from, subject, snippet, date, message_url}` |

> 个人微信、QQ 号没有官方的消息接口；第三方的“个人号机器人”违反服务条款，可能导致封号，所以 Mailbox 不提供。
> 想把一封邮件发到微信或 QQ，可以在邮件的“更多 → 分享”里选择微信 / QQ。需要先安装对应的 Mac 客户端，它们会出现在分享菜单里。

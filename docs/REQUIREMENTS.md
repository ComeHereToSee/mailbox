# Mailbox 需求说明（已对齐）

> 本文是与用户对齐后的需求基线。AI 功能不在本仓库，见 `ComeHereToSee/mailbox-ai`。

## 1. 定位与决策

| 项目 | 决定 |
|---|---|
| 平台 | macOS 14 Sonoma 及以上，Universal（Apple 芯片 + Intel） |
| 技术路线 | SwiftUI 原生界面 + Rust 核心（收发、同步、存储、搜索全部在 Rust） |
| 用途 | 自用 / 小圈子，不上架 |
| 签名 | 无苹果开发者账号 → ad-hoc 本地签名；首次打开需右键「打开」或移除隔离属性 |
| 推送 | 本地后台轻服务（登录项）+ IMAP IDLE 实时收信 + macOS 系统通知；可选转发到 Bark（APNs）/ Server酱 / 企业微信 / 飞书 / 钉钉 / Telegram |
| 登录 | Gmail / Outlook 走 OAuth（在默认浏览器里登录，像 Chrome 一样）；QQ / 163 / 126 等走授权码（内置浏览器引导）；另有通用 IMAP/POP3 手动配置；「网页模式」兜底 |
| 微信 / QQ | 系统分享菜单 + 通知转发；不做个人号机器人（违反条款、会封号） |
| OAuth 客户端 | 用户在设置里填写自己注册的 Google / Microsoft 客户端 ID（提供图文教程）；同时支持应用专用密码 |
| 界面语言 | 中文为主，带英文 |
| 交付范围 | M1 + M2 + M3（全部 P0 / P1 / P2） |

## 2. 账户与协议

- 协议：IMAP（IDLE、CONDSTORE、MOVE、UIDPLUS、ID、Gmail 扩展 X-GM-LABELS / X-GM-THRID）、POP3（STLS、UIDL、保留/定期删除）、SMTP（SSL / STARTTLS、PLAIN / LOGIN / XOAUTH2）、Microsoft Graph（可选）、JMAP（Fastmail 等，可选）
- 认证：密码、授权码、应用专用密码、OAuth2（PKCE + 本地回环回调，自动刷新令牌）
- 内置预设：Gmail、Outlook / Hotmail / Live / MSN、Office 365、QQ、Foxmail、163、126、yeah.net、188、iCloud、Yahoo、AOL、ProtonMail（Bridge）、腾讯企业邮、阿里邮箱（个人 / 企业）、网易企业邮、新浪、搜狐、Zoho、Fastmail、GMX、Yandex、mail.ru
- 自动发现：内置预设 → MX 记录识别托管商 → Mozilla ISPDB → 域名 autoconfig → DNS SRV → 主机名猜测
- 网易系必须发送 IMAP `ID` 命令，否则报 `Unsafe Login`
- 多账户：统一收件箱、账户自定义名称 / 颜色 / 图标、多发件身份（别名）、每身份签名
- 每账户可设：是否通知、同步窗口、发送后是否保存到已发送、允许自签名证书

## 3. 后台与提醒

- 「Mailbox Helper」作为登录项常驻：持有同步引擎、IDLE 长连接、菜单栏图标（未读数 + 迷你收件箱）
- 主程序关掉也不影响收信；主程序只是界面
- 通知标题注明账户：`[QQ·工作] 张三`，副标题为主题，正文为摘要；按账户分组
- 通知按钮：标为已读、归档、删除、快速回复
- 通知策略：每账户开关、仅 VIP、按分类过滤（如推广不提醒）、免打扰时段、暂停 1 小时
- Dock 角标
- 外部转发（M3）：Bark、Server酱、PushPlus、企业微信机器人、飞书机器人、钉钉机器人、Telegram Bot、通用 Webhook

## 4. 功能清单

### 读信
- P0：统一收件箱、按账户 / 文件夹浏览、HTML 安全渲染（禁 JS、默认阻止远程图片与跟踪像素）、附件 Quick Look 预览与保存
- P1：会话（线程）视图、查看原始邮件、打印 / 导出 PDF、链接真实地址提示
### 处理
- P0：已读 / 未读、星标、归档、删除、移动、垃圾邮件、批量多选
- P1：Gmail 标签、置顶、稍后提醒（Snooze）、一键退订（RFC 8058）、拉黑、撤销操作、Gmail 风格快捷键、滑动手势
### 写信
- P0：富文本（字体、字号、颜色、粗斜体、列表、引用、表格、图片、链接、对齐、清除格式）、收件人 / 抄送 / 密送 + 联系人补全、回复 / 全部回复 / 转发、附件拖拽 / 粘贴、草稿自动保存、发件箱失败重试
- P1：撤销发送、定时发送、模板与快捷短语、多身份签名、作为附件转发、Markdown / 纯文本模式、已读回执请求
### 搜索
- P0：本地全文搜索（中文双字切分）
- P1：服务器端搜索、高级语法（`from:` `to:` `subject:` `has:attachment` `is:unread` `is:starred` `before:` `after:` `in:` `label:` `account:`）、保存为智能文件夹
### 规则与分类
- P1：本地过滤规则（条件 → 动作）、自动分类（主要 / 社交 / 推广 / 通知 / 论坛）、VIP
- P2：服务器端 Sieve 规则（ManageSieve）
### 日历
- P1：识别 iCalendar 邀请 → 接受 / 暂定 / 拒绝（发送 iMIP 回复）、加入系统日历（EventKit）、从邮件创建日程 / 提醒事项
### 系统集成
- P0：设为默认邮件应用（mailto:）
- P1：分享扩展（任意 App → 新邮件）、服务菜单、系统分享（微信 / QQ / AirDrop / 备忘录）、菜单栏迷你收件箱
- P2：Spotlight 索引、快捷指令（App Intents）、Touch ID 应用锁
### 安全与数据
- P0：凭据加密存储（主密钥在钥匙串）
- P1：钓鱼提示（显示名伪装、链接不一致）、缓存范围控制、存储清理
- P2：S/MIME / PGP（解密 / 验签 / 签名 / 加密）、本地数据库加密、导入导出 mbox / eml
### 外观
- P0：浅色 / 深色、中英文
- P1：列表密度、三栏 / 两栏布局
### 网页模式（M3）
- 任意网页邮箱嵌入为账户标签页，独立 Cookie 存储，拦截网页通知转为系统通知

## 5. 非功能要求

- 轻量：Helper 常驻内存目标 < 40 MB，主程序空闲 < 150 MB，安装包 < 30 MB
- 离线优先：所有操作先改本地，再排队同步到服务器，失败自动重试
- 隐私：不经过任何第三方服务器；凭据只存本机
- 可测试：协议层在 Linux 上用 Dovecot / GreenMail 做集成测试；macOS 包由 GitHub Actions 构建

## 6. 里程碑

- M0：工程骨架、CI、Rust 核心与测试
- M1：账户添加（预设 / 自动发现 / OAuth / 授权码）、IMAP / POP3 / SMTP、收信读信、富文本写信、附件、后台 + 通知、本地搜索
- M2：全部 P1
- M3：全部 P2 + 网页模式 + 通知转发 + Graph / JMAP

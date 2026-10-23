import AppKit
import SwiftUI
import WebKit

/// Add-account flow: pick a provider (or type an address), then OAuth, 授权码 or manual servers.
struct AddAccountView: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    enum Step: Equatable {
        case choose
        case oauth
        case password
        case manual
        case web
    }

    @State private var step: Step = .choose
    @State private var presets: [Provider] = []
    @State private var provider: Provider?
    @State private var email = ""
    @State private var name = NSFullUserName()
    @State private var label = ""
    @State private var password = ""
    @State private var smtpPassword = ""
    @State private var usePop = false
    @State private var busy = false
    @State private var error: String?
    @State private var discovery: Discovery?
    @State private var oauthState: String?
    @State private var oauthEmail: String?
    @State private var showWebLogin = false
    @State private var showAdvanced = false
    // manual
    @State private var imap = ServerConfig(host: "", port: 993, security: .tls)
    @State private var pop = ServerConfig(host: "", port: 995, security: .tls)
    @State private var smtp = ServerConfig(host: "", port: 465, security: .tls)
    @State private var acceptInvalid = false
    // web mode
    @State private var webURL = "https://"

    private let featured = ["qq", "163", "126", "gmail", "outlook", "icloud", "yahoo", "exmail", "aliyun_qiye", "proton", "sina", "139"]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                if step != .choose {
                    Button { step = .choose; error = nil } label: { Image(systemName: "chevron.left") }.buttonStyle(.borderless)
                }
                Text(title).font(.title3.weight(.semibold))
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            .padding()
            Divider()
            ScrollView {
                Group {
                    switch step {
                    case .choose: chooseView
                    case .oauth: oauthView
                    case .password: passwordView
                    case .manual: manualView
                    case .web: webView
                    }
                }
                .padding(20)
            }
            if let error {
                Divider()
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .padding(.horizontal, 20).padding(.vertical, 10)
            }
        }
        .frame(width: 640, height: 600)
        .task { presets = (try? await state.api.presets()) ?? [] }
        .sheet(isPresented: $showWebLogin) {
            if let p = provider, let s = p.webUrl, let url = URL(string: s) {
                WebLoginSheet(url: url, steps: p.helpSteps, passwordLabel: p.passwordLabel) { code in
                    if let code { password = code }
                    showWebLogin = false
                }
            }
        }
    }

    private var title: String {
        switch step {
        case .choose: return "添加邮箱账户"
        case .oauth, .password: return provider?.name ?? "登录"
        case .manual: return "手动设置"
        case .web: return "网页邮箱"
        }
    }

    // MARK: choose

    private var chooseView: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 8) {
                Text("输入邮箱地址，自动识别服务器").font(.headline)
                HStack {
                    TextField("name@example.com", text: $email)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { Task { await discover() } }
                    Button("继续") { Task { await discover() } }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!email.contains("@") || busy)
                }
                if busy { ProgressView().controlSize(.small) }
            }
            Text("或选择邮箱服务商").font(.headline)
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                ForEach(featured.compactMap { id in presets.first { $0.id == id } }) { p in
                    Button { pick(p) } label: {
                        VStack(spacing: 6) {
                            Circle().fill(Color(hex: p.color, fallback: .blue).gradient).frame(width: 34, height: 34)
                                .overlay(Text(String(p.label.prefix(2))).font(.caption.bold()).foregroundStyle(.white))
                            Text(p.name).font(.caption).lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }
                Button { step = .manual } label: {
                    VStack(spacing: 6) {
                        Image(systemName: "server.rack").font(.title2).frame(width: 34, height: 34)
                        Text("其他 IMAP / POP3").font(.caption)
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
                Button { step = .web } label: {
                    VStack(spacing: 6) {
                        Image(systemName: "globe").font(.title2).frame(width: 34, height: 34)
                        Text("网页模式").font(.caption)
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
            Text("Gmail / Outlook 通过浏览器登录授权；QQ、163、126 等需要在网页版设置中开启 IMAP 并生成授权码，我们会一步步引导你。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func pick(_ p: Provider) {
        provider = p
        error = nil
        label = p.label
        if p.auth == .oauth2 {
            step = .oauth
        } else {
            step = .password
        }
    }

    private func discover() async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let d = try await state.api.autoconfig(email: email.trimmingCharacters(in: .whitespaces))
            discovery = d
            if let p = d.provider {
                provider = p
                label = p.label
                step = p.auth == .oauth2 ? .oauth : .password
            } else {
                if let i = d.imap.first { imap = i }
                if let p = d.pop3.first { pop = p }
                if let s = d.smtp.first { smtp = s }
                step = .manual
            }
        } catch {
            self.error = error.localizedDescription
            step = .manual
        }
    }

    // MARK: OAuth

    private var oauthConfigured: Bool {
        switch provider?.oauthProvider {
        case "google": return !state.settings.oauth.googleClientId.isEmpty
        case "microsoft": return !state.settings.oauth.microsoftClientId.isEmpty
        default: return false
        }
    }

    private var oauthView: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !oauthConfigured {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("需要先配置 OAuth 客户端 ID", systemImage: "key").font(.headline)
                        Text(provider?.oauthProvider == "google"
                             ? "Google 要求每个应用使用自己注册的客户端。按照文档《Gmail 登录配置》在 Google Cloud 创建一个“桌面应用”客户端，把客户端 ID 和密钥填到 设置 → 高级 → OAuth。"
                             : "在 Microsoft Entra（Azure）注册一个应用（支持个人账户，重定向 URI 填 http://localhost/oauth/callback），把应用程序 ID 填到 设置 → 高级 → OAuth。")
                            .font(.callout).foregroundStyle(.secondary)
                        HStack {
                            SettingsLink { Text("打开设置") }
                            if let p = provider, p.id == "gmail" || p.id == "yahoo" {
                                Button("改用应用专用密码") { step = .password }
                            }
                        }
                    }
                    .padding(6)
                }
            }
            TextField("邮箱地址（可选，用于预填登录）", text: $email).textFieldStyle(.roundedBorder)
            TextField("显示名称", text: $name).textFieldStyle(.roundedBorder)
            TextField("账户标签（通知中显示，如：Gmail·个人）", text: $label).textFieldStyle(.roundedBorder)
            HStack {
                Button {
                    Task { await startOAuth() }
                } label: {
                    Label(oauthState == nil ? "在浏览器中登录" : "重新打开登录页面", systemImage: "safari")
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .disabled(!oauthConfigured || busy)
                if busy { ProgressView().controlSize(.small) }
            }
            if let e = oauthEmail {
                Label("已授权：\(e)", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
            } else if oauthState != nil {
                Text("请在浏览器中完成登录，完成后会自动回到这里…").foregroundStyle(.secondary)
            }
            Text("登录在你的默认浏览器中进行（就像在 Chrome 里登录一样），Mailbox 不会看到你的密码，只保存访问令牌。")
                .font(.caption).foregroundStyle(.secondary)
            if let notes = provider?.notes, !notes.isEmpty {
                Text(notes).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func startOAuth() async {
        guard let p = provider, let op = p.oauthProvider else { return }
        busy = true
        error = nil
        do {
            let r = try await state.api.startOAuth(provider: op, loginHint: email.isEmpty ? nil : email)
            oauthState = r.state
            NSWorkspace.shared.open(r.url)
            for _ in 0..<600 {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                let s = try await state.api.oauthStatus(r.state)
                if s.done {
                    oauthEmail = s.email
                    if let e = s.email, !e.isEmpty { email = e }
                    await finishOAuth(state: r.state)
                    break
                }
            }
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    private func finishOAuth(state oauth: String) async {
        guard let p = provider else { return }
        var cfg = AccountConfig()
        cfg.imap = p.imap
        cfg.smtp = p.smtp
        cfg.auth = .oauth2
        cfg.oauthProvider = p.oauthProvider
        cfg.sendId = p.sendId
        cfg.saveSentCopy = p.saveSentCopy
        var req = NewAccount()
        req.kind = .imap
        req.email = email
        req.name = name
        req.label = label
        req.color = p.color
        req.provider = p.id
        req.config = cfg
        req.oauthState = oauth
        await add(req)
    }

    // MARK: password / 授权码

    private var passwordView: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let p = provider, !p.helpSteps.isEmpty {
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("获取\(p.passwordLabel)", systemImage: "lightbulb").font(.headline)
                        ForEach(Array(p.helpSteps.enumerated()), id: \.offset) { i, s in
                            Text("\(i + 1). \(s)").font(.callout)
                        }
                        HStack {
                            if p.webUrl != nil {
                                Button("在内置浏览器中打开网页版") { showWebLogin = true }
                            }
                            if let h = p.helpUrl, let url = URL(string: h) {
                                Button("官方说明") { NSWorkspace.shared.open(url) }
                            }
                        }
                        .padding(.top, 4)
                    }
                    .padding(6)
                }
            }
            if provider?.requiresBridge == true {
                Label("ProtonMail 需要先安装并登录 Proton Mail Bridge（付费套餐），在 Bridge 中复制邮箱密码填到下面。", systemImage: "info.circle")
                    .font(.callout).foregroundStyle(.secondary)
            }
            TextField("邮箱地址", text: $email).textFieldStyle(.roundedBorder)
            SecureField(provider?.passwordLabel ?? "密码", text: $password).textFieldStyle(.roundedBorder)
            TextField("显示名称（发信人名字）", text: $name).textFieldStyle(.roundedBorder)
            TextField("账户标签（通知中显示，如：QQ·工作）", text: $label).textFieldStyle(.roundedBorder)
            DisclosureGroup("高级", isExpanded: $showAdvanced) {
                VStack(alignment: .leading) {
                    Toggle("使用 POP3 收信（默认 IMAP）", isOn: $usePop).disabled(provider?.pop3 == nil)
                    SecureField("SMTP 密码（与上面不同时填写）", text: $smtpPassword).textFieldStyle(.roundedBorder)
                    Button("改为手动配置服务器") {
                        if let p = provider {
                            imap = p.imap ?? imap
                            pop = p.pop3 ?? pop
                            smtp = p.smtp ?? smtp
                        }
                        step = .manual
                    }
                }
                .padding(.top, 6)
            }
            HStack {
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("测试并添加") { Task { await addWithPassword() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || !email.contains("@") || password.isEmpty)
            }
        }
    }

    private func addWithPassword() async {
        guard let p = provider else { return }
        var cfg = AccountConfig()
        cfg.imap = usePop ? nil : p.imap
        cfg.pop3 = usePop ? p.pop3 : nil
        cfg.smtp = p.smtp
        cfg.sendId = p.sendId
        cfg.saveSentCopy = p.saveSentCopy
        var req = NewAccount()
        req.kind = usePop ? .pop3 : .imap
        req.email = email.trimmingCharacters(in: .whitespaces)
        req.name = name
        req.label = label
        req.color = p.color
        req.provider = p.id
        req.config = cfg
        req.password = password
        req.smtpPassword = smtpPassword.isEmpty ? nil : smtpPassword
        await add(req)
    }

    // MARK: manual

    private var manualView: some View {
        VStack(alignment: .leading, spacing: 12) {
            if discovery != nil && discovery?.provider == nil {
                Text("已根据 \(discovery?.source ?? "") 自动填写，请核对。").font(.caption).foregroundStyle(.secondary)
            }
            TextField("邮箱地址", text: $email).textFieldStyle(.roundedBorder)
            SecureField("密码 / 授权码", text: $password).textFieldStyle(.roundedBorder)
            TextField("显示名称", text: $name).textFieldStyle(.roundedBorder)
            TextField("账户标签", text: $label).textFieldStyle(.roundedBorder)
            Picker("收信协议", selection: $usePop) {
                Text("IMAP").tag(false)
                Text("POP3").tag(true)
            }
            .pickerStyle(.segmented)
            .frame(width: 240)
            GroupBox(usePop ? "POP3 服务器" : "IMAP 服务器") {
                ServerFields(server: usePop ? $pop : $imap)
            }
            GroupBox("SMTP 发信服务器") {
                ServerFields(server: $smtp)
                SecureField("SMTP 密码（不同于收信密码时填写）", text: $smtpPassword).textFieldStyle(.roundedBorder)
            }
            Toggle("允许自签名证书（仅限自建服务器）", isOn: $acceptInvalid)
            HStack {
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("测试并添加") { Task { await addManual() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || !email.contains("@"))
            }
        }
    }

    private func addManual() async {
        var cfg = AccountConfig()
        var incoming = usePop ? pop : imap
        incoming.acceptInvalidCerts = acceptInvalid
        var out = smtp
        out.acceptInvalidCerts = acceptInvalid
        if usePop { cfg.pop3 = incoming } else { cfg.imap = incoming }
        cfg.smtp = out
        var req = NewAccount()
        req.kind = usePop ? .pop3 : .imap
        req.email = email.trimmingCharacters(in: .whitespaces)
        req.name = name
        req.label = label
        req.config = cfg
        req.password = password
        req.smtpPassword = smtpPassword.isEmpty ? nil : smtpPassword
        await add(req)
    }

    // MARK: web mode

    private var webView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("把任意网页邮箱嵌入为一个账户：直接用网页登录，适合不支持 IMAP 的邮箱。网页内的新邮件提醒会转为系统通知。")
                .font(.callout).foregroundStyle(.secondary)
            TextField("网页邮箱地址，如 https://mail.qq.com", text: $webURL).textFieldStyle(.roundedBorder)
            TextField("名称", text: $label).textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("添加") { Task { await addWeb() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(URL(string: webURL)?.host == nil)
            }
        }
    }

    private func addWeb() async {
        guard let url = URL(string: webURL), let host = url.host else { return }
        var cfg = AccountConfig()
        cfg.webUrl = webURL
        var req = NewAccount()
        req.kind = .web
        req.email = host
        req.label = label.isEmpty ? host : label
        req.config = cfg
        req.skipTest = true
        await add(req)
    }

    private func add(_ req: NewAccount) async {
        busy = true
        defer { busy = false }
        error = nil
        do {
            let acc = try await state.api.addAccount(req)
            await state.reloadAll()
            state.select(mailbox: acc.kind == .web ? "web:\(acc.id)" : "account:\(acc.id):inbox")
            dismiss()
        } catch let e as APIError {
            error = hint(for: e)
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func hint(for e: APIError) -> String {
        var msg = e.message
        if e.isAuth {
            switch provider?.id {
            case "qq", "exmail":
                msg += "\n提示：QQ 邮箱需在网页版 设置 → 账号与安全 中开启 IMAP/SMTP 服务，并使用生成的授权码（不是 QQ 密码）。"
            case "163", "126", "yeah", "188":
                msg += "\n提示：网易邮箱需在网页版 设置 → POP3/SMTP/IMAP 中开启服务，并使用授权码登录。"
            case "gmail":
                msg += "\n提示：Gmail 需开启两步验证并生成“应用专用密码”，或使用浏览器登录（OAuth）。"
            case "icloud":
                msg += "\n提示：请在 appleid.apple.com 生成 App 专用密码。"
            default:
                break
            }
        }
        return msg
    }
}

struct ServerFields: View {
    @Binding var server: ServerConfig

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 8) {
            GridRow {
                Text("服务器").foregroundStyle(.secondary)
                TextField("imap.example.com", text: $server.host).textFieldStyle(.roundedBorder)
            }
            GridRow {
                Text("端口").foregroundStyle(.secondary)
                HStack {
                    TextField("993", value: $server.port, format: .number.grouping(.never)).textFieldStyle(.roundedBorder).frame(width: 80)
                    Picker("", selection: $server.security) {
                        ForEach(ConnectionSecurity.allCases) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                    .frame(width: 140)
                }
            }
            GridRow {
                Text("用户名").foregroundStyle(.secondary)
                TextField("默认使用邮箱地址", text: Binding(get: { server.username ?? "" }, set: { server.username = $0.isEmpty ? nil : $0 }))
                    .textFieldStyle(.roundedBorder)
            }
        }
        .padding(6)
    }
}

/// In-app browser for webmail settings pages (to turn on IMAP and create an 授权码).
struct WebLoginSheet: View {
    let url: URL
    let steps: [String]
    let passwordLabel: String
    let onDone: (String?) -> Void
    @State private var code = ""

    var body: some View {
        HSplitView {
            BrowserView(url: url)
                .frame(minWidth: 620, minHeight: 560)
            VStack(alignment: .leading, spacing: 10) {
                Text("操作步骤").font(.headline)
                ForEach(Array(steps.enumerated()), id: \.offset) { i, s in
                    Text("\(i + 1). \(s)").font(.callout)
                }
                Divider()
                Text("拿到\(passwordLabel)后粘贴到这里").font(.callout)
                TextField(passwordLabel, text: $code).textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                Spacer()
                HStack {
                    Button("取消") { onDone(nil) }
                    Spacer()
                    Button("使用此\(passwordLabel)") { onDone(code.replacingOccurrences(of: " ", with: "")) }
                        .buttonStyle(.borderedProminent)
                        .disabled(code.isEmpty)
                }
            }
            .padding()
            .frame(width: 260)
        }
        .frame(width: 940, height: 640)
    }
}

struct BrowserView: NSViewRepresentable {
    let url: URL
    var dataStore: WKWebsiteDataStore = .default()

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = dataStore
        let web = WKWebView(frame: .zero, configuration: config)
        web.customUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        web.load(URLRequest(url: url))
        return web
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

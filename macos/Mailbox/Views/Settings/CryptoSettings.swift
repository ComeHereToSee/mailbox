import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// PGP keys and S/MIME certificates: import, generate, export, delete; signing / encryption defaults.
struct CryptoSettings: View {
    @EnvironmentObject private var state: AppState
    @State private var keys: [KeyInfo] = []
    @State private var error: String?
    @State private var showGenerate = false
    @State private var showPaste = false
    @State private var pendingP12: Data?
    @State private var p12Password = ""
    @State private var passphraseFor: KeyInfo?
    @State private var passphrase = ""

    var body: some View {
        Form {
            Section {
                Picker("同时可用时优先使用", selection: $state.settings.cryptoPrefer) {
                    Text("OpenPGP").tag("pgp")
                    Text("S/MIME").tag("smime")
                }
                Toggle("新邮件默认数字签名", isOn: $state.settings.cryptoSignDefault)
                Toggle("所有收件人都有公钥时自动加密", isOn: $state.settings.cryptoAutoEncrypt)
            } header: {
                Text("签名与加密")
            } footer: {
                Text("收到的加密邮件会用你的私钥自动解密，签名会自动验证。别人发来的 S/MIME 签名邮件会自动保存对方证书，方便回信时加密。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("我的密钥和联系人公钥") {
                if keys.isEmpty {
                    Text("还没有密钥。可以生成一把新的 PGP 密钥，或导入已有的 PGP 密钥 / S/MIME 证书（.p12）。")
                        .foregroundStyle(.secondary)
                }
                ForEach(keys) { k in
                    KeyRow(key: k) { action in handle(action, k) }
                }
                HStack {
                    Button("生成 PGP 密钥…") { showGenerate = true }
                    Button("导入文件…") { importFile() }
                    Button("粘贴公钥…") { showPaste = true }
                }
            }
            if let error {
                Text(error).foregroundStyle(.red).font(.callout)
            }
        }
        .formStyle(.grouped)
        .task { await load() }
        .onChange(of: state.settings) { _, _ in
            Task { _ = try? await state.api.saveSettings(state.settings) }
        }
        .sheet(isPresented: $showGenerate) {
            GenerateKeySheet(identities: state.identities) { await load() }
        }
        .sheet(isPresented: $showPaste) {
            PasteKeySheet { await load() }
        }
        .sheet(isPresented: Binding(get: { pendingP12 != nil }, set: { if !$0 { pendingP12 = nil } })) {
            VStack(alignment: .leading, spacing: 12) {
                Text("输入证书文件的密码").font(.headline)
                SecureField("密码", text: $p12Password).frame(width: 300)
                HStack {
                    Spacer()
                    Button("取消") { pendingP12 = nil }
                    Button("导入") {
                        let data = pendingP12
                        pendingP12 = nil
                        if let data { submit(KeyImportRequest(dataBase64: data.base64EncodedString(), password: p12Password)) }
                        p12Password = ""
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(20)
        }
        .sheet(item: $passphraseFor) { k in
            VStack(alignment: .leading, spacing: 12) {
                Text("私钥口令").font(.headline)
                Text("保存后，签名和解密时不再询问。口令加密保存在本机。").font(.caption).foregroundStyle(.secondary)
                SecureField("口令（留空表示清除）", text: $passphrase).frame(width: 300)
                HStack {
                    Spacer()
                    Button("取消") { passphraseFor = nil }
                    Button("保存") {
                        let value = passphrase
                        passphraseFor = nil
                        passphrase = ""
                        Task {
                            do { try await state.api.setKeyPassphrase(k.id, value.isEmpty ? nil : value) }
                            catch { self.error = error.localizedDescription }
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(20)
        }
    }

    private func load() async {
        keys = (try? await state.api.keys()) ?? []
    }

    private func submit(_ req: KeyImportRequest) {
        Task {
            do {
                _ = try await state.api.importKey(req)
                error = nil
                await load()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func importFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = ["asc", "pgp", "gpg", "key", "pub", "p12", "pfx", "pem", "cer", "crt", "der"]
            .compactMap { UTType(filenameExtension: $0) }
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            guard let data = try? Data(contentsOf: url) else { continue }
            let ext = url.pathExtension.lowercased()
            if ext == "p12" || ext == "pfx" {
                p12Password = ""
                pendingP12 = data
            } else if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN") {
                submit(KeyImportRequest(text: text))
            } else {
                submit(KeyImportRequest(dataBase64: data.base64EncodedString()))
            }
        }
    }

    private func handle(_ action: KeyRow.Action, _ k: KeyInfo) {
        switch action {
        case .copyPublic:
            Task {
                guard let text = try? await state.api.exportKey(k.id) else { return }
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                state.show(Toast(text: "公钥已复制"))
            }
        case .exportPublic, .exportSecret:
            let secret = action == .exportSecret
            if secret {
                let alert = NSAlert()
                alert.messageText = "导出私钥？"
                alert.informativeText = "任何拿到私钥文件的人都能解密你的邮件、以你的名义签名。请妥善保管。"
                alert.addButton(withTitle: "导出")
                alert.addButton(withTitle: "取消")
                guard alert.runModal() == .alertFirstButtonReturn else { return }
            }
            Task {
                do {
                    let text = try await state.api.exportKey(k.id, secret: secret)
                    let panel = NSSavePanel()
                    let base = k.emails.first ?? k.shortId
                    let ext = k.kind == "smime" ? "pem" : "asc"
                    panel.nameFieldStringValue = secret ? "\(base)-私钥.\(ext)" : "\(base).\(ext)"
                    guard panel.runModal() == .OK, let url = panel.url else { return }
                    try text.write(to: url, atomically: true, encoding: .utf8)
                } catch {
                    self.error = error.localizedDescription
                }
            }
        case .passphrase:
            passphrase = ""
            passphraseFor = k
        case .delete:
            let alert = NSAlert()
            alert.messageText = k.hasSecret ? "删除这把私钥？" : "删除这个公钥？"
            alert.informativeText = k.hasSecret ? "删除后将无法解密用它加密的邮件。建议先导出备份。" : (k.emails.joined(separator: "、"))
            alert.alertStyle = k.hasSecret ? .critical : .warning
            alert.addButton(withTitle: "删除")
            alert.addButton(withTitle: "取消")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            Task {
                try? await state.api.deleteKey(k.id)
                await load()
            }
        }
    }
}

struct KeyRow: View {
    enum Action { case copyPublic, exportPublic, exportSecret, passphrase, delete }
    let key: KeyInfo
    let onAction: (Action) -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: key.hasSecret ? "key.fill" : "person.badge.key")
                .foregroundStyle(key.hasSecret ? Color.orange : Color.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(key.names.first ?? key.emails.first ?? key.shortId).fontWeight(.medium)
                    Text(key.kindLabel)
                        .font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15), in: Capsule())
                    if key.hasSecret { Text("我的").font(.caption2).foregroundStyle(.orange) }
                    if key.expired { Text("已过期").font(.caption2).foregroundStyle(.red) }
                }
                Text(key.emails.joined(separator: "、")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text(key.id.chunked(4)).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Menu {
                Button("复制公钥") { onAction(.copyPublic) }
                Button("导出公钥…") { onAction(.exportPublic) }
                if key.hasSecret {
                    Button("导出私钥…") { onAction(.exportSecret) }
                    if key.kind == "pgp" { Button("设置私钥口令…") { onAction(.passphrase) } }
                }
                Divider()
                Button("删除…", role: .destructive) { onAction(.delete) }
            } label: { Image(systemName: "ellipsis.circle") }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        }
        .padding(.vertical, 2)
    }
}

private extension String {
    /// "ABCD EF01 …" for fingerprints.
    func chunked(_ n: Int) -> String {
        var out = ""
        for (i, c) in enumerated() {
            if i > 0 && i % n == 0 { out.append(" ") }
            out.append(c)
        }
        return out
    }
}

struct GenerateKeySheet: View {
    let identities: [Identity]
    let onDone: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var email = ""
    @State private var passphrase = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("生成 PGP 密钥").font(.headline)
            Form {
                if !identities.isEmpty {
                    Picker("发件身份", selection: Binding(get: { email }, set: { e in
                        email = e
                        if let i = identities.first(where: { $0.email == e }), name.isEmpty { name = i.name }
                    })) {
                        Text("自定义").tag("")
                        ForEach(identities) { i in Text("\(i.name) <\(i.email)>").tag(i.email) }
                    }
                }
                TextField("姓名", text: $name)
                TextField("邮箱地址", text: $email)
                SecureField("私钥口令（可选）", text: $passphrase)
            }
            Text("生成 Ed25519 + X25519 密钥。把公钥发给联系人后，他们就能给你发加密邮件。")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).foregroundStyle(.red).font(.callout) }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消") { dismiss() }
                Button("生成") {
                    working = true
                    Task {
                        do {
                            _ = try await APIClient.shared.generateKey(name: name, email: email, passphrase: passphrase.isEmpty ? nil : passphrase)
                            await onDone()
                            dismiss()
                        } catch {
                            self.error = error.localizedDescription
                        }
                        working = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working || !email.contains("@"))
            }
        }
        .padding(20)
        .frame(width: 440)
    }
}

struct PasteKeySheet: View {
    let onDone: () async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("粘贴公钥或证书").font(.headline)
            Text("支持 -----BEGIN PGP PUBLIC KEY BLOCK----- 和 -----BEGIN CERTIFICATE-----。")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $text)
                .font(.system(.caption, design: .monospaced))
                .frame(width: 460, height: 220)
                .border(Color.secondary.opacity(0.3))
            if let error { Text(error).foregroundStyle(.red).font(.callout) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                Button("导入") {
                    Task {
                        do {
                            _ = try await APIClient.shared.importKey(KeyImportRequest(text: text))
                            await onDone()
                            dismiss()
                        } catch {
                            self.error = error.localizedDescription
                        }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(20)
    }
}

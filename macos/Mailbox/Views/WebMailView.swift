import AppKit
import SwiftUI
import UserNotifications
import WebKit

/// Web mode: a webmail page embedded as an account, with its own cookie store.
@MainActor
final class WebMailStore: NSObject, ObservableObject, WKScriptMessageHandler {
    static let shared = WebMailStore()
    @Published var unread: [String: Int] = [:]
    private var views: [String: WKWebView] = [:]
    private var observers: [String: NSKeyValueObservation] = [:]
    private var labels: [String: String] = [:]

    private static let notificationShim = """
    (function() {
      const N = function(title, opts) {
        try { window.webkit.messageHandlers.notify.postMessage({ title: String(title), body: (opts && opts.body) || '' }); } catch (e) {}
      };
      N.permission = 'granted';
      N.requestPermission = function(cb) { if (cb) cb('granted'); return Promise.resolve('granted'); };
      window.Notification = N;
    })();
    """

    private static func storeIdentifier(for accountId: String) -> UUID {
        let hex = (accountId.filter(\.isHexDigit) + String(repeating: "0", count: 32)).prefix(32)
        let s = Array(hex)
        let str = "\(String(s[0..<8]))-\(String(s[8..<12]))-\(String(s[12..<16]))-\(String(s[16..<20]))-\(String(s[20..<32]))"
        return UUID(uuidString: str) ?? UUID()
    }

    func webView(for account: Account) -> WKWebView {
        if let v = views[account.id] { return v }
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore(forIdentifier: Self.storeIdentifier(for: account.id))
        let script = WKUserScript(source: Self.notificationShim, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        config.userContentController.addUserScript(script)
        config.userContentController.add(self, name: "notify")
        let web = WKWebView(frame: .zero, configuration: config)
        web.customUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        web.allowsBackForwardNavigationGestures = true
        if let s = account.config.webUrl, let url = URL(string: s) {
            web.load(URLRequest(url: url))
        }
        let id = account.id
        labels[id] = account.displayLabel
        observers[id] = web.observe(\.title, options: [.new]) { [weak self] view, _ in
            let title = view.title ?? ""
            Task { @MainActor in self?.updateUnread(id, title: title) }
        }
        views[id] = web
        return web
    }

    private func updateUnread(_ id: String, title: String) {
        if let r = title.range(of: #"\((\d+)\)"#, options: .regularExpression) {
            unread[id] = Int(title[r].dropFirst().dropLast()) ?? 0
        } else {
            unread[id] = 0
        }
    }

    nonisolated func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any] else { return }
        let title = body["title"] as? String ?? "新邮件"
        let text = body["body"] as? String ?? ""
        let webView = message.webView
        Task { @MainActor in
            let id = self.views.first { $0.value === webView }?.key
            let label = id.flatMap { self.labels[$0] } ?? "网页邮箱"
            let content = UNMutableNotificationContent()
            content.title = "[\(label)] \(title)"
            content.body = text
            content.sound = .default
            try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }
}

struct WebMailView: NSViewRepresentable {
    let account: Account

    func makeNSView(context: Context) -> NSView {
        let container = NSView()
        attach(to: container)
        return container
    }

    func updateNSView(_ container: NSView, context: Context) {
        attach(to: container)
    }

    @MainActor
    private func attach(to container: NSView) {
        let web = WebMailStore.shared.webView(for: account)
        guard web.superview !== container else { return }
        web.removeFromSuperview()
        container.subviews.forEach { $0.removeFromSuperview() }
        web.frame = container.bounds
        web.autoresizingMask = [.width, .height]
        container.addSubview(web)
    }
}

struct WebAccountDetail: View {
    @EnvironmentObject private var state: AppState
    let accountId: String

    var body: some View {
        if let acc = state.accountsById[accountId] {
            WebMailView(account: acc)
                .navigationTitle(acc.displayLabel)
                .toolbar {
                    ToolbarItemGroup {
                        Button {
                            let web = WebMailStore.shared.webView(for: acc)
                            web.goBack()
                        } label: { Label("后退", systemImage: "chevron.left") }
                        Button {
                            WebMailStore.shared.webView(for: acc).reload()
                        } label: { Label("刷新", systemImage: "arrow.clockwise") }
                    }
                }
        } else {
            ContentUnavailableView("账户不存在", systemImage: "globe")
        }
    }
}

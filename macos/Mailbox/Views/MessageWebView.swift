import AppKit
import SwiftUI
import WebKit

/// Content blocker that stops every network load (remote images, trackers) in mail bodies.
@MainActor
final class RemoteBlocker {
    static let shared = RemoteBlocker()
    private(set) var ruleList: WKContentRuleList?

    func prepare() async {
        guard ruleList == nil else { return }
        let rules = """
        [{"trigger":{"url-filter":"^https?://.*"},"action":{"type":"block"}},
         {"trigger":{"url-filter":"^wss?://.*"},"action":{"type":"block"}}]
        """
        ruleList = try? await WKContentRuleListStore.default().compileContentRuleList(forIdentifier: "mailbox-block-remote", encodedContentRuleList: rules)
    }
}

/// Serves `mailbox-cid://<message>/<content-id>` (inline images) from the engine.
final class CidSchemeHandler: NSObject, WKURLSchemeHandler {
    private var stopped = Set<ObjectIdentifier>()
    private let lock = NSLock()

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url, let host = url.host, let mid = Int64(host) else {
            task.didFailWithError(URLError(.badURL))
            return
        }
        let cid = url.path.hasPrefix("/") ? String(url.path.dropFirst()) : url.path
        let key = ObjectIdentifier(task)
        Task {
            let encoded = cid.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? cid
            let result: (Data, String)?
            if let data = try? await APIClient.shared.raw("GET", "/v1/messages/\(mid)/cid/\(encoded)") {
                result = (data, Self.mime(for: data))
            } else {
                result = nil
            }
            await MainActor.run {
                let isStopped = self.lock.withLock { self.stopped.remove(key) != nil }
                if isStopped { return }
                if let (data, mime) = result {
                    task.didReceive(URLResponse(url: url, mimeType: mime, expectedContentLength: data.count, textEncodingName: nil))
                    task.didReceive(data)
                    task.didFinish()
                } else {
                    task.didFailWithError(URLError(.fileDoesNotExist))
                }
            }
        }
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {
        _ = lock.withLock { stopped.insert(ObjectIdentifier(task)) }
    }

    private static func mime(for data: Data) -> String {
        let b = [UInt8](data.prefix(4))
        if b.starts(with: [0x89, 0x50]) { return "image/png" }
        if b.starts(with: [0xFF, 0xD8]) { return "image/jpeg" }
        if b.starts(with: [0x47, 0x49]) { return "image/gif" }
        return "application/octet-stream"
    }
}

/// WKWebView that lets the surrounding SwiftUI ScrollView handle scrolling.
final class PassthroughWebView: WKWebView {
    override func scrollWheel(with event: NSEvent) {
        nextResponder?.scrollWheel(with: event)
    }
}

struct MessageWebView: NSViewRepresentable {
    let html: String
    let messageId: Int64
    let allowRemote: Bool
    @Binding var height: CGFloat

    func makeCoordinator() -> Coordinator { Coordinator(height: $height) }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.setURLSchemeHandler(context.coordinator.cid, forURLScheme: "mailbox-cid")
        config.defaultWebpagePreferences.allowsContentJavaScript = false
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        config.suppressesIncrementalRendering = true
        let web = PassthroughWebView(frame: .zero, configuration: config)
        web.navigationDelegate = context.coordinator
        web.setValue(false, forKey: "drawsBackground")
        web.allowsMagnification = true
        web.appearance = NSAppearance(named: .aqua)
        return web
    }

    func updateNSView(_ web: WKWebView, context: Context) {
        let key = "\(messageId)-\(allowRemote)-\(html.count)"
        guard context.coordinator.loadedKey != key else { return }
        context.coordinator.loadedKey = key
        let controller = web.configuration.userContentController
        controller.removeAllContentRuleLists()
        if !allowRemote, let rules = RemoteBlocker.shared.ruleList {
            controller.add(rules)
        }
        web.loadHTMLString(Self.wrap(html), baseURL: URL(string: "about:blank"))
    }

    static func wrap(_ body: String) -> String {
        """
        <!doctype html><html><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="color-scheme" content="light">
        <style>
        html, body { margin: 0; padding: 0; background: #fff; }
        body { padding: 14px 16px; font: 14px/1.6 -apple-system, "PingFang SC", "Helvetica Neue", sans-serif; color: #1d1d1f;
               word-wrap: break-word; overflow-wrap: anywhere; -webkit-text-size-adjust: none; }
        img { max-width: 100%; height: auto; }
        table { max-width: 100% !important; }
        pre, code { white-space: pre-wrap; font-family: ui-monospace, Menlo, monospace; font-size: 12.5px; }
        blockquote { margin: 0 0 0 .8ex; border-left: 2px solid #ccc; padding-left: 1ex; color: #555; }
        a { color: #0a66d6; }
        </style></head><body>\(body)</body></html>
        """
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        let cid = CidSchemeHandler()
        var loadedKey = ""
        @Binding var height: CGFloat

        init(height: Binding<CGFloat>) {
            _height = height
        }

        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = action.request.url else {
                decisionHandler(.cancel)
                return
            }
            if action.navigationType == .other && (url.scheme == "about" || url.scheme == "mailbox-cid") {
                decisionHandler(.allow)
                return
            }
            decisionHandler(.cancel)
            if url.scheme == "mailto" {
                Task { @MainActor in AppState.shared.compose(AppState.composeRequest(mailto: url)) }
            } else if ["http", "https"].contains(url.scheme ?? "") {
                NSWorkspace.shared.open(url)
            }
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            measure(webView)
            for delay in [0.3, 1.0, 2.5] {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self, weak webView] in
                    if let webView { self?.measure(webView) }
                }
            }
        }

        private func measure(_ webView: WKWebView) {
            let js = "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)"
            webView.evaluateJavaScript(js, in: nil, in: .defaultClient) { [weak self] result in
                if case .success(let value) = result, let h = value as? Double, h > 0 {
                    let newHeight = CGFloat(h) + 4
                    if abs((self?.height ?? 0) - newHeight) > 1 {
                        self?.height = min(newHeight, 20000)
                    }
                }
            }
        }
    }
}

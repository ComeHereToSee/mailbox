import AppKit
import SwiftUI
import UniformTypeIdentifiers
import WebKit

/// Drives the contenteditable WKWebView used for composing HTML mail.
@MainActor
final class RichEditorController: NSObject, ObservableObject, WKScriptMessageHandler, WKNavigationDelegate {
    weak var webView: WKWebView?
    private var pendingHTML: String?
    /// Last known content, so a closing window can still save it.
    private(set) var lastHTML = ""
    private var ready = false
    var onChange: (() -> Void)?

    func attach(_ web: WKWebView) {
        webView = web
        // A fresh page: content is applied again once it reports "ready".
        ready = false
        pendingHTML = lastHTML
    }

    func setHTML(_ html: String) {
        lastHTML = html
        guard ready, let web = webView else {
            pendingHTML = html
            return
        }
        web.evaluateJavaScript("setContent(\(Self.jsString(html)))")
    }

    func html() async -> String {
        guard let web = webView, ready else { return lastHTML }
        if let s = (try? await web.evaluateJavaScript("getContent()")) as? String {
            lastHTML = s
        }
        return lastHTML
    }

    func exec(_ command: String, _ value: String? = nil) {
        let arg = value.map { Self.jsString($0) } ?? "null"
        webView?.evaluateJavaScript("exec('\(command)', \(arg))")
    }

    func insertHTML(_ html: String) {
        webView?.evaluateJavaScript("insertHTML(\(Self.jsString(html)))")
    }

    func replaceSignature(_ html: String) {
        webView?.evaluateJavaScript("replaceSignature(\(Self.jsString(html)))")
    }

    func focus() {
        webView?.evaluateJavaScript("document.getElementById('editor').focus()")
    }

    static func jsString(_ s: String) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: [s])) ?? Data("[\"\"]".utf8)
        let arr = String(data: data, encoding: .utf8) ?? "[\"\"]"
        return String(arr.dropFirst().dropLast())
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        let body = message.body as? String
        if body == "ready" {
            ready = true
            if let html = pendingHTML {
                pendingHTML = nil
                setHTML(html)
            }
        } else {
            Task {
                _ = await self.html()
                self.onChange?()
            }
        }
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // The editor never navigates: dropped files and clicked links must not replace it.
        if action.navigationType == .other, action.request.url?.scheme == "about" || action.request.url?.scheme == "mailbox-cid" {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
        }
    }

    static let page = """
    <!doctype html><html><head><meta charset="utf-8"><meta name="color-scheme" content="light dark">
    <style>
    html, body { margin: 0; height: 100%; }
    body { font: 14px/1.6 -apple-system, "PingFang SC", sans-serif; }
    #editor { min-height: 100%; padding: 12px 16px; outline: none; box-sizing: border-box; word-wrap: break-word; }
    #editor img { max-width: 100%; }
    #editor blockquote { margin: 0 0 0 .8ex; border-left: 2px solid #ccc; padding-left: 1ex; color: #666; }
    #editor table { border-collapse: collapse; }
    #editor td, #editor th { border: 1px solid #bbb; padding: 4px 8px; min-width: 40px; }
    #editor pre { background: rgba(127,127,127,.12); padding: 8px; border-radius: 6px; white-space: pre-wrap; }
    #mailbox-signature { color: #666; }
    @media (prefers-color-scheme: dark) { body { color: #e8e8e8; background: #1e1e1e; } a { color: #6cb4ff; } }
    </style></head>
    <body><div id="editor" contenteditable="true"></div>
    <script>
    const ed = document.getElementById('editor');
    let timer = null;
    function changed() { clearTimeout(timer); timer = setTimeout(() => window.webkit.messageHandlers.editor.postMessage('change'), 300); }
    ed.addEventListener('input', changed);
    function setContent(html) { ed.innerHTML = html; }
    function getContent() { return ed.innerHTML; }
    function exec(cmd, val) { ed.focus(); document.execCommand(cmd, false, val); changed(); }
    function insertHTML(html) { ed.focus(); document.execCommand('insertHTML', false, html); changed(); }
    function replaceSignature(html) {
      let sig = document.getElementById('mailbox-signature');
      if (!sig) { sig = document.createElement('div'); sig.id = 'mailbox-signature'; const q = document.getElementById('mailbox-quote'); ed.insertBefore(sig, q); }
      sig.innerHTML = html; changed();
    }
    function readImages(files) {
      for (const f of files) {
        if (!f.type.startsWith('image/')) continue;
        const r = new FileReader();
        r.onload = () => insertHTML('<img src="' + r.result + '">');
        r.readAsDataURL(f);
      }
    }
    ed.addEventListener('paste', e => {
      const files = [...(e.clipboardData?.files || [])];
      if (files.some(f => f.type.startsWith('image/'))) { e.preventDefault(); readImages(files); }
    });
    document.addEventListener('dragover', e => e.preventDefault());
    document.addEventListener('drop', e => {
      const files = [...(e.dataTransfer?.files || [])];
      if (files.length) { e.preventDefault(); readImages(files); }
    });
    window.webkit.messageHandlers.editor.postMessage('ready');
    </script></body></html>
    """
}

struct RichEditor: NSViewRepresentable {
    let controller: RichEditorController

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.userContentController.add(controller, name: "editor")
        config.setURLSchemeHandler(CidSchemeHandler(), forURLScheme: "mailbox-cid")
        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = controller
        web.setValue(false, forKey: "drawsBackground")
        controller.attach(web)
        web.loadHTMLString(RichEditorController.page, baseURL: URL(string: "about:blank"))
        return web
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

/// Formatting toolbar above the editor.
struct FormatBar: View {
    let editor: RichEditorController
    @State private var textColor = Color.primary
    @State private var showLink = false
    @State private var linkURL = "https://"

    var body: some View {
        HStack(spacing: 2) {
            Menu {
                ForEach([("系统字体", "-apple-system"), ("苹方", "PingFang SC"), ("宋体", "Songti SC"), ("黑体", "Heiti SC"),
                         ("楷体", "Kaiti SC"), ("Helvetica", "Helvetica"), ("Times", "Times New Roman"), ("Courier", "Courier New")], id: \.1) { f in
                    Button(f.0) { editor.exec("fontName", f.1) }
                }
            } label: { Image(systemName: "textformat") }
            .menuStyle(.borderlessButton).frame(width: 36)
            Menu {
                Button("小") { editor.exec("fontSize", "2") }
                Button("正常") { editor.exec("fontSize", "3") }
                Button("大") { editor.exec("fontSize", "5") }
                Button("特大") { editor.exec("fontSize", "6") }
            } label: { Image(systemName: "textformat.size") }
            .menuStyle(.borderlessButton).frame(width: 36)
            Divider().frame(height: 16)
            tool("bold", "bold")
            tool("italic", "italic")
            tool("underline", "underline")
            tool("strikethrough", "strikethrough")
            ColorPicker("", selection: $textColor, supportsOpacity: false)
                .labelsHidden()
                .frame(width: 28)
                .onChange(of: textColor) { _, c in
                    if let hex = NSColor(c).usingColorSpace(.sRGB).map({ String(format: "#%02X%02X%02X", Int($0.redComponent * 255), Int($0.greenComponent * 255), Int($0.blueComponent * 255)) }) {
                        editor.exec("foreColor", hex)
                    }
                }
            Divider().frame(height: 16)
            tool("list.bullet", "insertUnorderedList")
            tool("list.number", "insertOrderedList")
            tool("decrease.indent", "outdent")
            tool("increase.indent", "indent")
            Button { editor.exec("formatBlock", "blockquote") } label: { Image(systemName: "text.quote") }.help("引用")
            Menu {
                Button("左对齐") { editor.exec("justifyLeft") }
                Button("居中") { editor.exec("justifyCenter") }
                Button("右对齐") { editor.exec("justifyRight") }
            } label: { Image(systemName: "text.alignleft") }
            .menuStyle(.borderlessButton).frame(width: 36)
            Divider().frame(height: 16)
            Button { showLink = true } label: { Image(systemName: "link") }.help("插入链接")
                .popover(isPresented: $showLink) {
                    HStack {
                        TextField("https://", text: $linkURL).frame(width: 260)
                        Button("插入") {
                            editor.exec("createLink", linkURL)
                            showLink = false
                        }
                    }
                    .padding()
                }
            Button { insertImage() } label: { Image(systemName: "photo") }.help("插入图片")
            Button {
                let row = "<tr>" + String(repeating: "<td>&nbsp;</td>", count: 3) + "</tr>"
                editor.insertHTML("<table>" + String(repeating: row, count: 3) + "</table><br>")
            } label: { Image(systemName: "tablecells") }.help("插入表格")
            Button { editor.exec("formatBlock", "pre") } label: { Image(systemName: "chevron.left.forwardslash.chevron.right") }.help("代码块")
            Button { editor.exec("insertHorizontalRule") } label: { Image(systemName: "minus") }.help("分隔线")
            Button { editor.exec("removeFormat") } label: { Image(systemName: "eraser") }.help("清除格式")
            Spacer()
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    private func tool(_ symbol: String, _ cmd: String) -> some View {
        Button { editor.exec(cmd) } label: { Image(systemName: symbol) }
    }

    private func insertImage() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = true
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            guard let data = try? Data(contentsOf: url) else { continue }
            let ext = url.pathExtension.lowercased()
            let mime = ext == "png" ? "image/png" : ext == "gif" ? "image/gif" : "image/jpeg"
            editor.insertHTML("<img src=\"data:\(mime);base64,\(data.base64EncodedString())\">")
        }
    }
}

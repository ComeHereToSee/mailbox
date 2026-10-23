import Foundation

/// Runs the Rust engine (libmailcore.a) inside the helper process.
final class EngineHost {
    static let shared = EngineHost()

    private(set) var port: Int32 = 0
    private(set) var lastError: String?
    var onEvent: ((Data) -> Void)?

    func start() -> Bool {
        let dir = Daemon.dataDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        let result: Int32 = dir.path.withCString { path in
            mailcore_start(path, 0, { ctx, json in
                guard let ctx, let json else { return }
                let host = Unmanaged<EngineHost>.fromOpaque(ctx).takeUnretainedValue()
                let data = Data(bytes: json, count: strlen(json))
                host.onEvent?(data)
            }, ctx)
        }
        if result < 0 {
            if let err = mailcore_last_error() {
                lastError = String(cString: err)
                mailcore_free_string(err)
            }
            return false
        }
        port = result
        APIClient.shared.reloadInfo()
        return true
    }

    func stop() {
        mailcore_stop()
    }

    var version: String {
        guard let v = mailcore_version() else { return "" }
        return String(cString: v)
    }
}

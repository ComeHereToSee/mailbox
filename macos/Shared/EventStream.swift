import Foundation

/// WebSocket subscription to `/v1/events` with automatic reconnect.
final class EventStream: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private var stopped = false
    private var backoff: TimeInterval = 1
    private let handler: @Sendable (MailEvent) -> Void
    private let onConnectionChange: @Sendable (Bool) -> Void

    init(handler: @escaping @Sendable (MailEvent) -> Void, onConnectionChange: @escaping @Sendable (Bool) -> Void = { _ in }) {
        self.handler = handler
        self.onConnectionChange = onConnectionChange
        super.init()
    }

    func start() {
        stopped = false
        connect()
    }

    func stop() {
        stopped = true
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
    }

    private func connect() {
        guard !stopped else { return }
        APIClient.shared.reloadInfo()
        guard let httpURL = APIClient.shared.url("/v1/events", withToken: true),
              var comps = URLComponents(url: httpURL, resolvingAgainstBaseURL: false) else {
            scheduleReconnect()
            return
        }
        comps.scheme = "ws"
        guard let url = comps.url else { return }
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        self.session = session
        let task = session.webSocketTask(with: url)
        self.task = task
        task.resume()
        receive(task)
    }

    private func receive(_ task: URLSessionWebSocketTask) {
        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                self.backoff = 1
                switch message {
                case .string(let s):
                    if let d = s.data(using: .utf8) { self.handler(MailEvent.decode(d)) }
                case .data(let d):
                    self.handler(MailEvent.decode(d))
                @unknown default:
                    break
                }
                self.receive(task)
            case .failure:
                self.onConnectionChange(false)
                self.scheduleReconnect()
            }
        }
    }

    private func scheduleReconnect() {
        guard !stopped else { return }
        let delay = backoff
        backoff = min(backoff * 2, 15)
        DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [weak self] in self?.connect() }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        onConnectionChange(true)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        onConnectionChange(false)
        scheduleReconnect()
    }
}

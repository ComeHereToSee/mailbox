import AppKit
import UserNotifications

/// Background helper: hosts the mail engine, shows notifications and the menu bar extra.
final class HelperDelegate: NSObject, NSApplicationDelegate {
    private let notifications = NotificationController()
    private let statusItem = StatusItemController()
    private var refreshWork: DispatchWorkItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let me = ProcessInfo.processInfo.processIdentifier
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: Daemon.helperBundleId)
            .filter { $0.processIdentifier != me }
        if !others.isEmpty {
            NSApp.terminate(nil)
            return
        }
        notifications.setup()
        statusItem.setup()
        EngineHost.shared.onEvent = { [weak self] data in
            let event = MailEvent.decode(data)
            DispatchQueue.main.async { self?.handle(event) }
        }
        if !EngineHost.shared.start() {
            statusItem.showError(EngineHost.shared.lastError ?? "邮件引擎启动失败")
            return
        }
        scheduleMenuRefresh()
    }

    func applicationWillTerminate(_ notification: Notification) {
        EngineHost.shared.stop()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            Daemon.openMainApp(url: url)
        }
    }

    private func handle(_ event: MailEvent) {
        switch event {
        case let .newMail(_, label, _, message, notify, sound):
            if notify {
                notifications.post(message: message, accountLabel: label, sound: sound)
            }
            scheduleMenuRefresh()
        case let .unreadCounts(total, _):
            statusItem.unread = total
            scheduleMenuRefresh()
        case .messagesChanged, .accountsChanged, .settingsChanged, .snoozed:
            scheduleMenuRefresh()
        case let .accountStatus(status):
            statusItem.updateStatus(status)
        case let .outbox(_, status, error):
            if status == .failed, let error {
                notifications.postSendFailure(error)
            }
        default:
            break
        }
    }

    private func scheduleMenuRefresh() {
        refreshWork?.cancel()
        let work = DispatchWorkItem { [weak self] in
            Task { await self?.statusItem.refresh() }
        }
        refreshWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: work)
    }
}

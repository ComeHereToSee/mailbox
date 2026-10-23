import SwiftUI

struct SnoozePicker: View {
    let onPick: (Date?) -> Void
    @State private var custom = Date().addingTimeInterval(3600 * 3)

    private var presets: [(String, Date)] {
        let cal = Calendar.current
        let now = Date()
        let later = now.addingTimeInterval(3 * 3600)
        let tonight = cal.date(bySettingHour: 20, minute: 0, second: 0, of: now) ?? later
        let tomorrow = cal.date(bySettingHour: 8, minute: 0, second: 0, of: cal.date(byAdding: .day, value: 1, to: now) ?? now) ?? later
        let weekend: Date = {
            var c = DateComponents()
            c.weekday = 7
            c.hour = 9
            return cal.nextDate(after: now, matching: c, matchingPolicy: .nextTime) ?? tomorrow
        }()
        let nextWeek: Date = {
            var c = DateComponents()
            c.weekday = 2
            c.hour = 8
            return cal.nextDate(after: now, matching: c, matchingPolicy: .nextTime) ?? tomorrow
        }()
        var out: [(String, Date)] = [("3 小时后", later)]
        if tonight > now.addingTimeInterval(1800) { out.append(("今晚 20:00", tonight)) }
        out += [("明天早上 8:00", tomorrow), ("本周末", weekend), ("下周一", nextWeek)]
        return out
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("稍后提醒").font(.headline)
            ForEach(presets, id: \.0) { p in
                Button {
                    onPick(p.1)
                } label: {
                    HStack {
                        Text(p.0)
                        Spacer()
                        Text(Fmt.full(Int64(p.1.timeIntervalSince1970))).foregroundStyle(.secondary).font(.caption)
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
            Divider()
            DatePicker("自定义", selection: $custom, in: Date()...)
            HStack {
                Button("取消") { onPick(nil) }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("确定") { onPick(custom) }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 360)
    }
}

struct MoveToFolderSheet: View {
    @EnvironmentObject private var state: AppState
    let messageIds: [Int64]
    let onDone: () -> Void
    @State private var filter = ""

    private var accountId: String? {
        let first = state.messages.first { messageIds.contains($0.id) }
        return first?.accountId ?? state.accounts.first?.id
    }

    private var folders: [Folder] {
        let fs = state.folders[accountId ?? ""] ?? []
        let selectable = fs.filter { $0.selectable && $0.role != .all && $0.role != .flagged }
        guard !filter.isEmpty else { return selectable }
        return selectable.filter { $0.name.localizedCaseInsensitiveContains(filter) || $0.role.title.contains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("移动到文件夹").font(.headline)
            TextField("搜索文件夹", text: $filter).textFieldStyle(.roundedBorder)
            List(folders) { f in
                Button {
                    Task {
                        await state.act(messageIds, .move(folderId: f.id))
                        onDone()
                    }
                } label: {
                    Label(f.role == .custom ? f.name : f.role.title, systemImage: f.role.symbol)
                }
                .buttonStyle(.plain)
            }
            .frame(height: 260)
            HStack {
                Spacer()
                Button("取消", action: onDone).keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 360)
    }
}

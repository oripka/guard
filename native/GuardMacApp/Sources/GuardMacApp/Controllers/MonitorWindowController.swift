import AppKit

struct GuardActivityRow {
    let time: String
    let process: String
    let destination: String
    let decision: String
    let detail: String
}

final class MonitorWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let tableView = NSTableView()
    private let statusLabel = NSTextField(labelWithString: "Loading activity…")
    private var rows: [GuardActivityRow] = []
    private var refreshTimer: Timer?
    private lazy var rulesWindowController = RulesWindowController()
    private lazy var settingsWindowController = GuardSettingsWindowController()
    private lazy var accountsWindowController = AccountsWindowController()

    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Monitor"
        window.subtitle = "Live policy and network activity"
        window.setFrameAutosaveName("dev.guard.monitor.window")
        window.titlebarAppearsTransparent = true
        super.init(window: window)
        buildContent()
        reloadActivity()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.reloadActivity()
        }
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    deinit {
        refreshTimer?.invalidate()
    }

    func showRules() {
        rulesWindowController.update(rows: rows)
        rulesWindowController.showWindow(nil)
        rulesWindowController.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func showSettings() {
        settingsWindowController.showWindow(nil)
        settingsWindowController.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func showAccounts() {
        accountsWindowController.showWindow(nil)
        accountsWindowController.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func buildContent() {
        guard let window else { return }
        let root = NSVisualEffectView()
        root.material = .sidebar
        root.blendingMode = .behindWindow
        root.state = .active
        window.contentView = root

        let title = NSTextField(labelWithString: "Network Activity")
        title.font = .systemFont(ofSize: 24, weight: .semibold)
        let subtitle = NSTextField(labelWithString: "Recent allow, deny, inspection, and policy events")
        subtitle.textColor = .secondaryLabelColor

        let refreshButton = NSButton(title: "Refresh", target: self, action: #selector(refresh))
        refreshButton.bezelStyle = .rounded
        refreshButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        let rulesButton = NSButton(title: "Rules", target: self, action: #selector(openRules))
        rulesButton.bezelStyle = .rounded
        rulesButton.image = NSImage(systemSymbolName: "list.bullet.rectangle", accessibilityDescription: nil)
        let settingsButton = NSButton(title: "Settings", target: self, action: #selector(openSettings))
        settingsButton.bezelStyle = .rounded
        settingsButton.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)

        let accountsButton = NSButton(title: "Accounts", target: self, action: #selector(openAccounts))
        accountsButton.bezelStyle = .rounded
        accountsButton.image = NSImage(systemSymbolName: "person.crop.circle.badge.checkmark", accessibilityDescription: nil)

        let buttonStack = NSStackView(views: [refreshButton, accountsButton, rulesButton, settingsButton])
        buttonStack.orientation = .horizontal
        buttonStack.spacing = 8
        let spacer = NSView()
        let header = NSStackView(views: [title, spacer, buttonStack])
        header.orientation = .horizontal
        header.alignment = .centerY

        for (identifier, title, width) in [
            ("time", "Time", 112.0),
            ("process", "Process", 210.0),
            ("destination", "Destination / Activity", 440.0),
            ("decision", "Decision", 120.0)
        ] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            column.minWidth = 80
            tableView.addTableColumn(column)
        }
        tableView.delegate = self
        tableView.dataSource = self
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 28
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tableView.doubleAction = #selector(copySelectedDetail)

        let scrollView = NSScrollView()
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .bezelBorder

        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingMiddle

        let stack = NSStackView(views: [header, subtitle, scrollView, statusLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        scrollView.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 440).isActive = true
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 22),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 46),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18)
        ])
    }

    @objc private func refresh() {
        reloadActivity()
    }

    @objc private func openRules() {
        showRules()
    }

    @objc private func openSettings() {
        showSettings()
    }

    @objc private func openAccounts() {
        showAccounts()
    }

    @objc private func copySelectedDetail() {
        guard tableView.selectedRow >= 0, tableView.selectedRow < rows.count else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(rows[tableView.selectedRow].detail, forType: .string)
        statusLabel.stringValue = "Copied event details."
    }

    private func reloadActivity() {
        let url = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/guard/events.jsonl")
        guard let content = try? String(contentsOf: url, encoding: .utf8) else {
            rows = []
            tableView.reloadData()
            statusLabel.stringValue = "No daemon event log yet. Guard per-run mode remains available."
            rulesWindowController.update(rows: rows)
            return
        }
        rows = content.split(separator: "\n").suffix(500).reversed().compactMap { line in
            guard let data = line.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return nil
            }
            let time = Self.firstString(in: object, keys: ["at", "time", "timestamp"])
            let process = Self.firstString(in: object, keys: ["process", "command", "app", "executable"])
            let host = Self.firstString(in: object, keys: ["host", "destination", "target", "path"])
            let type = Self.firstString(in: object, keys: ["type", "event", "kind"])
            let decision = Self.decision(in: object)
            return GuardActivityRow(
                time: Self.shortTime(time),
                process: process.isEmpty ? "Guard" : process,
                destination: host.isEmpty ? (type.isEmpty ? "Policy event" : type) : host,
                decision: decision,
                detail: String(data: data, encoding: .utf8) ?? String(line)
            )
        }
        if UserDefaults.standard.bool(forKey: "GuardDeniedFirst") {
            rows.sort { ($0.decision == "Denied" ? 0 : 1) < ($1.decision == "Denied" ? 0 : 1) }
        }
        tableView.reloadData()
        let denied = rows.filter { $0.decision == "Denied" }.count
        statusLabel.stringValue = "\(rows.count) recent events  •  \(denied) denied  •  Double-click an event to copy its JSON"
        rulesWindowController.update(rows: rows)
    }

    private static func firstString(in object: [String: Any], keys: [String]) -> String {
        for key in keys {
            if let value = object[key] as? String, !value.isEmpty { return value }
        }
        return ""
    }

    private static func decision(in object: [String: Any]) -> String {
        if let allowed = object["allowed"] as? Bool { return allowed ? "Allowed" : "Denied" }
        let value = firstString(in: object, keys: ["decision", "action", "result", "outcome"]).lowercased()
        if value.contains("deny") || value.contains("block") { return "Denied" }
        if value.contains("allow") { return "Allowed" }
        if value.contains("inspect") { return "Inspected" }
        if value.contains("pending") || value.contains("ask") { return "Pending" }
        return "Observed"
    }

    private static func shortTime(_ value: String) -> String {
        guard !value.isEmpty else { return "—" }
        if let t = value.firstIndex(of: "T") {
            return String(value[value.index(after: t)...].prefix(8))
        }
        return String(value.prefix(19))
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        rows.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < rows.count, let identifier = tableColumn?.identifier.rawValue else { return nil }
        let item = rows[row]
        let value: String
        switch identifier {
        case "time": value = item.time
        case "process": value = item.process
        case "destination": value = item.destination
        default: value = item.decision
        }
        let cell = NSTableCellView()
        let field = NSTextField(labelWithString: value)
        field.lineBreakMode = .byTruncatingTail
        if identifier == "decision" {
            field.textColor = item.decision == "Denied" ? .systemRed :
                item.decision == "Allowed" ? .systemGreen : .secondaryLabelColor
            field.font = .systemFont(ofSize: 12, weight: .medium)
        }
        field.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(field)
        cell.textField = field
        NSLayoutConstraint.activate([
            field.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
            field.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
            field.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }
}

final class RulesWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate {
    private let tableView = NSTableView()
    private var rows: [GuardActivityRow] = []

    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 860, height: 520),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Rules"
        super.init(window: window)
        let root = NSView()
        window.contentView = root
        let heading = NSTextField(labelWithString: "Recent policy decisions")
        heading.font = .systemFont(ofSize: 20, weight: .semibold)
        let note = NSTextField(labelWithString: "Persistent rules remain stored in Guard profiles; this review shows the decisions that produced or matched them.")
        note.textColor = .secondaryLabelColor
        note.maximumNumberOfLines = 2
        for (id, title, width) in [("process", "Process", 210.0), ("destination", "Rule target", 430.0), ("decision", "Action", 110.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
            column.title = title
            column.width = width
            tableView.addTableColumn(column)
        }
        tableView.delegate = self
        tableView.dataSource = self
        tableView.usesAlternatingRowBackgroundColors = true
        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        let stack = NSStackView(views: [heading, note, scroll])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        scroll.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -20)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func update(rows: [GuardActivityRow]) {
        self.rows = rows.filter { $0.decision != "Observed" }
        tableView.reloadData()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < rows.count else { return nil }
        let item = rows[row]
        let value = tableColumn?.identifier.rawValue == "process" ? item.process :
            tableColumn?.identifier.rawValue == "destination" ? item.destination : item.decision
        let field = NSTextField(labelWithString: value)
        field.lineBreakMode = .byTruncatingTail
        return field
    }
}

final class GuardSettingsWindowController: NSWindowController {
    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 540, height: 300),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Settings"
        super.init(window: window)
        let root = NSView()
        window.contentView = root
        let heading = NSTextField(labelWithString: "Monitor")
        heading.font = .systemFont(ofSize: 20, weight: .semibold)
        let deniedFirst = NSButton(checkboxWithTitle: "Show denied events first", target: self, action: #selector(toggleDeniedFirst(_:)))
        deniedFirst.state = UserDefaults.standard.bool(forKey: "GuardDeniedFirst") ? .on : .off
        let enforcement = NSTextField(labelWithString: "Enforcement: Guard per-run sandbox and daemon policy are independent of this monitor.")
        enforcement.textColor = .secondaryLabelColor
        enforcement.maximumNumberOfLines = 2
        let privacy = NSTextField(labelWithString: "Privacy: event details are read locally from Guard’s Application Support directory.")
        privacy.textColor = .secondaryLabelColor
        privacy.maximumNumberOfLines = 2
        let stack = NSStackView(views: [heading, deniedFirst, enforcement, privacy])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 24)
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    @objc private func toggleDeniedFirst(_ sender: NSButton) {
        UserDefaults.standard.set(sender.state == .on, forKey: "GuardDeniedFirst")
    }
}

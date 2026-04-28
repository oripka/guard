import AppKit
import Darwin
import Foundation
import UserNotifications

extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

struct GuardAppConfig: Decodable {
    let mode: String?
    let profile: String
    let displayName: String
    let guardPath: String
    let bundleIdentifier: String
    let eventLogPath: String?
}

struct GuardAskNetworkInput: Decodable {
    let target: String?
    let host: String
    let port: Int?
    let profile: String?
    let projectDir: String?
    let runDir: String?
    let command: String?
    let launcherApp: String?
    let launcherProcess: String?
    let launcherPid: Int?
    let parentChain: String?
}

struct GuardHttpPolicyRequest: Codable {
    let host: String
    let method: String
    let path: String
}

struct GuardHttpPolicyRule: Codable {
    let host: String?
    let cidr: String?
    let methods: [String]?
    let paths: [String]?
}

struct GuardAskHttpPolicyInput: Decodable {
    let request: GuardHttpPolicyRequest
    let suggestedRule: GuardHttpPolicyRule
    let profile: String?
    let projectDir: String?
    let runDir: String?
    let command: String?
    let launcherApp: String?
    let launcherProcess: String?
    let launcherPid: Int?
    let parentChain: String?
}

struct GuardAskDecision: Encodable {
    let action: String
    let rule: GuardHttpPolicyRule?
    let duration: String?
}

struct GuardFinding: Decodable {
    let severity: String
    let id: String
    let message: String
    let values: [String]?
}

struct GuardNetworkSummary: Decodable {
    let mode: String
    let allowedDomains: [String]
    let allowedRawTcp: [GuardRawTcpRule]?
    let httpRules: [GuardHttpPolicyRule]?
    let deniedDomains: [String]
    let deniedDomainPresets: [String]
    let tlsInspection: GuardTlsInspection?
    let allowLocalBinding: Bool?
    let allowLoopbackConnections: Bool?
    let allowLoopbackHighPorts: Bool?
    let allowLoopbackListeningHighPorts: Bool?
    let allowLoopbackListeningHighPortProcesses: [String]?
    let allowLoopbackPorts: [Int]?
}

struct GuardRawTcpRule: Codable {
    let ip: String?
    let host: String?
    let resolveAtLaunch: Bool?
    let port: Int?
    let reason: String?
}

struct GuardTlsInspection: Codable {
    let enabled: Bool?
    let explicit: Bool?
    let mode: String?
    let caScope: String?
    let trustedBy: [String]?
    let userApprovalRequired: Bool?
}

struct GuardFilesystemSummary: Decodable {
    let allowRead: [String]
    let denyRead: [String]
    let allowWrite: [String]
    let denyWrite: [String]
}

struct GuardAppSummary: Decodable {
    let profile: String
    let description: String
    let risk: String
    let status: String
    let appBundle: String?
    let network: GuardNetworkSummary
    let filesystem: GuardFilesystemSummary
    let findings: [GuardFinding]
}

@discardableResult
func runProcess(_ executable: String, _ arguments: [String]) throws -> (Int32, Data, Data) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments

    let stdout = Pipe()
    let stderr = Pipe()
    process.standardOutput = stdout
    process.standardError = stderr

    try process.run()
    process.waitUntilExit()

    return (
        process.terminationStatus,
        stdout.fileHandleForReading.readDataToEndOfFile(),
        stderr.fileHandleForReading.readDataToEndOfFile()
    )
}

func loadConfig() throws -> GuardAppConfig {
    guard let url = Bundle.main.url(forResource: "GuardAppConfig", withExtension: "json") else {
        throw NSError(domain: "GuardAppLauncher", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "Missing GuardAppConfig.json in app bundle resources."
        ])
    }
    return try JSONDecoder().decode(GuardAppConfig.self, from: Data(contentsOf: url))
}

func loadSummary(config: GuardAppConfig) throws -> GuardAppSummary {
    let (status, stdout, stderr) = try runProcess(config.guardPath, [
        "app-summary",
        "--profile",
        config.profile,
        "--json"
    ])
    if status != 0 {
        let message = String(data: stderr.isEmpty ? stdout : stderr, encoding: .utf8) ?? "Unknown guard error."
        throw NSError(domain: "GuardAppLauncher", code: Int(status), userInfo: [
            NSLocalizedDescriptionKey: message
        ])
    }
    return try JSONDecoder().decode(GuardAppSummary.self, from: stdout)
}

final class GuardApplicationDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    var monitorController: MonitorWindowController?
    var launcherController: LauncherWindowController?
    var statusController: GuardStatusItemController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.setNotificationCategories([
            UNNotificationCategory(
                identifier: "GUARD_PENDING_ALERT",
                actions: [
                    UNNotificationAction(identifier: "OPEN_GUARD", title: "Open Guard", options: [.foreground])
                ],
                intentIdentifiers: [],
                options: []
            )
        ])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if revealMonitor() {
            return true
        }
        if let controller = launcherController {
            if let window = controller.window {
                if window.isMiniaturized {
                    window.deminiaturize(nil)
                }
                window.makeKeyAndOrderFront(nil)
                window.orderFrontRegardless()
            } else {
                controller.show()
            }
            sender.activate(ignoringOtherApps: true)
            return true
        }
        return true
    }

    @objc func showMonitor(_ sender: Any?) {
        _ = revealMonitor()
    }

    @discardableResult
    func revealMonitor() -> Bool {
        guard let controller = monitorController else { return false }
        if let window = controller.window {
            if window.isMiniaturized {
                window.deminiaturize(nil)
            }
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
        } else {
            controller.show()
        }
        NSApp.unhide(nil)
        NSApp.activate(ignoringOtherApps: true)
        return true
    }

    @objc func showRules(_ sender: Any?) {
        monitorController?.openRulesWindow(sender)
    }

    @objc func showSettings(_ sender: Any?) {
        monitorController?.openSettingsWindow(sender)
    }

    @objc func refreshMonitor(_ sender: Any?) {
        monitorController?.reloadEvents(sender)
    }

    @objc func focusMonitorSearch(_ sender: Any?) {
        monitorController?.focusSearch(sender)
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await MainActor.run {
            showMonitor(nil)
        }
    }
}

final class GuardStatusItemController: NSObject {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let popover = NSPopover()
    weak var monitor: MonitorWindowController?
    let modeLabel = NSTextField(labelWithString: "Mode")
    let modeValueLabel = NSTextField(labelWithString: "Monitor")
    let daemonBadgeLabel = NSTextField(labelWithString: "guardd")
    let extensionBadgeLabel = NSTextField(labelWithString: "NetworkExtension")
    let allowedPillLabel = NSTextField(labelWithString: "0 allowed")
    let deniedPillLabel = NSTextField(labelWithString: "0 denied")
    let sparkline = TrafficSparklineView()
    let trafficEmptyLabel = NSTextField(labelWithString: "5 minutes ago")
    let trafficNowLabel = NSTextField(labelWithString: "now")
    let recentStack = NSStackView()
    let deniedBadgeLabel = NSTextField(labelWithString: "0")
    let deniedRow = NSButton()
    let popoverContentWidth: CGFloat = 360
    var lastNotifiedPendingCount = 0

    init(monitor: MonitorWindowController) {
        self.monitor = monitor
        super.init()
        if let button = statusItem.button {
            if #available(macOS 11.0, *) {
                button.image = statusImage(named: "shield.lefthalf.filled", description: "Guard Monitor")
                button.title = ""
            } else {
                button.title = "G"
            }
            button.imagePosition = .imageOnly
            button.imageScaling = .scaleProportionallyDown
            button.target = self
            button.action = #selector(togglePopover(_:))
            button.toolTip = "Guard Monitor"
        }
        popover.behavior = .transient
        popover.contentSize = NSSize(width: 388, height: 580)
        popover.contentViewController = NSViewController()
        popover.contentViewController?.view = makePopoverView()
    }

    @available(macOS 11.0, *)
    func statusImage(named symbolName: String, description: String) -> NSImage? {
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: description)?
            .withSymbolConfiguration(config)
            ?? NSImage(systemSymbolName: "shield", accessibilityDescription: description)
        image?.isTemplate = true
        image?.size = NSSize(width: 18, height: 18)
        return image
    }

    func makePopoverView() -> NSView {
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .width
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        root.wantsLayer = true
        root.layer?.cornerRadius = 18
        root.layer?.cornerCurve = .continuous
        root.translatesAutoresizingMaskIntoConstraints = false
        root.widthAnchor.constraint(equalToConstant: popoverContentWidth).isActive = true

        root.addArrangedSubview(popoverHeader())
        root.addArrangedSubview(statusBadgeRow())
        root.addArrangedSubview(trafficCard())

        let recentTitle = NSTextField(labelWithString: "Recent Network Activity")
        recentTitle.font = NSFont.systemFont(ofSize: 16, weight: .bold)
        recentTitle.textColor = .secondaryLabelColor
        recentTitle.alignment = .left
        root.addArrangedSubview(recentTitle)

        recentStack.orientation = .vertical
        recentStack.alignment = .width
        recentStack.spacing = 8
        root.addArrangedSubview(recentStack)

        root.addArrangedSubview(separator())
        root.addArrangedSubview(recentDeniedRow())
        root.addArrangedSubview(separator())
        root.addArrangedSubview(menuAction("Open Monitor...", action: #selector(openMonitor(_:))))
        root.addArrangedSubview(menuAction("Manage Rules...", action: #selector(openRules(_:))))
        root.addArrangedSubview(menuAction("Guard Settings...", action: #selector(openSettings(_:))))
        return root
    }

    func popoverHeader() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10

        let tile = NSStackView()
        tile.orientation = .horizontal
        tile.alignment = .centerY
        tile.spacing = 10
        tile.edgeInsets = NSEdgeInsets(top: 10, left: 12, bottom: 10, right: 12)
        tile.wantsLayer = true
        tile.layer?.cornerRadius = 12
        tile.layer?.cornerCurve = .continuous
        tile.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.55).cgColor
        tile.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.25).cgColor
        tile.layer?.borderWidth = 0.5
        tile.translatesAutoresizingMaskIntoConstraints = false
        tile.widthAnchor.constraint(equalToConstant: 240).isActive = true

        tile.addArrangedSubview(symbolCircle("bell.fill", tint: .systemOrange, fallback: "!"))
        let labelStack = NSStackView()
        labelStack.orientation = .vertical
        labelStack.spacing = 0
        modeLabel.font = NSFont.systemFont(ofSize: 12, weight: .bold)
        modeLabel.textColor = .secondaryLabelColor
        modeValueLabel.font = NSFont.systemFont(ofSize: 20, weight: .bold)
        modeValueLabel.textColor = .labelColor
        labelStack.addArrangedSubview(modeLabel)
        labelStack.addArrangedSubview(modeValueLabel)
        tile.addArrangedSubview(labelStack)
        row.addArrangedSubview(tile)

        row.addArrangedSubview(iconButton("bell.slash.fill", action: #selector(openSettings(_:)), tint: .secondaryLabelColor, tooltip: "Alert settings"))
        row.addArrangedSubview(iconButton("network", action: #selector(openMonitor(_:)), tint: .systemBlue, tooltip: "Open live monitor"))
        return row
    }

    func statusBadgeRow() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 6
        row.addArrangedSubview(statusBadge(daemonBadgeLabel, symbol: "bolt.horizontal.circle.fill", width: 132))
        row.addArrangedSubview(statusBadge(extensionBadgeLabel, symbol: "shield.lefthalf.filled", width: 222))
        return row
    }

    func statusBadge(_ label: NSTextField, symbol: String, width: CGFloat) -> NSView {
        let badge = NSStackView()
        badge.orientation = .horizontal
        badge.alignment = .centerY
        badge.spacing = 5
        badge.edgeInsets = NSEdgeInsets(top: 4, left: 8, bottom: 4, right: 8)
        badge.wantsLayer = true
        badge.layer?.cornerRadius = 7
        badge.layer?.cornerCurve = .continuous
        badge.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.34).cgColor
        badge.translatesAutoresizingMaskIntoConstraints = false
        badge.widthAnchor.constraint(equalToConstant: width).isActive = true
        badge.addArrangedSubview(symbolImage(symbol, tint: .secondaryLabelColor, size: 11))
        label.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        label.textColor = .secondaryLabelColor
        label.lineBreakMode = .byTruncatingMiddle
        label.maximumNumberOfLines = 1
        badge.addArrangedSubview(label)
        return badge
    }

    func trafficCard() -> NSView {
        let card = NSStackView()
        card.orientation = .vertical
        card.alignment = .width
        card.spacing = 8
        card.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 10, right: 12)
        card.wantsLayer = true
        card.layer?.cornerRadius = 12
        card.layer?.cornerCurve = .continuous
        card.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.50).cgColor
        card.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.26).cgColor
        card.layer?.borderWidth = 0.5

        let pills = NSStackView()
        pills.orientation = .horizontal
        pills.alignment = .centerY
        pills.spacing = 8
        pills.addArrangedSubview(metricPill(label: allowedPillLabel, symbol: "arrow.up", tint: .systemPurple))
        pills.addArrangedSubview(metricPill(label: deniedPillLabel, symbol: "xmark", tint: .systemRed))
        card.addArrangedSubview(pills)

        sparkline.heightAnchor.constraint(equalToConstant: 124).isActive = true
        card.addArrangedSubview(sparkline)

        let timeline = NSStackView()
        timeline.orientation = .horizontal
        trafficEmptyLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        trafficEmptyLabel.textColor = .tertiaryLabelColor
        trafficNowLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        trafficNowLabel.textColor = .tertiaryLabelColor
        timeline.addArrangedSubview(trafficEmptyLabel)
        timeline.addArrangedSubview(NSView())
        timeline.addArrangedSubview(trafficNowLabel)
        card.addArrangedSubview(timeline)
        return card
    }

    func metricPill(label: NSTextField, symbol: String, tint: NSColor) -> NSView {
        let pill = NSStackView()
        pill.orientation = .horizontal
        pill.alignment = .centerY
        pill.spacing = 6
        pill.edgeInsets = NSEdgeInsets(top: 6, left: 10, bottom: 6, right: 10)
        pill.wantsLayer = true
        pill.layer?.cornerRadius = 7
        pill.layer?.cornerCurve = .continuous
        pill.layer?.backgroundColor = tint.withAlphaComponent(0.30).cgColor
        pill.addArrangedSubview(symbolImage(symbol, tint: tint, size: 15))
        label.font = NSFont.systemFont(ofSize: 15, weight: .bold)
        label.textColor = .labelColor
        pill.addArrangedSubview(label)
        pill.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return pill
    }

    func recentDeniedRow() -> NSView {
        deniedRow.title = ""
        deniedRow.isBordered = false
        deniedRow.target = self
        deniedRow.action = #selector(openDenied(_:))
        deniedRow.wantsLayer = true
        deniedRow.layer?.cornerRadius = 8
        deniedRow.layer?.cornerCurve = .continuous
        deniedRow.contentTintColor = .labelColor
        deniedRow.translatesAutoresizingMaskIntoConstraints = false
        deniedRow.heightAnchor.constraint(equalToConstant: 38).isActive = true
        deniedRow.widthAnchor.constraint(equalToConstant: popoverContentWidth).isActive = true

        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10
        row.edgeInsets = NSEdgeInsets(top: 0, left: 8, bottom: 0, right: 6)
        row.translatesAutoresizingMaskIntoConstraints = false
        deniedRow.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: deniedRow.leadingAnchor),
            row.trailingAnchor.constraint(equalTo: deniedRow.trailingAnchor),
            row.topAnchor.constraint(equalTo: deniedRow.topAnchor),
            row.bottomAnchor.constraint(equalTo: deniedRow.bottomAnchor)
        ])

        deniedBadgeLabel.font = NSFont.systemFont(ofSize: 15, weight: .bold)
        deniedBadgeLabel.textColor = .white
        deniedBadgeLabel.alignment = .center
        deniedBadgeLabel.wantsLayer = true
        deniedBadgeLabel.layer?.cornerRadius = 12
        deniedBadgeLabel.layer?.cornerCurve = .continuous
        deniedBadgeLabel.layer?.backgroundColor = NSColor.systemRed.cgColor
        deniedBadgeLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 34).isActive = true
        deniedBadgeLabel.heightAnchor.constraint(equalToConstant: 24).isActive = true
        row.addArrangedSubview(deniedBadgeLabel)

        let label = NSTextField(labelWithString: "Recently Denied")
        label.font = NSFont.systemFont(ofSize: 16, weight: .bold)
        row.addArrangedSubview(label)
        row.addArrangedSubview(NSView())
        row.addArrangedSubview(symbolImage("chevron.right", tint: .secondaryLabelColor, size: 15))
        return deniedRow
    }

    func menuAction(_ title: String, action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.isBordered = false
        button.alignment = .left
        button.cell?.alignment = .left
        button.font = NSFont.systemFont(ofSize: 14, weight: .semibold)
        button.contentTintColor = .labelColor
        button.translatesAutoresizingMaskIntoConstraints = false
        button.heightAnchor.constraint(equalToConstant: 28).isActive = true
        button.widthAnchor.constraint(equalToConstant: popoverContentWidth).isActive = true
        return button
    }

    func iconButton(_ symbol: String, action: Selector, tint: NSColor, tooltip: String) -> NSButton {
        let button = NSButton()
        button.isBordered = false
        button.target = self
        button.action = action
        button.toolTip = tooltip
        button.image = symbolImage(symbol, tint: tint, size: 20).image
        button.imagePosition = .imageOnly
        button.wantsLayer = true
        button.layer?.cornerRadius = 12
        button.layer?.cornerCurve = .continuous
        button.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.55).cgColor
        button.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.25).cgColor
        button.layer?.borderWidth = 0.5
        button.translatesAutoresizingMaskIntoConstraints = false
        button.widthAnchor.constraint(equalToConstant: 50).isActive = true
        button.heightAnchor.constraint(equalToConstant: 50).isActive = true
        return button
    }

    func symbolCircle(_ symbol: String, tint: NSColor, fallback: String) -> NSView {
        let holder = NSView()
        holder.wantsLayer = true
        holder.layer?.cornerRadius = 18
        holder.layer?.cornerCurve = .continuous
        holder.layer?.backgroundColor = tint.cgColor
        holder.translatesAutoresizingMaskIntoConstraints = false
        holder.widthAnchor.constraint(equalToConstant: 36).isActive = true
        holder.heightAnchor.constraint(equalToConstant: 36).isActive = true
        let image = symbolImage(symbol, tint: .white, size: 18)
        image.translatesAutoresizingMaskIntoConstraints = false
        holder.addSubview(image)
        NSLayoutConstraint.activate([
            image.centerXAnchor.constraint(equalTo: holder.centerXAnchor),
            image.centerYAnchor.constraint(equalTo: holder.centerYAnchor)
        ])
        return holder
    }

    func symbolImage(_ symbol: String, tint: NSColor, size: CGFloat) -> NSImageView {
        let imageView = NSImageView()
        if #available(macOS 11.0, *) {
            let config = NSImage.SymbolConfiguration(pointSize: size, weight: .bold)
            let image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?.withSymbolConfiguration(config)
            image?.isTemplate = true
            imageView.image = image
        }
        imageView.contentTintColor = tint
        imageView.imageScaling = .scaleProportionallyDown
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.widthAnchor.constraint(equalToConstant: size + 4).isActive = true
        imageView.heightAnchor.constraint(equalToConstant: size + 4).isActive = true
        return imageView
    }

    func separator() -> NSView {
        let line = NSBox()
        line.boxType = .separator
        return line
    }

    func refresh() {
        guard let monitor else { return }
        let denied = monitor.recentDeniedCount
        let pending = monitor.pendingAlertCount
        modeValueLabel.stringValue = pending > 0 ? "Alert" : "Monitor"
        daemonBadgeLabel.stringValue = monitor.daemonStateLabel.stringValue
        extensionBadgeLabel.stringValue = monitor.extensionSyncText
        allowedPillLabel.stringValue = "\(monitor.recentAllowedCount) allowed"
        deniedPillLabel.stringValue = "\(denied) denied"
        deniedBadgeLabel.stringValue = "\(denied)"
        sparkline.buckets = monitor.trafficSparkline.buckets
        recentStack.arrangedSubviews.forEach { view in
            recentStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        let recentEvents = monitor.events.filter { event in
            event.type == "network.decision" ||
                event.type.hasPrefix("guard.alert.") ||
                (!event.host.isEmpty && event.result != "inactive")
        }.prefix(4)
        if recentEvents.isEmpty {
            recentStack.addArrangedSubview(emptyRecentRow())
        } else {
            for event in recentEvents {
                recentStack.addArrangedSubview(recentActivityRow(event))
            }
        }
        statusItem.button?.contentTintColor = pending > 0 || denied > 0 ? .systemOrange : NSColor.controlTextColor
        if pending > 0 && pending != lastNotifiedPendingCount {
            notifyPendingAlerts(count: pending)
        }
        lastNotifiedPendingCount = pending
    }

    func recentActivityRow(_ event: GuardMonitorEvent) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 9

        let denied = event.result == "deny" || event.result == "denied"
        row.addArrangedSubview(miniSymbolCircle(denied ? "xmark.shield.fill" : "checkmark.shield.fill", tint: denied ? .systemRed : .systemBlue))

        let text = NSStackView()
        text.orientation = .vertical
        text.spacing = 1
        let title = NSTextField(labelWithString: compactActorLabel(for: event))
        title.font = NSFont.systemFont(ofSize: 14, weight: .semibold)
        title.lineBreakMode = .byTruncatingTail
        let detail = NSTextField(labelWithString: compactDestinationLabel(for: event))
        detail.font = NSFont.systemFont(ofSize: 11)
        detail.textColor = denied ? .systemRed : .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingMiddle
        text.addArrangedSubview(title)
        text.addArrangedSubview(detail)
        row.addArrangedSubview(text)
        return row
    }

    func emptyRecentRow() -> NSView {
        let label = NSTextField(labelWithString: "No recent network activity")
        label.font = NSFont.systemFont(ofSize: 13)
        label.textColor = .tertiaryLabelColor
        return label
    }

    func miniSymbolCircle(_ symbol: String, tint: NSColor) -> NSView {
        let holder = NSView()
        holder.wantsLayer = true
        holder.layer?.cornerRadius = 9
        holder.layer?.cornerCurve = .continuous
        holder.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.62).cgColor
        holder.translatesAutoresizingMaskIntoConstraints = false
        holder.widthAnchor.constraint(equalToConstant: 22).isActive = true
        holder.heightAnchor.constraint(equalToConstant: 22).isActive = true
        let image = symbolImage(symbol, tint: tint, size: 13)
        image.translatesAutoresizingMaskIntoConstraints = false
        holder.addSubview(image)
        NSLayoutConstraint.activate([
            image.centerXAnchor.constraint(equalTo: holder.centerXAnchor),
            image.centerYAnchor.constraint(equalTo: holder.centerYAnchor)
        ])
        return holder
    }

    func compactActorLabel(for event: GuardMonitorEvent) -> String {
        if !event.launcherApp.isEmpty { return event.launcherApp }
        if !event.launcherProcess.isEmpty { return event.launcherProcess }
        if !event.command.isEmpty {
            return (event.command as NSString).lastPathComponent
        }
        if !event.processPath.isEmpty {
            return (event.processPath as NSString).lastPathComponent
        }
        return event.type.isEmpty ? "Guard" : event.type
    }

    func compactDestinationLabel(for event: GuardMonitorEvent) -> String {
        let destination = event.host.isEmpty ? event.target : event.host
        let result = event.result.isEmpty ? "" : "\(event.result) "
        return destination.isEmpty ? event.type : "\(result)\(destination)"
    }

    func notifyPendingAlerts(count: Int) {
        let content = UNMutableNotificationContent()
        content.title = "Guard needs a network decision"
        content.body = "\(count) pending alert\(count == 1 ? "" : "s") waiting for review."
        content.sound = .default
        content.categoryIdentifier = "GUARD_PENDING_ALERT"
        let request = UNNotificationRequest(identifier: "dev.guard.pending-alerts", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    @objc func togglePopover(_ sender: Any?) {
        refresh()
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    @objc func openMonitor(_ sender: Any?) {
        monitor?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        popover.performClose(sender)
    }

    @objc func openRules(_ sender: Any?) {
        monitor?.openRulesWindow(sender)
        popover.performClose(sender)
    }

    @objc func openSettings(_ sender: Any?) {
        monitor?.openSettingsWindow(sender)
        popover.performClose(sender)
    }

    @objc func openDenied(_ sender: Any?) {
        monitor?.monitorFilterControl.selectedSegment = 2
        monitor?.rebuildActivityRows(keepSelection: false)
        monitor?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        popover.performClose(sender)
    }
}

func installMainMenu(appName: String, delegate: GuardApplicationDelegate) {
    let mainMenu = NSMenu()

    let appItem = NSMenuItem()
    let appMenu = NSMenu(title: appName)
    let quitTitle = "Quit \(appName)"
    let quit = NSMenuItem(title: quitTitle, action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    quit.target = NSApp
    appMenu.addItem(quit)
    appItem.submenu = appMenu
    mainMenu.addItem(appItem)

    let fileItem = NSMenuItem()
    let fileMenu = NSMenu(title: "File")
    let close = NSMenuItem(title: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
    close.target = nil
    fileMenu.addItem(close)
    let refresh = NSMenuItem(title: "Refresh", action: #selector(GuardApplicationDelegate.refreshMonitor(_:)), keyEquivalent: "r")
    refresh.target = delegate
    fileMenu.addItem(refresh)
    fileItem.submenu = fileMenu
    mainMenu.addItem(fileItem)

    let viewItem = NSMenuItem()
    let viewMenu = NSMenu(title: "View")
    let monitor = NSMenuItem(title: "Show Monitor", action: #selector(GuardApplicationDelegate.showMonitor(_:)), keyEquivalent: "0")
    let rules = NSMenuItem(title: "Rules", action: #selector(GuardApplicationDelegate.showRules(_:)), keyEquivalent: "1")
    let settings = NSMenuItem(title: "Settings", action: #selector(GuardApplicationDelegate.showSettings(_:)), keyEquivalent: ",")
    let search = NSMenuItem(title: "Find", action: #selector(GuardApplicationDelegate.focusMonitorSearch(_:)), keyEquivalent: "f")
    for item in [monitor, rules, settings, search] {
        item.target = delegate
        viewMenu.addItem(item)
    }
    viewItem.submenu = viewMenu
    mainMenu.addItem(viewItem)

    NSApp.mainMenu = mainMenu
}

func logFileHandle(profile: String) throws -> FileHandle {
    let logDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library")
        .appendingPathComponent("Logs")
        .appendingPathComponent("guard")
    try FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
    let logURL = logDir.appendingPathComponent("\(profile).log")
    if !FileManager.default.fileExists(atPath: logURL.path) {
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
    }
    let handle = try FileHandle(forWritingTo: logURL)
    try handle.seekToEnd()
    let header = "\n--- \(Date()) launching \(profile) ---\n"
    if let data = header.data(using: .utf8) {
        try handle.write(contentsOf: data)
    }
    return handle
}

func launchGuardedApp(config: GuardAppConfig) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: config.guardPath)
    process.arguments = ["run", config.profile]

    let log = try logFileHandle(profile: config.profile)
    process.standardOutput = log
    process.standardError = log

    try process.run()
    try? log.close()
}

func showError(_ message: String) {
    let alert = NSAlert()
    alert.messageText = "Guard Launcher Failed"
    alert.informativeText = message
    alert.alertStyle = .critical
    alert.addButton(withTitle: "OK")
    alert.runModal()
}

func jsonArgument() -> String? {
    let args = CommandLine.arguments
    guard let index = args.firstIndex(of: "--json"), index + 1 < args.count else {
        return nil
    }
    return args[index + 1]
}

func emitDecision(_ decision: GuardAskDecision) {
    let encoder = JSONEncoder()
    if let data = try? encoder.encode(decision), let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        print("{\"action\":\"deny\"}")
    }
}

func decodeJsonArgument<T: Decodable>(_ type: T.Type) throws -> T {
    guard let json = jsonArgument(), let data = json.data(using: .utf8) else {
        throw NSError(domain: "GuardAppLauncher", code: 2, userInfo: [
            NSLocalizedDescriptionKey: "Missing --json payload."
        ])
    }
    return try JSONDecoder().decode(T.self, from: data)
}

enum GuardPromptChoice {
    case deny
    case allowOnce
    case allowExact
    case allowPath
    case allowDomain
}

final class GuardConnectionPromptController: NSObject, NSWindowDelegate {
    let titleText: String
    let actor: String
    let destination: String
    let context: String
    let scopeRows: [(String, String)]
    let detailRows: [(String, String)]
    let actions: [(String, GuardPromptChoice, Bool)]
    let scopeOptions: [(String, GuardPromptChoice)]
    let lifetimeOptions: [(String, String)]
    let methodOptions: [(String, [String]?)]
    let editablePath: String?
    var selectedChoice: GuardPromptChoice = .deny
    var scopePopup: NSPopUpButton?
    var lifetimePopup: NSPopUpButton?
    var methodPopup: NSPopUpButton?
    var pathField: NSTextField?
    var detailsView: NSView?
    var detailsButton: NSButton?

    init(
        titleText: String,
        actor: String,
        destination: String,
        context: String,
        scopeRows: [(String, String)],
        detailRows: [(String, String)],
        actions: [(String, GuardPromptChoice, Bool)],
        scopeOptions: [(String, GuardPromptChoice)] = [],
        lifetimeOptions: [(String, String)] = [],
        methodOptions: [(String, [String]?)] = [],
        editablePath: String? = nil
    ) {
        self.titleText = titleText
        self.actor = actor
        self.destination = destination
        self.context = context
        self.scopeRows = scopeRows
        self.detailRows = detailRows
        self.actions = actions
        self.scopeOptions = scopeOptions
        self.lifetimeOptions = lifetimeOptions
        self.methodOptions = methodOptions
        self.editablePath = editablePath
    }

    func run() -> GuardPromptChoice {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 390),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.minSize = NSSize(width: 700, height: 390)
        panel.maxSize = NSSize(width: 700, height: 530)
        panel.title = "Guard Connection"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.delegate = self

        let background = NSVisualEffectView()
        background.material = .windowBackground
        background.blendingMode = .behindWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView = background

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .width
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 34, left: 38, bottom: 18, right: 28)
        root.translatesAutoresizingMaskIntoConstraints = false
        background.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: background.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: background.trailingAnchor),
            root.topAnchor.constraint(equalTo: background.topAnchor),
            root.bottomAnchor.constraint(equalTo: background.bottomAnchor)
        ])

        root.addArrangedSubview(makeHeader())
        root.addArrangedSubview(makeScopePanel())

        let details = makeDetailsPanel()
        details.isHidden = true
        details.setContentHuggingPriority(.defaultLow, for: .horizontal)
        detailsView = details
        root.addArrangedSubview(details)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .vertical)
        root.addArrangedSubview(spacer)
        root.addArrangedSubview(makeActionBar(panel: panel))

        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        NSApp.runModal(for: panel)
        panel.orderOut(nil)
        return selectedChoice
    }

    func windowWillClose(_ notification: Notification) {
        selectedChoice = .deny
        NSApp.stopModal()
    }

    @objc func chooseAction(_ sender: NSButton) {
        if sender.tag >= 0 && sender.tag < actions.count {
            selectedChoice = actions[sender.tag].1
        } else {
            selectedChoice = .deny
        }
        if selectedChoice != .deny, let scopePopup, scopePopup.indexOfSelectedItem >= 0, scopePopup.indexOfSelectedItem < scopeOptions.count {
            selectedChoice = scopeOptions[scopePopup.indexOfSelectedItem].1
        }
        NSApp.stopModal()
    }

    @objc func toggleDetails(_ sender: NSButton) {
        guard let detailsView else { return }
        detailsView.isHidden.toggle()
        sender.title = detailsView.isHidden ? "Details" : "Hide Details"
        if let panel = sender.window {
            panel.setContentSize(NSSize(width: 700, height: detailsView.isHidden ? 390 : 530))
        }
    }

    @objc func showPathHelp(_ sender: NSButton) {
        let alert = NSAlert()
        alert.messageText = "HTTP Path Rules"
        alert.informativeText = [
            "Use /v1/responses for one exact endpoint.",
            "Use /v1/* to allow everything below a path group.",
            "Use /* only when every path on this host is acceptable.",
            "Query strings are visible after TLS inspection and are matched as part of the path when present."
        ].joined(separator: "\n")
        alert.addButton(withTitle: "OK")
        if let window = sender.window {
            alert.beginSheetModal(for: window)
        } else {
            alert.runModal()
        }
    }

    func makeHeader() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 12

        let iconWrap = NSView()
        iconWrap.wantsLayer = true
        iconWrap.layer?.cornerRadius = 9
        iconWrap.layer?.cornerCurve = .continuous
        iconWrap.layer?.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.16).cgColor
        iconWrap.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            iconWrap.widthAnchor.constraint(equalToConstant: 38),
            iconWrap.heightAnchor.constraint(equalToConstant: 38)
        ])

        let icon = NSImageView()
        if #available(macOS 11.0, *) {
            icon.image = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: "Network request")
            icon.contentTintColor = .controlAccentColor
        } else {
            icon.image = NSImage(named: NSImage.networkName)
        }
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.translatesAutoresizingMaskIntoConstraints = false
        iconWrap.addSubview(icon)
        NSLayoutConstraint.activate([
            icon.centerXAnchor.constraint(equalTo: iconWrap.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: iconWrap.centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 21),
            icon.heightAnchor.constraint(equalToConstant: 21)
        ])

        let title = promptLabel(titleText, size: 18, weight: .bold)
        let subtitle = promptLabel(context, size: 11.5, weight: .regular, color: .secondaryLabelColor)
        subtitle.maximumNumberOfLines = 1

        let actorLine = makeKeyValueLine("Actor", actor, strong: true)
        let targetLine = makeKeyValueLine("Destination", destination, strong: true)

        let text = NSStackView(views: [title, subtitle, actorLine, targetLine])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 5
        text.setContentHuggingPriority(.defaultLow, for: .horizontal)

        row.addArrangedSubview(iconWrap)
        row.addArrangedSubview(text)
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    func makeScopePanel() -> NSView {
        let container = promptCard()
        let stack = paddedPromptStack(in: container, inset: 12)
        stack.spacing = 8

        let heading = promptLabel("Decision", size: 12, weight: .semibold, color: .secondaryLabelColor)
        stack.addArrangedSubview(heading)
        if !scopeOptions.isEmpty {
            let popup = NSPopUpButton()
            popup.addItems(withTitles: scopeOptions.map { $0.0 })
            popup.controlSize = .regular
            popup.font = NSFont.systemFont(ofSize: 13, weight: .medium)
            popup.translatesAutoresizingMaskIntoConstraints = false
            popup.widthAnchor.constraint(equalToConstant: 430).isActive = true
            scopePopup = popup
            stack.addArrangedSubview(makeControlLine("Scope", popup))
        }
        if !lifetimeOptions.isEmpty {
            let popup = NSPopUpButton()
            popup.addItems(withTitles: lifetimeOptions.map { $0.0 })
            popup.selectItem(at: min(1, lifetimeOptions.count - 1))
            popup.controlSize = .regular
            popup.font = NSFont.systemFont(ofSize: 13, weight: .medium)
            popup.translatesAutoresizingMaskIntoConstraints = false
            popup.widthAnchor.constraint(equalToConstant: 220).isActive = true
            lifetimePopup = popup
            stack.addArrangedSubview(makeControlLine("Lifetime", popup))
        }
        if !methodOptions.isEmpty {
            let popup = NSPopUpButton()
            popup.addItems(withTitles: methodOptions.map { $0.0 })
            popup.controlSize = .regular
            popup.font = NSFont.systemFont(ofSize: 13, weight: .medium)
            popup.translatesAutoresizingMaskIntoConstraints = false
            popup.widthAnchor.constraint(equalToConstant: 220).isActive = true
            methodPopup = popup
            stack.addArrangedSubview(makeControlLine("Methods", popup))
        }
        if let editablePath {
            let field = NSTextField(string: editablePath)
            field.controlSize = .regular
            field.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
            field.lineBreakMode = .byTruncatingMiddle
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: 430).isActive = true
            pathField = field
            stack.addArrangedSubview(makePathControlLine(field))
        }
        for (label, value) in scopeRows {
            stack.addArrangedSubview(makeKeyValueLine(label, value, strong: false))
        }
        return container
    }

    func makeDetailsPanel() -> NSView {
        let container = promptCard()
        let stack = paddedPromptStack(in: container, inset: 12)
        stack.spacing = 7
        stack.addArrangedSubview(promptLabel("Connection Details", size: 12, weight: .semibold, color: .secondaryLabelColor))
        for (label, value) in detailRows {
            stack.addArrangedSubview(makeKeyValueLine(label, value, strong: false))
        }
        return container
    }

    func makeActionBar(panel: NSPanel) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 6

        let details = NSButton(title: "Details", target: self, action: #selector(toggleDetails(_:)))
        details.bezelStyle = .regularSquare
        details.controlSize = .regular
        detailsButton = details
        row.addArrangedSubview(details)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)

        for (index, action) in actions.enumerated() {
            let button = NSButton(title: action.0, target: self, action: #selector(chooseAction(_:)))
            button.bezelStyle = action.2 ? .rounded : .regularSquare
            button.tag = index
            button.controlSize = .regular
            button.setContentHuggingPriority(.required, for: .horizontal)
            if action.2 {
                button.keyEquivalent = "\r"
                button.keyEquivalentModifierMask = []
            }
            if action.1 == .deny {
                button.hasDestructiveAction = true
                button.keyEquivalent = "\u{1b}"
                button.keyEquivalentModifierMask = []
            }
            row.addArrangedSubview(button)
        }
        return row
    }

    func makeKeyValueLine(_ key: String, _ value: String, strong: Bool) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 8

        let keyLabel = promptLabel(key, size: 11, weight: .medium, color: .tertiaryLabelColor)
        keyLabel.alignment = .right
        keyLabel.translatesAutoresizingMaskIntoConstraints = false
        keyLabel.widthAnchor.constraint(equalToConstant: 104).isActive = true

        let valueLabel = promptLabel(value.isEmpty ? "Unknown" : value, size: strong ? 13 : 12, weight: strong ? .semibold : .regular)
        valueLabel.lineBreakMode = .byTruncatingMiddle
        valueLabel.maximumNumberOfLines = 1
        valueLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)

        row.addArrangedSubview(keyLabel)
        row.addArrangedSubview(valueLabel)
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    func makeControlLine(_ key: String, _ control: NSView) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 9

        let keyLabel = promptLabel(key, size: 11, weight: .medium, color: .tertiaryLabelColor)
        keyLabel.alignment = .right
        keyLabel.translatesAutoresizingMaskIntoConstraints = false
        keyLabel.widthAnchor.constraint(equalToConstant: 104).isActive = true

        row.addArrangedSubview(keyLabel)
        row.addArrangedSubview(control)
        return row
    }

    func makePathControlLine(_ control: NSView) -> NSView {
        let row = makeControlLine("Path", control) as! NSStackView
        let help = NSButton(title: "?", target: self, action: #selector(showPathHelp(_:)))
        help.bezelStyle = .helpButton
        help.toolTip = "Show path wildcard examples."
        row.addArrangedSubview(help)
        return row
    }

    var selectedDuration: String {
        guard let lifetimePopup, lifetimePopup.indexOfSelectedItem >= 0, lifetimePopup.indexOfSelectedItem < lifetimeOptions.count else {
            return "run"
        }
        return lifetimeOptions[lifetimePopup.indexOfSelectedItem].1
    }

    var selectedPath: String {
        pathField?.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? "/"
    }

    var selectedMethods: [String]? {
        guard let methodPopup,
              methodPopup.indexOfSelectedItem >= 0,
              methodPopup.indexOfSelectedItem < methodOptions.count else {
            return nil
        }
        return methodOptions[methodPopup.indexOfSelectedItem].1
    }

    func promptCard() -> NSView {
        let view = NSView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.wantsLayer = true
        view.layer?.cornerRadius = 6
        view.layer?.cornerCurve = .continuous
        view.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.22).cgColor
        view.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.12).cgColor
        view.layer?.borderWidth = 0.5
        return view
    }

    func paddedPromptStack(in view: NSView, inset: CGFloat) -> NSStackView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: inset),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -inset),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: inset),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -inset)
        ])
        return stack
    }

    func promptLabel(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = NSFont.systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byWordWrapping
        return field
    }
}

func runAskNetworkPanel(input: GuardAskNetworkInput) -> GuardAskDecision {
    let target = input.target ?? "\(input.host)\(input.port.map { ":\($0)" } ?? "")"
    let actorCommand = input.command?.isEmpty == false ? input.command! : "Guard run"
    let actor = input.launcherApp?.isEmpty == false ? "\(actorCommand) via \(input.launcherApp!)" : actorCommand
    let domainParts = input.host.split(separator: ".")
    let wildcard = domainParts.count > 2 ? "*." + domainParts.suffix(domainParts.count - 2).joined(separator: ".") : "*.\(input.host)"
    let controller = GuardConnectionPromptController(
        titleText: "Connection Request",
        actor: actor,
        destination: target,
        context: "Choose the narrowest network rule that fits this request.",
        scopeRows: [
            ("Type", "Destination only"),
            ("TLS", "Not inspected; path and query are not visible here"),
            ("Profile", input.profile ?? "guard")
        ],
        detailRows: [
            ("Host", input.host),
            ("Port", input.port.map { "\($0)" } ?? "default"),
            ("Launched By", input.launcherApp?.isEmpty == false ? input.launcherApp! : "Not recorded"),
            ("Visibility", "Host and port before TLS handshake"),
            ("Project", input.projectDir ?? "Unknown"),
            ("Run", input.runDir ?? "Unknown")
        ],
        actions: [
            ("Deny", .deny, false),
            ("Allow", .allowOnce, true)
        ],
        scopeOptions: [
            ("Exact host: \(input.host)", .allowDomain),
            ("Subdomains: \(wildcard)", .allowPath)
        ],
        lifetimeOptions: promptLifetimeOptions()
    )
    let choice = controller.run()
    return GuardAskDecision(
        action: choice == .deny ? "deny" : "allow",
        rule: nil,
        duration: controller.selectedDuration
    )
}

func runAskHttpPolicyPanel(input: GuardAskHttpPolicyInput) -> GuardAskDecision {
    let request = input.request
    let actorCommand = input.command?.isEmpty == false ? input.command! : "Guard run"
    let actor = input.launcherApp?.isEmpty == false ? "\(actorCommand) via \(input.launcherApp!)" : actorCommand
    let suggestedPaths = input.suggestedRule.paths?.joined(separator: ", ") ?? "Any path"
    let suggestedMethods = input.suggestedRule.methods?.joined(separator: ", ") ?? "Any method"
    let controller = GuardConnectionPromptController(
        titleText: "HTTP Policy Request",
        actor: actor,
        destination: "\(request.method) \(request.host)\(request.path)",
        context: "Choose the narrowest HTTP rule that fits this request.",
        scopeRows: [
            ("Type", "HTTP request"),
            ("TLS", "Inspected by iron-proxy for this guarded process"),
            ("Suggested", "\(suggestedMethods) \(suggestedPaths)"),
            ("Host", request.host)
        ],
        detailRows: [
            ("Host", request.host),
            ("Method", request.method),
            ("Path", request.path),
            ("Launched By", input.launcherApp?.isEmpty == false ? input.launcherApp! : "Not recorded"),
            ("Visibility", "Method, path, and query visible after TLS interception"),
            ("Profile", input.profile ?? "guard"),
            ("Project", input.projectDir ?? "Unknown"),
            ("Run", input.runDir ?? "Unknown")
        ],
        actions: [
            ("Deny", .deny, false),
            ("Allow", .allowExact, true)
        ],
        scopeOptions: [
            ("Exact path", .allowExact),
            ("Path group: \(suggestedPaths)", .allowPath),
            ("Entire host: \(request.host)", .allowDomain)
        ],
        lifetimeOptions: promptLifetimeOptions(),
        methodOptions: [
            ("All methods", nil),
            ("Only \(request.method)", [request.method]),
            ("Read methods: GET, HEAD", ["GET", "HEAD"]),
            ("Write methods: POST, PUT, PATCH, DELETE", ["POST", "PUT", "PATCH", "DELETE"])
        ],
        editablePath: request.path
    )
    switch controller.run() {
    case .allowExact:
        return GuardAskDecision(
            action: "allow",
            rule: GuardHttpPolicyRule(host: request.host, cidr: nil, methods: controller.selectedMethods, paths: [controller.selectedPath]),
            duration: controller.selectedDuration
        )
    case .allowPath:
        let path = controller.selectedPath
        let rulePath = path == request.path ? (input.suggestedRule.paths?.first ?? path) : path
        return GuardAskDecision(
            action: "allow",
            rule: GuardHttpPolicyRule(host: request.host, cidr: nil, methods: controller.selectedMethods, paths: [rulePath]),
            duration: controller.selectedDuration
        )
    case .allowDomain:
        return GuardAskDecision(
            action: "allow",
            rule: GuardHttpPolicyRule(host: request.host, cidr: nil, methods: nil, paths: nil),
            duration: controller.selectedDuration
        )
    default:
        return GuardAskDecision(action: "deny", rule: nil, duration: controller.selectedDuration)
    }
}

func promptLifetimeOptions() -> [(String, String)] {
    [
        ("Once", "once"),
        ("5 minutes", "5m"),
        ("1 hour", "1h"),
        ("2 days", "2d"),
        ("5 days", "5d"),
        ("Forever", "forever")
    ]
}

func runCliAskModeIfNeeded() -> Bool {
    guard CommandLine.arguments.count > 1 else { return false }
    let mode = CommandLine.arguments[1]
    guard mode == "ask-network" || mode == "ask-http-policy" else { return false }
    NSApp.setActivationPolicy(.accessory)
    do {
        if mode == "ask-network" {
            let input = try decodeJsonArgument(GuardAskNetworkInput.self)
            emitDecision(runAskNetworkPanel(input: input))
            return true
        }
        if mode == "ask-http-policy" {
            let input = try decodeJsonArgument(GuardAskHttpPolicyInput.self)
            emitDecision(runAskHttpPolicyPanel(input: input))
            return true
        }
    } catch {
        emitDecision(GuardAskDecision(action: "deny", rule: nil, duration: nil))
        return true
    }
    return false
}

final class CardView: NSView {
    init(fill: NSColor = NSColor.controlBackgroundColor.withAlphaComponent(0.46), border: NSColor = NSColor.clear) {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.cornerRadius = 14
        layer?.cornerCurve = .continuous
        layer?.backgroundColor = fill.cgColor
        layer?.borderColor = border.cgColor
        layer?.borderWidth = 0
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

final class HoverPolicySwitch: NSControl {
    var selectedSegment: Int = 1 {
        didSet { needsDisplay = true }
    }
    private var hoveredSegment: Int?
    private let denyColor = NSColor.systemRed
    private let allowColor = NSColor.systemGreen

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        toolTip = "Allow or deny this domain"
        translatesAutoresizingMaskIntoConstraints = false
        widthAnchor.constraint(equalToConstant: 62).isActive = true
        heightAnchor.constraint(equalToConstant: 24).isActive = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        for area in trackingAreas {
            removeTrackingArea(area)
        }
        addTrackingArea(NSTrackingArea(
            rect: bounds,
            options: [.mouseEnteredAndExited, .mouseMoved, .activeInKeyWindow, .inVisibleRect],
            owner: self,
            userInfo: nil
        ))
    }

    override func mouseEntered(with event: NSEvent) {
        updateHover(with: event)
    }

    override func mouseMoved(with event: NSEvent) {
        updateHover(with: event)
    }

    override func mouseExited(with event: NSEvent) {
        hoveredSegment = nil
        needsDisplay = true
    }

    override func mouseDown(with event: NSEvent) {
        selectedSegment = segment(at: convert(event.locationInWindow, from: nil))
        sendAction(action, to: target)
    }

    private func updateHover(with event: NSEvent) {
        let segment = segment(at: convert(event.locationInWindow, from: nil))
        if hoveredSegment != segment {
            hoveredSegment = segment
            needsDisplay = true
        }
    }

    private func segment(at point: NSPoint) -> Int {
        point.x < bounds.midX ? 0 : 1
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let baseRect = bounds.insetBy(dx: 0.5, dy: 0.5)
        let path = NSBezierPath(roundedRect: baseRect, xRadius: 6, yRadius: 6)
        NSColor.controlBackgroundColor.withAlphaComponent(0.62).setFill()
        path.fill()
        NSColor.separatorColor.withAlphaComponent(0.48).setStroke()
        path.lineWidth = 0.8
        path.stroke()

        let selectedRect = segmentRect(selectedSegment).insetBy(dx: 1.5, dy: 1.5)
        let selectedPath = NSBezierPath(roundedRect: selectedRect, xRadius: 5, yRadius: 5)
        (selectedSegment == 0 ? denyColor : allowColor).withAlphaComponent(0.82).setFill()
        selectedPath.fill()

        if let hoveredSegment, hoveredSegment != selectedSegment {
            let hoverRect = segmentRect(hoveredSegment).insetBy(dx: 2, dy: 2)
            let hoverPath = NSBezierPath(roundedRect: hoverRect, xRadius: 5, yRadius: 5)
            NSColor.white.withAlphaComponent(0.16).setFill()
            hoverPath.fill()
        }

        NSColor.separatorColor.withAlphaComponent(0.36).setStroke()
        let divider = NSBezierPath()
        divider.move(to: NSPoint(x: bounds.midX, y: bounds.minY + 4))
        divider.line(to: NSPoint(x: bounds.midX, y: bounds.maxY - 4))
        divider.lineWidth = 0.6
        divider.stroke()

        drawSymbol("xmark", in: segmentRect(0), selected: selectedSegment == 0, color: denyColor)
        drawSymbol("checkmark", in: segmentRect(1), selected: selectedSegment == 1, color: allowColor)
    }

    private func segmentRect(_ segment: Int) -> NSRect {
        let width = bounds.width / 2
        return NSRect(x: segment == 0 ? bounds.minX : bounds.midX, y: bounds.minY, width: width, height: bounds.height)
    }

    private func drawSymbol(_ name: String, in rect: NSRect, selected: Bool, color: NSColor) {
        let symbolColor = selected ? NSColor.white : NSColor.tertiaryLabelColor
        symbolColor.setStroke()
        let path = NSBezierPath()
        path.lineWidth = 2.1
        path.lineCapStyle = .round
        path.lineJoinStyle = .round
        if name == "xmark" {
            path.move(to: NSPoint(x: rect.midX - 4.2, y: rect.midY - 4.2))
            path.line(to: NSPoint(x: rect.midX + 4.2, y: rect.midY + 4.2))
            path.move(to: NSPoint(x: rect.midX - 4.2, y: rect.midY + 4.2))
            path.line(to: NSPoint(x: rect.midX + 4.2, y: rect.midY - 4.2))
        } else {
            path.move(to: NSPoint(x: rect.midX - 5, y: rect.midY - 0.5))
            path.line(to: NSPoint(x: rect.midX - 1.4, y: rect.midY - 4))
            path.line(to: NSPoint(x: rect.midX + 5, y: rect.midY + 4.4))
        }
        path.stroke()
    }
}

final class DisclosureButton: NSButton {
    weak var disclosureView: NSView?

    init(expanded: Bool) {
        super.init(frame: .zero)
        title = expanded ? "⌄" : "›"
        isBordered = false
        bezelStyle = .regularSquare
        font = NSFont.systemFont(ofSize: 20, weight: .semibold)
        contentTintColor = .tertiaryLabelColor
        setButtonType(.momentaryChange)
        translatesAutoresizingMaskIntoConstraints = false
        widthAnchor.constraint(equalToConstant: 18).isActive = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

final class SettingsRowView: NSView {
    weak var disclosureView: NSView?
    weak var disclosureButton: DisclosureButton?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        addGestureRecognizer(NSClickGestureRecognizer(target: self, action: #selector(handleClick(_:))))
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    @objc private func handleClick(_ recognizer: NSClickGestureRecognizer) {
        toggleDisclosure()
    }

    @objc func toggleDisclosure() {
        guard let detail = disclosureView else { return }
        detail.isHidden.toggle()
        disclosureButton?.title = detail.isHidden ? "›" : "⌄"
    }
}

final class LauncherWindowController: NSObject, NSWindowDelegate {
    let config: GuardAppConfig
    let summary: GuardAppSummary
    var window: NSWindow?

    init(config: GuardAppConfig, summary: GuardAppSummary) {
        self.config = config
        self.summary = summary
    }

    func show() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 500),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard \(config.displayName)"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.center()
        window.delegate = self

        let background = NSVisualEffectView()
        background.material = .contentBackground
        background.blendingMode = .behindWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = background

        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 18, left: 34, bottom: 16, right: 34)
        root.translatesAutoresizingMaskIntoConstraints = false
        background.addSubview(root)

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: background.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: background.trailingAnchor),
            root.topAnchor.constraint(equalTo: background.topAnchor),
            root.bottomAnchor.constraint(equalTo: background.bottomAnchor)
        ])

        root.addArrangedSubview(makeHeader())
        root.addArrangedSubview(makePolicyList())
        root.addArrangedSubview(makeActionBar())

        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) {
        NSApp.terminate(nil)
    }

    @objc func cancelLaunch(_ sender: Any?) {
        NSApp.terminate(nil)
    }

    @objc func launchApp(_ sender: Any?) {
        do {
            try launchGuardedApp(config: config)
            NSApp.terminate(nil)
        } catch {
            showError(error.localizedDescription)
        }
    }

    @objc func toggleDisclosure(_ sender: DisclosureButton) {
        guard let detail = sender.disclosureView else { return }
        detail.isHidden.toggle()
        sender.title = detail.isHidden ? "›" : "⌄"
    }

    func makeHeader() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12

        let icon = NSImageView()
        icon.image = NSApp.applicationIconImage
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 44),
            icon.heightAnchor.constraint(equalToConstant: 44)
        ])

        let title = label("Launch \(config.displayName) with Guard", size: 20, weight: .bold)
        let subtitle = label(
            summary.description.isEmpty ? "Review the locked sandbox before opening the app." : summary.description,
            size: 13,
            weight: .regular,
            color: .secondaryLabelColor
        )

        let titleStack = NSStackView(views: [title, subtitle, makeMetaLine()])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 5

        row.addArrangedSubview(icon)
        row.addArrangedSubview(titleStack)
        return row
    }

    func makeMetaLine() -> NSView {
        let warningText = summary.findings.isEmpty ? "No warnings" : "\(summary.findings.count) warning\(summary.findings.count == 1 ? "" : "s")"
        return label(
            "\(summary.status.capitalized) profile • \(summary.risk.capitalized) risk • \(summary.network.mode.capitalized) network • \(warningText)",
            size: 11,
            weight: .regular,
            color: .tertiaryLabelColor
        )
    }

    func makePolicyList() -> NSView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: 300).isActive = true

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false

        let group = CardView()
        let groupStack = paddedStack(in: group, inset: 0)
        groupStack.spacing = 0
        groupStack.alignment = .width

        groupStack.addArrangedSubview(settingsRow(
            symbol: "network",
            title: "Network Allowlist",
            subtitle: "Allows \(exampleText(summary.network.allowedDomains, empty: "no domains")).",
            values: summary.network.allowedDomains,
            tint: .systemGreen,
            countText: "\(summary.network.allowedDomains.count)",
            initiallyExpanded: true
        ))
        groupStack.addArrangedSubview(separator())
        groupStack.addArrangedSubview(settingsRow(
            symbol: "folder",
            title: "Read Access",
            subtitle: "Allows \(exampleText(summary.filesystem.allowRead, empty: "no paths")).",
            values: summary.filesystem.allowRead,
            tint: .systemBlue,
            countText: "\(summary.filesystem.allowRead.count)",
            initiallyExpanded: true
        ))
        groupStack.addArrangedSubview(separator())
        let protectedPaths = summary.filesystem.denyRead + summary.filesystem.denyWrite
        groupStack.addArrangedSubview(settingsRow(
            symbol: "lock",
            title: "Protected Paths",
            subtitle: "Denies \(exampleText(protectedPaths, empty: "no paths")).",
            values: protectedPaths,
            tint: .systemOrange,
            countText: "\(protectedPaths.count)",
            initiallyExpanded: true
        ))
        groupStack.addArrangedSubview(separator())
        groupStack.addArrangedSubview(settingsRow(
            symbol: summary.findings.isEmpty ? "checkmark.shield" : "exclamationmark.triangle",
            title: "Review",
            subtitle: reviewSubtitle(),
            values: reviewValues(),
            tint: summary.findings.isEmpty ? .systemGreen : .systemOrange,
            countText: summary.findings.isEmpty ? "0" : "\(summary.findings.count)",
            initiallyExpanded: !summary.findings.isEmpty
        ))
        stack.addArrangedSubview(group)

        scroll.documentView = stack
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            stack.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            stack.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor)
        ])
        return scroll
    }

    func makeActionBar() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10

        let note = label("~/Library/Logs/guard/\(config.profile).log", size: 11, weight: .regular, color: .tertiaryLabelColor)
        note.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelLaunch(_:)))
        cancel.bezelStyle = .rounded

        let launch = NSButton(title: "Launch \(config.displayName)", target: self, action: #selector(launchApp(_:)))
        launch.bezelStyle = .rounded
        launch.keyEquivalent = "\r"
        launch.hasDestructiveAction = false

        row.addArrangedSubview(note)
        row.addArrangedSubview(cancel)
        row.addArrangedSubview(launch)
        return row
    }

    func settingsRow(
        symbol: String,
        title: String,
        subtitle: String,
        values: [String],
        tint: NSColor,
        countText: String,
        initiallyExpanded: Bool
    ) -> NSView {
        let rowContainer = SettingsRowView()
        let stack = paddedStack(in: rowContainer, inset: 10)
        stack.spacing = 4
        stack.alignment = .width

        let header = NSStackView()
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 10
        header.translatesAutoresizingMaskIntoConstraints = false
        header.heightAnchor.constraint(greaterThanOrEqualToConstant: 36).isActive = true

        header.addArrangedSubview(symbolTile(symbol, color: tint))

        let labels = NSStackView()
        labels.orientation = .vertical
        labels.spacing = 1
        labels.alignment = .leading
        labels.addArrangedSubview(label(title, size: 14, weight: .semibold))
        let subtitleLabel = label(subtitle, size: 11, weight: .regular, color: .secondaryLabelColor)
        subtitleLabel.maximumNumberOfLines = 2
        subtitleLabel.lineBreakMode = .byTruncatingMiddle
        labels.addArrangedSubview(subtitleLabel)
        header.addArrangedSubview(labels)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        header.addArrangedSubview(spacer)

        let count = label(countText, size: 13, weight: .semibold, color: .secondaryLabelColor)
        count.alignment = .right
        count.translatesAutoresizingMaskIntoConstraints = false
        count.widthAnchor.constraint(greaterThanOrEqualToConstant: 22).isActive = true
        header.addArrangedSubview(count)

        let disclosure = DisclosureButton(expanded: initiallyExpanded)
        disclosure.target = rowContainer
        disclosure.action = #selector(SettingsRowView.toggleDisclosure)
        header.addArrangedSubview(disclosure)

        stack.addArrangedSubview(header)

        let details = makeDetails(values: values)
        details.isHidden = !initiallyExpanded
        disclosure.disclosureView = details
        rowContainer.disclosureView = details
        rowContainer.disclosureButton = disclosure
        stack.addArrangedSubview(details)

        return rowContainer
    }

    func separator() -> NSView {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.backgroundColor = NSColor.separatorColor.withAlphaComponent(0.16).cgColor
        view.translatesAutoresizingMaskIntoConstraints = false
        view.heightAnchor.constraint(equalToConstant: 0.5).isActive = true
        return view
    }

    func paddedStack(in view: NSView, inset: CGFloat) -> NSStackView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: inset),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -inset),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: inset),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -inset)
        ])
        return stack
    }

    func symbolView(_ name: String, color: NSColor, size: CGFloat = 18) -> NSView {
        let imageView = NSImageView()
        if #available(macOS 11.0, *) {
            imageView.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
            imageView.contentTintColor = color
        } else {
            imageView.image = NSImage(named: NSImage.cautionName)
        }
        imageView.imageScaling = .scaleProportionallyUpOrDown
        imageView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            imageView.widthAnchor.constraint(equalToConstant: size),
            imageView.heightAnchor.constraint(equalToConstant: size)
        ])
        return imageView
    }

    func symbolTile(_ name: String, color: NSColor) -> NSView {
        let tile = CardView(fill: NSColor.controlBackgroundColor.withAlphaComponent(0.64), border: NSColor.separatorColor.withAlphaComponent(0.16))
        tile.layer?.cornerRadius = 7
        tile.layer?.borderWidth = 0.5
        tile.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            tile.widthAnchor.constraint(equalToConstant: 26),
            tile.heightAnchor.constraint(equalToConstant: 26)
        ])

        let symbol = symbolView(name, color: color, size: 15)
        symbol.translatesAutoresizingMaskIntoConstraints = false
        tile.addSubview(symbol)
        NSLayoutConstraint.activate([
            symbol.centerXAnchor.constraint(equalTo: tile.centerXAnchor),
            symbol.centerYAnchor.constraint(equalTo: tile.centerYAnchor)
        ])
        return tile
    }

    func label(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = NSFont.systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byWordWrapping
        return field
    }

    func makeDetails(values: [String]) -> NSView {
        let container = NSView()
        let list = NSStackView()
        list.orientation = .vertical
        list.alignment = .leading
        list.spacing = 3
        list.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(list)

        if values.isEmpty {
            list.addArrangedSubview(label("None", size: 11, weight: .regular, color: .tertiaryLabelColor))
        } else {
            for value in values.prefix(5) {
                let line = label(value, size: 11, weight: .regular, color: .secondaryLabelColor)
                line.lineBreakMode = .byTruncatingMiddle
                line.maximumNumberOfLines = 1
                list.addArrangedSubview(line)
            }
            if values.count > 5 {
                list.addArrangedSubview(label("+ \(values.count - 5) more in the policy file", size: 11, weight: .regular, color: .tertiaryLabelColor))
            }
        }

        NSLayoutConstraint.activate([
            list.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 36),
            list.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -28),
            list.topAnchor.constraint(equalTo: container.topAnchor),
            list.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -4)
        ])
        return container
    }

    func statusColor() -> NSColor {
        summary.status == "locked" ? .systemGreen : .systemOrange
    }

    func riskColor() -> NSColor {
        switch summary.risk.lowercased() {
        case "low": return .systemGreen
        case "medium": return .systemOrange
        case "high", "critical": return .systemRed
        default: return .secondaryLabelColor
        }
    }

    func reviewSubtitle() -> String {
        if summary.findings.isEmpty {
            return "No risky policy choices were found."
        }
        return summary.findings.first?.message ?? "\(summary.findings.count) policy warning\(summary.findings.count == 1 ? "" : "s") needs review."
    }

    func reviewValues() -> [String] {
        if summary.findings.isEmpty {
            return []
        }
        return summary.findings.map { "[\($0.severity)] \($0.message)" }
    }

    func exampleText(_ values: [String], empty: String) -> String {
        if values.isEmpty {
            return empty
        }
        let shown = values.prefix(2).joined(separator: ", ")
        let suffix = values.count > 2 ? ", +\(values.count - 2) more" : ""
        return "\(shown)\(suffix)"
    }

}

struct GuardMonitorEvent {
    let id: String
    let at: String
    let type: String
    let profile: String
    let projectDir: String
    let cwd: String
    let runDir: String
    let command: String
    let processPath: String
    let launcherApp: String
    let launcherProcess: String
    let launcherPid: Int
    let parentChain: String
    let pid: Int
    let bundleIdentifier: String
    let bytesSent: Int
    let bytesReceived: Int
    let host: String
    let target: String
    let result: String
    let detail: String
    let status: String
    let expiresAt: String
    let duration: String
    let rulePersisted: Bool
    let ruleId: String
}

struct MonitorActivityRow {
    let isGroup: Bool
    let kind: String
    let level: Int
    let rowKey: String
    let app: String
    let destination: String
    let activity: String
    let decision: String
    let time: String
    let event: GuardMonitorEvent?

    init(
        isGroup: Bool,
        kind: String = "event",
        level: Int = 0,
        rowKey: String = "",
        app: String,
        destination: String,
        activity: String,
        decision: String,
        time: String,
        event: GuardMonitorEvent?
    ) {
        self.isGroup = isGroup
        self.kind = kind
        self.level = level
        self.rowKey = rowKey.isEmpty ? "\(kind):\(app):\(destination)" : rowKey
        self.app = app
        self.destination = destination
        self.activity = activity
        self.decision = decision
        self.time = time
        self.event = event
    }
}

struct GuardDaemonResponse {
    let statusCode: Int
    let data: Data
}

final class GuardDaemonClient {
    let baseURL: URL
    let apiToken: String?
    let timeout: TimeInterval = 0.8

    init?(apiTokenOverride: String? = nil, baseURLOverride: String? = nil) {
        let env = ProcessInfo.processInfo.environment
        let configured = env["GUARD_DAEMON_URL"] ?? env["GUARDD_URL"]
        let rawURL: String
        if let baseURLOverride, !baseURLOverride.isEmpty {
            rawURL = baseURLOverride
        } else if let configured = configured, !configured.isEmpty {
            rawURL = configured
        } else {
            let host = env["GUARDD_HOST"]?.isEmpty == false ? env["GUARDD_HOST"]! : "127.0.0.1"
            let port = env["GUARDD_PORT"]?.isEmpty == false ? env["GUARDD_PORT"]! : "8765"
            rawURL = "http://\(host):\(port)"
        }
        guard let url = URL(string: rawURL) else { return nil }
        baseURL = url
        apiToken = apiTokenOverride ?? (env["GUARDD_API_TOKEN"]?.isEmpty == false ? env["GUARDD_API_TOKEN"] : nil)
    }

    func url(path: String, queryItems: [URLQueryItem] = []) -> URL? {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else { return nil }
        let basePath = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let requestPath = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.path = "/" + [basePath, requestPath].filter { !$0.isEmpty }.joined(separator: "/")
        components.queryItems = queryItems.isEmpty ? nil : queryItems
        return components.url
    }

    func request(path: String, method: String = "GET", body: [String: Any]? = nil, queryItems: [URLQueryItem] = []) -> GuardDaemonResponse? {
        guard let requestURL = url(path: path, queryItems: queryItems) else { return nil }
        var request = URLRequest(url: requestURL, timeoutInterval: timeout)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token = apiToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body = body {
            guard JSONSerialization.isValidJSONObject(body),
                  let data = try? JSONSerialization.data(withJSONObject: body) else {
                return nil
            }
            request.httpBody = data
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let semaphore = DispatchSemaphore(value: 0)
        var result: GuardDaemonResponse?
        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            if let http = response as? HTTPURLResponse {
                result = GuardDaemonResponse(statusCode: http.statusCode, data: data ?? Data())
            }
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + timeout + 0.2) == .timedOut {
            task.cancel()
            return nil
        }
        return result
    }

    func getJSON(path: String, queryItems: [URLQueryItem] = []) -> [String: Any]? {
        guard let response = request(path: path, queryItems: queryItems),
              (200..<300).contains(response.statusCode),
              let object = try? JSONSerialization.jsonObject(with: response.data) as? [String: Any] else {
            return nil
        }
        return object
    }

    func postRule(profile: String, field: String, value: String, ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = ["action": "add", "field": field, "value": value]
        if let ifMatch, !ifMatch.isEmpty { body["ifMatch"] = ifMatch }
        return request(
            path: "/profiles/\(profile.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? profile)/rules",
            method: "POST",
            body: body
        )
    }

    func addProject(root: String, label: String = "") -> GuardDaemonResponse? {
        var body: [String: Any] = ["root": root]
        if !label.isEmpty { body["label"] = label }
        return request(path: "/projects", method: "POST", body: body)
    }

    func mutateRule(profile: String, action: String, field: String, value: Any, disabled: Bool = false, ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = ["action": action, "field": field, "disabled": disabled]
        if let ifMatch, !ifMatch.isEmpty { body["ifMatch"] = ifMatch }
        if field == "network.httpRules", let rule = value as? [String: Any] {
            body["rule"] = rule
        } else {
            body["value"] = value
        }
        return request(
            path: "/profiles/\(profile.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? profile)/rules",
            method: "POST",
            body: body
        )
    }

    func postTLS(profile: String, enabled: Bool, ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = ["enabled": enabled]
        if let ifMatch, !ifMatch.isEmpty { body["ifMatch"] = ifMatch }
        return request(
            path: "/profiles/\(profile.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? profile)/tls",
            method: "POST",
            body: body
        )
    }

    func postTLSCA(action: String, days: Int = 30) -> GuardDaemonResponse? {
        request(
            path: "/tls/ca",
            method: "POST",
            body: ["action": action, "days": days]
        )
    }

    func postAlertDecision(profile: String, host: String, port: Int = 0, action: String, duration: String, method: String = "", path: String = "", scope: String = "", launcherApp: String = "", launcherProcess: String = "", launcherPid: Int = 0, parentChain: String = "", ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = [
            "profile": profile,
            "host": host,
            "port": port,
            "action": action,
            "duration": duration,
            "method": method,
            "path": path,
            "scope": scope,
            "launcherApp": launcherApp,
            "launcherProcess": launcherProcess,
            "launcherPid": launcherPid,
            "parentChain": parentChain,
            "reason": "monitor-alert-action"
        ]
        if let ifMatch, !ifMatch.isEmpty { body["ifMatch"] = ifMatch }
        return request(path: "/alerts/decision", method: "POST", body: body)
    }

    func resolvePendingAlert(alertId: String, action: String, duration: String, scope: String = "", ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = [
            "action": action,
            "duration": duration,
            "scope": scope,
            "reason": "monitor-pending-alert-action"
        ]
        if let ifMatch, !ifMatch.isEmpty { body["ifMatch"] = ifMatch }
        return request(
            path: "/alerts/\(alertId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? alertId)/resolve",
            method: "POST",
            body: body
        )
    }

    func pendingAlerts(limit: Int = 20) -> [String: Any]? {
        getJSON(path: "/alerts/pending", queryItems: [URLQueryItem(name: "limit", value: "\(limit)")])
    }

    func postExtensionSync(profile: String, mode: String = "strict-deny") -> GuardDaemonResponse? {
        request(path: "/extension/sync", method: "POST", body: ["profile": profile, "mode": mode])
    }

    func invalidateExtensionSync(reason: String = "monitor-request") -> GuardDaemonResponse? {
        request(path: "/extension/sync", method: "POST", body: ["action": "invalidate", "reason": reason])
    }

    func previewTemplate(template: String, profile: String) -> [String: Any]? {
        getJSON(
            path: "/templates/\(template.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? template)/preview",
            queryItems: [URLQueryItem(name: "profile", value: profile)]
        )
    }

    func applyTemplate(template: String, profile: String, force: Bool = false) -> GuardDaemonResponse? {
        request(
            path: "/templates/\(template.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? template)/apply",
            method: "POST",
            body: ["profile": profile, "force": force]
        )
    }
}

enum MonitorInspectorTab: Int {
    case events = 0
    case rules = 1
    case templates = 2
    case settings = 3
}

struct MonitorRuleRow {
    let id: String
    let kind: String
    let action: String
    let scope: String
    let detail: String
    let enabled: Bool
    let source: String
    let field: String
    let value: Any
    let layer: String
    let lifetime: String
    let approvalState: String
    let notes: String
    let expiresAt: String

    init(
        id: String = "",
        kind: String,
        action: String,
        scope: String,
        detail: String,
        enabled: Bool,
        source: String,
        field: String,
        value: Any,
        layer: String = "",
        lifetime: String = "persistent",
        approvalState: String = "approved",
        notes: String = "",
        expiresAt: String = ""
    ) {
        self.id = id
        self.kind = kind
        self.action = action
        self.scope = scope
        self.detail = detail
        self.enabled = enabled
        self.source = source
        self.field = field
        self.value = value
        self.layer = layer
        self.lifetime = lifetime
        self.approvalState = approvalState
        self.notes = notes
        self.expiresAt = expiresAt
    }
}

struct MonitorTemplateRow {
    let name: String
    let description: String
    let detail: String
}

final class EventLogWindowController: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate {
    weak var parent: MonitorWindowController?
    var window: NSWindow?
    var events: [GuardMonitorEvent] = []
    let tableView = NSTableView()
    let detailView = NSTextView()
    let statusLabel = NSTextField(labelWithString: "")

    init(parent: MonitorWindowController) {
        self.parent = parent
        super.init()
    }

    func show() {
        events = parent?.events ?? []
        if let window {
            tableView.reloadData()
            statusLabel.stringValue = "\(events.count) loaded events"
            window.makeKeyAndOrderFront(nil)
            return
        }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 560), styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        window.title = "Guard Event Log"
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("dev.guard.event-log.window")
        window.center()

        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.translatesAutoresizingMaskIntoConstraints = false
        let content = NSVisualEffectView()
        content.material = .contentBackground
        content.blendingMode = .behindWindow
        content.state = .active
        content.addSubview(split)
        window.contentView = content
        NSLayoutConstraint.activate([
            split.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            split.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            split.topAnchor.constraint(equalTo: content.topAnchor),
            split.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        let tableScroll = NSScrollView()
        tableScroll.hasVerticalScroller = true
        tableView.headerView = NSTableHeaderView()
        tableView.rowHeight = 28
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.autosaveName = "dev.guard.event-log.columns"
        tableView.autosaveTableColumns = true
        tableView.dataSource = self
        tableView.delegate = self
        tableView.addTableColumn(column("time", "Time", 150))
        tableView.addTableColumn(column("type", "Type", 170))
        tableView.addTableColumn(column("target", "Target", 260))
        tableView.addTableColumn(column("result", "Result", 90))
        tableScroll.documentView = tableView

        detailView.isEditable = false
        detailView.isRichText = false
        detailView.usesFindBar = true
        detailView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        let detailScroll = NSScrollView()
        detailScroll.hasVerticalScroller = true
        detailScroll.documentView = detailView

        split.addArrangedSubview(tableScroll)
        split.addArrangedSubview(detailScroll)
        tableScroll.widthAnchor.constraint(greaterThanOrEqualToConstant: 520).isActive = true
        self.window = window
        tableView.reloadData()
        statusLabel.stringValue = "\(events.count) loaded events"
        window.makeKeyAndOrderFront(nil)
    }

    func column(_ identifier: String, _ title: String, _ width: CGFloat) -> NSTableColumn {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
        column.title = title
        column.width = width
        column.minWidth = 60
        return column
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func numberOfRows(in tableView: NSTableView) -> Int { events.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < events.count else { return nil }
        let event = events[row]
        let id = tableColumn?.identifier.rawValue ?? ""
        let text: String
        switch id {
        case "time": text = event.at
        case "type": text = event.type
        case "target": text = event.target.isEmpty ? event.command : event.target
        case "result": text = event.result
        default: text = ""
        }
        let cell = NSTableCellView()
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 12)
        label.lineBreakMode = .byTruncatingMiddle
        label.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 6),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -6),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = tableView.selectedRow
        guard row >= 0 && row < events.count else {
            detailView.string = "Select an event."
            return
        }
        let event = events[row]
        detailView.string = [
            "time: \(event.at)",
            "type: \(event.type)",
            "profile: \(event.profile)",
            "process: \(event.command)",
            "path: \(event.processPath)",
            "target: \(event.target)",
            "result: \(event.result)",
            "rule: \(event.ruleId)",
            "detail: \(event.detail)"
        ].joined(separator: "\n")
    }
}

final class TrafficSparklineView: NSView {
    var buckets: [(allowed: Int, denied: Int)] = [] {
        didSet {
            needsDisplay = true
            toolTip = buckets.isEmpty
                ? "No recent network decisions"
                : "Recent policy decisions. Purple bars are allowed; red bars are denied."
        }
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        layer?.cornerRadius = 7
        layer?.cornerCurve = .continuous
        layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.42).cgColor
        translatesAutoresizingMaskIntoConstraints = false
        widthAnchor.constraint(greaterThanOrEqualToConstant: 280).isActive = true
        let defaultHeight = heightAnchor.constraint(equalToConstant: 42)
        defaultHeight.priority = .defaultLow
        defaultHeight.isActive = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard !buckets.isEmpty else {
            NSColor.separatorColor.withAlphaComponent(0.45).setStroke()
            let mid = bounds.midY
            let path = NSBezierPath()
            path.move(to: NSPoint(x: bounds.minX + 8, y: mid))
            path.line(to: NSPoint(x: bounds.maxX - 8, y: mid))
            path.lineWidth = 1
            path.stroke()
            return
        }

        let inset: CGFloat = 7
        let drawing = bounds.insetBy(dx: inset, dy: inset)
        let maxValue = max(1, buckets.map { $0.allowed + $0.denied }.max() ?? 1)
        let gap: CGFloat = 2
        let barWidth = max(2, (drawing.width - gap * CGFloat(max(0, buckets.count - 1))) / CGFloat(buckets.count))
        let midY = drawing.midY

        for (index, bucket) in buckets.enumerated() {
            let x = drawing.minX + CGFloat(index) * (barWidth + gap)
            let allowedHeight = bucket.allowed == 0 ? 0 : max(2, (drawing.height * 0.46) * CGFloat(bucket.allowed) / CGFloat(maxValue))
            let deniedHeight = bucket.denied == 0 ? 0 : max(2, (drawing.height * 0.46) * CGFloat(bucket.denied) / CGFloat(maxValue))

            if allowedHeight > 0 {
                let allowedRect = NSRect(x: x, y: midY, width: barWidth, height: allowedHeight)
                NSColor.systemPurple.withAlphaComponent(0.78).setFill()
                NSBezierPath(roundedRect: allowedRect, xRadius: 1.5, yRadius: 1.5).fill()
            }

            if deniedHeight > 0 {
                let deniedRect = NSRect(x: x, y: midY - deniedHeight, width: barWidth, height: deniedHeight)
                NSColor.systemRed.withAlphaComponent(0.82).setFill()
                NSBezierPath(roundedRect: deniedRect, xRadius: 1.5, yRadius: 1.5).fill()
            }
        }
    }
}

final class MonitorRowView: NSTableRowView {
    var denied = false
    var group = false
    var odd = false

    override func drawBackground(in dirtyRect: NSRect) {
        if !isSelected && !group && odd {
            NSColor.controlBackgroundColor.withAlphaComponent(0.10).setFill()
            NSBezierPath(rect: bounds).fill()
        }
    }

    override func drawSeparator(in dirtyRect: NSRect) {
        NSColor.separatorColor.withAlphaComponent(group ? 0.24 : 0.10).setStroke()
        let path = NSBezierPath()
        path.move(to: NSPoint(x: bounds.minX + 8, y: bounds.minY))
        path.line(to: NSPoint(x: bounds.maxX - 8, y: bounds.minY))
        path.lineWidth = 0.5
        path.stroke()
    }
}

final class FlippedStackView: NSStackView {
    override var isFlipped: Bool { true }
}

final class RulesWindowController: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate, NSToolbarDelegate {
    weak var parent: MonitorWindowController?
    let client: GuardDaemonClient?
    let tableView = NSTableView()
    let searchField = NSSearchField()
    let profilePopup = NSPopUpButton()
    let sidebar = NSOutlineView()
    let inspectorStack = NSStackView()
    let filterControl = NSSegmentedControl(labels: ["All", "Allow", "Deny", "HTTP", "Off"], trackingMode: .selectOne, target: nil, action: nil)
    let statusLabel = NSTextField(labelWithString: "")
    weak var rulesToolbarSearchField: NSSearchField?
    var window: NSWindow?
    var profileNames: [String]
    var selectedProfile: String
    var rows: [MonitorRuleRow]
    var renderedRows: [MonitorRuleRow] = []
    let sidebarSections = ["All Rules", "Active", "Deny", "Recent Changes", "Temporary", "Unapproved", "Rule Groups", "Blocklists"]

    init(client: GuardDaemonClient?, profileNames: [String], selectedProfile: String, rows: [MonitorRuleRow], parent: MonitorWindowController) {
        self.client = client
        self.profileNames = Array(Set(profileNames + [selectedProfile, "guard"])).filter { !$0.isEmpty }.sorted()
        self.selectedProfile = selectedProfile.isEmpty ? "guard" : selectedProfile
        self.rows = rows
        self.parent = parent
        super.init()
    }

    func show() {
        if let window = window {
            syncProfilePopup()
            renderRows()
            window.makeKeyAndOrderFront(nil)
            return
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 960, height: 620),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Rules"
        window.titlebarAppearsTransparent = false
        let toolbar = NSToolbar(identifier: NSToolbar.Identifier("dev.guard.rules.toolbar"))
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        toolbar.allowsUserCustomization = true
        toolbar.autosavesConfiguration = true
        window.toolbar = toolbar
        window.isReleasedWhenClosed = false
        window.animationBehavior = .none
        window.delegate = self
        window.setFrameAutosaveName("dev.guard.rules.window")
        if #available(macOS 11.0, *) {
            window.toolbarStyle = .unifiedCompact
        }
        window.center()

        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 0
        root.edgeInsets = NSEdgeInsets(top: 0, left: 0, bottom: 8, right: 0)
        root.translatesAutoresizingMaskIntoConstraints = false
        let content = NSVisualEffectView()
        content.material = .contentBackground
        content.blendingMode = .behindWindow
        content.state = .active
        content.addSubview(root)
        window.contentView = content
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        root.addArrangedSubview(makeRulesSplitView())
        root.addArrangedSubview(makeActionBar())

        self.window = window
        syncProfilePopup()
        renderRows()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [
            NSToolbarItem.Identifier("rulesRefresh"),
            NSToolbarItem.Identifier("rulesProfile"),
            NSToolbarItem.Identifier("rulesFilter"),
            NSToolbarItem.Identifier("rulesSearch"),
            .flexibleSpace
        ]
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        toolbarDefaultItemIdentifiers(toolbar) + [.space]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        let item = NSToolbarItem(itemIdentifier: itemIdentifier)
        switch itemIdentifier.rawValue {
        case "rulesRefresh":
            item.label = "Refresh"
            item.paletteLabel = "Refresh"
            item.target = self
            item.action = #selector(refresh(_:))
            if #available(macOS 11.0, *) {
                item.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: "Refresh")
            }
        case "rulesProfile":
            item.label = "Profile"
            item.paletteLabel = "Profile"
            syncProfilePopup()
            profilePopup.target = self
            profilePopup.action = #selector(profileChanged(_:))
            profilePopup.controlSize = .regular
            profilePopup.widthAnchor.constraint(equalToConstant: 230).isActive = true
            item.view = profilePopup
        case "rulesFilter":
            item.label = "Filter"
            item.paletteLabel = "Filter"
            filterControl.selectedSegment = 0
            filterControl.target = self
            filterControl.action = #selector(filterChanged(_:))
            filterControl.segmentStyle = .texturedRounded
            filterControl.controlSize = .regular
            filterControl.widthAnchor.constraint(equalToConstant: 300).isActive = true
            item.view = filterControl
        case "rulesSearch":
            if #available(macOS 11.0, *) {
                let search = NSSearchToolbarItem(itemIdentifier: itemIdentifier)
                search.label = "Search"
                search.searchField.placeholderString = "Search rules"
                search.searchField.target = self
                search.searchField.action = #selector(rulesToolbarSearchChanged(_:))
                rulesToolbarSearchField = search.searchField
                return search
            }
            item.label = "Search"
            item.target = self
            item.action = #selector(focusRulesSearch(_:))
            item.image = NSImage(named: NSImage.touchBarSearchTemplateName)
        default:
            return nil
        }
        return item
    }

    @objc func rulesToolbarSearchChanged(_ sender: NSSearchField) {
        searchField.stringValue = sender.stringValue
        filterChanged(sender)
    }

    @objc func focusRulesSearch(_ sender: Any?) {
        window?.makeFirstResponder(rulesToolbarSearchField ?? searchField)
    }

    func makeRulesSplitView() -> NSView {
        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.translatesAutoresizingMaskIntoConstraints = false
        split.heightAnchor.constraint(greaterThanOrEqualToConstant: 500).isActive = true

        let sidebarScroll = NSScrollView()
        sidebarScroll.borderType = .noBorder
        sidebarScroll.hasVerticalScroller = true
        sidebar.headerView = nil
        sidebar.rowHeight = 28
        if #available(macOS 11.0, *) {
            sidebar.style = .sourceList
        }
        sidebar.addTableColumn(NSTableColumn(identifier: NSUserInterfaceItemIdentifier("section")))
        sidebar.outlineTableColumn = sidebar.tableColumns.first
        sidebar.dataSource = self
        sidebar.delegate = self
        sidebar.target = self
        sidebar.action = #selector(ruleSidebarChanged(_:))
        sidebarScroll.documentView = sidebar
        sidebar.reloadData()
        sidebar.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        let table = makeTable()
        let inspector = makeRuleInspector()
        sidebarScroll.translatesAutoresizingMaskIntoConstraints = false
        table.translatesAutoresizingMaskIntoConstraints = false
        inspector.translatesAutoresizingMaskIntoConstraints = false
        split.addArrangedSubview(sidebarScroll)
        split.addArrangedSubview(table)
        split.addArrangedSubview(inspector)
        sidebarScroll.widthAnchor.constraint(equalToConstant: 190).isActive = true
        table.widthAnchor.constraint(greaterThanOrEqualToConstant: 700).isActive = true
        inspector.widthAnchor.constraint(equalToConstant: 230).isActive = true
        return split
    }

    func syncProfilePopup() {
        let current = selectedProfile.isEmpty ? "guard" : selectedProfile
        profilePopup.removeAllItems()
        profilePopup.addItems(withTitles: Array(Set(profileNames + [current, "guard"])).filter { !$0.isEmpty }.sorted())
        profilePopup.selectItem(withTitle: current)
    }

    func makeTable() -> NSView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.borderType = .noBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 500).isActive = true
        tableView.headerView = NSTableHeaderView()
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.allowsMultipleSelection = true
        tableView.rowHeight = 30
        tableView.dataSource = self
        tableView.delegate = self
        let menu = NSMenu(title: "Rule Actions")
        menu.delegate = self
        tableView.menu = menu
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        tableView.addTableColumn(column("state", "State", 54))
        tableView.addTableColumn(column("action", "Action", 82))
        tableView.addTableColumn(column("kind", "Kind", 108))
        tableView.addTableColumn(column("scope", "Scope", 320))
        tableView.addTableColumn(column("detail", "Detail", 210))
        tableView.addTableColumn(column("lifetime", "Lifetime", 86))
        tableView.addTableColumn(column("approval", "Review", 76))
        tableView.autosaveName = "dev.guard.rules.columns"
        tableView.autosaveTableColumns = true
        tableView.sortDescriptors = [
            NSSortDescriptor(key: "kind", ascending: true),
            NSSortDescriptor(key: "scope", ascending: true)
        ]
        scroll.documentView = tableView
        DispatchQueue.main.async {
            self.resizeRulesColumns()
            self.resetRulesTableScrollOrigin()
        }
        return scroll
    }

    func makeRuleInspector() -> NSView {
        let panel = NSVisualEffectView()
        panel.material = .sidebar
        panel.blendingMode = .withinWindow
        panel.state = .active
        panel.translatesAutoresizingMaskIntoConstraints = false
        panel.widthAnchor.constraint(greaterThanOrEqualToConstant: 210).isActive = true

        inspectorStack.orientation = .vertical
        inspectorStack.alignment = .leading
        inspectorStack.spacing = 8
        inspectorStack.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        inspectorStack.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(inspectorStack)
        NSLayoutConstraint.activate([
            inspectorStack.leadingAnchor.constraint(equalTo: panel.leadingAnchor),
            inspectorStack.trailingAnchor.constraint(equalTo: panel.trailingAnchor),
            inspectorStack.topAnchor.constraint(equalTo: panel.topAnchor),
            inspectorStack.bottomAnchor.constraint(lessThanOrEqualTo: panel.bottomAnchor)
        ])
        renderInspector()
        return panel
    }

    func makeActionBar() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        row.edgeInsets = NSEdgeInsets(top: 8, left: 12, bottom: 0, right: 12)
        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.lineBreakMode = .byTruncatingTail
        let enable = NSButton(title: "Enable", target: self, action: #selector(enableSelected(_:)))
        let disable = NSButton(title: "Disable", target: self, action: #selector(disableSelected(_:)))
        let delete = NSButton(title: "Delete", target: self, action: #selector(deleteSelected(_:)))
        let disableVisible = NSButton(title: "Disable Visible", target: self, action: #selector(disableVisible(_:)))
        let close = NSButton(title: "Close", target: self, action: #selector(closeWindow(_:)))
        for button in [enable, disable, delete, disableVisible, close] {
            button.bezelStyle = .rounded
        }
        row.addArrangedSubview(statusLabel)
        row.addArrangedSubview(enable)
        row.addArrangedSubview(disable)
        row.addArrangedSubview(delete)
        row.addArrangedSubview(disableVisible)
        row.addArrangedSubview(close)
        return row
    }

    func column(_ identifier: String, _ title: String, _ width: CGFloat) -> NSTableColumn {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
        column.title = title
        column.width = width
        column.minWidth = 50
        return column
    }

    func resizeRulesColumns() {
        guard tableView.numberOfColumns >= 6 else { return }
        let available = tableView.enclosingScrollView?.contentView.bounds.width ?? tableView.bounds.width
        guard available > 0 else { return }
        let fixed: CGFloat = 54 + 82 + 108 + 86 + 76
        let remaining = max(320, available - fixed - 12)
        let scopeWidth = floor(remaining * 0.58)
        let detailWidth = floor(remaining - scopeWidth)
        let widths: [String: CGFloat] = [
            "state": 54,
            "action": 82,
            "kind": 108,
            "scope": max(260, scopeWidth),
            "detail": max(160, detailWidth),
            "lifetime": 86,
            "approval": 76
        ]
        for column in tableView.tableColumns {
            guard let width = widths[column.identifier.rawValue] else { continue }
            column.width = width
            column.minWidth = min(width, 70)
        }
    }

    func resetRulesTableScrollOrigin() {
        guard let clipView = tableView.enclosingScrollView?.contentView else { return }
        let current = clipView.bounds.origin
        clipView.scroll(to: NSPoint(x: 0, y: current.y))
        tableView.enclosingScrollView?.reflectScrolledClipView(clipView)
    }

    @objc func filterChanged(_ sender: Any?) {
        renderRows()
    }

    @objc func ruleSidebarChanged(_ sender: Any?) {
        renderRows()
    }

    @objc func profileChanged(_ sender: NSPopUpButton) {
        selectedProfile = sender.titleOfSelectedItem ?? selectedProfile
        refresh(nil)
    }

    @objc func refresh(_ sender: Any?) {
        parent?.loadDaemonPolicyState(profile: selectedProfile)
        rows = parent?.ruleRows ?? rows
        renderRows()
        statusLabel.stringValue = "Loaded \(rows.count) rules for \(selectedProfile)."
    }

    func renderRows() {
        let search = searchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let filter = filterControl.selectedSegment
        let selectedSection = sidebar.selectedRow >= 0 ? sidebarSections[safe: sidebar.selectedRow] ?? "All Rules" : "All Rules"
        renderedRows = rows.filter { row in
            let text = [row.kind, row.action, row.scope, row.detail, row.source].joined(separator: " ").lowercased()
            let matchesSearch = search.isEmpty || text.contains(search)
            let matchesFilter: Bool
            switch filter {
            case 1: matchesFilter = row.action == "allow"
            case 2: matchesFilter = row.action == "deny"
            case 3: matchesFilter = row.kind == "HTTP"
            case 4: matchesFilter = !row.enabled
            default: matchesFilter = true
            }
            let matchesSection: Bool
            switch selectedSection {
            case "Active": matchesSection = row.enabled
            case "Deny": matchesSection = row.action == "deny"
            case "Recent Changes": matchesSection = !row.detail.isEmpty || !row.id.isEmpty
            case "Temporary": matchesSection = row.lifetime != "persistent"
            case "Unapproved": matchesSection = row.approvalState != "approved"
            case "Rule Groups": matchesSection = row.kind == "HTTP" || row.kind == "Domain"
            case "Blocklists": matchesSection = row.action == "deny" && row.kind == "Domain"
            default: matchesSection = true
            }
            return matchesSearch && matchesFilter && matchesSection
        }
        tableView.reloadData()
        resizeRulesColumns()
        resetRulesTableScrollOrigin()
        if !renderedRows.isEmpty && tableView.selectedRow < 0 {
            tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        }
        sidebar.reloadData()
        renderInspector()
        statusLabel.stringValue = rows.isEmpty
            ? "No rules are loaded for \(selectedProfile). Connect guardd or select another profile."
            : "\(renderedRows.count) visible of \(rows.count) rules."
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        renderInspector()
    }

    func renderInspector() {
        for view in inspectorStack.arrangedSubviews {
            inspectorStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        guard tableView.selectedRow >= 0, tableView.selectedRow < renderedRows.count else {
            inspectorStack.addArrangedSubview(inspectorLabel("Rule Inspector", weight: .semibold))
            inspectorStack.addArrangedSubview(inspectorLabel("Select a rule to review scope, lifetime, approval, source, and notes.", color: .secondaryLabelColor))
            return
        }
        let rule = renderedRows[tableView.selectedRow]
        inspectorStack.addArrangedSubview(inspectorLabel(rule.scope, weight: .semibold))
        inspectorStack.addArrangedSubview(inspectorBadge(rule.enabled ? "Enabled" : "Disabled", color: rule.enabled ? .systemGreen : .secondaryLabelColor))
        for (key, value) in [
            ("Action", rule.action.capitalized),
            ("Layer", rule.layer.isEmpty ? rule.kind : rule.layer),
            ("Lifetime", rule.lifetime),
            ("Review", rule.approvalState),
            ("Source", rule.source),
            ("Detail", rule.detail.isEmpty ? "None" : rule.detail),
            ("Notes", rule.notes.isEmpty ? "None" : rule.notes)
        ] {
            inspectorStack.addArrangedSubview(inspectorLabel("\(key): \(value)", color: .labelColor))
        }
    }

    func inspectorLabel(_ text: String, weight: NSFont.Weight = .regular, color: NSColor = .labelColor) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: weight == .semibold ? 13 : 11.5, weight: weight)
        label.textColor = color
        label.maximumNumberOfLines = 0
        label.lineBreakMode = .byWordWrapping
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return label
    }

    func inspectorBadge(_ text: String, color: NSColor) -> NSView {
        let field = inspectorLabel(text, weight: .semibold, color: color)
        let box = NSBox()
        box.boxType = .custom
        box.borderType = .lineBorder
        box.borderColor = color.withAlphaComponent(0.22)
        box.fillColor = color.withAlphaComponent(0.10)
        box.cornerRadius = 6
        box.translatesAutoresizingMaskIntoConstraints = false
        field.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(field)
        NSLayoutConstraint.activate([
            field.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 7),
            field.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -7),
            field.topAnchor.constraint(equalTo: box.topAnchor, constant: 3),
            field.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -3)
        ])
        return box
    }

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        item == nil ? sidebarSections.count : 0
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        sidebarSections[index]
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        false
    }

    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        let title = item as? String ?? ""
        let cell = NSTableCellView()
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 6
        row.translatesAutoresizingMaskIntoConstraints = false
        let icon = NSImageView()
        if #available(macOS 11.0, *) {
            icon.image = NSImage(systemSymbolName: sidebarSymbol(for: title), accessibilityDescription: title)
            icon.contentTintColor = .secondaryLabelColor
        }
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 16).isActive = true
        let count = sidebarCount(for: title)
        let label = NSTextField(labelWithString: count > 0 && title != "All Rules" ? "\(title)  \(count)" : title)
        label.font = NSFont.systemFont(ofSize: 12, weight: title == "All Rules" ? .semibold : .regular)
        row.addArrangedSubview(icon)
        row.addArrangedSubview(label)
        cell.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 8),
            row.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -6),
            row.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    func sidebarSymbol(for title: String) -> String {
        switch title {
        case "Active": return "checkmark.circle"
        case "Deny": return "xmark.octagon"
        case "Recent Changes": return "clock.arrow.circlepath"
        case "Temporary": return "timer"
        case "Unapproved": return "smallcircle.filled.circle"
        case "Rule Groups": return "folder"
        case "Blocklists": return "hand.raised"
        default: return "list.bullet"
        }
    }

    func sidebarCount(for title: String) -> Int {
        switch title {
        case "Active": return rows.filter { $0.enabled }.count
        case "Deny": return rows.filter { $0.action == "deny" }.count
        case "Temporary": return rows.filter { $0.lifetime != "persistent" }.count
        case "Unapproved": return rows.filter { $0.approvalState != "approved" }.count
        case "Blocklists": return rows.filter { $0.action == "deny" && $0.kind == "Domain" }.count
        default: return rows.count
        }
    }

    func selectedRule() -> MonitorRuleRow? {
        let row = tableView.selectedRow
        guard row >= 0 && row < renderedRows.count else {
            statusLabel.stringValue = "Select a rule first."
            return nil
        }
        return renderedRows[row]
    }

    func selectedRules() -> [MonitorRuleRow] {
        let indexes = tableView.selectedRowIndexes
        let selected = indexes.compactMap { index in
            index >= 0 && index < renderedRows.count ? renderedRows[index] : nil
        }
        return selected.isEmpty ? selectedRule().map { [$0] } ?? [] : selected
    }

    @objc func enableSelected(_ sender: Any?) {
        mutateSelected(action: "enable")
    }

    @objc func disableSelected(_ sender: Any?) {
        mutateSelected(action: "disable")
    }

    @objc func deleteSelected(_ sender: Any?) {
        mutateSelected(action: "remove")
    }

    @objc func disableVisible(_ sender: Any?) {
        mutateRules(Array(renderedRows.prefix(100)), action: "disable")
    }

    @objc func closeWindow(_ sender: Any?) {
        window?.orderOut(nil)
    }

    func mutateSelected(action: String) {
        mutateRules(selectedRules(), action: action)
    }

    func isMutableRule(_ row: MonitorRuleRow) -> Bool {
        switch row.field {
        case "network.allowedDomains",
             "network.deniedDomains",
             "network.httpRules",
             "filesystem.allowRead",
             "filesystem.allowWrite",
             "filesystem.denyRead",
             "filesystem.denyWrite":
            return true
        default:
            return false
        }
    }

    func mutateRules(_ targetRows: [MonitorRuleRow], action: String) {
        guard !targetRows.isEmpty, let client = client else {
            statusLabel.stringValue = "guardd must be connected before editing rules."
            return
        }
        let editableRows = targetRows.filter(isMutableRule)
        guard !editableRows.isEmpty else {
            statusLabel.stringValue = "Selected rules are derived from runtime settings and cannot be edited here yet."
            return
        }
        var changed = 0
        for row in editableRows {
            guard let response = client.mutateRule(
                profile: selectedProfile,
                action: action,
                field: row.field,
                value: row.value,
                disabled: action == "disable",
                ifMatch: parent?.profileVersionText
            ) else {
                statusLabel.stringValue = "Rule update failed."
                return
            }
            if response.statusCode == 412 {
                parent?.loadDaemonPolicyState(profile: selectedProfile)
                rows = parent?.ruleRows ?? rows
                renderRows()
                statusLabel.stringValue = "Profile changed on disk. Reloaded latest rules; retry the action."
                return
            }
            if !(200..<300).contains(response.statusCode) {
                statusLabel.stringValue = parent?.daemonErrorMessage(response) ?? "Rule update failed."
                return
            }
            changed += 1
        }
        let skipped = targetRows.count - editableRows.count
        statusLabel.stringValue = "\(action.capitalized) \(changed) rule\(changed == 1 ? "" : "s")\(skipped > 0 ? "; \(skipped) derived rule\(skipped == 1 ? "" : "s") skipped." : ".")"
        parent?.didMutateRules(profile: selectedProfile)
        rows = parent?.ruleRows ?? rows
        renderRows()
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        renderedRows.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < renderedRows.count else { return nil }
        let rule = renderedRows[row]
        let id = tableColumn?.identifier.rawValue ?? ""
        let text: String
        switch id {
        case "state": text = rule.enabled ? "On" : "Off"
        case "action": text = rule.action
        case "kind": text = rule.kind
        case "scope": text = rule.scope
        case "detail": text = rule.detail
        case "lifetime": text = rule.lifetime
        case "approval": text = rule.approvalState
        case "source": text = rule.source
        default: text = ""
        }
        let cell = NSTableCellView()
        if id == "state" {
            let toggle = NSButton(checkboxWithTitle: "", target: self, action: #selector(toggleRuleCheckbox(_:)))
            toggle.state = rule.enabled ? .on : .off
            toggle.tag = row
            toggle.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(toggle)
            NSLayoutConstraint.activate([
                toggle.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 8),
                toggle.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            return cell
        }
        if id == "action" || id == "kind" || id == "lifetime" {
            let rowView = NSStackView()
            rowView.orientation = .horizontal
            rowView.alignment = .centerY
            rowView.spacing = 5
            rowView.translatesAutoresizingMaskIntoConstraints = false
            let icon = NSImageView()
            if #available(macOS 11.0, *) {
                icon.image = NSImage(systemSymbolName: ruleSymbol(rule, column: id), accessibilityDescription: text)
                icon.contentTintColor = id == "action"
                    ? (rule.action == "deny" ? .systemRed : .systemGreen)
                    : .secondaryLabelColor
            }
            icon.translatesAutoresizingMaskIntoConstraints = false
            icon.widthAnchor.constraint(equalToConstant: 15).isActive = true
            let label = NSTextField(labelWithString: text)
            label.font = NSFont.systemFont(ofSize: 12, weight: id == "action" ? .semibold : .regular)
            label.lineBreakMode = .byTruncatingTail
            label.textColor = id == "action" ? (rule.action == "deny" ? .systemRed : .systemGreen) : .labelColor
            rowView.addArrangedSubview(icon)
            rowView.addArrangedSubview(label)
            cell.addSubview(rowView)
            NSLayoutConstraint.activate([
                rowView.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 6),
                rowView.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -6),
                rowView.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            return cell
        }
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: 12)
        label.lineBreakMode = .byTruncatingMiddle
        if id == "state" {
            label.textColor = rule.enabled ? .systemGreen : .secondaryLabelColor
        } else if id == "action" {
            label.textColor = rule.action == "deny" ? .systemRed : .systemGreen
        }
        label.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 6),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -6),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    func ruleSymbol(_ rule: MonitorRuleRow, column: String) -> String {
        if column == "action" {
            return rule.action == "deny" ? "xmark.octagon.fill" : "checkmark.circle.fill"
        }
        if column == "lifetime" {
            return rule.lifetime == "persistent" ? "infinity" : "timer"
        }
        switch rule.kind {
        case "HTTP": return "arrow.left.arrow.right"
        case "Raw TCP": return "point.3.connected.trianglepath.dotted"
        case "Filesystem": return "folder"
        case "Domain": return "globe"
        default: return "slider.horizontal.3"
        }
    }

    @objc func toggleRuleCheckbox(_ sender: NSButton) {
        guard sender.tag >= 0 && sender.tag < renderedRows.count else { return }
        mutateRules([renderedRows[sender.tag]], action: sender.state == .on ? "enable" : "disable")
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        guard selectedRule() != nil else { return }
        menu.addItem(withTitle: "Enable Rule", action: #selector(enableSelected(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Disable Rule", action: #selector(disableSelected(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Delete Rule", action: #selector(deleteSelected(_:)), keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(withTitle: "Copy Scope", action: #selector(copySelectedRuleScope(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Open Inspector", action: #selector(showSelectedRuleInspector(_:)), keyEquivalent: "")
        for item in menu.items { item.target = self }
    }

    @objc func copySelectedRuleScope(_ sender: Any?) {
        guard let rule = selectedRule() else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(rule.scope, forType: .string)
    }

    @objc func showSelectedRuleInspector(_ sender: Any?) {
        guard let rule = selectedRule() else { return }
        let alert = NSAlert()
        alert.messageText = rule.scope
        alert.informativeText = [
            "Action: \(rule.action)",
            "Layer: \(rule.layer.isEmpty ? rule.kind : rule.layer)",
            "Lifetime: \(rule.lifetime)",
            "Review: \(rule.approvalState)",
            "Source: \(rule.source)",
            rule.notes.isEmpty ? nil : "Notes: \(rule.notes)"
        ].compactMap { $0 }.joined(separator: "\n")
        alert.addButton(withTitle: "OK")
        if let window {
            alert.beginSheetModal(for: window)
        } else {
            alert.runModal()
        }
    }
}

final class SettingsWindowController: NSObject, NSWindowDelegate, NSToolbarDelegate {
    enum Pane: String, CaseIterable {
        case general = "General"
        case alerts = "Alerts"
        case proxyTLS = "Proxy / TLS"
        case daemon = "Daemon"
        case extensionStatus = "Network Extension"
        case privacy = "Privacy"
        case advanced = "Advanced"

        var symbolName: String {
            switch self {
            case .general: return "gearshape"
            case .alerts: return "bell.badge"
            case .proxyTLS: return "lock.shield"
            case .daemon: return "server.rack"
            case .extensionStatus: return "network"
            case .privacy: return "hand.raised"
            case .advanced: return "wrench.and.screwdriver"
            }
        }
    }

    weak var parent: MonitorWindowController?
    var window: NSWindow?
    var selectedPane: Pane = .general
    let contentStack = NSStackView()
    let toolbarIdentifier = NSToolbar.Identifier("dev.guard.monitor.settings.toolbar")

    init(parent: MonitorWindowController) {
        self.parent = parent
    }

    func show() {
        if let window = window {
            render()
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 420),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = selectedPane.rawValue
        window.titleVisibility = .visible
        window.titlebarAppearsTransparent = false
        window.minSize = NSSize(width: 660, height: 360)
        window.isReleasedWhenClosed = false
        window.animationBehavior = .none
        window.delegate = self
        window.setFrameAutosaveName("dev.guard.settings.window")
        if #available(macOS 11.0, *) {
            window.toolbarStyle = .preference
        }
        window.center()
        let toolbar = NSToolbar(identifier: toolbarIdentifier)
        toolbar.delegate = self
        toolbar.displayMode = .iconAndLabel
        toolbar.sizeMode = .regular
        toolbar.allowsUserCustomization = false
        toolbar.autosavesConfiguration = false
        toolbar.selectedItemIdentifier = toolbarItemIdentifier(for: selectedPane)
        window.toolbar = toolbar

        let background = NSVisualEffectView()
        background.material = .contentBackground
        background.blendingMode = .behindWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = background

        contentStack.orientation = .vertical
        contentStack.alignment = .width
        contentStack.spacing = 14
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        background.addSubview(contentStack)
        NSLayoutConstraint.activate([
            contentStack.topAnchor.constraint(equalTo: background.topAnchor, constant: 36),
            contentStack.centerXAnchor.constraint(equalTo: background.centerXAnchor),
            contentStack.widthAnchor.constraint(equalToConstant: 620),
            contentStack.bottomAnchor.constraint(lessThanOrEqualTo: background.bottomAnchor, constant: -24)
        ])

        self.window = window
        render()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func toolbarItemIdentifier(for pane: Pane) -> NSToolbarItem.Identifier {
        NSToolbarItem.Identifier("dev.guard.monitor.settings.\(pane.rawValue)")
    }

    func pane(for identifier: NSToolbarItem.Identifier) -> Pane? {
        Pane.allCases.first { toolbarItemIdentifier(for: $0) == identifier }
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        Pane.allCases.map(toolbarItemIdentifier(for:))
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        Pane.allCases.map(toolbarItemIdentifier(for:))
    }

    func toolbarSelectableItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        Pane.allCases.map(toolbarItemIdentifier(for:))
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        guard let pane = pane(for: itemIdentifier) else { return nil }
        let item = NSToolbarItem(itemIdentifier: itemIdentifier)
        item.label = pane.rawValue
        item.paletteLabel = pane.rawValue
        item.toolTip = pane.rawValue
        item.target = self
        item.action = #selector(selectToolbarPane(_:))
        if #available(macOS 11.0, *) {
            let image = NSImage(systemSymbolName: pane.symbolName, accessibilityDescription: pane.rawValue)
            image?.isTemplate = true
            image?.size = NSSize(width: 28, height: 28)
            item.image = image
        }
        return item
    }

    @objc func selectToolbarPane(_ sender: NSToolbarItem) {
        guard let pane = pane(for: sender.itemIdentifier) else {
            return
        }
        selectedPane = pane
        render()
    }

    func render() {
        window?.title = selectedPane.rawValue
        window?.toolbar?.selectedItemIdentifier = toolbarItemIdentifier(for: selectedPane)
        for view in contentStack.arrangedSubviews {
            contentStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
        switch selectedPane {
        case .general: renderGeneral()
        case .alerts: renderAlerts()
        case .proxyTLS: renderProxyTLS()
        case .daemon: renderDaemon()
        case .extensionStatus: renderExtension()
        case .privacy: renderPrivacy()
        case .advanced: renderAdvanced()
        }
    }

    func renderGeneral() {
        addHeader("General", "")
        let trafficOptions = ["15 minutes", "30 minutes", "1 hour", "All events"]
        let trafficSelection: String
        if let minutes = parent?.monitorTimeWindowMinutes {
            trafficSelection = minutes == 60 ? "1 hour" : "\(minutes) minutes"
        } else {
            trafficSelection = "All events"
        }
        addControlSection("Current Profile", rows: [
            ("Profile", readOnlyText(parent?.selectedProfileName.isEmpty == false ? parent?.selectedProfileName ?? "guard" : "guard")),
            ("Traffic Window", popup(trafficOptions, selected: trafficSelection, defaultsKey: "dev.guard.settings.trafficWindow")),
            ("Events", readOnlyText("\(parent?.events.count ?? 0) loaded")),
            ("Top Host", readOnlyText(parent?.recentTopHost ?? "-"))
        ], actions: [
            actionButton("Refresh", #selector(MonitorWindowController.reloadEvents(_:)))
        ])
    }

    func renderAlerts() {
        addHeader("Alerts", "")
        addControlSection("Prompt Service", rows: [
            ("Alert Mode", popup(["Ask", "Allow silently", "Deny silently"], selected: "Ask", defaultsKey: "dev.guard.settings.alertMode")),
            ("Default Lifetime", popup(["Once", "5 minutes", "1 hour", "2 days", "5 days", "Forever"], selected: "5 minutes", defaultsKey: "dev.guard.settings.defaultLifetime")),
            ("Pending Alerts", readOnlyText(parent?.pendingAlertSummaryText ?? "Unavailable")),
            ("Default Scope", popup(["Exact host", "Subdomains", "Any destination"], selected: "Exact host", defaultsKey: "dev.guard.settings.defaultScope")),
            ("Bind To", readOnlyText("Profile, actor, destination, launcher"))
        ], actions: [])
    }

    func renderProxyTLS() {
        addHeader("Proxy / TLS", "")
        addControlSection("TLS Inspection", rows: [
            ("Inspection", switchControl(isOn: !(parent?.tlsStateText.localizedCaseInsensitiveContains("disabled") ?? false), enabled: false)),
            ("Profile State", readOnlyText(parent?.tlsStateText ?? "Unknown")),
            ("Trust", readOnlyText(parent?.tlsTrustText ?? "Unavailable")),
            ("Recent Status", readOnlyText(parent?.tlsInspectionStatus() ?? "Unknown")),
            ("Inspection", buttonRow([
                actionButton("Enable", #selector(MonitorWindowController.enableTLS(_:))),
                actionButton("Disable", #selector(MonitorWindowController.disableTLS(_:)))
            ])),
            ("Certificate", buttonRow([
                actionButton("Generate CA", #selector(MonitorWindowController.generateTLSCA(_:))),
                actionButton("Rotate CA", #selector(MonitorWindowController.rotateTLSCA(_:))),
                actionButton("Revoke CA", #selector(MonitorWindowController.revokeTLSCA(_:)))
            ]))
        ], actions: [])
    }

    func renderDaemon() {
        addHeader("Daemon", "")
        addControlSection("guardd", rows: [
            ("Run Daemon", switchControl(isOn: parent?.daemonConnected ?? false, enabled: false)),
            ("State", readOnlyText(parent?.daemonStatusText ?? "offline")),
            ("Health", readOnlyText(parent?.daemonHealthText ?? "Not checked")),
            ("API", readOnlyText(parent?.daemonURLHint() ?? "Unavailable")),
            ("Policy Root", readOnlyText(parent?.defaultDaemonPolicyRoot() ?? "Unavailable"))
        ], actions: [
            actionButton("Start", #selector(MonitorWindowController.startDaemon(_:))),
            actionButton("Stop", #selector(MonitorWindowController.stopDaemon(_:)))
        ])
    }

    func renderExtension() {
        addHeader("Network Extension", "")
        addControlSection("Extension State", rows: [
            ("Network Filter", switchControl(isOn: false, enabled: false)),
            ("Status", readOnlyText(parent?.extensionSyncText ?? "Not checked")),
            ("Backend", readOnlyText("Proxy and sandbox fallback")),
            ("Purpose", readOnlyText("Direct egress and bypass detection")),
            ("Approval", readOnlyText("Open macOS Network settings to approve the extension when packaged."))
        ], actions: [
            actionButton("Sync", #selector(MonitorWindowController.syncExtension(_:))),
            actionButton("Invalidate", #selector(MonitorWindowController.invalidateExtension(_:))),
            actionButton("Open Network Settings", #selector(MonitorWindowController.openNetworkSettings(_:)))
        ])
    }

    func renderPrivacy() {
        addHeader("Privacy", "")
        addControlSection("Local Data", rows: [
            ("Event Log", readOnlyText(parent?.eventLogPath() ?? "Unavailable")),
            ("Retention", popup(["1 hour", "24 hours", "7 days", "30 days"], selected: "1 hour", defaultsKey: "dev.guard.settings.retention")),
            ("HTTP Details", readOnlyText("Only with TLS inspection"))
        ], actions: [
            actionButton("Open Log", #selector(MonitorWindowController.revealLog(_:)))
        ])
    }

    func renderAdvanced() {
        addHeader("Advanced", "")
        addControlSection("Security Posture", rows: [
            ("Status", readOnlyText(parent?.securityStatusText ?? "Not checked")),
            ("Templates", readOnlyText(parent?.templatesSummaryText ?? "Unavailable")),
            ("Rule Store", readOnlyText(parent?.profileSummaryText ?? "Unavailable"))
        ], actions: [
            actionButton("Rules", #selector(MonitorWindowController.openRulesWindow(_:))),
            actionButton("Templates", #selector(MonitorWindowController.openTemplatesWindow(_:))),
            actionButton("Refresh", #selector(MonitorWindowController.reloadEvents(_:)))
        ])
    }

    func addHeader(_ title: String, _ subtitle: String) {
        guard !subtitle.isEmpty else { return }
        let subtitleLabel = label(subtitle, size: 13, weight: .regular, color: .secondaryLabelColor)
        subtitleLabel.maximumNumberOfLines = 2
        subtitleLabel.lineBreakMode = .byWordWrapping
        subtitleLabel.alignment = .center
        let stack = NSStackView(views: [subtitleLabel])
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 3
        contentStack.addArrangedSubview(stack)
    }

    func addSection(_ title: String, rows: [(String, String)], actions: [NSButton]) {
        addControlSection(title, rows: rows.map { ($0.0, valueLabel($0.1)) }, actions: actions)
    }

    func addControlSection(_ title: String, rows: [(String, NSView)], actions: [NSButton]) {
        let grid = NSGridView()
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.rowSpacing = 13
        grid.columnSpacing = 14
        for row in rows {
            let gridRow = grid.addRow(with: [settingLabel(row.0), row.1])
            gridRow.yPlacement = .center
        }
        if !actions.isEmpty {
            let actionStack = NSStackView(views: actions)
            actionStack.orientation = .horizontal
            actionStack.alignment = .centerY
            actionStack.spacing = 8
            let gridRow = grid.addRow(with: [settingLabel(""), actionStack])
            gridRow.yPlacement = .center
        }
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).xPlacement = .leading
        grid.column(at: 1).width = 480
        contentStack.addArrangedSubview(grid)
    }

    func settingLabel(_ title: String) -> NSTextField {
        let titleLabel = label(title, size: 12, weight: .medium, color: .secondaryLabelColor)
        titleLabel.alignment = .right
        titleLabel.widthAnchor.constraint(equalToConstant: 170).isActive = true
        return titleLabel
    }

    func valueLabel(_ value: String) -> NSTextField {
        let valueLabel = label(value, size: 13, weight: .regular)
        valueLabel.maximumNumberOfLines = 3
        valueLabel.lineBreakMode = .byWordWrapping
        valueLabel.widthAnchor.constraint(equalToConstant: 480).isActive = true
        valueLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return valueLabel
    }

    func readOnlyText(_ value: String) -> NSTextField {
        let field = valueLabel(value)
        field.textColor = .labelColor
        return field
    }

    func popup(_ options: [String], selected: String, defaultsKey: String = "") -> NSPopUpButton {
        let control = NSPopUpButton()
        control.addItems(withTitles: options)
        let persisted = defaultsKey.isEmpty ? "" : UserDefaults.standard.string(forKey: defaultsKey) ?? ""
        control.selectItem(withTitle: persisted.isEmpty ? selected : persisted)
        if control.indexOfSelectedItem < 0, let first = options.first {
            control.selectItem(withTitle: first)
        }
        control.controlSize = .regular
        control.bezelStyle = .rounded
        control.widthAnchor.constraint(equalToConstant: 280).isActive = true
        if !defaultsKey.isEmpty {
            control.identifier = NSUserInterfaceItemIdentifier(defaultsKey)
            control.target = self
            control.action = #selector(persistPopup(_:))
        }
        return control
    }

    @objc func persistPopup(_ sender: NSPopUpButton) {
        guard let key = sender.identifier?.rawValue else { return }
        UserDefaults.standard.set(sender.titleOfSelectedItem ?? "", forKey: key)
    }

    func buttonRow(_ buttons: [NSButton]) -> NSStackView {
        let row = NSStackView(views: buttons)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        row.translatesAutoresizingMaskIntoConstraints = false
        row.widthAnchor.constraint(equalToConstant: 480).isActive = true
        return row
    }

    func switchControl(isOn: Bool, enabled: Bool) -> NSControl {
        if #available(macOS 10.15, *) {
            let control = NSSwitch()
            control.state = isOn ? .on : .off
            control.isEnabled = enabled
            return control
        }
        let control = NSButton(checkboxWithTitle: "", target: nil, action: nil)
        control.state = isOn ? .on : .off
        control.isEnabled = enabled
        return control
    }

    func actionButton(_ title: String, _ action: Selector) -> NSButton {
        let button = NSButton(title: title, target: parent, action: action)
        button.bezelStyle = .rounded
        button.controlSize = .regular
        return button
    }

    func label(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor = .labelColor) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: size, weight: weight)
        label.textColor = color
        label.lineBreakMode = .byTruncatingTail
        label.maximumNumberOfLines = 1
        return label
    }
}

final class MonitorWindowController: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate, NSToolbarDelegate {
    let config: GuardAppConfig
    var window: NSWindow?
    var events: [GuardMonitorEvent] = []
    var activityRows: [MonitorActivityRow] = []
    var refreshTimer: Timer?
    var pendingAlertTimer: Timer?
    var pendingAlertPollInFlight = false
    var fullRefreshInFlight = false
    var selectedEventKey: String?
    var selectedActivityRowKey: String?
    var renderedInspectorRowKey: String?
    var suppressSelectionChange = false
    var daemonClient = GuardDaemonClient()
    var daemonConnected = false
    var daemonStatusText = "guardd offline"
    var daemonHealthText = "Health not checked."
    var managedDaemon: Process?
    var managedDaemonToken: String?
    var managedDaemonURL: String?
    var profileSummaryText = "Profile rules unavailable until guardd is reachable."
    var profileRulesText = "No profile rules loaded."
    var templatesSummaryText = "Templates unavailable until guardd is reachable."
    var selectedProfileName = "guard"
    var selectedTemplateName = ""
    var profileVersionText = ""
    var tlsStateText = "TLS inspection unknown."
    var tlsTrustText = "TLS trust diagnostics unavailable."
    var tlsOnboardingText = "TLS onboarding unavailable until guardd is reachable."
    var securityStatusText = "Security posture not checked."
    var extensionSyncText = "NetworkExtension sync not checked."
    var templateNames: [String] = []
    var profileNames: [String] = ["guard"]
    var ruleRows: [MonitorRuleRow] = []
    var renderedRuleRows: [MonitorRuleRow] = []
    var templateRows: [MonitorTemplateRow] = []
    var projectSummaryCache: [String: GuardAppSummary?] = [:]
    var projectSummaryMissCache = Set<String>()
    var codeSignatureCache: [String: (status: String, signer: String, teamId: String, bundleIdentifier: String)] = [:]
    var presentedPendingAlertIds = Set<String>()
    var recentAllowedCount = 0
    var recentDeniedCount = 0
    var recentTopHost = "-"
    var pendingAlertCount = 0
    var pendingAlertSummaryText = "Pending alerts unavailable until guardd is reachable."
    var profileRiskLabel = "risk unknown"
    var expandedApps = Set<String>()
    var hiddenActivityRowKeys = Set<String>()
    var didAutoExpandActivityGroups = false
    var rulesWindowController: RulesWindowController?
    let trafficSparkline = TrafficSparklineView()
    let tableView = NSOutlineView()
    let monitorSearchField = NSSearchField()
    let clearMonitorSearchButton = NSButton()
    let focusMonitorSearchButton = NSButton()
    let monitorTimeWindowButton = NSButton()
    weak var toolbarSearchField: NSSearchField?
    let monitorFilterControl = NSSegmentedControl(labels: ["All", "Net", "Denied", "Files", "Alerts"], trackingMode: .selectOne, target: nil, action: nil)
    let statusLabel = NSTextField(labelWithString: "")
    let daemonStateLabel = NSTextField(labelWithString: "guardd offline")
    let riskStatusLabel = NSTextField(labelWithString: "risk unknown")
    let ruleStatusLabel = NSTextField(labelWithString: "rules unavailable")
    let inspectorHelpLabel = NSTextField(labelWithString: "Selected Event")
    let inspectorTitleLabel = NSTextField(labelWithString: "No event selected")
    let inspectorBodyLabel = NSTextField(labelWithString: "Select a monitor event to review the destination, result, and rule action that will be applied.")
    let inspectorRuleLabel = NSTextField(labelWithString: "Rule action: unavailable until a network event with a project profile is selected.")
    let inspectorNoteLabel = NSTextField(labelWithString: "Actions update the selected profile from the event project directory.")
    let inspectorSummaryStack = NSStackView()
    let footerAllowedRateLabel = NSTextField(labelWithString: "allowed 0")
    let footerDeniedRateLabel = NSTextField(labelWithString: "denied 0")
    let trafficSummaryLabel = NSTextField(labelWithString: "Traffic: waiting for events")
    let focusTopHostButton = NSButton()
    let allowDomainButton = NSButton()
    let denyDomainButton = NSButton()
    let allowOnceButton = NSButton()
    let denyOnceButton = NSButton()
    let startDaemonButton = NSButton()
    let stopDaemonButton = NSButton()
    let enableTLSButton = NSButton()
    let disableTLSButton = NSButton()
    let generateTLSCAButton = NSButton()
    let rotateTLSCAButton = NSButton()
    let revokeTLSCAButton = NSButton()
    let syncExtensionButton = NSButton()
    let invalidateExtensionButton = NSButton()
    let openRulesWindowButton = NSButton()
    let openTemplatesWindowButton = NSButton()
    let openSettingsWindowButton = NSButton()
    let addProjectFolderButton = NSButton()
    let previewTemplateButton = NSButton()
    let applyTemplateButton = NSButton()
    let profilePopup = NSPopUpButton()
    let templatePopup = NSPopUpButton()
    let ruleSearchField = NSSearchField()
    let ruleFilterControl = NSSegmentedControl(labels: ["All", "Allow", "Deny", "HTTP", "Off"], trackingMode: .selectOne, target: nil, action: nil)
    let inspectorControlStack = NSStackView()
    let advancedActionStack = NSStackView()
    let ruleRowsStack = NSStackView()
    let templateRowsStack = NSStackView()
    let ruleRowsScroll = NSScrollView()
    let templateRowsScroll = NSScrollView()
    var monitorTableContainer: NSView?
    var inspectorWidthConstraint: NSLayoutConstraint?
    var settingsWindow: NSWindow?
    var settingsWindowController: SettingsWindowController?
    var templatesWindow: NSWindow?
    var logWindow: NSWindow?
    var logTextView: NSTextView?
    var eventLogWindowController: EventLogWindowController?
    var monitorTimeWindowMinutes: Int? = 60
    var didCleanUp = false

    init(config: GuardAppConfig) {
        self.config = config
    }

    func show() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Monitor"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.setFrameAutosaveName("dev.guard.monitor.window")
        let toolbar = NSToolbar(identifier: NSToolbar.Identifier("dev.guard.monitor.toolbar"))
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        toolbar.allowsUserCustomization = true
        toolbar.autosavesConfiguration = true
        window.toolbar = toolbar
        window.isMovableByWindowBackground = true
        window.minSize = NSSize(width: 700, height: 440)
        window.isRestorable = false
        window.center()
        window.delegate = self

        let background = NSVisualEffectView()
        background.material = .windowBackground
        background.blendingMode = .behindWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = background

        let monitorBody = makeMonitorBody()
        let actionBar = makeActionBar()
        monitorBody.translatesAutoresizingMaskIntoConstraints = false
        actionBar.translatesAutoresizingMaskIntoConstraints = false
        background.addSubview(monitorBody)
        background.addSubview(actionBar)
        NSLayoutConstraint.activate([
            monitorBody.leadingAnchor.constraint(equalTo: background.leadingAnchor, constant: 12),
            monitorBody.trailingAnchor.constraint(equalTo: background.trailingAnchor, constant: -12),
            monitorBody.topAnchor.constraint(equalTo: background.topAnchor, constant: 10),
            actionBar.leadingAnchor.constraint(equalTo: background.leadingAnchor, constant: 12),
            actionBar.trailingAnchor.constraint(equalTo: background.trailingAnchor, constant: -12),
            actionBar.topAnchor.constraint(equalTo: monitorBody.bottomAnchor),
            actionBar.bottomAnchor.constraint(equalTo: background.bottomAnchor, constant: -8)
        ])

        self.window = window
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillTerminate(_:)),
            name: NSApplication.willTerminateNotification,
            object: nil
        )
        applyPreferredWindowFrame(window)
        window.makeKeyAndOrderFront(nil)
        DispatchQueue.main.async {
            self.applyPreferredWindowFrame(window)
        }
        NSApp.activate(ignoringOtherApps: true)
        statusLabel.stringValue = "Loading recent Guard activity..."
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            self.autoStartDaemonIfNeeded()
            self.reloadEvents(nil)
            self.showFirstRunOnboardingIfNeeded()
        }
        let refreshTimer = Timer(timeInterval: 8.0, target: self, selector: #selector(reloadEvents(_:)), userInfo: nil, repeats: true)
        let pendingAlertTimer = Timer(timeInterval: 0.05, target: self, selector: #selector(pollPendingAlerts(_:)), userInfo: nil, repeats: true)
        self.refreshTimer = refreshTimer
        self.pendingAlertTimer = pendingAlertTimer
        RunLoop.main.add(refreshTimer, forMode: .common)
        RunLoop.main.add(pendingAlertTimer, forMode: .common)
    }

    func applyPreferredWindowFrame(_ window: NSWindow) {
        let screenFrame = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1280, height: 800)
        let width = min(CGFloat(1100), screenFrame.width - 80)
        let height = min(CGFloat(680), screenFrame.height - 80)
        window.setFrame(
            NSRect(
                x: screenFrame.midX - width / 2,
                y: screenFrame.midY - height / 2,
                width: width,
                height: height
            ),
            display: true
        )
    }

    func windowWillClose(_ notification: Notification) {
        guard let closedWindow = notification.object as? NSWindow, closedWindow === window else {
            return
        }
        cleanupMonitorRuntime()
    }

    @objc func applicationWillTerminate(_ notification: Notification) {
        cleanupMonitorRuntime()
    }

    func cleanupMonitorRuntime() {
        guard !didCleanUp else { return }
        didCleanUp = true
        refreshTimer?.invalidate()
        pendingAlertTimer?.invalidate()
        stopManagedDaemon()
    }

    func showFirstRunOnboardingIfNeeded() {
        let key = "dev.guard.monitor.didShowFirstRun"
        guard UserDefaults.standard.bool(forKey: key) == false, let window else { return }
        UserDefaults.standard.set(true, forKey: key)
        let alert = NSAlert()
        alert.messageText = "Set Up Guard Monitoring"
        alert.informativeText = [
            "Guard can run daemon-free for per-run protection.",
            "For the richer macOS monitor, connect guardd, review Network Extension status, and enable notifications for pending decisions.",
            "TLS inspection and the Network Extension remain explicit opt-in surfaces."
        ].joined(separator: "\n\n")
        alert.addButton(withTitle: "Open Settings")
        alert.addButton(withTitle: "Later")
        alert.beginSheetModal(for: window) { response in
            if response == .alertFirstButtonReturn {
                self.openSettingsWindow(nil)
            }
        }
    }

    func windowDidResize(_ notification: Notification) {
        resizeActivityColumns()
        resetActivityTableScrollOrigin()
    }

    func makeHeader() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        focusTopHostButton.title = ""
        focusTopHostButton.target = self
        focusTopHostButton.action = #selector(focusTopHostInRules(_:))
        focusTopHostButton.bezelStyle = .texturedRounded
        focusTopHostButton.controlSize = .small
        if #available(macOS 11.0, *) {
            focusTopHostButton.image = NSImage(systemSymbolName: "scope", accessibilityDescription: "Focus top host")
            focusTopHostButton.imagePosition = .imageOnly
        } else {
            focusTopHostButton.title = "Focus"
        }
        focusTopHostButton.toolTip = "Open the Rules window filtered to the busiest recent destination."
        trafficSummaryLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .semibold)
        trafficSummaryLabel.textColor = .secondaryLabelColor
        trafficSummaryLabel.alignment = .right
        trafficSummaryLabel.maximumNumberOfLines = 1
        let trafficStack = NSStackView(views: [trafficSummaryLabel, focusTopHostButton])
        trafficStack.orientation = .horizontal
        trafficStack.alignment = .centerY
        trafficStack.spacing = 6
        trafficStack.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(trafficStack)

        let tools = NSStackView()
        tools.orientation = .horizontal
        tools.alignment = .centerY
        tools.spacing = 5
        configureToolButton(openRulesWindowButton, title: "Rules", symbol: "slider.horizontal.3", action: #selector(openRulesWindow(_:)), tooltip: "Open profile and network rules.")
        configureToolButton(openTemplatesWindowButton, title: "Templates", symbol: "square.grid.2x2", action: #selector(openTemplatesWindow(_:)), tooltip: "Open reusable policy templates.")
        configureToolButton(openSettingsWindowButton, title: "Settings", symbol: "gearshape", action: #selector(openSettingsWindow(_:)), tooltip: "Open monitor, daemon, TLS, and extension settings.")
        tools.addArrangedSubview(openRulesWindowButton)
        tools.addArrangedSubview(openTemplatesWindowButton)
        tools.addArrangedSubview(openSettingsWindowButton)
        row.addArrangedSubview(tools)
        return row
    }

    func configureToolButton(_ button: NSButton, title: String, symbol: String, action: Selector, tooltip: String) {
        button.title = ""
        button.target = self
        button.action = action
        button.bezelStyle = .texturedRounded
        button.controlSize = .small
        button.toolTip = tooltip
        if #available(macOS 11.0, *) {
            button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: title)
            button.imagePosition = .imageOnly
        } else {
            button.title = title
        }
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [
            NSToolbarItem.Identifier("refresh"),
            NSToolbarItem.Identifier("rules"),
            NSToolbarItem.Identifier("templates"),
            NSToolbarItem.Identifier("settings"),
            NSToolbarItem.Identifier("search"),
            .flexibleSpace,
            NSToolbarItem.Identifier("log"),
            NSToolbarItem.Identifier("syncExtension")
        ]
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        toolbarDefaultItemIdentifiers(toolbar) + [.flexibleSpace, .space]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        let item = NSToolbarItem(itemIdentifier: itemIdentifier)
        switch itemIdentifier.rawValue {
        case "refresh":
            item.label = "Refresh"
            item.paletteLabel = "Refresh"
            item.target = self
            item.action = #selector(reloadEvents(_:))
            if #available(macOS 11.0, *) { item.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: "Refresh") }
        case "rules":
            item.label = "Rules"
            item.paletteLabel = "Rules"
            item.target = self
            item.action = #selector(openRulesWindow(_:))
            if #available(macOS 11.0, *) { item.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: "Rules") }
        case "templates":
            item.label = "Templates"
            item.paletteLabel = "Templates"
            item.target = self
            item.action = #selector(openTemplatesWindow(_:))
            if #available(macOS 11.0, *) { item.image = NSImage(systemSymbolName: "square.grid.2x2", accessibilityDescription: "Templates") }
        case "settings":
            item.label = "Settings"
            item.paletteLabel = "Settings"
            item.target = self
            item.action = #selector(openSettingsWindow(_:))
            if #available(macOS 11.0, *) { item.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: "Settings") }
        case "search":
            if #available(macOS 11.0, *) {
                let search = NSSearchToolbarItem(itemIdentifier: itemIdentifier)
                search.label = "Search"
                search.searchField.placeholderString = "Search activity"
                search.searchField.target = self
                search.searchField.action = #selector(toolbarSearchChanged(_:))
                toolbarSearchField = search.searchField
                return search
            }
            item.label = "Search"
            item.target = self
            item.action = #selector(focusSearch(_:))
            item.image = NSImage(named: NSImage.touchBarSearchTemplateName)
        case "log":
            item.label = "Log"
            item.paletteLabel = "Log"
            item.target = self
            item.action = #selector(revealLog(_:))
            if #available(macOS 11.0, *) { item.image = NSImage(systemSymbolName: "list.bullet.rectangle", accessibilityDescription: "Log") }
        case "syncExtension":
            item.label = "Sync Extension"
            item.paletteLabel = "Sync Extension"
            item.target = self
            item.action = #selector(syncExtension(_:))
            if #available(macOS 11.0, *) { item.image = NSImage(systemSymbolName: "network", accessibilityDescription: "Sync Extension") }
        default:
            return nil
        }
        return item
    }

    @objc func toolbarSearchChanged(_ sender: NSSearchField) {
        monitorSearchField.stringValue = sender.stringValue
        filterMonitorRows(sender)
    }

    func makeStatusStrip() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 5
        riskStatusLabel.stringValue = "risk unknown"
        ruleStatusLabel.stringValue = "rules unavailable"
        let mode = label("per-run safe", size: 11, weight: .semibold, color: .systemBlue)
        for field in [mode, riskStatusLabel, ruleStatusLabel] {
            field.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
            field.maximumNumberOfLines = 1
            field.lineBreakMode = .byTruncatingTail
            row.addArrangedSubview(field)
            if field !== ruleStatusLabel {
                row.addArrangedSubview(label("·", size: 11, weight: .medium, color: .tertiaryLabelColor))
            }
        }
        return row
    }

    func statusChip(_ text: String, color: NSColor) -> NSView {
        let field = label(text, size: 10.5, weight: .semibold, color: color)
        return statusChipView(field, color: color)
    }

    func statusChipView(_ field: NSTextField, color: NSColor) -> NSView {
        field.font = NSFont.systemFont(ofSize: 10.5, weight: .semibold)
        field.textColor = color
        field.maximumNumberOfLines = 1
        field.lineBreakMode = .byTruncatingTail
        let chip = CardView(fill: color.withAlphaComponent(0.10), border: color.withAlphaComponent(0.24))
        chip.layer?.cornerRadius = 6
        chip.layer?.borderWidth = 0.5
        let stack = paddedStack(in: chip, inset: 5)
        stack.alignment = .centerX
        stack.spacing = 0
        stack.addArrangedSubview(field)
        return chip
    }

    func makeMonitorBody() -> NSView {
        let body = NSStackView()
        body.orientation = .horizontal
        body.alignment = .height
        body.distribution = .fill
        body.spacing = 0
        body.translatesAutoresizingMaskIntoConstraints = false
        body.heightAnchor.constraint(greaterThanOrEqualToConstant: 360).isActive = true

        let listPane = NSStackView()
        listPane.orientation = .vertical
        listPane.alignment = .width
        listPane.spacing = 6
        listPane.translatesAutoresizingMaskIntoConstraints = false
        listPane.setContentHuggingPriority(.defaultLow, for: .horizontal)
        listPane.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        listPane.addArrangedSubview(makeMonitorToolbar())
        let table = makeTable()
        listPane.addArrangedSubview(table)
        listPane.addArrangedSubview(makeTrafficFooter())

        let inspector = makeInspector()
        inspector.setContentHuggingPriority(.required, for: .horizontal)
        inspector.setContentCompressionResistancePriority(.required, for: .horizontal)
        monitorTableContainer = listPane
        body.addArrangedSubview(listPane)
        body.addArrangedSubview(inspector)
        listPane.widthAnchor.constraint(greaterThanOrEqualToConstant: 420).isActive = true
        inspectorWidthConstraint = inspector.widthAnchor.constraint(equalToConstant: 380)
        inspectorWidthConstraint?.isActive = true
        return body
    }

    func makeTrafficFooter() -> NSView {
        let container = NSStackView()
        container.orientation = .vertical
        container.alignment = .width
        container.spacing = 5
        container.translatesAutoresizingMaskIntoConstraints = false
        container.heightAnchor.constraint(equalToConstant: 62).isActive = true

        let windowLabel = label("Recent policy decisions", size: 11, weight: .medium, color: .tertiaryLabelColor)
        windowLabel.alignment = .right
        container.addArrangedSubview(windowLabel)
        container.addArrangedSubview(trafficSparkline)
        return container
    }

    func makeMonitorToolbar() -> NSView {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false

        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        row.translatesAutoresizingMaskIntoConstraints = false

        monitorSearchField.placeholderString = "Search activity"
        monitorSearchField.target = self
        monitorSearchField.action = #selector(filterMonitorRows(_:))
        monitorSearchField.controlSize = .regular
        monitorSearchField.font = NSFont.systemFont(ofSize: NSFont.systemFontSize(for: .regular))
        monitorSearchField.bezelStyle = .roundedBezel
        monitorSearchField.focusRingType = .default
        monitorSearchField.translatesAutoresizingMaskIntoConstraints = false
        monitorSearchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 1).isActive = true
        monitorSearchField.widthAnchor.constraint(lessThanOrEqualToConstant: 1).isActive = true
        monitorSearchField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        monitorSearchField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        monitorSearchField.sendsSearchStringImmediately = true
        monitorSearchField.toolTip = "Search all activity, or use app:, process:, host:, rule:, path:, profile:, and type: prefixes."

        configureInlineToolButton(clearMonitorSearchButton, symbol: "xmark.rectangle", title: "Clear", action: #selector(clearMonitorSearch(_:)), tooltip: "Clear the current search.")
        configureInlineToolButton(focusMonitorSearchButton, symbol: "scope", title: "Top Host", action: #selector(focusTopHostSearch(_:)), tooltip: "Search for the busiest recent host.")
        configureInlineToolButton(monitorTimeWindowButton, symbol: "clock", title: "1h", action: #selector(toggleMonitorTimeWindow(_:)), tooltip: "Cycle the activity time window.")
        updateMonitorSearchChrome()

        monitorFilterControl.selectedSegment = 0
        monitorFilterControl.target = self
        monitorFilterControl.action = #selector(filterMonitorRows(_:))
        monitorFilterControl.segmentStyle = .texturedRounded
        monitorFilterControl.controlSize = .regular
        monitorFilterControl.translatesAutoresizingMaskIntoConstraints = false
        monitorFilterControl.heightAnchor.constraint(equalToConstant: 30).isActive = true
        monitorFilterControl.setToolTip("Show all recent activity", forSegment: 0)
        monitorFilterControl.setToolTip("Show network decisions, proxy listeners, and alerts", forSegment: 1)
        monitorFilterControl.setToolTip("Show denied traffic", forSegment: 2)
        monitorFilterControl.setToolTip("Show filesystem and sandbox activity", forSegment: 3)
        monitorFilterControl.setToolTip("Show pending and resolved alert decisions", forSegment: 4)

        monitorSearchField.isHidden = true
        row.addArrangedSubview(monitorSearchField)
        row.addArrangedSubview(clearMonitorSearchButton)
        row.addArrangedSubview(focusMonitorSearchButton)
        row.addArrangedSubview(monitorTimeWindowButton)
        row.addArrangedSubview(monitorFilterControl)
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)

        container.addSubview(row)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 8),
            row.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -8),
            row.topAnchor.constraint(equalTo: container.topAnchor, constant: 6),
            row.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -6),
            container.heightAnchor.constraint(equalToConstant: 42)
        ])
        return container
    }

    func configureInlineToolButton(_ button: NSButton, symbol: String, title: String, action: Selector, tooltip: String) {
        button.title = title
        button.target = self
        button.action = action
        button.isBordered = true
        button.bezelStyle = .texturedRounded
        button.controlSize = .regular
        button.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .semibold)
        button.contentTintColor = .secondaryLabelColor
        button.toolTip = tooltip
        button.translatesAutoresizingMaskIntoConstraints = false
        button.heightAnchor.constraint(equalToConstant: 30).isActive = true
        if #available(macOS 11.0, *), symbol != "clock" {
            button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: title)
            button.imagePosition = .imageOnly
            button.widthAnchor.constraint(equalToConstant: 32).isActive = true
        } else {
            button.widthAnchor.constraint(greaterThanOrEqualToConstant: 44).isActive = true
        }
    }

    func makeTable() -> NSView {
        let scroll = NSScrollView()
        configureOverlayScrollView(scroll)
        scroll.translatesAutoresizingMaskIntoConstraints = false

        tableView.translatesAutoresizingMaskIntoConstraints = true
        tableView.frame = scroll.contentView.bounds
        tableView.autoresizingMask = [.width, .height]
        tableView.headerView = nil
        tableView.usesAlternatingRowBackgroundColors = false
        tableView.backgroundColor = .clear
        tableView.selectionHighlightStyle = .regular
        tableView.intercellSpacing = NSSize(width: 0, height: 0.5)
        tableView.rowHeight = 26
        tableView.columnAutoresizingStyle = .noColumnAutoresizing
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(toggleSelectedActivityGroup(_:))
        let rowMenu = NSMenu(title: "Connection Actions")
        rowMenu.delegate = self
        tableView.menu = rowMenu
        let appColumn = column("app", title: "App / Command", width: 260)
        tableView.addTableColumn(appColumn)
        tableView.outlineTableColumn = appColumn
        tableView.indentationPerLevel = 18
        tableView.indentationMarkerFollowsCell = true
        tableView.addTableColumn(column("destination", title: "Destination", width: 280))
        tableView.addTableColumn(column("activity", title: "Policy", width: 360))
        tableView.addTableColumn(column("decision", title: "State", width: 76))
        scroll.documentView = tableView
        tableView.frame = scroll.contentView.bounds
        DispatchQueue.main.async {
            self.resizeActivityColumns()
            self.resetActivityTableScrollOrigin()
        }
        return scroll
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        guard let row = selectedActivityRowForAction() else { return }
        let event = row.event
        if row.isGroup {
            menu.addItem(withTitle: expandedApps.contains(row.rowKey) ? "Collapse" : "Expand", action: #selector(toggleSelectedActivityGroup(_:)), keyEquivalent: "")
            menu.addItem(.separator())
        }
        if event?.host.isEmpty == false {
            menu.addItem(withTitle: "Allow Once", action: #selector(allowSelectedOnce(_:)), keyEquivalent: "")
            menu.addItem(withTitle: "Allow for 5 Minutes", action: #selector(allowSelectedFiveMinutes(_:)), keyEquivalent: "")
            menu.addItem(withTitle: "Allow for 1 Hour", action: #selector(allowSelectedOneHour(_:)), keyEquivalent: "")
            menu.addItem(withTitle: "Deny Once", action: #selector(denySelectedOnce(_:)), keyEquivalent: "")
            menu.addItem(.separator())
            menu.addItem(withTitle: "Allow Domain", action: #selector(allowSelectedDomain(_:)), keyEquivalent: "")
            menu.addItem(withTitle: "Deny Domain", action: #selector(denySelectedDomain(_:)), keyEquivalent: "")
            menu.addItem(withTitle: "Remove Domain Rules", action: #selector(removeSelectedDomainRules(_:)), keyEquivalent: "")
            menu.addItem(.separator())
            menu.addItem(withTitle: "Copy Host", action: #selector(copySelectedHost(_:)), keyEquivalent: "")
        }
        if event?.processPath.isEmpty == false {
            menu.addItem(withTitle: "Reveal Process Binary", action: #selector(revealSelectedProcessBinary(_:)), keyEquivalent: "")
        }
        menu.addItem(withTitle: "Hide Connection", action: #selector(hideSelectedConnection(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Open Rules", action: #selector(openRulesWindow(_:)), keyEquivalent: "")
        for item in menu.items {
            item.target = self
        }
    }

    func resizeActivityColumns() {
        guard tableView.numberOfColumns >= 4 else { return }
        let available = tableView.enclosingScrollView?.contentView.bounds.width ?? tableView.bounds.width
        guard available > 0 else { return }
        if var frame = tableView.enclosingScrollView?.contentView.bounds {
            frame.origin.x = 0
            frame.size.width = available
            tableView.frame = frame
        }

        let decisionWidth: CGFloat = available < 760 ? 76 : 92
        var appWidth = min(max(available * 0.32, 220), 360)
        var destinationWidth = min(max(available * 0.26, 180), 360)
        let activityMinimum: CGFloat = available < 760 ? 160 : 220
        var activityWidth = available - appWidth - destinationWidth - decisionWidth

        if activityWidth < activityMinimum {
            var deficit = activityMinimum - activityWidth
            let appReduction = min(deficit * 0.55, max(0, appWidth - 200))
            appWidth -= appReduction
            deficit -= appReduction
            let destinationReduction = min(deficit, max(0, destinationWidth - 150))
            destinationWidth -= destinationReduction
            activityWidth = max(activityMinimum, available - appWidth - destinationWidth - decisionWidth)
        }

        if appWidth + destinationWidth + activityWidth + decisionWidth > available {
            activityWidth = max(activityMinimum, available - appWidth - destinationWidth - decisionWidth)
        }

        let widths: [String: CGFloat] = [
            "app": floor(appWidth),
            "destination": floor(destinationWidth),
            "activity": floor(activityWidth),
            "decision": floor(decisionWidth)
        ]
        for column in tableView.tableColumns {
            guard let width = widths[column.identifier.rawValue] else { continue }
            column.width = width
            column.minWidth = min(width, column.identifier.rawValue == "app" ? 190 : column.identifier.rawValue == "destination" ? 150 : column.identifier.rawValue == "activity" ? 160 : 70)
        }
    }

    func resetActivityTableScrollOrigin() {
        guard let clipView = tableView.enclosingScrollView?.contentView else { return }
        let current = clipView.bounds.origin
        clipView.scroll(to: NSPoint(x: 0, y: current.y))
        tableView.enclosingScrollView?.reflectScrolledClipView(clipView)
    }

    func configureOverlayScrollView(_ scroll: NSScrollView, border: NSBorderType = .noBorder) {
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = true
        scroll.scrollerStyle = .overlay
        scroll.borderType = border
        scroll.drawsBackground = false
        scroll.verticalScrollElasticity = .allowed
        scroll.contentView.drawsBackground = false
    }

    func makeInspector() -> NSView {
        let sidebar = NSView()
        sidebar.wantsLayer = true
        sidebar.layer?.backgroundColor = NSColor.clear.cgColor
        sidebar.translatesAutoresizingMaskIntoConstraints = false

        let leadingRule = NSView()
        leadingRule.wantsLayer = true
        leadingRule.layer?.backgroundColor = NSColor.separatorColor.withAlphaComponent(0.42).cgColor
        leadingRule.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(leadingRule)

        let scroll = NSScrollView()
        configureOverlayScrollView(scroll)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(scroll)

        let document = NSView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document

        let stack = FlippedStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 9
        stack.edgeInsets = NSEdgeInsets(top: 0, left: 0, bottom: 0, right: 0)
        stack.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(stack)
        NSLayoutConstraint.activate([
            leadingRule.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor),
            leadingRule.topAnchor.constraint(equalTo: sidebar.topAnchor),
            leadingRule.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor),
            leadingRule.widthAnchor.constraint(equalToConstant: 0.5),
            scroll.leadingAnchor.constraint(equalTo: sidebar.leadingAnchor, constant: 17),
            scroll.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor, constant: -16),
            scroll.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 0),
            scroll.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor, constant: -12),
            document.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            document.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            document.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            stack.leadingAnchor.constraint(equalTo: document.leadingAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: document.trailingAnchor),
            stack.topAnchor.constraint(equalTo: document.topAnchor),
            stack.bottomAnchor.constraint(equalTo: document.bottomAnchor),
            stack.widthAnchor.constraint(lessThanOrEqualTo: document.widthAnchor)
        ])

        inspectorTitleLabel.font = NSFont.systemFont(ofSize: 14, weight: .bold)
        inspectorTitleLabel.textColor = .labelColor
        inspectorTitleLabel.lineBreakMode = .byTruncatingMiddle
        inspectorTitleLabel.maximumNumberOfLines = 3
        inspectorTitleLabel.alignment = .left
        inspectorTitleLabel.setContentHuggingPriority(.required, for: .horizontal)

        inspectorBodyLabel.font = NSFont.systemFont(ofSize: 12)
        inspectorBodyLabel.textColor = .secondaryLabelColor
        inspectorBodyLabel.lineBreakMode = .byWordWrapping
        inspectorBodyLabel.maximumNumberOfLines = 0
        inspectorBodyLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        inspectorRuleLabel.font = NSFont.systemFont(ofSize: 11, weight: .medium)
        inspectorRuleLabel.textColor = .secondaryLabelColor
        inspectorRuleLabel.lineBreakMode = .byWordWrapping
        inspectorRuleLabel.maximumNumberOfLines = 0
        inspectorRuleLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        inspectorHelpLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        inspectorHelpLabel.textColor = .tertiaryLabelColor
        inspectorHelpLabel.lineBreakMode = .byTruncatingTail
        inspectorHelpLabel.maximumNumberOfLines = 1
        inspectorHelpLabel.alignment = .left
        inspectorHelpLabel.setContentHuggingPriority(.required, for: .horizontal)

        stack.addArrangedSubview(inspectorHelpLabel)
        stack.addArrangedSubview(inspectorTitleLabel)
        stack.addArrangedSubview(makeInspectorSummaryPanel())
        stack.addArrangedSubview(makeInspectorControls())
        stack.addArrangedSubview(inspectorBodyLabel)
        stack.addArrangedSubview(makeRowsScroll(ruleRowsScroll, content: ruleRowsStack))
        stack.addArrangedSubview(makeRowsScroll(templateRowsScroll, content: templateRowsStack))
        stack.addArrangedSubview(separator())
        stack.addArrangedSubview(inspectorRuleLabel)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .vertical)
        stack.addArrangedSubview(spacer)

        inspectorNoteLabel.font = NSFont.systemFont(ofSize: 10.5)
        inspectorNoteLabel.textColor = .tertiaryLabelColor
        inspectorNoteLabel.maximumNumberOfLines = 0
        inspectorNoteLabel.lineBreakMode = .byWordWrapping
        stack.addArrangedSubview(inspectorNoteLabel)
        return sidebar
    }

    func makeInspectorControls() -> NSView {
        inspectorControlStack.orientation = .vertical
        inspectorControlStack.alignment = .width
        inspectorControlStack.spacing = 8
        inspectorControlStack.translatesAutoresizingMaskIntoConstraints = false

        let profileRow = NSStackView()
        profileRow.orientation = .horizontal
        profileRow.alignment = .centerY
        profileRow.spacing = 6
        let profileLabel = label("Profile", size: 11, weight: .medium, color: .tertiaryLabelColor)
        profileLabel.translatesAutoresizingMaskIntoConstraints = false
        profileLabel.widthAnchor.constraint(equalToConstant: 52).isActive = true
        profilePopup.target = self
        profilePopup.action = #selector(selectProfile(_:))
        profilePopup.controlSize = .small
        profilePopup.font = NSFont.systemFont(ofSize: 12)
        profileRow.addArrangedSubview(profileLabel)
        profileRow.addArrangedSubview(profilePopup)

        let templateRow = NSStackView()
        templateRow.orientation = .horizontal
        templateRow.alignment = .centerY
        templateRow.spacing = 6
        let templateLabel = label("Template", size: 11, weight: .medium, color: .tertiaryLabelColor)
        templateLabel.translatesAutoresizingMaskIntoConstraints = false
        templateLabel.widthAnchor.constraint(equalToConstant: 52).isActive = true
        templatePopup.target = self
        templatePopup.action = #selector(selectTemplate(_:))
        templatePopup.controlSize = .small
        templatePopup.font = NSFont.systemFont(ofSize: 12)
        templateRow.addArrangedSubview(templateLabel)
        templateRow.addArrangedSubview(templatePopup)

        ruleSearchField.placeholderString = "Search rules"
        ruleSearchField.target = self
        ruleSearchField.action = #selector(filterRules(_:))
        ruleSearchField.controlSize = .small
        ruleSearchField.font = NSFont.systemFont(ofSize: 12)

        ruleFilterControl.selectedSegment = 0
        ruleFilterControl.target = self
        ruleFilterControl.action = #selector(filterRules(_:))
        ruleFilterControl.segmentStyle = .texturedRounded
        ruleFilterControl.controlSize = .small

        inspectorControlStack.addArrangedSubview(profileRow)
        inspectorControlStack.addArrangedSubview(templateRow)
        inspectorControlStack.addArrangedSubview(ruleSearchField)
        inspectorControlStack.addArrangedSubview(ruleFilterControl)
        updateProfileMenu()
        updateTemplateMenu()
        return inspectorControlStack
    }

    func makeInspectorSummaryPanel() -> NSView {
        inspectorSummaryStack.orientation = .vertical
        inspectorSummaryStack.alignment = .leading
        inspectorSummaryStack.spacing = 8
        inspectorSummaryStack.translatesAutoresizingMaskIntoConstraints = false
        inspectorSummaryStack.isHidden = true
        return inspectorSummaryStack
    }

    func clearInspectorSummaryPanel() {
        inspectorSummaryStack.arrangedSubviews.forEach { view in
            inspectorSummaryStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
    }

    func renderMonitorSummaryPanel() {
        inspectorHelpLabel.isHidden = false
        inspectorTitleLabel.isHidden = false
        clearInspectorSummaryPanel()
        inspectorSummaryStack.addArrangedSubview(rateStrip())
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Connections"))
        inspectorSummaryStack.addArrangedSubview(summaryMetric(symbol: "xmark.rectangle", value: "\(recentDeniedCount)", text: "denied"))
        inspectorSummaryStack.addArrangedSubview(summaryMetric(symbol: "checkmark.rectangle", value: "\(max(0, recentAllowedCount))", text: "allowed"))
        inspectorSummaryStack.addArrangedSubview(summaryMetric(symbol: "bell.badge", value: "\(pendingAlertCount)", text: "pending"))
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Statistics"))
        for item in topCounts(events.map { appLabel(for: $0) }, limit: 3) {
            inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "app.fill", text: item))
        }
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Top Destinations"))
        for item in topCounts(events.compactMap { $0.host.isEmpty ? nil : $0.host }, limit: 4) {
            inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "globe", text: item))
        }
    }

    func renderEventDetailsPanel(_ event: GuardMonitorEvent) {
        inspectorHelpLabel.isHidden = true
        inspectorTitleLabel.isHidden = true
        clearInspectorSummaryPanel()
        inspectorSummaryStack.addArrangedSubview(actorHeader(
            title: processLabel(for: event),
            subtitle: event.host.isEmpty ? appLabel(for: event) : hostPortLabel(for: event),
            icon: iconForApp(appLabel(for: event)),
            sent: event.bytesSent,
            received: event.bytesReceived
        ))
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Process"))
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Name", processLabel(for: event)),
            ("App", appLabel(for: event)),
            ("Launched By", event.launcherApp.isEmpty ? "Not recorded" : event.launcherApp),
            ("PID", event.pid > 0 ? "\(event.pid)" : "Not recorded"),
            ("Parent PID", event.launcherPid > 0 ? "\(event.launcherPid)" : "Not recorded"),
            ("Path", event.processPath.isEmpty ? "Not recorded" : event.processPath),
            ("Command", event.command.isEmpty ? "Unknown" : event.command),
            ("Project", event.projectDir.isEmpty ? "Not recorded" : event.projectDir),
            ("Profile", event.profile.isEmpty ? "guard" : event.profile),
            ("Parent Chain", event.parentChain.isEmpty ? "Not recorded" : event.parentChain)
        ]))

        inspectorSummaryStack.addArrangedSubview(inspectorSection("Internet Access Policy"))
        let lifetime = temporaryRuleSummary(for: event)
            ?? (event.expiresAt.isEmpty ? "Current profile/session" : "Expires \(event.expiresAt)")
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Outcome", decisionLabel(for: event).isEmpty ? "managed" : decisionLabel(for: event)),
            ("Reason", humanDecisionReason(event.detail, fallback: activityLabel(for: event))),
            ("Rule Scope", event.host.isEmpty ? "No destination host" : ruleScopePreview(for: event)),
            ("Lifetime", lifetime),
            ("Rule ID", event.ruleId.isEmpty ? "Not recorded" : event.ruleId)
        ], valueTint: event.result == "deny" ? .systemRed : .secondaryLabelColor))

        inspectorSummaryStack.addArrangedSubview(inspectorSection("Code Signature"))
        let signature = codeSignatureSummary(for: event)
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Status", signature.status),
            ("Signer", signature.signer),
            ("Team ID", signature.teamId),
            ("Bundle ID", event.bundleIdentifier.isEmpty ? signature.bundleIdentifier : event.bundleIdentifier)
        ]))

        inspectorSummaryStack.addArrangedSubview(inspectorSection("Connection Details"))
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Destination", event.host.isEmpty ? primaryText(for: event) : hostPortLabel(for: event)),
            ("Host", event.host.isEmpty ? "None" : event.host),
            ("Event", humanizeEventType(event.type)),
            ("Time", event.at.isEmpty ? "Unknown" : event.at)
        ]))

        if isFileActivity(event) || event.type == "proxy.started" || event.detail.lowercased().contains("tls") {
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Filesystem / Proxy"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
                ("Filesystem", isFileActivity(event) ? "Profile containment active" : "No file event selected"),
                ("Proxy / TLS", event.type == "proxy.started" || !event.host.isEmpty ? "Managed by Guard proxy path" : "Not observed"),
                ("Detail", event.detail.isEmpty ? "No raw detail" : event.detail)
            ]))
        }
    }

    func renderGroupDetailsPanel(app: String) {
        inspectorHelpLabel.isHidden = false
        inspectorTitleLabel.isHidden = false
        clearInspectorSummaryPanel()
        let groupEvents = events.filter { appLabel(for: $0) == app }
        let summary = projectSummary(for: groupEvents, allowSubprocess: false)
        let network = groupEvents.filter { isNetworkActivity($0) }
        let denied = network.filter { $0.result == "deny" || $0.result == "denied" }.count
        let allowed = network.filter { $0.result == "allow" || $0.result == "allowed" }.count
        let fileEvents = groupEvents.filter { isFileActivity($0) }
        if let summary {
            inspectorSummaryStack.addArrangedSubview(actorHeader(
                title: app,
                subtitle: "\(summary.status) · \(summary.risk)",
                icon: iconForApp(app),
                sent: 0,
                received: 0
            ))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Effective Policy"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
                ("Status", summary.findings.isEmpty ? "no dangerous defaults detected" : "\(summary.findings.count) finding\(summary.findings.count == 1 ? "" : "s")"),
                ("Network", networkRuleCountText(summary)),
                ("Filesystem", "\(summary.filesystem.allowRead.count) read allows, \(summary.filesystem.allowWrite.count) write allows"),
                ("Protections", "\(summary.filesystem.denyRead.count + summary.filesystem.denyWrite.count) deny rules")
            ], valueTint: summary.findings.isEmpty ? .secondaryLabelColor : .systemOrange))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Network Rules"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock(networkPolicyRows(summary)))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Proxy / TLS"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock(proxyAndTLSRows(summary)))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Filesystem Scope"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
                ("Read", compactPolicyList(summary.filesystem.allowRead)),
                ("Write", compactPolicyList(summary.filesystem.allowWrite)),
                ("Denied", compactPolicyList(summary.filesystem.denyRead + summary.filesystem.denyWrite))
            ]))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Rule Editing"))
            inspectorSummaryStack.addArrangedSubview(detailBlock([
                daemonConnected
                    ? "Open Rules to edit allow/deny domains, HTTP path rules, raw TCP exceptions, and disabled rule state."
                    : "Start guardd to edit persistent rules. Without guardd, domain actions are available only for selected events with a project directory."
            ]))
        }
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Recent Activity"))
        inspectorSummaryStack.addArrangedSubview(detailBlock([
            "Domains: \(Set(network.compactMap { $0.host.isEmpty ? nil : $0.host }).count)",
            "Allowed: \(allowed)",
            "Denied: \(denied)",
            "Filesystem: \(fileEvents.count) events"
        ]))
        inspectorSummaryStack.addArrangedSubview(detailSection("Top Destinations"))
        for item in topCounts(groupEvents.compactMap { $0.host.isEmpty ? nil : $0.host }, limit: 5) {
            inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "globe", text: item))
        }
        inspectorSummaryStack.addArrangedSubview(detailSection("Commands"))
        for item in topCounts(groupEvents.map { commandDisplay($0.command) }.filter { $0 != "Command" }, limit: 4) {
            inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "terminal", text: item))
        }
    }

    func compactPolicyList(_ values: [String], limit: Int = 4) -> String {
        if values.isEmpty { return "none" }
        return values.joined(separator: "\n")
    }

    func inlinePolicyList(_ values: [String], empty: String = "none") -> String {
        values.isEmpty ? empty : values.joined(separator: ", ")
    }

    func policyRows(for summary: GuardAppSummary, appKey: String, event: GuardMonitorEvent?) -> [MonitorActivityRow] {
        let networkKey = "\(appKey)/policy:network"
        let filesKey = "\(appKey)/policy:files"
        let proxyKey = "\(appKey)/policy:proxy"
        var rows: [MonitorActivityRow] = []
        rows.append(
            MonitorActivityRow(
                isGroup: true,
                kind: "policy-network",
                level: 1,
                rowKey: networkKey,
                app: "Network Policy",
                destination: networkRuleCountText(summary),
                activity: "",
                decision: summary.network.deniedDomains.isEmpty ? "active" : "review",
                time: "",
                event: event
            )
        )
        rows.append(contentsOf: networkPolicyTreeRows(summary, parentKey: networkKey, event: event))
        rows.append(
            MonitorActivityRow(
                isGroup: true,
                kind: "policy-files",
                level: 1,
                rowKey: filesKey,
                app: "Filesystem Policy",
                destination: "\(summary.filesystem.allowRead.count) read · \(summary.filesystem.allowWrite.count) write · \(summary.filesystem.denyRead.count + summary.filesystem.denyWrite.count) protected",
                activity: "",
                decision: summary.findings.isEmpty ? "active" : "review",
                time: "",
                event: event
            )
        )
        rows.append(contentsOf: filesystemPolicyTreeRows(summary, parentKey: filesKey, event: event))
        rows.append(
            MonitorActivityRow(
                isGroup: true,
                kind: "policy-proxy",
                level: 1,
                rowKey: proxyKey,
                app: "Proxy / TLS Policy",
                destination: summary.network.mode,
                activity: "",
                decision: summary.network.tlsInspection?.enabled == false ? "review" : "active",
                time: "",
                event: event
            )
        )
        rows.append(contentsOf: proxyPolicyTreeRows(summary, parentKey: proxyKey, event: event))
        return rows
    }

    func networkPolicyTreeRows(_ summary: GuardAppSummary, parentKey: String, event: GuardMonitorEvent?) -> [MonitorActivityRow] {
        var rows: [MonitorActivityRow] = []
        for host in summary.network.allowedDomains {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-allow-host", label: host, destination: "Allow host", activity: "Proxy-routed domain allowlist", decision: "active", event: event))
        }
        for host in summary.network.deniedDomains {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-deny-host", label: host, destination: "Deny host", activity: "Explicit network deny", decision: "deny", event: event))
        }
        for rule in summary.network.httpRules ?? [] {
            let host = rule.host ?? rule.cidr ?? "any host"
            let methods = rule.methods?.joined(separator: "|") ?? "any method"
            let paths = rule.paths?.joined(separator: ", ") ?? "any path"
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-http", label: host, destination: "HTTP rule", activity: "\(methods) \(paths)", decision: "active", event: event))
        }
        for rule in summary.network.allowedRawTcp ?? [] {
            let destination = rule.ip ?? rule.host ?? "unknown"
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-raw-tcp", label: "\(destination):\(rule.port.map { "\($0)" } ?? "?")", destination: "Raw TCP", activity: rule.reason ?? "Direct TCP exception", decision: "active", event: event))
        }
        if rows.isEmpty {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-empty", label: "No network rules", destination: "", activity: "", decision: "active", event: event))
        }
        return rows
    }

    func filesystemPolicyTreeRows(_ summary: GuardAppSummary, parentKey: String, event: GuardMonitorEvent?) -> [MonitorActivityRow] {
        var rows: [MonitorActivityRow] = []
        for value in summary.filesystem.allowRead {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-read", label: value, destination: "Read", activity: "", decision: "allow", event: event))
        }
        for value in summary.filesystem.allowWrite {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-write", label: value, destination: "Write", activity: "", decision: "allow", event: event))
        }
        for value in summary.filesystem.denyRead {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-deny-read", label: value, destination: "Deny read", activity: "", decision: "deny", event: event))
        }
        for value in summary.filesystem.denyWrite {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-deny-write", label: value, destination: "Deny write", activity: "", decision: "deny", event: event))
        }
        if rows.isEmpty {
            rows.append(policyLeaf(parentKey: parentKey, kind: "policy-empty", label: "No filesystem rules", destination: "", activity: "", decision: "active", event: event))
        }
        return rows
    }

    func proxyPolicyTreeRows(_ summary: GuardAppSummary, parentKey: String, event: GuardMonitorEvent?) -> [MonitorActivityRow] {
        [
            policyLeaf(parentKey: parentKey, kind: "policy-proxy-env", label: "HTTP proxy", destination: "enabled", activity: "", decision: "active", event: event),
            policyLeaf(parentKey: parentKey, kind: "policy-socks-env", label: "SOCKS / SSH", destination: "enabled", activity: "", decision: "active", event: event),
            policyLeaf(parentKey: parentKey, kind: "policy-tls", label: "TLS inspection", destination: tlsInspectionShortText(summary.network.tlsInspection), activity: "", decision: summary.network.tlsInspection?.enabled == false ? "review" : "active", event: event),
            policyLeaf(parentKey: parentKey, kind: "policy-loopback", label: "Loopback ports", destination: formatLoopbackPorts(summary.network), activity: "", decision: "active", event: event)
        ]
    }

    func tlsInspectionShortText(_ tls: GuardTlsInspection?) -> String {
        guard let tls else { return "default" }
        if tls.enabled == true {
            return tls.mode ?? "enabled"
        }
        return "off"
    }

    func policyLeaf(parentKey: String, kind: String, label: String, destination: String, activity: String, decision: String, event: GuardMonitorEvent?) -> MonitorActivityRow {
        MonitorActivityRow(
            isGroup: false,
            kind: kind,
            level: 2,
            rowKey: "\(parentKey)/\(kind):\(label)",
            app: label,
            destination: destination,
            activity: activity,
            decision: decision,
            time: "",
            event: event
        )
    }

    func networkRuleCountText(_ summary: GuardAppSummary) -> String {
        let raw = summary.network.allowedRawTcp?.count ?? 0
        let http = summary.network.httpRules?.count ?? 0
        let denied = summary.network.deniedDomains.count
        return [
            "\(summary.network.allowedDomains.count) allowed domains",
            denied > 0 ? "\(denied) denied" : nil,
            http > 0 ? "\(http) HTTP path rules" : nil,
            raw > 0 ? "\(raw) raw TCP" : nil
        ].compactMap { $0 }.joined(separator: ", ")
    }

    func networkPolicyRows(_ summary: GuardAppSummary) -> [(String, String)] {
        [
            ("Allowed Hosts", compactPolicyList(summary.network.allowedDomains)),
            ("Denied Hosts", compactPolicyList(summary.network.deniedDomains)),
            ("Deny Presets", compactPolicyList(summary.network.deniedDomainPresets)),
            ("HTTP Rules", formatHttpRules(summary.network.httpRules ?? [])),
            ("Raw TCP", formatRawTcpRules(summary.network.allowedRawTcp ?? [])),
            ("Loopback Ports", formatLoopbackPorts(summary.network))
        ]
    }

    func proxyAndTLSRows(_ summary: GuardAppSummary) -> [(String, String)] {
        [
            ("Mode", summary.network.mode),
            ("Proxy Env", "HTTP_PROXY/HTTPS_PROXY plus ALL_PROXY/GUARD_SOCKS_PROXY for guarded runs"),
            ("SSH/Git Proxy", "GUARD_SSH_PROXY_COMMAND and GIT_SSH_COMMAND when SOCKS proxy is active"),
            ("TLS Inspection", formatTlsInspection(summary.network.tlsInspection)),
            ("Local Binding", summary.network.allowLocalBinding == true ? "allowed" : "not allowed unless explicitly configured")
        ]
    }

    func formatHttpRules(_ rules: [GuardHttpPolicyRule]) -> String {
        if rules.isEmpty { return "none" }
        return rules.map { rule in
            let host = rule.host ?? rule.cidr ?? "any host"
            let methods = rule.methods?.joined(separator: "|") ?? "any method"
            let paths = rule.paths?.joined(separator: ", ") ?? "any path"
            return "\(host) \(methods) \(paths)"
        }.joined(separator: "\n")
    }

    func formatRawTcpRules(_ rules: [GuardRawTcpRule]) -> String {
        if rules.isEmpty { return "none" }
        return rules.map { rule in
            let destination = rule.ip ?? rule.host ?? "unknown"
            let launch = rule.resolveAtLaunch == true ? ", resolve at launch" : ""
            let reason = rule.reason?.isEmpty == false ? " — \(rule.reason!)" : ""
            return "\(destination):\(rule.port.map { "\($0)" } ?? "?")\(launch)\(reason)"
        }.joined(separator: "\n")
    }

    func formatLoopbackPorts(_ network: GuardNetworkSummary) -> String {
        var parts: [String] = []
        if network.allowLoopbackConnections == true { parts.append("loopback connections") }
        if network.allowLoopbackHighPorts == true { parts.append("high ports") }
        if network.allowLoopbackListeningHighPorts == true {
            let processes = network.allowLoopbackListeningHighPortProcesses ?? []
            parts.append(processes.isEmpty ? "listening high ports" : "listening high ports: \(processes.joined(separator: ", "))")
        }
        if let ports = network.allowLoopbackPorts, !ports.isEmpty {
            parts.append(ports.map(String.init).joined(separator: ", "))
        }
        return parts.isEmpty ? "none" : parts.joined(separator: "; ")
    }

    func formatTlsInspection(_ tls: GuardTlsInspection?) -> String {
        guard let tls else {
            return "default: active only when proxy/TLS backend enables it"
        }
        let enabled = tls.enabled == true ? "enabled" : "disabled"
        let explicit = tls.explicit == true ? "explicit profile rule" : "implicit/default"
        let mode = tls.mode ?? "unknown mode"
        let ca = tls.caScope ?? "unknown CA scope"
        let trustedBy = tls.trustedBy?.isEmpty == false ? tls.trustedBy!.joined(separator: ", ") : "no clients listed"
        let approval = tls.userApprovalRequired == true ? "user approval required" : "no approval flag"
        return "\(enabled), \(explicit), \(mode), CA \(ca), trusted by \(trustedBy), \(approval)"
    }

    func renderProcessDetailsPanel(row: MonitorActivityRow) {
        inspectorHelpLabel.isHidden = true
        inspectorTitleLabel.isHidden = true
        clearInspectorSummaryPanel()
        let processEvents = events.filter {
            appLabel(for: $0) == appLabelForRowKey(row.rowKey) && processLabel(for: $0) == row.app
        }
        let network = processEvents.filter { !$0.host.isEmpty }
        let denied = network.filter { $0.result == "deny" }.count
        let allowed = network.filter { $0.result == "allow" }.count
        let sampleEvent = processEvents.first
        let summary = projectSummary(for: processEvents, allowSubprocess: false)
        inspectorHelpLabel.stringValue = "Process"
        inspectorTitleLabel.stringValue = row.app
        inspectorSummaryStack.addArrangedSubview(actorHeader(
            title: row.app,
            subtitle: appLabelForRowKey(row.rowKey),
            icon: iconForActivityRow(row),
            sent: processEvents.reduce(0) { $0 + $1.bytesSent },
            received: processEvents.reduce(0) { $0 + $1.bytesReceived }
        ))
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Process"))
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Name", row.app),
            ("App", appLabelForRowKey(row.rowKey)),
            ("PID", sampleEvent?.pid ?? 0 > 0 ? "\(sampleEvent?.pid ?? 0)" : "Not recorded"),
            ("Path", sampleEvent?.processPath.isEmpty == false ? sampleEvent?.processPath ?? "Not recorded" : "Not recorded"),
            ("Command", sampleEvent?.command.isEmpty == false ? sampleEvent?.command ?? "Unknown" : "Unknown"),
            ("Project", sampleEvent?.projectDir.isEmpty == false ? sampleEvent?.projectDir ?? "Not recorded" : "Not recorded")
        ]))
        if let summary {
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Launch Policy"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
                ("Status", summary.findings.isEmpty ? "ok, no dangerous defaults" : "\(summary.findings.count) policy finding\(summary.findings.count == 1 ? "" : "s")"),
                ("Network", networkRuleCountText(summary)),
                ("Read", compactPolicyList(summary.filesystem.allowRead, limit: 3)),
                ("Write", compactPolicyList(summary.filesystem.allowWrite, limit: 3)),
                ("Protected", compactPolicyList(summary.filesystem.denyRead + summary.filesystem.denyWrite, limit: 3))
            ], valueTint: summary.findings.isEmpty ? .secondaryLabelColor : .systemOrange))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Network Rules"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock(networkPolicyRows(summary)))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Proxy / TLS"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock(proxyAndTLSRows(summary)))
        }
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Internet Access Policy"))
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Destinations", "\(Set(network.map { $0.host }).count)"),
            ("Allowed", "\(allowed)"),
            ("Denied", "\(denied)"),
            ("Current Risk", profileRiskLabel)
        ], valueTint: denied > 0 ? .systemOrange : .secondaryLabelColor))
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Top Destinations"))
        for item in topCounts(network.map { $0.host }, limit: 5) {
            inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "globe", text: item))
        }
        inspectorSummaryStack.addArrangedSubview(inspectorSection("Code Signature"))
        let signature = sampleEvent.map { codeSignatureSummary(for: $0) } ?? (status: "Not collected", signer: "Unavailable", teamId: "Unavailable", bundleIdentifier: "Unavailable")
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Status", signature.status),
            ("Signer", signature.signer),
            ("Team ID", signature.teamId),
            ("Bundle ID", sampleEvent?.bundleIdentifier.isEmpty == false ? sampleEvent?.bundleIdentifier ?? signature.bundleIdentifier : signature.bundleIdentifier)
        ]))
    }

    func appLabelForRowKey(_ rowKey: String) -> String {
        guard rowKey.hasPrefix("app:") else { return "" }
        let withoutPrefix = rowKey.dropFirst(4)
        if let slash = withoutPrefix.firstIndex(of: "/") {
            return String(withoutPrefix[..<slash])
        }
        return String(withoutPrefix)
    }

    func projectSummary(for events: [GuardMonitorEvent], allowSubprocess: Bool = true) -> GuardAppSummary? {
        guard let event = events.first(where: { !$0.projectDir.isEmpty }) else { return nil }
        let profile = event.profile.isEmpty ? config.profile : event.profile
        let key = "\(profile)|\(event.projectDir)"
        if projectSummaryMissCache.contains(key) {
            return nil
        }
        if let cached = projectSummaryCache[key] {
            return cached
        }
        if let localSummary = projectConfigSummary(for: event) {
            projectSummaryCache[key] = localSummary
            return localSummary
        }
        guard allowSubprocess else {
            return nil
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: config.guardPath)
        process.currentDirectoryURL = URL(fileURLWithPath: event.projectDir)
        process.arguments = ["app-summary", "--profile", profile, "--json"]
        let stdout = Pipe()
        process.standardOutput = stdout
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                let fallback = projectConfigSummary(for: event)
                if let fallback {
                    projectSummaryCache[key] = fallback
                } else {
                    projectSummaryMissCache.insert(key)
                }
                return fallback
            }
            let data = stdout.fileHandleForReading.readDataToEndOfFile()
            let summary = try decodeAppSummary(data)
            projectSummaryCache[key] = summary
            return summary
        } catch {
            let fallback = projectConfigSummary(for: event)
            if let fallback {
                projectSummaryCache[key] = fallback
            } else {
                projectSummaryMissCache.insert(key)
            }
            return fallback
        }
    }

    func projectConfigSummary(for event: GuardMonitorEvent) -> GuardAppSummary? {
        let configPath = URL(fileURLWithPath: event.projectDir).appendingPathComponent(".guard/guard.json").path
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let network = object["network"] as? [String: Any] ?? [:]
        let filesystem = object["filesystem"] as? [String: Any] ?? [:]
        let realHome = FileManager.default.homeDirectoryForCurrentUser.path
        let expand = { (value: String) -> String in
            value
                .replacingOccurrences(of: "${GUARD_PROJECT_DIR}", with: event.projectDir)
                .replacingOccurrences(of: "${GUARD_RUN_DIR}", with: event.runDir.isEmpty ? "<run>" : event.runDir)
                .replacingOccurrences(of: "${GUARD_REAL_HOME}", with: realHome)
                .replacingOccurrences(of: "~", with: realHome, options: [.anchored])
        }
        let expandArray = { (values: [String]) -> [String] in values.map(expand) }
        let denyWrite = filesystem["denyWrite"] as? [String] ?? []
        let secretsProtected = denyWrite.contains { value in
            value.contains(".env") || value.contains("secrets") || value.contains("*.key") || value.contains("*.pem")
        }
        return GuardAppSummary(
            profile: event.profile.isEmpty ? "guard" : event.profile,
            description: "",
            risk: secretsProtected ? "low, locked" : "unknown",
            status: secretsProtected ? "ok" : "review",
            appBundle: nil,
            network: GuardNetworkSummary(
                mode: (network["allowedDomains"] as? [String] ?? []).isEmpty ? "none" : "allowlist",
                allowedDomains: network["allowedDomains"] as? [String] ?? [],
                allowedRawTcp: decodeArray(GuardRawTcpRule.self, from: network["allowedRawTcp"]),
                httpRules: decodeArray(GuardHttpPolicyRule.self, from: network["httpRules"]),
                deniedDomains: network["deniedDomains"] as? [String] ?? [],
                deniedDomainPresets: network["deniedDomainPresets"] as? [String] ?? [],
                tlsInspection: decodeObject(GuardTlsInspection.self, from: network["tlsInspection"]),
                allowLocalBinding: network["allowLocalBinding"] as? Bool,
                allowLoopbackConnections: network["allowLoopbackConnections"] as? Bool,
                allowLoopbackHighPorts: network["allowLoopbackHighPorts"] as? Bool,
                allowLoopbackListeningHighPorts: network["allowLoopbackListeningHighPorts"] as? Bool,
                allowLoopbackListeningHighPortProcesses: network["allowLoopbackListeningHighPortProcesses"] as? [String],
                allowLoopbackPorts: network["allowLoopbackPorts"] as? [Int]
            ),
            filesystem: GuardFilesystemSummary(
                allowRead: expandArray(filesystem["allowRead"] as? [String] ?? []),
                denyRead: expandArray(filesystem["denyRead"] as? [String] ?? []),
                allowWrite: expandArray(filesystem["allowWrite"] as? [String] ?? []),
                denyWrite: expandArray(denyWrite)
            ),
            findings: secretsProtected ? [] : [
                GuardFinding(severity: "warning", id: "secrets-unprotected", message: "Secret write denies are incomplete.", values: nil)
            ]
        )
    }

    func decodeAppSummary(_ data: Data) throws -> GuardAppSummary {
        if let decoded = try? JSONDecoder().decode(GuardAppSummary.self, from: data) {
            return decoded
        }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NSError(domain: "GuardMonitor", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid app-summary JSON"])
        }
        let network = object["network"] as? [String: Any] ?? [:]
        let filesystem = object["filesystem"] as? [String: Any] ?? [:]
        let findings = (object["findings"] as? [[String: Any]] ?? []).map {
            GuardFinding(
                severity: $0["severity"] as? String ?? "info",
                id: $0["id"] as? String ?? "finding",
                message: $0["message"] as? String ?? "",
                values: $0["values"] as? [String]
            )
        }
        return GuardAppSummary(
            profile: object["profile"] as? String ?? "guard",
            description: object["description"] as? String ?? "",
            risk: object["risk"] as? String ?? "unknown",
            status: object["status"] as? String ?? "unknown",
            appBundle: object["appBundle"] as? String,
            network: GuardNetworkSummary(
                mode: network["mode"] as? String ?? "unknown",
                allowedDomains: network["allowedDomains"] as? [String] ?? [],
                allowedRawTcp: decodeArray(GuardRawTcpRule.self, from: network["allowedRawTcp"]),
                httpRules: decodeArray(GuardHttpPolicyRule.self, from: network["httpRules"]),
                deniedDomains: network["deniedDomains"] as? [String] ?? [],
                deniedDomainPresets: network["deniedDomainPresets"] as? [String] ?? [],
                tlsInspection: decodeObject(GuardTlsInspection.self, from: network["tlsInspection"]),
                allowLocalBinding: network["allowLocalBinding"] as? Bool,
                allowLoopbackConnections: network["allowLoopbackConnections"] as? Bool,
                allowLoopbackHighPorts: network["allowLoopbackHighPorts"] as? Bool,
                allowLoopbackListeningHighPorts: network["allowLoopbackListeningHighPorts"] as? Bool,
                allowLoopbackListeningHighPortProcesses: network["allowLoopbackListeningHighPortProcesses"] as? [String],
                allowLoopbackPorts: network["allowLoopbackPorts"] as? [Int]
            ),
            filesystem: GuardFilesystemSummary(
                allowRead: filesystem["allowRead"] as? [String] ?? [],
                denyRead: filesystem["denyRead"] as? [String] ?? [],
                allowWrite: filesystem["allowWrite"] as? [String] ?? [],
                denyWrite: filesystem["denyWrite"] as? [String] ?? []
            ),
            findings: findings
        )
    }

    func decodeObject<T: Decodable>(_ type: T.Type, from value: Any?) -> T? {
        guard let value,
              JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value) else {
            return nil
        }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    func decodeArray<T: Decodable>(_ type: T.Type, from value: Any?) -> [T] {
        guard let value,
              JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value) else {
            return []
        }
        return (try? JSONDecoder().decode([T].self, from: data)) ?? []
    }

    func policyTableSummary(_ summary: GuardAppSummary?) -> String? {
        guard let summary else { return nil }
        let network = summary.network.allowedDomains.count
        let read = summary.filesystem.allowRead.count
        let write = summary.filesystem.allowWrite.count
        let protected = summary.filesystem.denyRead.count + summary.filesystem.denyWrite.count
        var parts: [String] = []
        if network > 0 { parts.append("\(network) net") }
        if read > 0 || write > 0 { parts.append("\(read)R \(write)W") }
        if protected > 0 { parts.append("\(protected) protected") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    func isRunLifecycleActivity(_ event: GuardMonitorEvent) -> Bool {
        event.type == "proxy.started" ||
        event.type == "guard.project.profile" ||
        event.type == "sandbox.profile_written" ||
        event.type == "process.started" ||
        event.type == "process.exited"
    }

    func sortProcessNames(_ left: String, _ right: String) -> Bool {
        let leftRank = processDisplayRank(left)
        let rightRank = processDisplayRank(right)
        if leftRank != rightRank { return leftRank < rightRank }
        return left.localizedStandardCompare(right) == .orderedAscending
    }

    func processDisplayRank(_ value: String) -> Int {
        let lower = value.lowercased()
        if lower.contains("pnpm run") || lower.contains("npm run") { return 0 }
        if lower.contains("pnpm") || lower.contains("npm") { return 1 }
        if lower.contains("node --version") { return 9 }
        return 4
    }

    func codeSignatureSummary(for event: GuardMonitorEvent) -> (status: String, signer: String, teamId: String, bundleIdentifier: String) {
        let path = event.processPath.isEmpty ? executablePath(from: event.command) : event.processPath
        let cacheKey = "\(path)|\(event.bundleIdentifier)"
        if let cached = codeSignatureCache[cacheKey] {
            return cached
        }
        guard !path.isEmpty, FileManager.default.fileExists(atPath: path) else {
            return ("Not collected", "Process path unavailable", "Unavailable", event.bundleIdentifier.isEmpty ? "Unavailable" : event.bundleIdentifier)
        }

        let result = try? runProcess("/usr/bin/codesign", ["-dv", "--verbose=4", path])
        guard let result else {
            return ("Unavailable", "codesign failed", "Unavailable", event.bundleIdentifier.isEmpty ? "Unavailable" : event.bundleIdentifier)
        }
        let stderr = String(data: result.2, encoding: .utf8) ?? ""
        let authority = stderr
            .split(whereSeparator: \.isNewline)
            .compactMap { line -> String? in
                let text = String(line)
                return text.hasPrefix("Authority=") ? String(text.dropFirst("Authority=".count)) : nil
            }
            .first ?? "Unavailable"
        let teamId = fieldValue("TeamIdentifier", in: stderr) ?? "Unavailable"
        let identifier = event.bundleIdentifier.isEmpty
            ? (fieldValue("Identifier", in: stderr) ?? "Unavailable")
            : event.bundleIdentifier
        let status = result.0 == 0 ? "Signature valid" : "Signature invalid"
        let summary: (status: String, signer: String, teamId: String, bundleIdentifier: String) = (status, authority, teamId, identifier)
        codeSignatureCache[cacheKey] = summary
        return summary
    }

    func fieldValue(_ key: String, in text: String) -> String? {
        let prefix = "\(key)="
        return text
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .first(where: { $0.hasPrefix(prefix) })
            .map { String($0.dropFirst(prefix.count)) }
    }

    func executablePath(from command: String) -> String {
        let first = command.split(separator: " ").first.map(String.init) ?? ""
        guard !first.isEmpty else { return "" }
        if first.hasPrefix("/") { return first }
        let pathEntries = (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin")
            .split(separator: ":")
            .map(String.init)
        for entry in pathEntries {
            let candidate = URL(fileURLWithPath: entry).appendingPathComponent(first).path
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        return ""
    }

    func ruleScopePreview(for event: GuardMonitorEvent) -> String {
        if event.type == "guard.alert.pending" {
            return "\(event.host) for this alert decision"
        }
        if event.detail.lowercased().contains("httprules") {
            return "HTTP rule for \(event.host)"
        }
        return "Domain rule for \(event.host)"
    }

    func rateStrip() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        row.addArrangedSubview(ratePill(symbol: "arrow.up", title: "\(recentAllowedCount)", tint: .systemPurple))
        row.addArrangedSubview(ratePill(symbol: "xmark", title: "\(recentDeniedCount)", tint: .systemRed))
        return row
    }

    func actorHeader(title: String, subtitle: String, icon: NSImage?, sent: Int, received: Int) -> NSView {
        let container = NSStackView()
        container.orientation = .vertical
        container.alignment = .leading
        container.spacing = 8
        container.translatesAutoresizingMaskIntoConstraints = false
        container.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true

        let top = NSStackView()
        top.orientation = .horizontal
        top.alignment = .centerY
        top.spacing = 10
        top.translatesAutoresizingMaskIntoConstraints = false

        let imageView = NSImageView()
        imageView.image = icon ?? NSImage(named: NSImage.applicationIconName)
        imageView.imageScaling = .scaleProportionallyUpOrDown
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.widthAnchor.constraint(equalToConstant: 34).isActive = true
        imageView.heightAnchor.constraint(equalToConstant: 34).isActive = true
        top.addArrangedSubview(imageView)

        let labels = NSStackView()
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 2
        let titleLabel = label(title, size: 15, weight: .bold)
        titleLabel.lineBreakMode = .byTruncatingMiddle
        let subtitleLabel = label(subtitle, size: 11.5, weight: .medium, color: .secondaryLabelColor)
        subtitleLabel.lineBreakMode = .byTruncatingMiddle
        labels.addArrangedSubview(titleLabel)
        labels.addArrangedSubview(subtitleLabel)
        top.addArrangedSubview(labels)
        container.addArrangedSubview(top)

        let rates = NSStackView()
        rates.orientation = .horizontal
        rates.alignment = .centerY
        rates.spacing = 8
        rates.translatesAutoresizingMaskIntoConstraints = false
        rates.addArrangedSubview(ratePill(symbol: "arrow.up", title: sent > 0 ? byteCount(sent) : "0 B", tint: .systemPurple))
        rates.addArrangedSubview(ratePill(symbol: "arrow.down", title: received > 0 ? byteCount(received) : "0 B", tint: .systemBlue))
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        rates.addArrangedSubview(spacer)
        container.addArrangedSubview(rates)
        return container
    }

    func byteCount(_ value: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .file)
    }

    func ratePill(symbol: String, title: String, tint: NSColor) -> NSView {
        ratePill(symbol: symbol, field: label(title, size: 13, weight: .bold, color: .labelColor), tint: tint)
    }

    func ratePill(symbol: String, field: NSTextField, tint: NSColor) -> NSView {
        let container = CardView(fill: tint.withAlphaComponent(0.34), border: tint.withAlphaComponent(0.10))
        container.layer?.cornerRadius = 7
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 6
        row.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(row)
        let icon = NSImageView()
        if #available(macOS 11.0, *) {
            icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            icon.contentTintColor = tint.blended(withFraction: 0.35, of: .white) ?? tint
        }
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 14).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 14).isActive = true
        field.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        field.textColor = .labelColor
        field.maximumNumberOfLines = 1
        field.lineBreakMode = .byTruncatingTail
        row.addArrangedSubview(icon)
        row.addArrangedSubview(field)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 10),
            row.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -10),
            row.topAnchor.constraint(equalTo: container.topAnchor, constant: 6),
            row.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -6)
        ])
        return container
    }

    func inspectorSection(_ title: String) -> NSView {
        let container = CardView(fill: NSColor.controlBackgroundColor.withAlphaComponent(0.55), border: NSColor.clear)
        container.layer?.cornerRadius = 5
        container.translatesAutoresizingMaskIntoConstraints = false
        container.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true
        let field = label(title, size: 11.5, weight: .semibold, color: .secondaryLabelColor)
        field.alignment = .left
        let stack = paddedStack(in: container, inset: 6)
        stack.alignment = .leading
        stack.addArrangedSubview(field)
        return container
    }

    func detailSection(_ title: String) -> NSView {
        let field = label(title, size: 11.5, weight: .semibold, color: .tertiaryLabelColor)
        field.lineBreakMode = .byTruncatingTail
        field.setContentHuggingPriority(.required, for: .horizontal)
        return field
    }

    func detailBlock(_ lines: [String], tint: NSColor = .secondaryLabelColor) -> NSView {
        let field = NSTextField(labelWithString: lines.joined(separator: "\n"))
        field.font = NSFont.systemFont(ofSize: 12, weight: .medium)
        field.textColor = tint
        field.lineBreakMode = .byWordWrapping
        field.maximumNumberOfLines = 8
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.preferredMaxLayoutWidth = 270
        field.toolTip = lines.joined(separator: "\n")
        return field
    }

    func detailKeyValueBlock(_ rows: [(String, String)], valueTint: NSColor = .secondaryLabelColor) -> NSView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true
        for row in rows {
            let line = NSStackView()
            line.orientation = .vertical
            line.alignment = .leading
            line.spacing = 1
            line.translatesAutoresizingMaskIntoConstraints = false

            let key = label(row.0, size: 11, weight: .medium, color: .tertiaryLabelColor)
            key.alignment = .left
            key.setContentHuggingPriority(.required, for: .horizontal)
            key.setContentCompressionResistancePriority(.required, for: .horizontal)

            let value = label(row.1, size: 11.5, weight: .medium, color: valueTint)
            value.lineBreakMode = .byCharWrapping
            value.maximumNumberOfLines = 0
            value.alignment = .left
            value.toolTip = row.1
            value.translatesAutoresizingMaskIntoConstraints = false
            value.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true
            value.preferredMaxLayoutWidth = 330
            value.setContentHuggingPriority(.defaultLow, for: .horizontal)
            value.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

            line.addArrangedSubview(key)
            line.addArrangedSubview(value)
            stack.addArrangedSubview(line)
        }
        return stack
    }

    func summaryMetric(symbol: String, value: String, text: String) -> NSView {
        summaryListItem(symbol: symbol, text: "\(value) \(text)", prominent: true)
    }

    func summaryListItem(symbol: String, text: String, prominent: Bool = false) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 9
        row.translatesAutoresizingMaskIntoConstraints = false
        row.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true
        let icon = NSImageView()
        if #available(macOS 11.0, *) {
            icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            icon.contentTintColor = .secondaryLabelColor
        }
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 18).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 18).isActive = true
        let field = label(text, size: prominent ? 13 : 12, weight: prominent ? .semibold : .medium, color: .labelColor)
        field.lineBreakMode = .byTruncatingMiddle
        field.alignment = .left
        row.addArrangedSubview(icon)
        row.addArrangedSubview(field)
        return row
    }

    func makeRowsScroll(_ scroll: NSScrollView, content: NSStackView) -> NSView {
        configureOverlayScrollView(scroll)
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: 190).isActive = true

        content.orientation = .vertical
        content.alignment = .width
        content.spacing = 6
        content.edgeInsets = NSEdgeInsets(top: 6, left: 6, bottom: 6, right: 6)
        content.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = content
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            content.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            content.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            content.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor)
        ])
        scroll.isHidden = true
        return scroll
    }

    func makeActionBar() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        statusLabel.lineBreakMode = .byTruncatingMiddle

        allowDomainButton.title = "Allow Domain"
        allowDomainButton.target = self
        allowDomainButton.action = #selector(allowSelectedDomain(_:))
        allowDomainButton.bezelStyle = .rounded
        allowDomainButton.controlSize = .small
        allowDomainButton.toolTip = "Add the selected host to network.allowedDomains for the selected event profile."

        denyDomainButton.title = "Deny Domain"
        denyDomainButton.target = self
        denyDomainButton.action = #selector(denySelectedDomain(_:))
        denyDomainButton.bezelStyle = .rounded
        denyDomainButton.controlSize = .small
        denyDomainButton.toolTip = "Add the selected host to network.deniedDomains for the selected event profile."

        allowOnceButton.title = "Allow Once"
        allowOnceButton.target = self
        allowOnceButton.action = #selector(allowSelectedOnce(_:))
        allowOnceButton.bezelStyle = .rounded
        allowOnceButton.controlSize = .small
        allowOnceButton.toolTip = "Resolve a pending alert or record a non-persistent allow decision for the selected host."

        denyOnceButton.title = "Deny Once"
        denyOnceButton.target = self
        denyOnceButton.action = #selector(denySelectedOnce(_:))
        denyOnceButton.bezelStyle = .rounded
        denyOnceButton.controlSize = .small
        denyOnceButton.toolTip = "Resolve a pending alert or record a non-persistent deny decision for the selected host."

        startDaemonButton.title = "Start Daemon"
        startDaemonButton.target = self
        startDaemonButton.action = #selector(startDaemon(_:))
        startDaemonButton.bezelStyle = .rounded
        startDaemonButton.controlSize = .small
        startDaemonButton.toolTip = "Start a local guardd using a selected project, GUARD_PROJECT_DIR, or Guard's global app-support config."

        stopDaemonButton.title = "Stop Daemon"
        stopDaemonButton.target = self
        stopDaemonButton.action = #selector(stopDaemon(_:))
        stopDaemonButton.bezelStyle = .rounded
        stopDaemonButton.controlSize = .small
        stopDaemonButton.toolTip = "Stop the daemon started by this monitor window."

        enableTLSButton.title = "Enable TLS"
        enableTLSButton.target = self
        enableTLSButton.action = #selector(enableTLS(_:))
        enableTLSButton.bezelStyle = .rounded
        enableTLSButton.controlSize = .small
        enableTLSButton.toolTip = "Enable explicit TLS inspection policy for the selected profile through guardd."

        disableTLSButton.title = "Disable TLS"
        disableTLSButton.target = self
        disableTLSButton.action = #selector(disableTLS(_:))
        disableTLSButton.bezelStyle = .rounded
        disableTLSButton.controlSize = .small
        disableTLSButton.toolTip = "Disable explicit TLS inspection policy for the selected profile through guardd."

        generateTLSCAButton.title = "Generate Local CA"
        generateTLSCAButton.target = self
        generateTLSCAButton.action = #selector(generateTLSCA(_:))
        generateTLSCAButton.bezelStyle = .rounded
        generateTLSCAButton.controlSize = .small
        generateTLSCAButton.toolTip = "Create local Guard CA artifacts under guardd state without installing global trust."

        rotateTLSCAButton.title = "Rotate Local CA"
        rotateTLSCAButton.target = self
        rotateTLSCAButton.action = #selector(rotateTLSCA(_:))
        rotateTLSCAButton.bezelStyle = .rounded
        rotateTLSCAButton.controlSize = .small
        rotateTLSCAButton.toolTip = "Archive and replace local Guard CA artifacts; host certificates must be regenerated."

        revokeTLSCAButton.title = "Revoke Local CA"
        revokeTLSCAButton.target = self
        revokeTLSCAButton.action = #selector(revokeTLSCA(_:))
        revokeTLSCAButton.bezelStyle = .rounded
        revokeTLSCAButton.controlSize = .small
        revokeTLSCAButton.toolTip = "Mark the local Guard CA revoked without touching the macOS trust store."

        syncExtensionButton.title = "Sync Extension"
        syncExtensionButton.target = self
        syncExtensionButton.action = #selector(syncExtension(_:))
        syncExtensionButton.bezelStyle = .rounded
        syncExtensionButton.controlSize = .small
        syncExtensionButton.toolTip = "Write the current selected profile snapshot and digest to the NetworkExtension sync directory."

        invalidateExtensionButton.title = "Invalidate Extension"
        invalidateExtensionButton.target = self
        invalidateExtensionButton.action = #selector(invalidateExtension(_:))
        invalidateExtensionButton.bezelStyle = .rounded
        invalidateExtensionButton.controlSize = .small
        invalidateExtensionButton.toolTip = "Mark the current NetworkExtension sync manifest invalid so the extension falls back to strict stale-policy behavior."

        addProjectFolderButton.title = "Add Project"
        addProjectFolderButton.target = self
        addProjectFolderButton.action = #selector(addProjectFolder(_:))
        addProjectFolderButton.bezelStyle = .rounded
        addProjectFolderButton.controlSize = .small
        addProjectFolderButton.toolTip = "Register a project folder with .guard/*.json so inactive configurations are visible and manageable."

        previewTemplateButton.title = "Preview Template"
        previewTemplateButton.target = self
        previewTemplateButton.action = #selector(previewTemplate(_:))
        previewTemplateButton.bezelStyle = .rounded
        previewTemplateButton.controlSize = .small
        previewTemplateButton.toolTip = "Preview the first available template against the selected profile."

        applyTemplateButton.title = "Apply Template"
        applyTemplateButton.target = self
        applyTemplateButton.action = #selector(applyTemplate(_:))
        applyTemplateButton.bezelStyle = .rounded
        applyTemplateButton.controlSize = .small
        applyTemplateButton.toolTip = "Apply the first available template to the selected profile through guardd."

        row.addArrangedSubview(statusLabel)
        row.addArrangedSubview(denyOnceButton)
        row.addArrangedSubview(allowOnceButton)
        row.addArrangedSubview(denyDomainButton)
        row.addArrangedSubview(allowDomainButton)

        advancedActionStack.orientation = .horizontal
        advancedActionStack.alignment = .centerY
        advancedActionStack.spacing = 8
        advancedActionStack.addArrangedSubview(startDaemonButton)
        advancedActionStack.addArrangedSubview(stopDaemonButton)
        advancedActionStack.addArrangedSubview(enableTLSButton)
        advancedActionStack.addArrangedSubview(disableTLSButton)
        advancedActionStack.addArrangedSubview(generateTLSCAButton)
        advancedActionStack.addArrangedSubview(rotateTLSCAButton)
        advancedActionStack.addArrangedSubview(revokeTLSCAButton)
        advancedActionStack.addArrangedSubview(syncExtensionButton)
        advancedActionStack.addArrangedSubview(invalidateExtensionButton)
        advancedActionStack.addArrangedSubview(addProjectFolderButton)
        advancedActionStack.addArrangedSubview(previewTemplateButton)
        advancedActionStack.addArrangedSubview(applyTemplateButton)
        advancedActionStack.isHidden = true
        row.addArrangedSubview(advancedActionStack)
        updateActionButtons(nil)
        updateInspector(nil)
        return row
    }

    @objc func switchInspectorTab(_ sender: NSSegmentedControl) {
        updateInspector(currentSelectedEvent())
    }

    @objc func selectProfile(_ sender: NSPopUpButton) {
        selectedProfileName = sender.titleOfSelectedItem ?? selectedProfileName
        if daemonConnected {
            loadDaemonPolicyState(profile: selectedProfileName)
        }
        updateInspector(currentSelectedEvent())
    }

    @objc func selectTemplate(_ sender: NSPopUpButton) {
        selectedTemplateName = sender.titleOfSelectedItem ?? selectedTemplateName
        updateInspector(currentSelectedEvent())
    }

    @objc func filterRules(_ sender: Any?) {
        renderRuleRows()
    }

    @objc func filterMonitorRows(_ sender: Any?) {
        rebuildActivityRows(keepSelection: true)
        updateMonitorSearchChrome()
        statusLabel.stringValue = "\(events.count) recent event\(events.count == 1 ? "" : "s") · \(activityRows.count) visible row\(activityRows.count == 1 ? "" : "s") · \(daemonStatusText)"
    }

    @objc func clearMonitorSearch(_ sender: Any?) {
        monitorSearchField.stringValue = ""
        toolbarSearchField?.stringValue = ""
        filterMonitorRows(sender)
    }

    @objc func focusTopHostSearch(_ sender: Any?) {
        guard recentTopHost != "-" else {
            statusLabel.stringValue = "No network host has been observed yet."
            return
        }
        monitorSearchField.stringValue = "host:\(recentTopHost)"
        toolbarSearchField?.stringValue = monitorSearchField.stringValue
        filterMonitorRows(sender)
    }

    @objc func toggleMonitorTimeWindow(_ sender: Any?) {
        switch monitorTimeWindowMinutes {
        case 60:
            monitorTimeWindowMinutes = 15
        case 15:
            monitorTimeWindowMinutes = nil
        default:
            monitorTimeWindowMinutes = 60
        }
        filterMonitorRows(sender)
    }

    func updateMonitorSearchChrome() {
        clearMonitorSearchButton.isEnabled = !monitorSearchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        focusMonitorSearchButton.isEnabled = recentTopHost != "-"
        let title: String
        switch monitorTimeWindowMinutes {
        case .some(15): title = "15m"
        case .some(60): title = "1h"
        case .some(let minutes): title = "\(minutes)m"
        case .none: title = "All"
        }
        monitorTimeWindowButton.title = title
        monitorTimeWindowButton.contentTintColor = monitorTimeWindowMinutes == nil ? .secondaryLabelColor : .labelColor
    }

    @objc func toggleSelectedActivityGroup(_ sender: Any?) {
        let row = tableView.clickedRow >= 0 ? tableView.clickedRow : tableView.selectedRow
        guard let activityRow = activityRow(atVisibleRow: row), activityRow.isGroup else { return }
        toggleActivityGroup(row: activityRow)
    }

    @objc func focusTopHostInRules(_ sender: Any?) {
        guard recentTopHost != "-" else {
            statusLabel.stringValue = "No network host has been observed yet."
            return
        }
        ruleSearchField.stringValue = recentTopHost
        openRulesWindow(nil)
        statusLabel.stringValue = "Rules filtered to \(recentTopHost)."
    }

    func column(_ identifier: String, title: String, width: CGFloat) -> NSTableColumn {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
        column.title = title
        column.width = width
        column.minWidth = identifier == "time" ? 44 : 48
        return column
    }

    func separator() -> NSView {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.backgroundColor = NSColor.separatorColor.withAlphaComponent(0.2).cgColor
        view.translatesAutoresizingMaskIntoConstraints = false
        view.heightAnchor.constraint(equalToConstant: 0.5).isActive = true
        return view
    }

    func paddedStack(in view: NSView, inset: CGFloat) -> NSStackView {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: inset),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -inset),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: inset),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -inset)
        ])
        return stack
    }

    func eventLogPath() -> String {
        if let path = config.eventLogPath, !path.isEmpty {
            return path
        }
        return NSString(string: "~/Library/Application Support/guard/events.jsonl").expandingTildeInPath
    }

    func defaultDaemonPolicyRoot() -> String {
        let env = ProcessInfo.processInfo.environment
        if let policyRoot = env["GUARDD_POLICY_ROOT"], !policyRoot.isEmpty {
            return NSString(string: policyRoot).expandingTildeInPath
        }
        if let projectDir = env["GUARD_PROJECT_DIR"], !projectDir.isEmpty {
            return NSString(string: projectDir).expandingTildeInPath
        }
        if let stateDir = env["GUARD_STATE_DIR"], !stateDir.isEmpty {
            return NSString(string: stateDir).expandingTildeInPath
        }
        return URL(fileURLWithPath: eventLogPath()).deletingLastPathComponent().path
    }

    func selectedInspectorTab() -> MonitorInspectorTab {
        .events
    }

    func currentSelectedEvent() -> GuardMonitorEvent? {
        let row = tableView.selectedRow
        return activityRow(atVisibleRow: row)?.event
    }

    func daemonURLHint() -> String {
        if let url = ProcessInfo.processInfo.environment["GUARD_DAEMON_URL"], !url.isEmpty {
            return url
        }
        if let url = ProcessInfo.processInfo.environment["GUARDD_URL"], !url.isEmpty {
            return url
        }
        let env = ProcessInfo.processInfo.environment
        let host = env["GUARDD_HOST"]?.isEmpty == false ? env["GUARDD_HOST"]! : "127.0.0.1"
        let port = env["GUARDD_PORT"]?.isEmpty == false ? env["GUARDD_PORT"]! : "8765"
        return "http://\(host):\(port)"
    }

    func daemonPort() -> String {
        let env = ProcessInfo.processInfo.environment
        return env["GUARDD_PORT"]?.isEmpty == false ? env["GUARDD_PORT"]! : "8765"
    }

    func monitorDaemonPort() -> String {
        let env = ProcessInfo.processInfo.environment
        if env["GUARD_DAEMON_URL"]?.isEmpty == false || env["GUARDD_URL"]?.isEmpty == false || env["GUARDD_PORT"]?.isEmpty == false {
            return daemonPort()
        }
        for _ in 0..<20 {
            let candidate = Int.random(in: 18765...19765)
            if isPortAvailable(candidate) {
                return "\(candidate)"
            }
        }
        return daemonPort()
    }

    func isPortAvailable(_ port: Int) -> Bool {
        let socketDescriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else { return false }
        defer { close(socketDescriptor) }
        var reuse = Int32(1)
        setsockopt(socketDescriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(port).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketDescriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    func stopManagedDaemon() {
        removeManagedDaemonConnection()
        guard let process = managedDaemon else { return }
        if process.isRunning {
            process.terminate()
        }
        managedDaemon = nil
        managedDaemonToken = nil
        managedDaemonURL = nil
    }

    func autoStartDaemonIfNeeded() {
        if loadDaemonEvents() != nil {
            return
        }
        startDaemon(nil)
    }

    func tlsInspectionStatus() -> String {
        if events.contains(where: { $0.detail.localizedCaseInsensitiveContains("tls") && $0.result == "deny" }) {
            return "attention needed; recent TLS-related denial"
        }
        if events.contains(where: { $0.detail.localizedCaseInsensitiveContains("proxy") || $0.detail.localizedCaseInsensitiveContains("http") }) {
            return "active when traffic is routed through the Guard proxy"
        }
        return "no recent proxied HTTP/TLS events"
    }

    func settingsBodyText() -> String {
        [
            "Traffic: \(recentAllowedCount) allowed, \(recentDeniedCount) denied, top host \(recentTopHost)",
            "Alerts: \(pendingAlertSummaryText)",
            "Daemon: \(daemonStatusText)",
            "API: \(daemonURLHint())",
            "Health: \(daemonHealthText)",
            "TLS: \(tlsInspectionStatus())",
            "Profile TLS: \(tlsStateText)",
            "Trust: \(tlsTrustText)",
            "Network Extension: \(extensionSyncText)",
            "Security: \(securityStatusText)",
            "Templates: \(templatesSummaryText)",
            "Event log: \(eventLogPath())"
        ].joined(separator: "\n")
    }

    @objc func revealLog(_ sender: Any?) {
        openLogWindow()
    }

    func openLogWindow() {
        let controller = eventLogWindowController ?? EventLogWindowController(parent: self)
        eventLogWindowController = controller
        controller.show()
    }

    func logWindowText(limit: Int = 300) -> String {
        let path = eventLogPath()
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return "No event log found at:\n\(path)"
        }
        let lines = content.split(whereSeparator: \.isNewline).suffix(limit)
        return lines.reversed().joined(separator: "\n")
    }

    @objc func refreshLogWindow(_ sender: Any?) {
        reloadEvents(nil)
        logTextView?.string = logWindowText()
    }

    @objc func revealLogFile(_ sender: Any?) {
        let url = URL(fileURLWithPath: eventLogPath())
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    @objc func allowSelectedDomain(_ sender: Any?) {
        addSelectedDomain(to: "network.allowedDomains")
    }

    @objc func denySelectedDomain(_ sender: Any?) {
        addSelectedDomain(to: "network.deniedDomains")
    }

    @objc func allowSelectedOnce(_ sender: Any?) {
        postSelectedAlertDecision(action: "allow", duration: "once")
    }

    @objc func denySelectedOnce(_ sender: Any?) {
        postSelectedAlertDecision(action: "deny", duration: "once")
    }

    @objc func allowSelectedFiveMinutes(_ sender: Any?) {
        postSelectedAlertDecision(action: "allow", duration: "5m")
    }

    @objc func allowSelectedOneHour(_ sender: Any?) {
        postSelectedAlertDecision(action: "allow", duration: "1h")
    }

    @objc func enableTLS(_ sender: Any?) {
        mutateTLS(enabled: true)
    }

    @objc func disableTLS(_ sender: Any?) {
        mutateTLS(enabled: false)
    }

    @objc func generateTLSCA(_ sender: Any?) {
        mutateTLSCA(action: "generate", success: "Generated local TLS CA artifacts.")
    }

    @objc func rotateTLSCA(_ sender: Any?) {
        mutateTLSCA(action: "rotate", success: "Rotated local TLS CA artifacts; rerun guarded tools so they receive the new CA environment.")
    }

    @objc func revokeTLSCA(_ sender: Any?) {
        mutateTLSCA(action: "revoke", success: "Revoked local TLS CA metadata.")
    }

    @objc func openRulesWindow(_ sender: Any?) {
        guard daemonConnected else {
            statusLabel.stringValue = "guardd must be connected before opening the full rules window."
            return
        }
        let profile = selectedProfileName.isEmpty ? "guard" : selectedProfileName
        loadDaemonPolicyState(profile: profile)
        let controller = rulesWindowController ?? RulesWindowController(
            client: daemonClient,
            profileNames: profileNames,
            selectedProfile: profile,
            rows: ruleRows,
            parent: self
        )
        controller.profileNames = Array(Set(profileNames + [profile, "guard"])).filter { !$0.isEmpty }.sorted()
        controller.selectedProfile = profile
        controller.rows = ruleRows
        rulesWindowController = controller
        controller.show()
    }

    @objc func openTemplatesWindow(_ sender: Any?) {
        guard daemonConnected else {
            statusLabel.stringValue = "guardd must be connected before opening templates."
            return
        }
        loadDaemonPolicyState(profile: selectedProfileName.isEmpty ? "guard" : selectedProfileName)
        let window = utilityWindow(existing: templatesWindow, title: "Templates", width: 560, height: 460)
        templatesWindow = window
        let root = utilityRoot(in: window)
        root.addArrangedSubview(utilityTitle("Templates", subtitle: templatesSummaryText))

        let popupRow = NSStackView()
        popupRow.orientation = .horizontal
        popupRow.alignment = .centerY
        popupRow.spacing = 8
        let label = label("Template", size: 12, weight: .medium, color: .secondaryLabelColor)
        updateTemplateMenu()
        popupRow.addArrangedSubview(label)
        popupRow.addArrangedSubview(templatePopup)
        root.addArrangedSubview(popupRow)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .lineBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 6
        stack.edgeInsets = NSEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
        for row in templateRows {
            stack.addArrangedSubview(templateRowView(row))
        }
        if templateRows.isEmpty {
            stack.addArrangedSubview(emptyRow(templatesSummaryText))
        }
        scroll.documentView = stack
        root.addArrangedSubview(scroll)

        let actions = NSStackView()
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 8
        let preview = NSButton(title: "Preview", target: self, action: #selector(previewTemplate(_:)))
        let apply = NSButton(title: "Apply", target: self, action: #selector(applyTemplate(_:)))
        for button in [preview, apply] {
            button.bezelStyle = .rounded
        }
        actions.addArrangedSubview(NSView())
        actions.addArrangedSubview(preview)
        actions.addArrangedSubview(apply)
        root.addArrangedSubview(actions)
        window.makeKeyAndOrderFront(nil)
    }

    @objc func openSettingsWindow(_ sender: Any?) {
        loadDaemonPolicyState(profile: selectedProfileName.isEmpty ? "guard" : selectedProfileName)
        let controller = settingsWindowController ?? SettingsWindowController(parent: self)
        settingsWindowController = controller
        controller.show()
    }

    @objc func startDaemon(_ sender: Any?) {
        guard managedDaemon == nil else {
            statusLabel.stringValue = "guardd is already managed by this monitor."
            return
        }
        let eventProjectDir = currentSelectedEvent()?.projectDir.isEmpty == false
            ? currentSelectedEvent()!.projectDir
            : (ProcessInfo.processInfo.environment["GUARD_PROJECT_DIR"] ?? "")
        let policyRoot = eventProjectDir.isEmpty ? defaultDaemonPolicyRoot() : eventProjectDir
        do {
            try FileManager.default.createDirectory(
                at: URL(fileURLWithPath: policyRoot),
                withIntermediateDirectories: true
            )
        } catch {
            statusLabel.stringValue = "Could not create daemon policy root: \(error.localizedDescription)"
            return
        }
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let port = monitorDaemonPort()
        let daemonURL = "http://127.0.0.1:\(port)"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: config.guardPath)
        process.currentDirectoryURL = URL(fileURLWithPath: policyRoot)
        process.arguments = [
            "daemon",
            "--host", "127.0.0.1",
            "--port", port,
            "--event-log", eventLogPath(),
            "--policy-root", policyRoot,
            "--api-token", token
        ]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            managedDaemon = process
            managedDaemonToken = token
            managedDaemonURL = daemonURL
            writeManagedDaemonConnection(url: daemonURL, token: token)
            daemonClient = GuardDaemonClient(apiTokenOverride: token, baseURLOverride: daemonURL)
            daemonStatusText = "guardd starting"
            daemonStateLabel.stringValue = daemonStatusText
            daemonStateLabel.textColor = .secondaryLabelColor
            statusLabel.stringValue = eventProjectDir.isEmpty
                ? "Started guardd with global policy store \(policyRoot)."
                : "Started guardd for \(policyRoot)."
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                self.reloadEvents(nil)
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) {
                self.reloadEvents(nil)
            }
        } catch {
            statusLabel.stringValue = "Could not start guardd: \(error.localizedDescription)"
        }
    }

    @objc func stopDaemon(_ sender: Any?) {
        stopManagedDaemon()
        removeManagedDaemonConnection()
        daemonClient = GuardDaemonClient()
        daemonConnected = false
        daemonStatusText = "guardd stopped"
        daemonHealthText = "Stopped by monitor."
        daemonStateLabel.stringValue = daemonStatusText
        daemonStateLabel.textColor = .tertiaryLabelColor
        updateInspector(currentSelectedEvent())
        statusLabel.stringValue = "Stopped managed guardd."
    }

    func utilityWindow(existing: NSWindow?, title: String, width: CGFloat, height: CGFloat) -> NSWindow {
        if let existing = existing {
            existing.title = title
            return existing
        }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: height),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        window.center()
        return window
    }

    func utilityRoot(in window: NSWindow) -> NSStackView {
        let content = NSVisualEffectView()
        content.material = .contentBackground
        content.blendingMode = .behindWindow
        content.state = .active
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .width
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 16, right: 18)
        root.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(root)
        window.contentView = content
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor),
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])
        return root
    }

    func utilityTitle(_ title: String, subtitle: String) -> NSView {
        let titleLabel = label(title, size: 20, weight: .bold)
        let subtitleLabel = label(subtitle, size: 12, weight: .regular, color: .secondaryLabelColor)
        subtitleLabel.maximumNumberOfLines = 2
        subtitleLabel.lineBreakMode = .byWordWrapping
        let stack = NSStackView(views: [titleLabel, subtitleLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        return stack
    }

    @objc func previewTemplate(_ sender: Any?) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected to preview templates."
            return
        }
        let template = selectedTemplateName.isEmpty ? templateNames.first ?? "" : selectedTemplateName
        guard !template.isEmpty else {
            statusLabel.stringValue = "No template is available to preview."
            return
        }
        let profile = currentSelectedEvent()?.profile.isEmpty == false ? currentSelectedEvent()!.profile : selectedProfileName
        guard let preview = client.previewTemplate(template: template, profile: profile),
              let effective = preview["effective"] as? [String: Any],
              let summary = effective["summary"] as? [String: Any] else {
            statusLabel.stringValue = "Template preview failed."
            return
        }
        inspectorBodyLabel.stringValue = "Template: \(template)\nProfile: \(profile)\n\(summaryText(summary))"
        inspectorRuleLabel.stringValue = "Preview only; no profile file was written."
        statusLabel.stringValue = "Previewed \(template) for \(profile)."
    }

    @objc func applyTemplate(_ sender: Any?) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected to apply templates."
            return
        }
        let template = selectedTemplateName.isEmpty ? templateNames.first ?? "" : selectedTemplateName
        guard !template.isEmpty else {
            statusLabel.stringValue = "No template is available to apply."
            return
        }
        let profile = currentSelectedEvent()?.profile.isEmpty == false ? currentSelectedEvent()!.profile : selectedProfileName
        guard let response = client.applyTemplate(template: template, profile: profile) else {
            statusLabel.stringValue = "Template apply failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = "Applied \(template) to \(profile)."
            loadDaemonPolicyState(profile: profile)
            updateInspector(currentSelectedEvent())
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "Template apply failed."
        }
    }

    func selectedNetworkEvent() -> GuardMonitorEvent? {
        let row = tableView.selectedRow
        guard let event = activityRow(atVisibleRow: row)?.event else {
            statusLabel.stringValue = "Select a network event first."
            return nil
        }
        guard !event.host.isEmpty else {
            statusLabel.stringValue = "Selected event has no domain."
            return nil
        }
        guard daemonConnected || !event.projectDir.isEmpty else {
            statusLabel.stringValue = "Start guardd to write this rule to the global policy store."
            return nil
        }
        return event
    }

    func eventKey(_ event: GuardMonitorEvent) -> String {
        [event.id, event.at, event.type, event.profile, event.target, event.result, event.detail].joined(separator: "|")
    }

    func ruleReady(_ event: GuardMonitorEvent?) -> Bool {
        guard let event = event else { return false }
        return !event.host.isEmpty && (daemonConnected || !event.projectDir.isEmpty)
    }

    func updateActionButtons(_ event: GuardMonitorEvent?) {
        let canMutateRules = ruleReady(event)
        let hasNetworkSelection = event?.host.isEmpty == false
        allowDomainButton.isHidden = !hasNetworkSelection
        denyDomainButton.isHidden = !hasNetworkSelection
        allowOnceButton.isHidden = !hasNetworkSelection
        denyOnceButton.isHidden = !hasNetworkSelection
        allowDomainButton.isEnabled = canMutateRules
        denyDomainButton.isEnabled = canMutateRules
        let canResolveAlert = daemonConnected && event?.host.isEmpty == false
        allowOnceButton.isEnabled = canResolveAlert
        denyOnceButton.isEnabled = canResolveAlert
        startDaemonButton.isEnabled = managedDaemon == nil
        stopDaemonButton.isEnabled = managedDaemon != nil
        enableTLSButton.isEnabled = daemonConnected
        disableTLSButton.isEnabled = daemonConnected
        generateTLSCAButton.isEnabled = daemonConnected
        rotateTLSCAButton.isEnabled = daemonConnected
        revokeTLSCAButton.isEnabled = daemonConnected
        openRulesWindowButton.isEnabled = daemonConnected
        previewTemplateButton.isEnabled = daemonConnected && !templateNames.isEmpty
        applyTemplateButton.isEnabled = daemonConnected && !templateNames.isEmpty
    }

    func setInspectorControlMode(_ tab: MonitorInspectorTab) {
        let settingsMode = tab == .settings
        monitorTableContainer?.isHidden = settingsMode
        inspectorWidthConstraint?.isActive = !settingsMode
        inspectorControlStack.isHidden = tab == .events || tab == .settings
        advancedActionStack.isHidden = tab != .settings && tab != .templates
        profilePopup.superview?.isHidden = tab != .rules && tab != .templates
        templatePopup.superview?.isHidden = tab != .templates
        ruleSearchField.isHidden = tab != .rules
        ruleFilterControl.isHidden = tab != .rules
        ruleRowsScroll.isHidden = tab != .rules
        templateRowsScroll.isHidden = tab != .templates
        startDaemonButton.isHidden = tab != .settings
        stopDaemonButton.isHidden = tab != .settings
        enableTLSButton.isHidden = tab != .settings
        disableTLSButton.isHidden = tab != .settings
        generateTLSCAButton.isHidden = tab != .settings
        rotateTLSCAButton.isHidden = tab != .settings
        revokeTLSCAButton.isHidden = tab != .settings
        syncExtensionButton.isHidden = tab != .settings
        invalidateExtensionButton.isHidden = tab != .settings
        previewTemplateButton.isHidden = tab != .templates
        applyTemplateButton.isHidden = tab != .templates
        window?.contentView?.layoutSubtreeIfNeeded()
    }

    func updateProfileMenu() {
        let current = selectedProfileName.isEmpty ? "guard" : selectedProfileName
        profilePopup.removeAllItems()
        let names = Array(Set(profileNames + [current, config.profile, "guard"])).filter { !$0.isEmpty }.sorted()
        profileNames = names
        profilePopup.addItems(withTitles: names)
        profilePopup.selectItem(withTitle: current)
    }

    func updateTemplateMenu() {
        templatePopup.removeAllItems()
        if templateNames.isEmpty {
            templatePopup.addItem(withTitle: "No templates")
            templatePopup.isEnabled = false
            return
        }
        templatePopup.isEnabled = true
        templatePopup.addItems(withTitles: templateNames)
        templatePopup.selectItem(withTitle: selectedTemplateName.isEmpty ? templateNames[0] : selectedTemplateName)
    }

    func clearRows(_ stack: NSStackView) {
        for view in stack.arrangedSubviews {
            stack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
    }

    func renderRuleRows() {
        clearRows(ruleRowsStack)
        let search = ruleSearchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let filter = ruleFilterControl.selectedSegment
        let filtered = ruleRows.filter { row in
            let matchesSearch = search.isEmpty || [row.kind, row.action, row.scope, row.detail, row.source]
                .joined(separator: " ")
                .lowercased()
                .contains(search)
            let matchesFilter: Bool
            switch filter {
            case 1: matchesFilter = row.action == "allow"
            case 2: matchesFilter = row.action == "deny"
            case 3: matchesFilter = row.kind == "HTTP"
            case 4: matchesFilter = !row.enabled
            default: matchesFilter = true
            }
            return matchesSearch && matchesFilter
        }

        if filtered.isEmpty {
            renderedRuleRows = []
            ruleRowsStack.addArrangedSubview(emptyRow("No matching rules"))
            return
        }
        renderedRuleRows = Array(filtered.prefix(60))
        for (index, row) in renderedRuleRows.enumerated() {
            ruleRowsStack.addArrangedSubview(ruleRowView(row, index: index))
        }
        if filtered.count > 60 {
            ruleRowsStack.addArrangedSubview(emptyRow("+ \(filtered.count - 60) more rules"))
        }
    }

    func renderTemplateRows() {
        clearRows(templateRowsStack)
        if templateRows.isEmpty {
            templateRowsStack.addArrangedSubview(emptyRow(templatesSummaryText))
            return
        }
        for row in templateRows.prefix(40) {
            templateRowsStack.addArrangedSubview(templateRowView(row))
        }
    }

    func emptyRow(_ text: String) -> NSView {
        let label = label(text, size: 12, weight: .regular, color: .tertiaryLabelColor)
        label.maximumNumberOfLines = 2
        return label
    }

    func ruleRowView(_ row: MonitorRuleRow, index: Int) -> NSView {
        let container = CardView(fill: NSColor.controlBackgroundColor.withAlphaComponent(0.5), border: NSColor.separatorColor.withAlphaComponent(0.18))
        container.layer?.cornerRadius = 7
        container.layer?.borderWidth = 0.5
        let stack = paddedStack(in: container, inset: 7)
        stack.alignment = .width
        stack.spacing = 5

        let top = NSStackView()
        top.orientation = .horizontal
        top.alignment = .centerY
        top.spacing = 6

        let enabled = NSButton(checkboxWithTitle: "", target: nil, action: nil)
        enabled.state = row.enabled ? .on : .off
        enabled.isEnabled = false
        top.addArrangedSubview(enabled)
        top.addArrangedSubview(pill(row.action.uppercased(), color: row.action == "deny" ? .systemRed : .systemGreen))
        top.addArrangedSubview(pill(row.kind, color: row.kind == "HTTP" ? .systemPurple : .systemBlue))
        let risk = ruleRisk(row)
        top.addArrangedSubview(pill(risk.label, color: risk.color))

        let scope = label(row.scope, size: 12, weight: .semibold)
        scope.lineBreakMode = .byTruncatingMiddle
        scope.setContentHuggingPriority(.defaultLow, for: .horizontal)
        top.addArrangedSubview(scope)

        let toggle = NSButton(title: row.enabled ? "Disable" : "Enable", target: self, action: #selector(toggleRuleRow(_:)))
        toggle.bezelStyle = .rounded
        toggle.controlSize = .small
        toggle.tag = index
        top.addArrangedSubview(toggle)

        let remove = NSButton(title: "Delete", target: self, action: #selector(deleteRuleRow(_:)))
        remove.bezelStyle = .rounded
        remove.controlSize = .small
        remove.tag = index
        top.addArrangedSubview(remove)

        stack.addArrangedSubview(top)

        let details = label(row.detail.isEmpty ? row.source : "\(row.detail) · \(row.source)", size: 10.5, weight: .regular, color: .secondaryLabelColor)
        details.maximumNumberOfLines = 2
        details.lineBreakMode = .byTruncatingMiddle
        stack.addArrangedSubview(details)
        return container
    }

    func ruleRisk(_ row: MonitorRuleRow) -> (label: String, color: NSColor) {
        if !row.enabled {
            return ("OFF", .secondaryLabelColor)
        }
        if row.action == "deny" {
            return ("BLOCK", .systemRed)
        }
        if row.kind == "HTTP" && row.detail.localizedCaseInsensitiveContains("All paths") {
            return ("BROAD", .systemOrange)
        }
        if row.scope.contains("*") || row.scope.localizedCaseInsensitiveContains("any") {
            return ("BROAD", .systemOrange)
        }
        if row.kind == "HTTP" {
            return ("PATH", .systemGreen)
        }
        return ("HOST", .systemBlue)
    }

    @objc func toggleRuleRow(_ sender: NSButton) {
        mutateRuleRow(at: sender.tag, action: renderedRuleRows[safe: sender.tag]?.enabled == true ? "disable" : "enable")
    }

    @objc func deleteRuleRow(_ sender: NSButton) {
        mutateRuleRow(at: sender.tag, action: "remove")
    }

    func mutateRuleRow(at index: Int, action: String?) {
        guard let action = action,
              index >= 0,
              index < renderedRuleRows.count,
              daemonConnected,
              let client = daemonClient else {
            statusLabel.stringValue = "Connect guardd before editing rules."
            return
        }
        let row = renderedRuleRows[index]
        guard let response = client.mutateRule(
            profile: selectedProfileName.isEmpty ? "guard" : selectedProfileName,
            action: action,
            field: row.field,
            value: row.value,
            disabled: action == "disable"
        ) else {
            statusLabel.stringValue = "Rule update failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = "\(action.capitalized) \(row.scope)."
            loadDaemonPolicyState(profile: selectedProfileName.isEmpty ? "guard" : selectedProfileName)
            updateInspector(currentSelectedEvent())
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "Rule update failed."
        }
    }

    func didMutateRules(profile: String) {
        loadDaemonPolicyState(profile: profile)
        updateInspector(currentSelectedEvent())
    }

    func templateRowView(_ row: MonitorTemplateRow) -> NSView {
        let button = NSButton(title: row.name, target: self, action: #selector(selectTemplateRow(_:)))
        button.isBordered = false
        button.alignment = .left
        let weight: NSFont.Weight = row.name == selectedTemplateName ? .semibold : .regular
        button.font = NSFont.systemFont(ofSize: 12, weight: weight)
        button.contentTintColor = row.name == selectedTemplateName ? .systemBlue : .labelColor

        let description = label(row.description.isEmpty ? row.detail : row.description, size: 10.5, weight: .regular, color: .secondaryLabelColor)
        description.maximumNumberOfLines = 2
        let stack = NSStackView(views: [button, description])
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 1

        let container = CardView(fill: NSColor.controlBackgroundColor.withAlphaComponent(0.44), border: NSColor.separatorColor.withAlphaComponent(0.16))
        container.layer?.cornerRadius = 7
        container.layer?.borderWidth = 0.5
        let padded = paddedStack(in: container, inset: 7)
        padded.alignment = .width
        padded.addArrangedSubview(stack)
        return container
    }

    @objc func selectTemplateRow(_ sender: NSButton) {
        selectedTemplateName = sender.title
        updateTemplateMenu()
        renderTemplateRows()
        updateInspector(currentSelectedEvent())
    }

    func pill(_ text: String, color: NSColor) -> NSView {
        let field = label(text, size: 9.5, weight: .bold, color: color)
        field.alignment = .center
        field.maximumNumberOfLines = 1
        field.translatesAutoresizingMaskIntoConstraints = false
        field.widthAnchor.constraint(greaterThanOrEqualToConstant: 38).isActive = true
        return field
    }

    func updateInspector(_ event: GuardMonitorEvent?) {
        let tab = selectedInspectorTab()
        setInspectorControlMode(tab)
        inspectorWidthConstraint?.constant = event == nil && tab == .events ? 310 : 340
        inspectorSummaryStack.isHidden = true
        inspectorBodyLabel.isHidden = false
        inspectorRuleLabel.isHidden = false
        inspectorNoteLabel.isHidden = false
        inspectorHelpLabel.isHidden = false
        inspectorTitleLabel.isHidden = false
        if selectedInspectorTab() == .settings {
            inspectorHelpLabel.stringValue = "Settings"
            inspectorTitleLabel.stringValue = "Monitor Status"
            inspectorBodyLabel.stringValue = settingsBodyText()
            inspectorRuleLabel.stringValue = "Daemon lifecycle: start uses the selected event project when available, otherwise Guard's global app-support config."
            inspectorNoteLabel.stringValue = "TLS trust actions manage only local guardd CA files; Guard never installs a globally trusted CA."
            updateActionButtons(event)
            return
        }

        if selectedInspectorTab() == .rules {
            inspectorHelpLabel.stringValue = "Rules"
            inspectorTitleLabel.stringValue = event?.target.isEmpty == false ? event?.target ?? "No event selected" : "No event selected"
            if let event = event {
                inspectorBodyLabel.stringValue = [
                    "Profile: \(event.profile.isEmpty ? "guard" : event.profile)",
                    "Profile risk: \(profileRiskLabel)",
                    "Destination: \(event.host.isEmpty ? "none" : event.host)",
                    "Project: \(event.projectDir.isEmpty ? "not recorded" : event.projectDir)",
                    "Loaded rules: \(profileSummaryText)",
                    profileRulesText
                ].joined(separator: "\n")
            } else {
                inspectorBodyLabel.stringValue = [
                    onboardingText(),
                    "Profile risk: \(profileRiskLabel)",
                    "Loaded rules: \(profileSummaryText)",
                    profileRulesText
                ].joined(separator: "\n")
            }
            if ruleReady(event), let event = event {
                inspectorRuleLabel.stringValue = "Available actions: allow or deny \(event.host) in the selected profile."
                inspectorNoteLabel.stringValue = daemonConnected ? "Actions update the selected profile through guardd." : "Actions update the selected profile from the event project directory."
            } else {
                inspectorRuleLabel.stringValue = "Rule actions need a selected event with a destination host."
                inspectorNoteLabel.stringValue = daemonConnected ? "guardd will write profile changes to its configured policy store." : "Start guardd to use the global policy store, or select an event with a project directory for CLI fallback."
            }
            updateProfileMenu()
            renderRuleRows()
            updateActionButtons(event)
            return
        }

        if selectedInspectorTab() == .templates {
            inspectorHelpLabel.stringValue = "Templates"
            inspectorTitleLabel.stringValue = selectedTemplateName.isEmpty ? "Available Templates" : selectedTemplateName
            inspectorBodyLabel.stringValue = templatesBodyText()
            inspectorRuleLabel.stringValue = daemonConnected
                ? "Preview or apply the selected template to the selected profile."
                : "Connect or start guardd before previewing templates."
            inspectorNoteLabel.stringValue = "Template preview is read-only; apply writes through guardd."
            updateProfileMenu()
            updateTemplateMenu()
            renderTemplateRows()
            updateActionButtons(event)
            return
        }

        inspectorHelpLabel.stringValue = "Activity Details"
        inspectorNoteLabel.stringValue = "Actions update the selected profile from the event project directory."
        guard let event = event else {
            inspectorHelpLabel.stringValue = "Live Monitor"
            inspectorTitleLabel.stringValue = monitorSummaryTitle()
            renderMonitorSummaryPanel()
            inspectorSummaryStack.isHidden = false
            inspectorBodyLabel.isHidden = true
            inspectorBodyLabel.stringValue = ""
            inspectorRuleLabel.isHidden = true
            inspectorNoteLabel.isHidden = true
            inspectorRuleLabel.stringValue = monitorSummaryRuleText()
            inspectorNoteLabel.stringValue = ""
            if !activityRows.isEmpty, tableView.selectedRow < 0 {
                inspectorRuleLabel.isHidden = false
                inspectorRuleLabel.stringValue = "Select an app, process, destination, or policy row to inspect exact scope and available actions."
            }
            updateActionButtons(nil)
            return
        }

        inspectorTitleLabel.stringValue = detailTitle(for: event)
        renderEventDetailsPanel(event)
        inspectorSummaryStack.isHidden = false
        inspectorBodyLabel.isHidden = true
        inspectorBodyLabel.stringValue = ""
        inspectorRuleLabel.isHidden = true
        inspectorNoteLabel.isHidden = true

        if event.type == "guard.alert.pending" && !event.id.isEmpty {
            inspectorRuleLabel.stringValue = daemonConnected
                ? "Pending alert: choose Allow Once or Deny Once to resolve this queued decision."
                : "Pending alert resolution requires guardd."
        } else if ruleReady(event) {
            inspectorRuleLabel.stringValue = daemonConnected
                ? "Rule action: add \(event.host) to the selected profile through guardd."
                : "Rule action: add \(event.host) to the selected profile from \(event.projectDir)."
        } else if event.host.isEmpty {
            inspectorRuleLabel.stringValue = "Rule action: unavailable because this event has no destination host."
        } else {
            inspectorRuleLabel.stringValue = "Rule action: start guardd to save this decision in the global policy store."
        }
        updateActionButtons(event)
    }

    func humanizeStatus(_ value: String) -> String {
        switch value {
        case "pending": return "pending review"
        case "resolved": return "resolved"
        case "active": return "active"
        default: return value.replacingOccurrences(of: "_", with: " ")
        }
    }

    func humanizeEventType(_ value: String) -> String {
        switch value {
        case "network.decision": return "network decision"
        case "process.started": return "command started"
        case "process.exited": return "command finished"
        case "sandbox.profile_written": return "sandbox applied"
        case "proxy.started": return "proxy listeners ready"
        case "guard.alert.pending": return "alert pending"
        case "guard.alert.resolved": return "alert resolved"
        default: return value.replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: ".", with: " ")
        }
    }

    func ruleActionText(for event: GuardMonitorEvent) -> String {
        if event.type == "guard.alert.pending" && !event.id.isEmpty {
            return daemonConnected
                ? "Choose Allow Once or Deny Once to resolve this pending alert."
                : "Connect guardd before resolving this pending alert."
        }
        if ruleReady(event) {
            if daemonConnected {
                return "Allow Domain adds \(event.host) to the selected guardd profile. Deny Domain records it as blocked."
            }
            return "Allow Domain adds \(event.host) to the selected profile from \(event.projectDir). Deny Domain records it as blocked."
        }
        if event.host.isEmpty {
            return "No destination host is attached to this event, so no domain rule can be created."
        }
        return "Start guardd to save this decision in the global policy store."
    }

    func onboardingText() -> String {
        if daemonConnected {
            return "Select a traffic row to inspect the destination, matching rule, and profile actions."
        }
        return "Start or connect guardd to edit global rules, preview templates, sync NetworkExtension policy, and view live profile state."
    }

    func monitorSummaryTitle() -> String {
        let eventApps = Set(events.map { appLabel(for: $0) }).count
        let visibleApps = Set(activityRows.filter { $0.kind == "app" }.map { $0.app }).count
        let apps = max(eventApps, visibleApps)
        let eventDomains = Set(events.compactMap { $0.host.isEmpty ? nil : $0.host }).count
        let visibleDomains = Set(activityRows.filter { $0.kind == "destination" }.map { $0.app }).count
        let domains = max(eventDomains, visibleDomains)
        return "\(apps) app\(apps == 1 ? "" : "s"), \(domains) destination\(domains == 1 ? "" : "s")"
    }

    func monitorSummaryText() -> String {
        let network = events.filter { isNetworkActivity($0) }
        let fileEvents = events.filter { isFileActivity($0) }
        let pending = events.filter { $0.type == "guard.alert.pending" || $0.status == "pending" }.count
        let topApps = topCounts(events.map { appLabel(for: $0) } + activityRows.filter { $0.kind == "app" }.map { $0.app }, limit: 4)
        let topHosts = topCounts(events.compactMap { $0.host.isEmpty ? nil : $0.host } + activityRows.filter { $0.kind == "destination" }.map { $0.app }, limit: 4)
        return [
            "Connections: \(network.count)",
            "Denied: \(recentDeniedCount)",
            "Pending alerts: \(max(pendingAlertCount, pending))",
            "Filesystem/sandbox: \(fileEvents.count)",
            "",
            "Top Apps",
            topApps.isEmpty ? "None yet" : topApps.joined(separator: "\n"),
            "",
            "Top Destinations",
            topHosts.isEmpty ? "None yet" : topHosts.joined(separator: "\n")
        ].joined(separator: "\n")
    }

    func monitorSummaryRuleText() -> String {
        if !daemonConnected {
            return "guardd is offline; the monitor is showing local JSONL events and rule editing is limited to events with a recorded project directory."
        }
        if pendingAlertCount > 0 {
            return "\(pendingAlertCount) pending alert\(pendingAlertCount == 1 ? "" : "s") need a decision."
        }
        return "guardd is connected. Pick a destination row to allow, deny, or review the matching profile."
    }

    func detailTitle(for event: GuardMonitorEvent) -> String {
        if !event.host.isEmpty {
            let verb = event.result == "deny" ? "Blocked" : "Allowed"
            return "\(verb) \(hostPortLabel(for: event))"
        }
        if event.type == "process.started" { return "Started \(commandDisplay(event.command))" }
        if event.type == "process.exited" {
            return event.result == "exit 0" ? "Finished \(commandDisplay(event.command))" : "Command exited"
        }
        if event.type == "sandbox.profile_written" { return "Sandbox Profile Applied" }
        if event.type == "proxy.started" { return "Proxy Ready" }
        return activityLabel(for: event)
    }

    func detailBody(for event: GuardMonitorEvent) -> String {
        var sections: [String] = []
        sections.append([
            "What happened",
            activityLabel(for: event),
            event.result.isEmpty ? nil : "Outcome: \(decisionLabel(for: event))"
        ].compactMap { $0 }.joined(separator: "\n"))

        let scopeLines = [
            "Scope",
            "App: \(appLabel(for: event))",
            event.host.isEmpty ? nil : "Destination: \(hostPortLabel(for: event))",
            event.command.isEmpty ? nil : "Command: \(event.command)",
            event.projectDir.isEmpty ? nil : "Project: \(event.projectDir)"
        ].compactMap { $0 }
        sections.append(scopeLines.joined(separator: "\n"))

        let policyLines = [
            "Policy",
            "Profile: \(event.profile.isEmpty ? "guard" : event.profile)",
            "Risk: \(profileRiskLabel)",
            event.detail.isEmpty ? nil : "Reason: \(humanDecisionReason(event.detail, fallback: event.detail))",
            event.status.isEmpty ? nil : "Alert: \(event.status)",
            event.expiresAt.isEmpty ? nil : "Expires: \(event.expiresAt)"
        ].compactMap { $0 }
        sections.append(policyLines.joined(separator: "\n"))

        let technicalLines = [
            "Technical",
            "Time: \(event.at.isEmpty ? "unknown" : event.at)",
            "Event: \(event.type)",
            event.detail.isEmpty ? nil : "Raw detail: \(event.detail)"
        ].compactMap { $0 }
        sections.append(technicalLines.joined(separator: "\n"))
        return sections.joined(separator: "\n\n")
    }

    func topCounts(_ values: [String], limit: Int) -> [String] {
        var counts: [String: Int] = [:]
        for value in values where !value.isEmpty && value != "-" {
            counts[value, default: 0] += 1
        }
        return counts
            .sorted { lhs, rhs in lhs.value == rhs.value ? lhs.key < rhs.key : lhs.value > rhs.value }
            .prefix(limit)
            .map { "\($0.key)  \($0.value)" }
    }

    func addSelectedDomain(to field: String) {
        guard let event = selectedNetworkEvent() else { return }
        if field == "network.allowedDomains" {
            setExclusiveRuleValue(event.host, event: event, allowField: "network.allowedDomains", denyField: "network.deniedDomains", allow: true)
        } else if field == "network.deniedDomains" {
            setExclusiveRuleValue(event.host, event: event, allowField: "network.allowedDomains", denyField: "network.deniedDomains", allow: false)
        } else {
            addRuleValue(event.host, event: event, to: field)
        }
    }

    func setExclusiveRuleValue(_ value: String, event: GuardMonitorEvent, allowField: String, denyField: String, allow: Bool) {
        guard !value.isEmpty else { return }
        if allow {
            removeRuleValue(value, event: event, from: denyField, quietIfMissing: true)
            addRuleValue(value, event: event, to: allowField)
        } else {
            removeRuleValue(value, event: event, from: allowField, quietIfMissing: true)
            addRuleValue(value, event: event, to: denyField)
        }
    }

    func addRuleValue(_ value: String, event: GuardMonitorEvent, to field: String) {
        guard !value.isEmpty else { return }
        let profile = event.profile.isEmpty ? "guard" : event.profile
        if daemonConnected, let response = daemonClient?.postRule(profile: profile, field: field, value: value, ifMatch: profileVersionText) {
            if (200..<300).contains(response.statusCode) {
                statusLabel.stringValue = "Added \(value) to \(field) via guardd."
                loadDaemonPolicyState(profile: profile)
                updateInspector(event)
                reloadEvents(nil)
                return
            }
            if response.statusCode == 412 {
                loadDaemonPolicyState(profile: profile)
                updateInspector(event)
                statusLabel.stringValue = "Profile changed on disk. Reloaded latest profile; retry the rule action."
                return
            }
            if response.statusCode != 401 && response.statusCode != 403 {
                statusLabel.stringValue = daemonErrorMessage(response) ?? "guardd rule update failed; trying guard CLI."
            }
        }

        guard !event.projectDir.isEmpty else {
            statusLabel.stringValue = "guardd rule update unavailable and no project directory was recorded for CLI fallback."
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: config.guardPath)
        process.currentDirectoryURL = URL(fileURLWithPath: event.projectDir)
        process.arguments = [
            "profile",
            "add",
            "--profile",
            profile,
            field,
            value
        ]
        let stderr = Pipe()
        process.standardError = stderr
        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                statusLabel.stringValue = "Added \(value) to \(field) via guard CLI."
                projectSummaryCache.removeAll()
                reloadEvents(nil)
            } else {
                let data = stderr.fileHandleForReading.readDataToEndOfFile()
                let message = String(data: data, encoding: .utf8) ?? "Rule update failed."
                statusLabel.stringValue = message.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            statusLabel.stringValue = error.localizedDescription
        }
    }

    func removeRuleValue(_ value: String, event: GuardMonitorEvent, from field: String, quietIfMissing: Bool = false) {
        guard !value.isEmpty else { return }
        let profile = event.profile.isEmpty ? "guard" : event.profile
        if daemonConnected, let response = daemonClient?.mutateRule(profile: profile, action: "remove", field: field, value: value, ifMatch: profileVersionText) {
            if (200..<300).contains(response.statusCode) {
                statusLabel.stringValue = "Removed \(value) from \(field)."
                loadDaemonPolicyState(profile: profile)
                reloadEvents(nil)
                return
            }
            if response.statusCode == 412 {
                loadDaemonPolicyState(profile: profile)
                statusLabel.stringValue = "Profile changed on disk. Reloaded latest profile; retry the rule action."
                return
            }
            if quietIfMissing && response.statusCode == 404 {
                return
            }
            statusLabel.stringValue = daemonErrorMessage(response) ?? "Rule removal failed."
            return
        }
        guard !event.projectDir.isEmpty else {
            if !quietIfMissing {
                statusLabel.stringValue = "guardd must be connected to remove profile rules."
            }
            return
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: config.guardPath)
        process.currentDirectoryURL = URL(fileURLWithPath: event.projectDir)
        process.arguments = [
            "profile",
            "remove",
            "--profile",
            profile,
            field,
            value
        ]
        let stderr = Pipe()
        process.standardError = stderr
        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                if !quietIfMissing {
                    statusLabel.stringValue = "Removed \(value) from \(field) via guard CLI."
                }
                projectSummaryCache.removeAll()
                reloadEvents(nil)
            } else if !quietIfMissing {
                let data = stderr.fileHandleForReading.readDataToEndOfFile()
                let message = String(data: data, encoding: .utf8) ?? "Rule removal failed."
                statusLabel.stringValue = message.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            if !quietIfMissing {
                statusLabel.stringValue = error.localizedDescription
            }
        }
    }

    func postSelectedAlertDecision(action: String, duration: String) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected for alert decisions."
            return
        }
        guard let event = selectedNetworkEvent() else { return }
        let profile = event.profile.isEmpty ? selectedProfileName : event.profile
        let port = Int(event.target.split(separator: ":").last ?? "") ?? 0
        let response: GuardDaemonResponse?
        if event.type == "guard.alert.pending", !event.id.isEmpty {
            response = client.resolvePendingAlert(
                alertId: event.id,
                action: action,
                duration: duration,
                scope: "",
                ifMatch: duration == "forever" ? profileVersionText : nil
            )
        } else {
            response = client.postAlertDecision(
                profile: profile.isEmpty ? "guard" : profile,
                host: event.host,
                port: port,
                action: action,
                duration: duration,
                method: "",
                path: "",
                scope: "",
                launcherApp: event.launcherApp,
                launcherProcess: event.launcherProcess,
                launcherPid: event.launcherPid,
                parentChain: event.parentChain,
                ifMatch: duration == "forever" ? profileVersionText : nil
            )
        }
        guard let response else {
            statusLabel.stringValue = "Alert decision failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = event.type == "guard.alert.pending"
                ? "Resolved pending alert for \(event.host): \(action) \(duration)."
                : "\(action.capitalized) \(event.host) \(duration)."
            reloadEvents(nil)
        } else if response.statusCode == 412 {
            loadDaemonPolicyState(profile: profile)
            statusLabel.stringValue = "Profile changed on disk. Reloaded latest profile; retry alert action."
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "Alert decision failed."
        }
    }

    func selectedActivityRowForAction() -> MonitorActivityRow? {
        let row = tableView.clickedRow >= 0 ? tableView.clickedRow : tableView.selectedRow
        guard let activityRow = activityRow(atVisibleRow: row) else { return nil }
        if tableView.clickedRow >= 0 {
            tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        }
        return activityRow
    }

    @objc func revealSelectedProcessBinary(_ sender: Any?) {
        guard let path = selectedActivityRowForAction()?.event?.processPath, !path.isEmpty else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    @objc func hideSelectedConnection(_ sender: Any?) {
        guard let row = selectedActivityRowForAction() else { return }
        hiddenActivityRowKeys.insert(row.rowKey)
        filterMonitorRows(nil)
        statusLabel.stringValue = "Hidden \(row.app). Use Refresh to rebuild the visible list."
    }

    @objc func copySelectedHost(_ sender: Any?) {
        guard let event = selectedActivityRowForAction()?.event, !event.host.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(event.host, forType: .string)
        statusLabel.stringValue = "Copied \(event.host)."
    }

    @objc func removeSelectedDomainRules(_ sender: Any?) {
        guard let event = selectedActivityRowForAction()?.event, !event.host.isEmpty else { return }
        removeRuleValue(event.host, event: event, from: "network.allowedDomains")
        removeRuleValue(event.host, event: event, from: "network.deniedDomains")
    }

    func mutateTLS(enabled: Bool) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected to update TLS policy."
            return
        }
        let profile = currentSelectedEvent()?.profile.isEmpty == false ? currentSelectedEvent()!.profile : selectedProfileName
        guard let response = client.postTLS(profile: profile, enabled: enabled, ifMatch: profileVersionText) else {
            statusLabel.stringValue = "TLS policy update failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = enabled ? "Enabled TLS inspection for \(profile)." : "Disabled TLS inspection for \(profile)."
            loadDaemonPolicyState(profile: profile)
            updateInspector(currentSelectedEvent())
        } else if response.statusCode == 412 {
            loadDaemonPolicyState(profile: profile)
            updateInspector(currentSelectedEvent())
            statusLabel.stringValue = "Profile changed on disk. Reloaded latest profile; retry TLS change."
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "TLS policy update failed."
        }
    }

    func mutateTLSCA(action: String, success: String) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected to manage local TLS CA artifacts."
            return
        }
        guard let response = client.postTLSCA(action: action) else {
            statusLabel.stringValue = "TLS CA \(action) failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = success
            loadDaemonPolicyState(profile: selectedProfileName)
            updateInspector(currentSelectedEvent())
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "TLS CA \(action) failed."
        }
    }

    @objc func syncExtension(_ sender: Any?) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected to sync NetworkExtension policy."
            return
        }
        let profile = selectedProfileName.isEmpty ? "guard" : selectedProfileName
        guard let response = client.postExtensionSync(profile: profile) else {
            statusLabel.stringValue = "NetworkExtension sync failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = "Synced NetworkExtension policy for \(profile)."
            loadDaemonPolicyState(profile: profile)
            updateInspector(currentSelectedEvent())
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "NetworkExtension sync failed."
        }
    }

    @objc func invalidateExtension(_ sender: Any?) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "guardd must be connected to invalidate NetworkExtension sync."
            return
        }
        guard let response = client.invalidateExtensionSync() else {
            statusLabel.stringValue = "NetworkExtension invalidation failed."
            return
        }
        if (200..<300).contains(response.statusCode) {
            statusLabel.stringValue = "Invalidated NetworkExtension sync manifest."
            loadDaemonPolicyState(profile: selectedProfileName)
            updateInspector(currentSelectedEvent())
        } else {
            statusLabel.stringValue = daemonErrorMessage(response) ?? "NetworkExtension invalidation failed."
        }
    }

    @objc func openNetworkSettings(_ sender: Any?) {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension") {
            NSWorkspace.shared.open(url)
            return
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Library/PreferencePanes/Network.prefPane"))
    }

    @objc func addProjectFolder(_ sender: Any?) {
        guard daemonConnected, let client = daemonClient else {
            statusLabel.stringValue = "Start guardd before registering project folders."
            return
        }
        let panel = NSOpenPanel()
        panel.title = "Add Guard Project"
        panel.message = "Choose a project folder containing .guard/*.json."
        panel.prompt = "Add"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("code", isDirectory: true)
        let completion: (NSApplication.ModalResponse) -> Void = { [weak self] response in
            guard let self else { return }
            guard response == .OK, let url = panel.url else { return }
            guard FileManager.default.fileExists(atPath: url.appendingPathComponent(".guard", isDirectory: true).path) else {
                self.statusLabel.stringValue = "Selected folder has no .guard directory."
                return
            }
            guard let result = client.addProject(root: url.path) else {
                self.statusLabel.stringValue = "Failed to register project folder."
                return
            }
            if (200..<300).contains(result.statusCode) {
                self.statusLabel.stringValue = "Registered \(self.projectDisplayName(url.path)) as a known Guard project."
                self.reloadEvents(nil)
            } else {
                self.statusLabel.stringValue = self.daemonErrorMessage(result) ?? "Failed to register project folder."
            }
        }
        if let window {
            panel.beginSheetModal(for: window, completionHandler: completion)
        } else {
            completion(panel.runModal())
        }
    }

    @objc func reloadEvents(_ sender: Any?) {
        if sender is Timer {
            guard !fullRefreshInFlight, pendingAlertCount == 0 else { return }
        }
        fullRefreshInFlight = true
        defer { fullRefreshInFlight = false }
        let previousKey = selectedEventKey
        let previousRowKey = selectedActivityRowKey
        let loaded = loadEvents()
        events = Array(loaded.prefix(250))
        updateTrafficSummary()
        if managedDaemon?.isRunning == true && !daemonConnected {
            daemonStatusText = "guardd starting"
            daemonStateLabel.stringValue = daemonStatusText
            daemonStateLabel.textColor = .secondaryLabelColor
        }
        let eventProfiles = events.map { $0.profile.isEmpty ? "guard" : $0.profile }
        profileNames = Array(Set(profileNames + eventProfiles + [config.profile, "guard"])).filter { !$0.isEmpty }.sorted()
        updateProfileMenu()
        activityRows = buildActivityRows(from: filteredEventsForMonitor())
        suppressSelectionChange = true
        tableView.reloadData()
        restoreOutlineExpansion()
        resizeActivityColumns()
        resetActivityTableScrollOrigin()
        if let previousRowKey = previousRowKey, selectActivityRow(rowKey: previousRowKey) {
        } else if let previousKey = previousKey, let row = activityRows.first(where: { $0.event.map(eventKey) == previousKey }), selectActivityRow(rowKey: row.rowKey) {
        } else if selectFirstActivityRow() {
        } else {
            selectedEventKey = nil
            selectedActivityRowKey = nil
            tableView.deselectAll(nil)
        }
        suppressSelectionChange = false
        renderSelectedInspectorIfNeeded(force: sender != nil && !(sender is Timer))
        statusLabel.stringValue = "\(events.count) recent event\(events.count == 1 ? "" : "s") · \(daemonStatusText) · auto-refresh on"
        (NSApp.delegate as? GuardApplicationDelegate)?.statusController?.refresh()
    }

    @objc func focusSearch(_ sender: Any?) {
        if let toolbarSearchField {
            window?.makeFirstResponder(toolbarSearchField)
        } else {
            window?.makeFirstResponder(monitorSearchField)
        }
    }

    func rebuildActivityRows(keepSelection: Bool) {
        let previousKey = keepSelection ? selectedEventKey : nil
        let previousRowKey = keepSelection ? selectedActivityRowKey : nil
        activityRows = buildActivityRows(from: filteredEventsForMonitor())
        suppressSelectionChange = true
        tableView.reloadData()
        restoreOutlineExpansion()
        resizeActivityColumns()
        resetActivityTableScrollOrigin()
        if let previousRowKey = previousRowKey, selectActivityRow(rowKey: previousRowKey) {
        } else if let previousKey = previousKey, let row = activityRows.first(where: { $0.event.map(eventKey) == previousKey }), selectActivityRow(rowKey: row.rowKey) {
        } else if selectFirstActivityRow() {
        } else {
            selectedEventKey = nil
            selectedActivityRowKey = nil
            tableView.deselectAll(nil)
        }
        suppressSelectionChange = false
        renderSelectedInspectorIfNeeded(force: true)
    }

    func filteredEventsForMonitor() -> [GuardMonitorEvent] {
        let query = monitorSearchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let selectedFilter = monitorFilterControl.selectedSegment
        let cutoff = monitorTimeWindowMinutes.flatMap {
            Calendar.current.date(byAdding: .minute, value: -$0, to: Date())
        }
        return events.filter { event in
            let filterMatches: Bool
            switch selectedFilter {
            case 1:
                filterMatches = isNetworkActivity(event)
            case 2:
                filterMatches = event.result == "deny" || event.result == "denied"
            case 3:
                filterMatches = isFileActivity(event)
            case 4:
                filterMatches = event.type.hasPrefix("guard.alert.") || event.status == "pending"
            default:
                filterMatches = true
            }
            guard filterMatches else { return false }
            if let cutoff, let date = monitorEventDate(event.at), date < cutoff {
                return false
            }
            guard !query.isEmpty else { return true }
            return monitorEvent(event, matchesQuery: query)
        }
    }

    func monitorEvent(_ event: GuardMonitorEvent, matchesQuery query: String) -> Bool {
        let tokens = query
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
            .filter { !$0.isEmpty }
        guard !tokens.isEmpty else { return true }
        return tokens.allSatisfy { token in
            let parts = token.split(separator: ":", maxSplits: 1).map(String.init)
            if parts.count == 2 {
                return monitorScopedValue(parts[0], event: event).contains(parts[1])
            }
            let haystack = [
                appLabel(for: event),
                processLabel(for: event),
                commandDisplay(event.command),
                event.host,
                event.target,
                event.type,
                event.result,
                event.detail,
                event.profile,
                event.projectDir,
                event.processPath,
                event.launcherApp,
                event.launcherProcess,
                event.parentChain,
                event.bundleIdentifier,
                humanDecisionReason(event.detail, fallback: activityLabel(for: event))
            ].joined(separator: " ").lowercased()
            return haystack.contains(token)
        }
    }

    func monitorScopedValue(_ scope: String, event: GuardMonitorEvent) -> String {
        switch scope {
        case "app", "application":
            return appLabel(for: event).lowercased()
        case "process", "proc", "cmd", "command":
            return [
                processLabel(for: event),
                commandDisplay(event.command),
                event.processPath,
                event.launcherApp,
                event.launcherProcess,
                event.parentChain
            ].joined(separator: " ").lowercased()
        case "host", "domain", "destination", "dest":
            return [event.host, event.target].joined(separator: " ").lowercased()
        case "rule", "reason", "decision":
            return [event.result, event.detail, humanDecisionReason(event.detail, fallback: activityLabel(for: event))].joined(separator: " ").lowercased()
        case "path", "project", "file":
            return [event.projectDir, event.cwd, event.processPath, event.detail].joined(separator: " ").lowercased()
        case "profile":
            return event.profile.lowercased()
        case "type", "kind":
            return event.type.lowercased()
        default:
            return [
                appLabel(for: event),
                processLabel(for: event),
                event.host,
                event.target,
                event.type,
                event.result,
                event.detail,
                event.profile,
                event.projectDir,
                event.processPath,
                event.launcherApp,
                event.launcherProcess,
                event.parentChain
            ].joined(separator: " ").lowercased()
        }
    }

    func monitorEventDate(_ value: String) -> Date? {
        guard !value.isEmpty else { return nil }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = iso.date(from: value) {
            return date
        }
        iso.formatOptions = [.withInternetDateTime]
        return iso.date(from: value)
    }

    func updateTrafficSummary() {
        let networkEvents = events.filter { $0.type == "network.decision" }
        let proxyEvents = events.filter { $0.type == "proxy.started" }
        recentAllowedCount = networkEvents.filter { $0.result == "allow" }.count
        recentDeniedCount = networkEvents.filter { $0.result == "deny" }.count
        var counts: [String: Int] = [:]
        for event in networkEvents where !event.host.isEmpty {
            counts[event.host, default: 0] += 1
        }
        recentTopHost = counts.sorted { lhs, rhs in lhs.value == rhs.value ? lhs.key < rhs.key : lhs.value > rhs.value }.first?.key ?? "-"
        trafficSummaryLabel.stringValue = "\(recentAllowedCount) allowed · \(recentDeniedCount) denied · \(proxyEvents.count) proxy · \(pendingAlertCount) pending"
        footerAllowedRateLabel.stringValue = "allowed \(recentAllowedCount)"
        footerDeniedRateLabel.stringValue = "denied \(recentDeniedCount)"
        trafficSummaryLabel.textColor = pendingAlertCount > 0 || recentDeniedCount > 0 ? .systemOrange : .secondaryLabelColor
        focusTopHostButton.isEnabled = recentTopHost != "-"
        trafficSparkline.buckets = trafficBuckets(from: Array(networkEvents.reversed()))
        updateHeaderStatus()
    }

    func trafficBuckets(from networkEvents: [GuardMonitorEvent]) -> [(allowed: Int, denied: Int)] {
        guard !networkEvents.isEmpty else { return [] }
        let bucketSize = max(1, Int(ceil(Double(networkEvents.count) / 52.0)))
        var buckets: [(allowed: Int, denied: Int)] = []
        var allowed = 0
        var denied = 0
        for (index, event) in networkEvents.enumerated() {
            if event.result == "deny" {
                denied += 1
            } else if event.result == "allow" {
                allowed += 1
            }
            if (index + 1) % bucketSize == 0 {
                buckets.append((allowed, denied))
                allowed = 0
                denied = 0
            }
        }
        if allowed > 0 || denied > 0 {
            buckets.append((allowed, denied))
        }
        return Array(buckets.suffix(52))
    }

    func updateHeaderStatus() {
        riskStatusLabel.stringValue = profileRiskLabel
        riskStatusLabel.textColor = colorForRisk(profileRiskLabel)
        let active = ruleRows.filter { $0.enabled }.count
        let inactive = ruleRows.count - active
        ruleStatusLabel.stringValue = ruleRows.isEmpty ? "rules unavailable" : "\(active) rules on, \(inactive) off"
        ruleStatusLabel.textColor = ruleRows.isEmpty ? .secondaryLabelColor : .systemBlue
    }

    func colorForRisk(_ text: String) -> NSColor {
        let value = text.lowercased()
        if value.contains("critical") || value.contains("high") {
            return .systemRed
        }
        if value.contains("medium") || value.contains("unknown") {
            return .systemOrange
        }
        if value.contains("low") {
            return .systemGreen
        }
        return .secondaryLabelColor
    }

    func loadEvents() -> [GuardMonitorEvent] {
        if let daemonEvents = loadDaemonEvents() {
            return loadKnownProjectEvents() + daemonEvents
        }
        daemonConnected = false
        daemonStatusText = managedDaemon?.isRunning == true ? "guardd starting" : "guardd offline; showing local JSONL"
        pendingAlertCount = 0
        pendingAlertSummaryText = "Pending alerts unavailable until guardd is reachable."
        daemonStateLabel.stringValue = daemonStatusText
        daemonStateLabel.textColor = managedDaemon?.isRunning == true ? .secondaryLabelColor : .tertiaryLabelColor
        loadDaemonPolicyState(profile: config.profile)

        let path = eventLogPath()
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }
        return content
            .split(whereSeparator: \.isNewline)
            .compactMap { line in
                guard let data = String(line).data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data),
                      let json = object as? [String: Any] else {
                    return nil
                }
                return event(from: json)
            }
            .reversed()
    }

    func loadDaemonEvents() -> [GuardMonitorEvent]? {
        guard let client = daemonClient,
              let json = client.getJSON(path: "/events", queryItems: [URLQueryItem(name: "limit", value: "250")]),
              let rawEvents = json["events"] as? [[String: Any]] else {
            return nil
        }
        daemonConnected = true
        writeManagedDaemonConnection(url: client.baseURL.absoluteString, token: client.apiToken ?? "")
        daemonStatusText = managedDaemon == nil ? "guardd connected" : "guardd managed by monitor"
        daemonStateLabel.stringValue = daemonStatusText
        daemonStateLabel.textColor = .systemGreen
        return rawEvents.map { event(from: $0) }
    }

    func loadKnownProjectEvents() -> [GuardMonitorEvent] {
        guard let client = daemonClient,
              let json = client.getJSON(path: "/projects"),
              let projects = json["projects"] as? [[String: Any]] else {
            return []
        }
        return projects.flatMap { project -> [GuardMonitorEvent] in
            let root = project["root"] as? String ?? ""
            let label = project["label"] as? String ?? projectDisplayName(root)
            let profiles = project["profiles"] as? [[String: Any]] ?? []
            return profiles.map { profile in
                let name = profile["name"] as? String ?? "guard"
                let allowed = profile["allowedDomainsCount"].map { "\($0)" } ?? "0"
                let denied = profile["deniedDomainsCount"].map { "\($0)" } ?? "0"
                let description = profile["description"] as? String ?? ""
                return GuardMonitorEvent(
                    id: "project:\(root):\(name)",
                    at: "",
                    type: "guard.project.profile",
                    profile: name,
                    projectDir: root,
                    cwd: root,
                    runDir: "",
                    command: "\(label) \(name)",
                    processPath: profile["path"] as? String ?? "",
                    launcherApp: "",
                    launcherProcess: "",
                    launcherPid: 0,
                    parentChain: "",
                    pid: 0,
                    bundleIdentifier: "",
                    bytesSent: 0,
                    bytesReceived: 0,
                    host: "",
                    target: name,
                    result: "inactive",
                    detail: [description, "\(allowed) allowed domains", "\(denied) denied domains"].filter { !$0.isEmpty }.joined(separator: " · "),
                    status: "inactive",
                    expiresAt: "",
                    duration: "",
                    rulePersisted: false,
                    ruleId: ""
                )
            }
        }
    }

    func loadPendingAlertState(client: GuardDaemonClient) {
        applyPendingAlertState(client.pendingAlerts(limit: 20), client: client)
    }

    func applyPendingAlertState(_ pendingJSON: [String: Any]?, client: GuardDaemonClient) {
        guard let pendingJSON else {
            pendingAlertCount = 0
            pendingAlertSummaryText = "Pending alerts unavailable."
            return
        }
        pendingAlertCount = pendingJSON["pendingCount"] as? Int ?? 0
        let expired = pendingJSON["expiredCount"].map { "\($0)" } ?? "0"
        let alerts = pendingJSON["alerts"] as? [[String: Any]] ?? []
        let hostPreview = alerts.compactMap { $0["host"] as? String }.prefix(3).joined(separator: ", ")
        pendingAlertSummaryText = pendingAlertCount == 0
            ? "none pending, \(expired) expired"
            : "\(pendingAlertCount) pending\(hostPreview.isEmpty ? "" : ": \(hostPreview)")"
        presentNextPendingAlert(alerts, client: client)
    }

    @objc func pollPendingAlerts(_ sender: Any?) {
        guard daemonConnected, let client = daemonClient else { return }
        guard !pendingAlertPollInFlight else { return }
        pendingAlertPollInFlight = true
        DispatchQueue.global(qos: .userInteractive).async {
            let pending = client.pendingAlerts(limit: 8)
            DispatchQueue.main.async {
                self.pendingAlertPollInFlight = false
                self.applyPendingAlertState(pending, client: client)
                self.trafficSummaryLabel.stringValue = "\(self.recentAllowedCount) allowed · \(self.recentDeniedCount) denied · pending \(self.pendingAlertCount)"
                self.trafficSummaryLabel.textColor = self.pendingAlertCount > 0 || self.recentDeniedCount > 0 ? .systemOrange : .secondaryLabelColor
            }
        }
    }

    func writeManagedDaemonConnection(url: String, token: String) {
        let file = managedDaemonConnectionPath()
        let payload: [String: Any] = [
            "url": url,
            "token": token,
            "pid": managedDaemon?.processIdentifier ?? 0,
            "updatedAt": ISO8601DateFormatter().string(from: Date())
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]) else { return }
        try? FileManager.default.createDirectory(atPath: (file as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? data.write(to: URL(fileURLWithPath: file), options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file)
    }

    func removeManagedDaemonConnection() {
        try? FileManager.default.removeItem(atPath: managedDaemonConnectionPath())
    }

    func managedDaemonConnectionPath() -> String {
        let base = (eventLogPath() as NSString).deletingLastPathComponent
        return (base as NSString).appendingPathComponent("guardd-connection.json")
    }

    func presentNextPendingAlert(_ alerts: [[String: Any]], client: GuardDaemonClient) {
        guard let alert = alerts.first(where: { alert in
            let id = alert["id"] as? String ?? ""
            return !id.isEmpty && !presentedPendingAlertIds.contains(id)
        }) else { return }
        let id = alert["id"] as? String ?? ""
        presentedPendingAlertIds.insert(id)
        DispatchQueue.main.async {
            self.presentPendingAlert(alert, client: client)
        }
    }

    func presentPendingAlert(_ alert: [String: Any], client: GuardDaemonClient) {
        let id = alert["id"] as? String ?? ""
        guard !id.isEmpty else { return }
        let host = alert["host"] as? String ?? ""
        let method = alert["method"] as? String ?? ""
        let path = alert["path"] as? String ?? ""
        let port = Int("\(alert["port"] ?? 0)") ?? 0
        let profile = alert["profile"] as? String ?? selectedProfileName
        let command = alert["command"] as? String ?? "Guard run"
        let projectDir = alert["projectDir"] as? String ?? ""
        let runDir = alert["runDir"] as? String ?? ""
        let isHTTP = !method.isEmpty || !path.isEmpty
        let controller: GuardConnectionPromptController
        if isHTTP {
            controller = GuardConnectionPromptController(
                titleText: "HTTP Policy Request",
                actor: command,
                destination: "\(method.isEmpty ? "HTTP" : method) \(host)\(path)",
                context: "Choose the narrowest HTTP rule that fits this request.",
                scopeRows: [
                    ("Type", "HTTP request"),
                    ("TLS", "Inspected by iron-proxy for this guarded process"),
                    ("Host", host)
                ],
                detailRows: [
                    ("Host", host),
                    ("Method", method.isEmpty ? "GET" : method),
                    ("Path", path.isEmpty ? "/" : path),
                    ("Profile", profile),
                    ("Project", projectDir),
                    ("Run", runDir)
                ],
                actions: [("Deny", .deny, false), ("Allow", .allowExact, true)],
                scopeOptions: [
                    ("Exact method and path", .allowExact),
                    ("Path group", .allowPath),
                    ("Entire host: \(host)", .allowDomain)
                ],
                lifetimeOptions: promptLifetimeOptions(),
                editablePath: path.isEmpty ? "/" : path
            )
        } else {
            let parts = host.split(separator: ".")
            let wildcard = parts.count > 2 ? "*." + parts.suffix(parts.count - 2).joined(separator: ".") : "*.\(host)"
            controller = GuardConnectionPromptController(
                titleText: "Connection Request",
                actor: command,
                destination: "\(host)\(port > 0 ? ":\(port)" : "")",
                context: "Choose the narrowest network rule that fits this request.",
                scopeRows: [
                    ("Type", "Destination only"),
                    ("TLS", "Not inspected; path and query are not visible here"),
                    ("Profile", profile)
                ],
                detailRows: [
                    ("Host", host),
                    ("Port", port > 0 ? "\(port)" : "default"),
                    ("Visibility", "Host and port before TLS handshake"),
                    ("Project", projectDir),
                    ("Run", runDir)
                ],
                actions: [("Deny", .deny, false), ("Allow", .allowOnce, true)],
                scopeOptions: [
                    ("Exact host: \(host)", .allowDomain),
                    ("Subdomains: \(wildcard)", .allowPath)
                ],
                lifetimeOptions: promptLifetimeOptions()
            )
        }
        let choice = controller.run()
        let action = choice == .deny ? "deny" : "allow"
        let scope = alertScopeName(choice)
        _ = client.resolvePendingAlert(
            alertId: id,
            action: action,
            duration: controller.selectedDuration,
            scope: scope,
            ifMatch: controller.selectedDuration == "forever" ? profileVersionText : nil
        )
        reloadEvents(nil)
    }

    func alertScopeName(_ choice: GuardPromptChoice) -> String {
        switch choice {
        case .allowExact: return "exact"
        case .allowPath: return "path"
        case .allowDomain: return "domain"
        case .allowOnce: return "once"
        case .deny: return ""
        }
    }

    func loadDaemonPolicyState(profile: String) {
        guard daemonConnected, let client = daemonClient else {
            profileSummaryText = "Profile rules unavailable until guardd is reachable."
            templatesSummaryText = "Templates unavailable until guardd is reachable."
            tlsStateText = "TLS inspection unknown."
            tlsTrustText = "TLS trust diagnostics unavailable."
            tlsOnboardingText = "TLS onboarding unavailable until guardd is reachable."
            securityStatusText = "Security posture not checked."
            extensionSyncText = "NetworkExtension sync unavailable until guardd is reachable."
            ruleRows = []
            templateRows = []
            updateHeaderStatus()
            return
        }

        if let profileJSON = client.getJSON(path: "/profiles/\(profile.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? profile)") {
            profileSummaryText = summarizeProfile(profileJSON)
            selectedProfileName = profile
            profileVersionText = profileJSON["version"] as? String ?? ""
            profileRiskLabel = summarizeRisk(profileJSON)
            tlsStateText = summarizeTLS(profileJSON)
            profileRulesText = ruleBrowserText(profileJSON)
            ruleRows = extractRuleRows(profileJSON)
        } else {
            profileSummaryText = "Profile \(profile) not loaded from guardd."
            profileRulesText = "No profile rules loaded."
            profileVersionText = ""
            profileRiskLabel = "risk unknown"
            tlsStateText = "TLS inspection unknown."
            ruleRows = []
        }

        if let templatesJSON = client.getJSON(path: "/templates") {
            let previousTemplate = selectedTemplateName
            templatesSummaryText = summarizeTemplates(templatesJSON)
            templateNames = extractTemplateNames(templatesJSON)
            selectedTemplateName = templateNames.contains(previousTemplate) ? previousTemplate : templateNames.first ?? ""
            templateRows = extractTemplateRows(templatesJSON)
        } else {
            templatesSummaryText = "Template list not loaded from guardd."
            templateNames = []
            selectedTemplateName = ""
            templateRows = []
        }
        if let tlsJSON = client.getJSON(path: "/tls/status") {
            tlsTrustText = summarizeTLSTrust(tlsJSON)
            tlsOnboardingText = tlsTrustOnboarding(tlsJSON)
        } else {
            tlsTrustText = "TLS trust diagnostics unavailable."
            tlsOnboardingText = "TLS onboarding unavailable because /tls/status did not respond."
        }
        if let securityJSON = client.getJSON(path: "/security/status") {
            securityStatusText = summarizeSecurity(securityJSON)
        }
        if let syncJSON = client.getJSON(path: "/extension/sync") {
            extensionSyncText = summarizeExtensionSync(syncJSON)
        } else {
            extensionSyncText = "NetworkExtension sync status unavailable."
        }
        updateProfileMenu()
        updateTemplateMenu()
        updateHeaderStatus()
    }

    func summarizeProfile(_ json: [String: Any]) -> String {
        let config = json["config"] as? [String: Any] ?? json
        let network = config["network"] as? [String: Any] ?? [:]
        let allowed = network["allowedDomains"] as? [Any] ?? []
        let denied = network["deniedDomains"] as? [Any] ?? []
        let httpRules = network["httpRules"] as? [Any] ?? []
        let secrets = (network["secretInjection"] as? [Any] ?? network["secrets"] as? [Any]) ?? []
        let metadata = config["ruleMetadata"] as? [String: Any] ?? [:]
        let disabled = metadata.values.filter { value in
            guard let entry = value as? [String: Any] else { return false }
            return entry["disabled"] as? Bool == true
        }
        let source = json["source"] as? String ?? "profile"
        let version = json["shortHash"] as? String ?? ""
        return "\(source): \(allowed.count) allowed, \(denied.count) denied, \(httpRules.count) HTTP, \(secrets.count) secrets, \(disabled.count) disabled\(version.isEmpty ? "" : ", v\(version)")"
    }

    func summarizeRisk(_ json: [String: Any]) -> String {
        let config = json["config"] as? [String: Any] ?? json
        let metadata = config["metadata"] as? [String: Any] ?? [:]
        let risk = metadata["risk"] as? String ?? "unknown"
        let status = metadata["status"] as? String ?? json["source"] as? String ?? "profile"
        return "risk \(risk), \(status)"
    }

    func ruleBrowserText(_ json: [String: Any]) -> String {
        let config = json["config"] as? [String: Any] ?? json
        let network = config["network"] as? [String: Any] ?? [:]
        let allowed = (network["allowedDomains"] as? [String] ?? []).prefix(5).joined(separator: ", ")
        let denied = (network["deniedDomains"] as? [String] ?? []).prefix(5).joined(separator: ", ")
        let http = (network["httpRules"] as? [[String: Any]] ?? []).prefix(3).map { rule in
            let host = rule["host"] as? String ?? rule["cidr"] as? String ?? "unknown"
            let methods = (rule["methods"] as? [String] ?? []).joined(separator: "|")
            let paths = (rule["paths"] as? [String] ?? []).joined(separator: ",")
            return [host, methods, paths].filter { !$0.isEmpty }.joined(separator: " ")
        }.joined(separator: "; ")
        let secrets = ((network["secretInjection"] as? [[String: Any]] ?? network["secrets"] as? [[String: Any]]) ?? []).prefix(3).map { entry in
            let name = entry["name"] as? String
                ?? (entry["source"] as? [String: Any])?["var"] as? String
                ?? (entry["source"] as? [String: Any])?["secret_id"] as? String
                ?? "secret"
            let rules = entry["rules"] as? [[String: Any]] ?? []
            let host = entry["host"] as? String ?? rules.first?["host"] as? String ?? "scoped"
            let headers = (entry["matchHeaders"] as? [String] ?? entry["match_headers"] as? [String] ?? ["Authorization"]).joined(separator: ",")
            return "\(name) -> \(host) [\(headers)]"
        }.joined(separator: "; ")
        return [
            "Allowed: \(allowed.isEmpty ? "-" : allowed)",
            "Denied: \(denied.isEmpty ? "-" : denied)",
            "HTTP: \(http.isEmpty ? "-" : http)",
            "Secret injection: \(secrets.isEmpty ? "-" : secrets)"
        ].joined(separator: "\n")
    }

    func extractRuleRows(_ json: [String: Any]) -> [MonitorRuleRow] {
        let config = json["config"] as? [String: Any] ?? json
        let typedRules = (json["typedRules"] as? [[String: Any]] ?? []) + (json["temporaryRules"] as? [[String: Any]] ?? [])
        if !typedRules.isEmpty {
            return typedRules.map { typedRule in
                let layer = typedRule["layer"] as? String ?? ""
                let value = typedRule["value"] ?? typedRule["scope"] ?? ""
                let lifetime = typedRule["lifetime"] as? String ?? "persistent"
                let expiresAt = typedRule["expiresAt"] as? String ?? ""
                let approval = typedRule["approvalState"] as? String ?? "approved"
                let notes = typedRule["notes"] as? String ?? ""
                let detail = [
                    layer.isEmpty ? nil : layer,
                    lifetime.isEmpty ? nil : lifetime,
                    expiresAt.isEmpty ? nil : "expires \(shortTime(expiresAt))",
                    approval == "approved" ? nil : approval,
                    notes.isEmpty ? nil : notes
                ].compactMap { $0 }.joined(separator: " · ")
                return MonitorRuleRow(
                    id: typedRule["id"] as? String ?? "",
                    kind: ruleKindLabel(layer: layer, field: typedRule["field"] as? String ?? ""),
                    action: typedRule["action"] as? String ?? "allow",
                    scope: typedRule["scope"] as? String ?? "",
                    detail: detail.isEmpty ? "Typed Guard rule" : detail,
                    enabled: typedRule["enabled"] as? Bool ?? true,
                    source: typedRule["source"] as? String ?? "profile",
                    field: typedRule["field"] as? String ?? "",
                    value: value,
                    layer: layer,
                    lifetime: lifetime,
                    approvalState: approval,
                    notes: notes,
                    expiresAt: expiresAt
                )
            }.sorted { lhs, rhs in
                if lhs.enabled != rhs.enabled { return lhs.enabled && !rhs.enabled }
                if lhs.lifetime != rhs.lifetime { return lhs.lifetime < rhs.lifetime }
                return lhs.scope.localizedCaseInsensitiveCompare(rhs.scope) == .orderedAscending
            }
        }
        let network = config["network"] as? [String: Any] ?? [:]
        let filesystem = config["filesystem"] as? [String: Any] ?? [:]
        let metadata = config["ruleMetadata"] as? [String: Any] ?? [:]
        let source = json["source"] as? String ?? "profile"
        var rows: [MonitorRuleRow] = []

        for domain in network["allowedDomains"] as? [String] ?? [] {
            let meta = metadataFor(scope: domain, metadata: metadata)
            rows.append(MonitorRuleRow(
                kind: "Domain",
                action: "allow",
                scope: domain,
                detail: meta.detail.isEmpty ? "Proxy-routed domain allowlist" : meta.detail,
                enabled: meta.enabled,
                source: source,
                field: "network.allowedDomains",
                value: domain
            ))
        }

        for domain in network["deniedDomains"] as? [String] ?? [] {
            let meta = metadataFor(scope: domain, metadata: metadata)
            rows.append(MonitorRuleRow(
                kind: "Domain",
                action: "deny",
                scope: domain,
                detail: meta.detail.isEmpty ? "Explicit network deny rule" : meta.detail,
                enabled: meta.enabled,
                source: source,
                field: "network.deniedDomains",
                value: domain
            ))
        }

        for preset in network["deniedDomainPresets"] as? [String] ?? [] {
            rows.append(MonitorRuleRow(
                kind: "Domain",
                action: "deny",
                scope: preset,
                detail: "Deny preset; expands at policy evaluation time",
                enabled: true,
                source: source,
                field: "network.deniedDomainPresets",
                value: preset
            ))
        }

        for raw in network["allowedRawTcp"] as? [[String: Any]] ?? [] {
            let host = raw["host"] as? String ?? raw["ip"] as? String ?? "unknown"
            let port = raw["port"].map { "\($0)" } ?? "any"
            rows.append(MonitorRuleRow(
                kind: "Raw TCP",
                action: "allow",
                scope: "\(host):\(port)",
                detail: raw["resolveAtLaunch"] as? Bool == true ? "Resolved once when guarded run starts" : (raw["reason"] as? String ?? "Direct TCP exception"),
                enabled: true,
                source: source,
                field: "network.allowedRawTcp",
                value: raw
            ))
        }

        for rule in network["httpRules"] as? [[String: Any]] ?? [] {
            let host = rule["host"] as? String ?? rule["cidr"] as? String ?? "any host"
            let methods = (rule["methods"] as? [String] ?? []).joined(separator: ",")
            let paths = (rule["paths"] as? [String] ?? []).joined(separator: ",")
            let scope = [host, methods.isEmpty ? "" : methods].filter { !$0.isEmpty }.joined(separator: " ")
            let meta = metadataFor(scope: host, metadata: metadata)
            rows.append(MonitorRuleRow(
                kind: "HTTP",
                action: "allow",
                scope: scope,
                detail: paths.isEmpty ? "All paths" : "Paths: \(paths)",
                enabled: meta.enabled,
                source: source,
                field: "network.httpRules",
                value: rule
            ))
        }

        for entry in (network["secretInjection"] as? [[String: Any]] ?? network["secrets"] as? [[String: Any]] ?? []) {
            let sourceSpec = entry["source"] as? [String: Any] ?? [:]
            let name = entry["name"] as? String
                ?? sourceSpec["var"] as? String
                ?? sourceSpec["secret_id"] as? String
                ?? "secret"
            let rules = entry["rules"] as? [[String: Any]] ?? []
            let host = entry["host"] as? String ?? rules.first?["host"] as? String ?? "scoped request"
            let headers = (entry["matchHeaders"] as? [String] ?? entry["match_headers"] as? [String] ?? ["Authorization"]).joined(separator: ", ")
            rows.append(MonitorRuleRow(
                kind: "Secret",
                action: "inject",
                scope: host,
                detail: "\(name), headers: \(headers), value redacted",
                enabled: true,
                source: source,
                field: "network.secretInjection",
                value: entry
            ))
        }

        let filesystemFields: [(String, String, String, String)] = [
            ("filesystem.allowRead", "Filesystem", "allow", "Read"),
            ("filesystem.allowWrite", "Filesystem", "allow", "Write"),
            ("filesystem.denyRead", "Filesystem", "deny", "Deny read"),
            ("filesystem.denyWrite", "Filesystem", "deny", "Deny write")
        ]
        for (field, kind, action, detail) in filesystemFields {
            let key = field.split(separator: ".").last.map(String.init) ?? field
            for path in filesystem[key] as? [String] ?? [] {
                let meta = metadataFor(scope: path, metadata: metadata)
                rows.append(MonitorRuleRow(
                    kind: kind,
                    action: action,
                    scope: path,
                    detail: meta.detail.isEmpty ? detail : "\(detail), \(meta.detail)",
                    enabled: meta.enabled,
                    source: source,
                    field: field,
                    value: path
                ))
            }
        }

        for key in [
            "allowLocalBinding",
            "allowLoopbackConnections",
            "allowLoopbackHighPorts",
            "allowLoopbackListeningHighPorts"
        ] {
            if let enabled = network[key] as? Bool {
                rows.append(MonitorRuleRow(
                    kind: "Local Net",
                    action: enabled ? "allow" : "deny",
                    scope: key,
                    detail: enabled ? "Local networking enabled by profile" : "Local networking disabled by profile",
                    enabled: true,
                    source: source,
                    field: "network.\(key)",
                    value: enabled
                ))
            }
        }

        if let ports = network["allowLoopbackPorts"] as? [Int], !ports.isEmpty {
            rows.append(MonitorRuleRow(
                kind: "Local Net",
                action: "allow",
                scope: ports.map(String.init).joined(separator: ", "),
                detail: "Allowed loopback ports",
                enabled: true,
                source: source,
                field: "network.allowLoopbackPorts",
                value: ports
            ))
        }

        if let tls = network["tlsInspection"] as? [String: Any] {
            let enabled = tls["enabled"] as? Bool == true
            let mode = tls["mode"] as? String ?? (enabled ? "enabled" : "off")
            rows.append(MonitorRuleRow(
                kind: "TLS",
                action: enabled ? "allow" : "deny",
                scope: "TLS inspection",
                detail: "mode \(mode), CA \(tls["caScope"] as? String ?? "default")",
                enabled: true,
                source: source,
                field: "network.tlsInspection",
                value: tls
            ))
        }

        for (key, value) in metadata {
            guard let entry = value as? [String: Any],
                  entry["disabled"] as? Bool == true,
                  !rows.contains(where: { !$0.enabled && key.localizedCaseInsensitiveContains($0.scope) }) else {
                continue
            }
            rows.append(MonitorRuleRow(
                kind: "Rule",
                action: "allow",
                scope: key,
                detail: "Disabled by rule metadata",
                enabled: false,
                source: source,
                field: entry["field"] as? String ?? "network.allowedDomains",
                value: entry["value"] ?? key
            ))
        }

        return rows.sorted { lhs, rhs in
            if lhs.enabled != rhs.enabled { return lhs.enabled && !rhs.enabled }
            if lhs.action != rhs.action { return lhs.action < rhs.action }
            return lhs.scope.localizedCaseInsensitiveCompare(rhs.scope) == .orderedAscending
        }
    }

    func ruleKindLabel(layer: String, field: String) -> String {
        switch layer {
        case "http": return "HTTP"
        case "raw-tcp": return "Raw TCP"
        case "filesystem": return "Filesystem"
        case "destination": return "Domain"
        default:
            if field == "network.httpRules" { return "HTTP" }
            if field == "network.allowedRawTcp" { return "Raw TCP" }
            if field.hasPrefix("filesystem.") { return "Filesystem" }
            return "Rule"
        }
    }

    func metadataFor(scope: String, metadata: [String: Any]) -> (enabled: Bool, detail: String) {
        for (key, value) in metadata where key.localizedCaseInsensitiveContains(scope) || scope.localizedCaseInsensitiveContains(key) {
            guard let entry = value as? [String: Any] else { continue }
            let enabled = !(entry["disabled"] as? Bool ?? false)
            let note = entry["note"] as? String ?? entry["reason"] as? String ?? ""
            let approval = entry["approved"] as? Bool
            let approvalText = approval == nil ? "" : (approval == true ? "approved" : "unapproved")
            return (enabled, [note, approvalText].filter { !$0.isEmpty }.joined(separator: ", "))
        }
        return (true, "")
    }

    func summarizeTLS(_ json: [String: Any]) -> String {
        let config = json["config"] as? [String: Any] ?? json
        let network = config["network"] as? [String: Any] ?? [:]
        guard let tls = network["tlsInspection"] as? [String: Any] else {
            return "implicit default; enabled when using iron-proxy"
        }
        let enabled = tls["enabled"] as? Bool == true
        let mode = tls["mode"] as? String ?? (enabled ? "ephemeral-run-ca" : "off")
        let caScope = tls["caScope"] as? String ?? (enabled ? "guarded-process-env" : "none")
        return "\(enabled ? "enabled" : "disabled"), mode \(mode), CA \(caScope)"
    }

    func summarizeTLSTrust(_ json: [String: Any]) -> String {
        let ok = json["ok"] as? Bool == true
        let issued = json["issued"] as? [String: Any] ?? [:]
        let count = issued["count"].map { "\($0)" } ?? "0"
        let expired = issued["expiredCount"].map { "\($0)" } ?? "0"
        let ca = json["ca"] as? [String: Any] ?? [:]
        let lifecycle = ca["lifecycle"] as? String ?? "unknown"
        return "\(ok ? "ok" : "review"), CA \(lifecycle), \(count) host certs, \(expired) expired"
    }

    func tlsTrustOnboarding(_ json: [String: Any]) -> String {
        let ca = json["ca"] as? [String: Any] ?? [:]
        let paths = ca["paths"] as? [String: Any] ?? [:]
        let onboarding = json["onboarding"] as? [String: Any] ?? [:]
        let issued = json["issued"] as? [String: Any] ?? [:]
        let findings = json["findings"] as? [[String: Any]] ?? []
        let lifecycle = ca["lifecycle"] as? String ?? "unknown"
        let installGlobal = onboarding["installGlobalTrust"] as? Bool == true
        let envVars = (onboarding["environmentVariables"] as? [String] ?? []).prefix(5).joined(separator: ", ")
        let certificatePath = paths["certificatePath"] as? String ?? "not generated"
        let bundlePath = paths["bundlePath"] as? String ?? "not generated"
        let expired = issued["expiredCount"].map { "\($0)" } ?? "0"
        let findingText = findings.prefix(3).map { finding -> String in
            let id = finding["id"] as? String ?? "finding"
            let severity = finding["severity"] as? String ?? "review"
            let message = finding["message"] as? String ?? "Review TLS trust state."
            return "\(severity) \(id): \(message)"
        }.joined(separator: "\n")
        return [
            "TLS onboarding:",
            "1. Generate Local CA creates per-daemon artifacts only; global trust install is \(installGlobal ? "requested" : "not offered").",
            "2. Guarded tools trust that CA through process environment variables: \(envVars.isEmpty ? "-" : envVars).",
            "3. Rotate Local CA when artifacts are stale or exposed; rerun guarded tools afterward so they receive the new bundle.",
            "4. Revoke Local CA for recovery; then generate a fresh local CA before using decrypted TLS inspection again.",
            "CA lifecycle: \(lifecycle)",
            "CA certificate: \(certificatePath)",
            "CA bundle: \(bundlePath)",
            "Recovery diagnostics: \(expired) expired cached host certs\(findingText.isEmpty ? "" : "\n\(findingText)")"
        ].joined(separator: "\n")
    }

    func summarizeSecurity(_ json: [String: Any]) -> String {
        let ok = json["ok"] as? Bool == true
        let summary = json["summary"] as? [String: Any] ?? [:]
        let high = summary["high"].map { "\($0)" } ?? "0"
        let medium = summary["medium"].map { "\($0)" } ?? "0"
        return "\(ok ? "ok" : "review"), high \(high), medium \(medium)"
    }

    func summarizeExtensionSync(_ json: [String: Any]) -> String {
        if let status = json["status"] as? [String: Any] {
            let running = status["running"] as? Bool == true ? "running" : "not running"
            let degraded = status["degraded"] as? Bool == true ? "degraded" : "healthy"
            let stale = status["stale"] as? Bool == true ? "stale" : "fresh"
            let fallback = status["fallbackMode"] as? String ?? "unknown fallback"
            let heartbeat = status["lastHeartbeatAt"] as? String ?? "no heartbeat"
            return "\(running), \(degraded), \(stale), fallback \(fallback), heartbeat \(heartbeat)"
        }
        let configured = json["configured"] as? Bool == true
        let invalidated = json["invalidated"] as? Bool == true
        let validDigest = json["validPolicyDigest"] as? Bool == true
        let manifest = json["manifest"] as? [String: Any] ?? [:]
        let sequence = manifest["sequence"].map { "\($0)" } ?? "-"
        let profile = manifest["profile"] as? String ?? "-"
        let heartbeat = json["heartbeat"] as? [String: Any] ?? [:]
        let heartbeatAt = heartbeat["at"] as? String ?? "no heartbeat"
        if invalidated {
            let reason = manifest["invalidateReason"] as? String ?? "manual-invalidation"
            return "invalidated seq \(sequence), reason \(reason), last heartbeat \(heartbeatAt)"
        }
        if configured {
            return "profile \(profile), seq \(sequence), digest \(validDigest ? "ok" : "review"), last heartbeat \(heartbeatAt)"
        }
        return "not configured"
    }

    func summarizeHealth(_ json: [String: Any]) -> String {
        let retained = json["retainedEventCount"].map { "\($0)" } ?? "0"
        let auth = (json["authRequired"] as? Bool == true) ? "token required" : "read-only without token"
        let policyRoot = json["policyRoot"] as? String ?? "unknown policy root"
        return "\(retained) events, \(auth), \(policyRoot)"
    }

    func summarizeTemplates(_ json: [String: Any]) -> String {
        guard let templates = json["templates"] as? [[String: Any]] else {
            return "no templates reported"
        }
        let names = templates.compactMap { $0["name"] as? String }.prefix(3).joined(separator: ", ")
        let suffix = templates.count > 3 ? ", +\(templates.count - 3) more" : ""
        return templates.isEmpty ? "no templates reported" : "\(templates.count) available: \(names)\(suffix)"
    }

    func extractTemplateNames(_ json: [String: Any]) -> [String] {
        guard let templates = json["templates"] as? [[String: Any]] else { return [] }
        return templates.compactMap { $0["name"] as? String }
    }

    func extractTemplateRows(_ json: [String: Any]) -> [MonitorTemplateRow] {
        guard let templates = json["templates"] as? [[String: Any]] else { return [] }
        return templates.compactMap { template in
            guard let name = template["name"] as? String else { return nil }
            let description = template["description"] as? String ?? template["summary"] as? String ?? ""
            let category = template["category"] as? String ?? template["kind"] as? String ?? "policy template"
            let risk = template["risk"] as? String ?? ""
            let detail = [category, risk].filter { !$0.isEmpty }.joined(separator: " · ")
            return MonitorTemplateRow(name: name, description: description, detail: detail)
        }
    }

    func templatesBodyText() -> String {
        if templateNames.isEmpty {
            return templatesSummaryText
        }
        let listed = templateNames.prefix(8).enumerated().map { index, name in
            "\(index == 0 ? "selected" : "template"): \(name)"
        }.joined(separator: "\n")
        return [
            "Profile: \(selectedProfileName)",
            "Templates: \(templatesSummaryText)",
            listed
        ].joined(separator: "\n")
    }

    func summaryText(_ summary: [String: Any]) -> String {
        let network = summary["network"] as? [String: Any] ?? [:]
        let filesystem = summary["filesystem"] as? [String: Any] ?? [:]
        let allowed = network["allowedDomainsCount"].map { "\($0)" } ?? "0"
        let denied = network["deniedDomainsCount"].map { "\($0)" } ?? "0"
        let http = network["httpRulesCount"].map { "\($0)" } ?? "0"
        let read = filesystem["allowReadCount"].map { "\($0)" } ?? "0"
        let write = filesystem["allowWriteCount"].map { "\($0)" } ?? "0"
        let denyRead = filesystem["denyReadCount"].map { "\($0)" } ?? "0"
        return "Network: \(allowed) allowed, \(denied) denied, \(http) HTTP rules\nFilesystem: \(read) read allows, \(write) write allows, \(denyRead) read denies"
    }

    func daemonErrorMessage(_ response: GuardDaemonResponse) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: response.data) as? [String: Any] else {
            return nil
        }
        if let error = object["error"] as? String {
            return "guardd: \(error)"
        }
        return nil
    }

    func event(from json: [String: Any]) -> GuardMonitorEvent {
        let type = json["type"] as? String ?? "unknown"
        let host = json["host"] as? String ?? ""
        let port = json["port"].map { "\($0)" } ?? ""
        let command = json["command"] as? String ?? ""
        let proxyTarget: String
        if type == "proxy.started" {
            let httpPort = json["httpProxyPort"].map { "\($0)" } ?? ""
            let socksPort = json["socksProxyPort"].map { "\($0)" } ?? ""
            let listeners = [
                httpPort.isEmpty ? nil : "HTTP 127.0.0.1:\(httpPort)",
                socksPort.isEmpty ? nil : "SOCKS 127.0.0.1:\(socksPort)"
            ].compactMap { $0 }
            proxyTarget = listeners.isEmpty ? "Local proxy" : listeners.joined(separator: ", ")
        } else {
            proxyTarget = ""
        }
        let target = host.isEmpty ? (proxyTarget.isEmpty ? command : proxyTarget) : "\(host)\(port.isEmpty ? "" : ":\(port)")"
        let status = json["status"] as? String ?? ""
        let result: String
        if type == "network.decision" {
            result = (json["allowed"] as? Bool ?? false) ? "allow" : "deny"
        } else if type.hasPrefix("guard.alert.") {
            result = (json["action"] as? String) ?? status
        } else if let code = json["code"] {
            result = "exit \(code)"
        } else {
            result = ""
        }
        let detailParts = [
            json["backend"] as? String,
            json["reason"] as? String,
            status.isEmpty ? nil : "status=\(status)",
            proxyTarget.isEmpty ? nil : proxyTarget,
            json["method"] as? String,
            json["path"] as? String
        ].compactMap { $0 }.filter { !$0.isEmpty }
        return GuardMonitorEvent(
            id: json["id"] as? String ?? json["alertId"] as? String ?? "",
            at: json["at"] as? String ?? "",
            type: type,
            profile: json["profile"] as? String ?? "",
            projectDir: json["projectDir"] as? String ?? "",
            cwd: json["cwd"] as? String ?? "",
            runDir: json["runDir"] as? String ?? "",
            command: command,
            processPath: json["processPath"] as? String ?? json["executablePath"] as? String ?? "",
            launcherApp: json["launcherApp"] as? String ?? "",
            launcherProcess: json["launcherProcess"] as? String ?? "",
            launcherPid: Int("\(json["launcherPid"] ?? 0)") ?? 0,
            parentChain: json["parentChain"] as? String ?? "",
            pid: Int("\(json["pid"] ?? 0)") ?? 0,
            bundleIdentifier: json["bundleIdentifier"] as? String ?? json["bundleId"] as? String ?? "",
            bytesSent: Int("\(json["bytesSent"] ?? json["sentBytes"] ?? json["uploadBytes"] ?? 0)") ?? 0,
            bytesReceived: Int("\(json["bytesReceived"] ?? json["receivedBytes"] ?? json["downloadBytes"] ?? 0)") ?? 0,
            host: host,
            target: target,
            result: result,
            detail: detailParts.joined(separator: " "),
            status: status,
            expiresAt: json["expiresAt"] as? String ?? "",
            duration: json["duration"] as? String ?? "",
            rulePersisted: json["rulePersisted"] as? Bool ?? false,
            ruleId: json["ruleId"] as? String ?? ""
        )
    }

    func buildActivityRows(from events: [GuardMonitorEvent]) -> [MonitorActivityRow] {
        let showingFiles = monitorFilterControl.selectedSegment == 3
        var order: [String] = []
        var grouped: [String: [GuardMonitorEvent]] = [:]
        for event in events {
            let app = appLabel(for: event)
            if grouped[app] == nil {
                order.append(app)
                grouped[app] = []
            }
            grouped[app]?.append(event)
        }

        if !didAutoExpandActivityGroups && expandedApps.isEmpty {
            let reviewApps = order.filter { app in
                (grouped[app] ?? []).contains { !$0.host.isEmpty && ($0.result == "deny" || $0.result == "denied") }
            }
            if reviewApps.isEmpty, let firstApp = order.first {
                expandedApps.insert("app:\(firstApp)")
            } else {
                expandedApps.formUnion(reviewApps.prefix(2).map { "app:\($0)" })
            }
            didAutoExpandActivityGroups = true
        }

        var rows: [MonitorActivityRow] = []
        for app in order {
            let groupEvents = grouped[app] ?? []
            let summary = projectSummary(for: groupEvents, allowSubprocess: false)
            let network = groupEvents.filter { isNetworkActivity($0) }
            let decisions = network.filter { !$0.host.isEmpty }
            let denied = decisions.filter { $0.result == "deny" }.count
            let allowed = decisions.filter { $0.result == "allow" }.count
            let domains = Set(decisions.map { $0.host }).count
            let fileLike = groupEvents.filter { isFileActivity($0) }.count
            let summaryParts = [
                domains == 0 ? nil : "\(domains) destination\(domains == 1 ? "" : "s")",
                decisions.isEmpty ? nil : "\(allowed) allowed",
                denied == 0 ? nil : "\(denied) denied",
                network.contains { $0.type == "proxy.started" } ? "proxy ready" : nil,
                policyTableSummary(summary),
                showingFiles && fileLike > 0 ? "\(fileLike) file event\(fileLike == 1 ? "" : "s")" : nil
            ].compactMap { $0 }
            let appKey = "app:\(app)"
            rows.append(MonitorActivityRow(
                isGroup: true,
                kind: "app",
                level: 0,
                rowKey: appKey,
                app: app,
                destination: topDestinationSummary(for: groupEvents),
                activity: summaryParts.isEmpty ? "No policy activity yet" : summaryParts.joined(separator: " · "),
                decision: denied > 0 ? "review" : "active",
                time: "",
                event: groupEvents.first
            ))
            if let summary {
                rows.append(contentsOf: policyRows(for: summary, appKey: appKey, event: groupEvents.first))
            }

            let visibleEvents = showingFiles
                ? groupEvents
                : groupEvents.filter { isNetworkActivity($0) || isRunLifecycleActivity($0) }
            let processGroups = Dictionary(grouping: visibleEvents, by: { processLabel(for: $0) })
            for process in processGroups.keys.sorted(by: sortProcessNames) {
                let processEvents = processGroups[process] ?? []
                let processNetwork = processEvents.filter { isNetworkActivity($0) }
                let processDecisions = processNetwork.filter { !$0.host.isEmpty }
                let hasFilePolicy = processEvents.contains(where: isFileActivity)
                let hasKnownConfig = processEvents.contains { $0.type == "guard.project.profile" }
                if processDecisions.isEmpty && (!showingFiles || !hasFilePolicy) && !hasKnownConfig {
                    continue
                }
                let processDenied = processDecisions.filter { $0.result == "deny" }.count
                let processAllowed = processDecisions.filter { $0.result == "allow" }.count
                let processKey = "\(appKey)/process:\(process)"
                let processRowLabel = process == app ? "Connections" : process
                rows.append(MonitorActivityRow(
                    isGroup: true,
                    kind: "process",
                    level: 1,
                    rowKey: processKey,
                    app: processRowLabel,
                    destination: topDestinationSummary(for: processEvents),
                    activity: [
                        processDecisions.isEmpty ? nil : "\(processAllowed) allowed",
                        processDenied == 0 ? nil : "\(processDenied) denied",
                        showingFiles && processEvents.contains(where: isFileActivity) ? "filesystem policy" : nil,
                        hasKnownConfig ? "inactive configuration" : nil,
                        proxyManagementLabel(for: processEvents)
                    ].compactMap { $0 }.joined(separator: " · "),
                    decision: processDenied > 0 ? "review" : "active",
                    time: shortTime(processEvents.first?.at ?? ""),
                    event: processEvents.first
                ))

                let hosts = Dictionary(grouping: processDecisions, by: { hostListLabel(for: $0) })
                for host in hosts.keys.sorted() {
                    let hostEvents = hosts[host] ?? []
                    let hostDenied = hostEvents.contains { $0.result == "deny" }
                    let hostAllowed = hostEvents.filter { $0.result == "allow" }.count
                    let hostBlocked = hostEvents.filter { $0.result == "deny" }.count
                    let representative = hostEvents.first
                    let temporary = hostEvents.compactMap { temporaryRuleSummary(for: $0) }.first
                    rows.append(MonitorActivityRow(
                        isGroup: false,
                        kind: "destination",
                        level: 2,
                        rowKey: "\(processKey)/host:\(host)",
                        app: host,
                        destination: hostPortLabel(for: representative ?? hostEvents[0]),
                        activity: hostDenied
                            ? ["Blocked by network policy", "\(hostBlocked) denied", temporary].compactMap { $0 }.joined(separator: " · ")
                            : ["Allowed by network policy", "\(hostAllowed) allowed", temporary].compactMap { $0 }.joined(separator: " · "),
                        decision: hostDenied ? "deny" : "allow",
                        time: shortTime(representative?.at ?? ""),
                        event: representative
                    ))
                }

                for event in processNetwork.filter({ $0.type == "proxy.started" }).prefix(2) {
                    rows.append(MonitorActivityRow(
                        isGroup: false,
                        kind: "proxy",
                        level: 2,
                        rowKey: "\(processKey)/proxy:\(eventKey(event))",
                        app: "Local proxy",
                        destination: event.target.isEmpty ? "Local proxy" : event.target,
                        activity: "HTTP/SOCKS listeners ready for this guarded run",
                        decision: "active",
                        time: shortTime(event.at),
                        event: event
                    ))
                }

                let nonNetwork = processEvents.filter {
                    $0.host.isEmpty && ((showingFiles && isFileActivity($0)) || $0.type == "guard.project.profile")
                }
                for event in nonNetwork.prefix(3) {
                    rows.append(MonitorActivityRow(
                        isGroup: false,
                        kind: "event",
                        level: 2,
                        rowKey: "\(processKey)/event:\(eventKey(event))",
                        app: activityLabel(for: event),
                        destination: primaryText(for: event),
                        activity: humanDecisionReason(event.detail, fallback: event.detail.isEmpty ? humanizeEventType(event.type) : event.detail),
                        decision: decisionLabel(for: event).isEmpty ? "managed" : decisionLabel(for: event),
                        time: shortTime(event.at),
                        event: event
                    ))
                }
            }

            if visibleEvents.isEmpty && network.count > 0 {
                let appEvents = groupEvents.filter { !$0.host.isEmpty }
                let hosts = Dictionary(grouping: appEvents, by: { hostListLabel(for: $0) })
                for host in hosts.keys.sorted() {
                    let hostEvents = hosts[host] ?? []
                    let hostDenied = hostEvents.contains { $0.result == "deny" }
                    let representative = hostEvents.first
                    let temporary = hostEvents.compactMap { temporaryRuleSummary(for: $0) }.first
                    rows.append(MonitorActivityRow(
                        isGroup: false,
                        kind: "destination",
                        level: 1,
                        rowKey: "\(appKey)/host:\(host)",
                        app: host,
                        destination: host,
                        activity: [hostDenied ? "Blocked by network policy" : "Allowed by network policy", temporary].compactMap { $0 }.joined(separator: " · "),
                        decision: hostDenied ? "deny" : "allow",
                        time: shortTime(representative?.at ?? ""),
                        event: representative
                    ))
                }
            }
        }
        return rows.filter { !hiddenActivityRowKeys.contains($0.rowKey) }
    }

    func proxyManagementLabel(for events: [GuardMonitorEvent]) -> String? {
        if events.contains(where: { $0.detail.contains("iron-proxy") }) {
            return "TLS inspected"
        }
        if events.contains(where: { $0.type == "proxy.started" || !$0.host.isEmpty }) {
            return "proxy routed"
        }
        return nil
    }

    func temporaryRuleSummary(for event: GuardMonitorEvent) -> String? {
        guard event.type != "guard.alert.pending" else { return nil }
        let duration = event.duration.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if event.rulePersisted || duration == "forever" {
            return "persistent rule"
        }
        if let remaining = timeLeftText(event.expiresAt) {
            return "temporary · \(remaining) left"
        }
        if duration == "once" {
            return "one-time rule"
        }
        if duration == "session" {
            return "temporary · session"
        }
        return nil
    }

    func timeLeftText(_ iso: String) -> String? {
        guard let date = monitorEventDate(iso) else { return nil }
        let seconds = Int(date.timeIntervalSinceNow)
        guard seconds > 0 else { return "expired" }
        if seconds < 90 { return "\(seconds)s" }
        let minutes = seconds / 60
        if minutes < 90 { return "\(minutes)m" }
        let hours = minutes / 60
        if hours < 48 { return "\(hours)h" }
        return "\(hours / 24)d"
    }

    func processLabel(for event: GuardMonitorEvent) -> String {
        if let identity = processIdentity(from: event.command) {
            return identity
        }
        if event.type.hasPrefix("process."), let identity = processIdentity(from: event.target) {
            return identity
        }
        if !event.profile.isEmpty {
            return event.profile
        }
        return "Guarded process"
    }

    func processIdentity(from raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "-" else { return nil }
        let parts = trimmed.split(separator: " ").map(String.init)
        guard let executable = parts.first else { return nil }
        let base = URL(fileURLWithPath: executable).lastPathComponent
        guard !base.isEmpty, base != "-", !base.hasSuffix(".py") else { return nil }
        let lower = base.lowercased()

        if lower == "pnpm" || lower == "npm" || lower == "yarn" {
            if let runIndex = parts.firstIndex(of: "run"), runIndex + 1 < parts.count {
                return "\(base) run \(parts[runIndex + 1])"
            }
            return base
        }
        if lower == "node" {
            return parts.contains("--version") ? "node --version" : "node"
        }
        if lower.hasPrefix("python") {
            return "python"
        }
        if lower == "bash" || lower == "zsh" || lower == "sh" {
            if let script = parts.dropFirst().first(where: { !$0.hasPrefix("-") }) {
                let scriptName = URL(fileURLWithPath: script).lastPathComponent
                return scriptName.isEmpty ? base : "\(base) \(scriptName)"
            }
            return base
        }
        return base
    }

    func isFileActivity(_ event: GuardMonitorEvent) -> Bool {
        let value = "\(event.type) \(event.detail)".lowercased()
        return value.contains("file") || value.contains("sandbox") || value.contains("read") || value.contains("write")
    }

    func isNetworkActivity(_ event: GuardMonitorEvent) -> Bool {
        event.type == "network.decision" ||
            event.type == "proxy.started" ||
            event.type.hasPrefix("guard.alert.")
    }

    func topDestinationSummary(for events: [GuardMonitorEvent]) -> String {
        var counts: [String: Int] = [:]
        let networkEvents = events.filter { !$0.host.isEmpty }
        for event in networkEvents {
            counts[hostListLabel(for: event), default: 0] += 1
        }
        if counts.isEmpty {
            if let command = events
                .map({ commandDisplay($0.command) })
                .first(where: { $0 != "Command" && $0 != "node --version" }) {
                return command
            }
            for event in events {
                let destination = primaryText(for: event)
                if !destination.isEmpty && destination != "-" {
                    counts[destination, default: 0] += 1
                }
            }
        }
        return counts.sorted { lhs, rhs in lhs.value == rhs.value ? lhs.key < rhs.key : lhs.value > rhs.value }.first?.key ?? "Local activity"
    }

    func primaryText(for event: GuardMonitorEvent) -> String {
        if !event.host.isEmpty { return hostListLabel(for: event) }
        if isFileActivity(event) {
            return "Filesystem policy"
        }
        if event.type == "process.started" || event.type == "process.exited" {
            return commandDisplay(event.command)
        }
        if event.type == "guard.project.profile" {
            return event.profile.isEmpty ? "guard profile" : event.profile
        }
        if event.type == "proxy.started" {
            return "Local proxy"
        }
        return event.target.isEmpty ? event.type : event.target
    }

    func hostListLabel(for event: GuardMonitorEvent) -> String {
        event.host.isEmpty ? "-" : event.host
    }

    func hostPortLabel(for event: GuardMonitorEvent) -> String {
        guard !event.host.isEmpty else { return "-" }
        if event.target.hasPrefix("\(event.host):") {
            return event.target
        }
        return event.host
    }

    func decisionLabel(for event: GuardMonitorEvent) -> String {
        if event.result == "allow" { return "allowed" }
        if event.result == "deny" { return "denied" }
        if event.result.hasPrefix("exit ") {
            let code = event.result.replacingOccurrences(of: "exit ", with: "")
            return code == "0" ? "ok" : "exit \(code)"
        }
        return event.result.isEmpty ? "" : event.result
    }

    func groupSummaryText(for app: String) -> String {
        let groupEvents = events.filter { appLabel(for: $0) == app }
        let network = groupEvents.filter { isNetworkActivity($0) }
        let denied = network.filter { $0.result == "deny" || $0.result == "denied" }.count
        let allowed = network.filter { $0.result == "allow" || $0.result == "allowed" }.count
        let fileEvents = groupEvents.filter { isFileActivity($0) }
        let topHosts = topCounts(groupEvents.compactMap { $0.host.isEmpty ? nil : $0.host }, limit: 5)
        let commands = topCounts(groupEvents.map { commandDisplay($0.command) }.filter { $0 != "Command" }, limit: 4)
        return [
            "Policy Overview",
            "Internet domains: \(Set(network.compactMap { $0.host.isEmpty ? nil : $0.host }).count)",
            "Allowed: \(allowed)",
            "Denied: \(denied)",
            "Filesystem policy events: \(fileEvents.count)",
            "Proxy/TLS: \(network.isEmpty ? "not observed" : "managed")",
            "",
            "Domains",
            topHosts.isEmpty ? "None recorded" : topHosts.joined(separator: "\n"),
            "",
            "Commands",
            commands.isEmpty ? "None recorded" : commands.joined(separator: "\n")
        ].joined(separator: "\n")
    }

    func childRows(of item: Any?) -> [MonitorActivityRow] {
        guard let parentKey = item as? String,
              let parent = activityRows.first(where: { $0.rowKey == parentKey }) else {
            return activityRows.filter { $0.level == 0 }
        }
        guard let parentIndex = activityRows.firstIndex(where: { $0.rowKey == parent.rowKey }) else {
            return []
        }
        var children: [MonitorActivityRow] = []
        var index = parentIndex + 1
        while index < activityRows.count {
            let row = activityRows[index]
            if row.level <= parent.level { break }
            if row.level == parent.level + 1 {
                children.append(row)
            }
            index += 1
        }
        return children
    }

    func childRowKeys(of item: Any?) -> [String] {
        childRows(of: item).map(\.rowKey)
    }

    func activityRow(atVisibleRow row: Int) -> MonitorActivityRow? {
        guard row >= 0 else { return nil }
        guard let key = tableView.item(atRow: row) as? String else { return nil }
        return activityRows.first { $0.rowKey == key }
    }

    func restoreOutlineExpansion() {
        for row in activityRows where row.isGroup && expandedApps.contains(row.rowKey) {
            tableView.expandItem(row.rowKey)
        }
    }

    @discardableResult
    func selectActivityRow(rowKey: String) -> Bool {
        guard let row = activityRows.first(where: { $0.rowKey == rowKey }) else { return false }
        expandAncestors(for: row)
        let visibleRow = tableView.row(forItem: row.rowKey)
        guard visibleRow >= 0 else { return false }
        tableView.selectRowIndexes(IndexSet(integer: visibleRow), byExtendingSelection: false)
        selectedActivityRowKey = row.rowKey
        selectedEventKey = row.event.map(eventKey)
        return true
    }

    @discardableResult
    func selectFirstActivityRow() -> Bool {
        guard tableView.numberOfRows > 0, let row = activityRow(atVisibleRow: 0) else { return false }
        tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        selectedActivityRowKey = row.rowKey
        selectedEventKey = row.event.map(eventKey)
        return true
    }

    func expandAncestors(for row: MonitorActivityRow) {
        var currentLevel = row.level - 1
        guard currentLevel >= 0, let rowIndex = activityRows.firstIndex(where: { $0.rowKey == row.rowKey }) else { return }
        var index = rowIndex - 1
        while index >= 0 && currentLevel >= 0 {
            let candidate = activityRows[index]
            if candidate.level == currentLevel {
                expandedApps.insert(candidate.rowKey)
                tableView.expandItem(candidate.rowKey)
                currentLevel -= 1
            }
            index -= 1
        }
    }

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        childRowKeys(of: item).count
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        childRowKeys(of: item)[index]
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        !childRowKeys(of: item).isEmpty
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        self.tableView.numberOfRows
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let activityRow = activityRow(atVisibleRow: row) else { return nil }
        return activityCellView(for: activityRow, tableColumn: tableColumn, row: row)
    }

    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        guard let rowKey = item as? String,
              let activityRow = activityRows.first(where: { $0.rowKey == rowKey }) else {
            return nil
        }
        let row = outlineView.row(forItem: item)
        return activityCellView(for: activityRow, tableColumn: tableColumn, row: row)
    }

    func activityCellView(for activityRow: MonitorActivityRow, tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let id = tableColumn?.identifier.rawValue ?? ""
        let text: String
        switch id {
        case "app":
            return appCell(for: activityRow, rowIndex: row)
        case "destination": text = activityRow.destination
        case "activity": text = activityRow.activity
        case "decision":
            return policySwitchCell(for: activityRow, rowIndex: row)
        case "time": text = activityRow.time
        default: text = ""
        }
        let cell = NSTableCellView()
        let label = NSTextField(labelWithString: text)
        label.lineBreakMode = .byTruncatingTail
        label.font = activityRow.isGroup
            ? NSFont.systemFont(ofSize: 12.4, weight: id == "activity" ? .regular : .medium)
            : NSFont.systemFont(ofSize: 11.5)
        if id == "decision" {
            label.textColor = decisionColor(text)
        } else if activityRow.kind.hasPrefix("policy-") && id != "activity" {
            label.textColor = activityRow.isGroup ? .labelColor : .secondaryLabelColor
        } else if id == "activity" && activityRow.isGroup {
            label.textColor = .secondaryLabelColor
        } else if activityRow.isGroup {
            label.textColor = .labelColor
        }
        label.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 5),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -5),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    func policySwitchCell(for row: MonitorActivityRow, rowIndex: Int) -> NSView {
        let cell = NSTableCellView()
        let stack = NSStackView()
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(stack)

        let editable = editablePolicyTarget(for: row)
        if editable == nil {
            let lifecycle = policyLifecycle(for: row)
            guard lifecycle != nil || (!row.decision.isEmpty && row.decision != "active") else {
                return cell
            }
            if let lifecycle {
                stack.addArrangedSubview(policyLifecycleChip(lifecycle.text, color: lifecycle.color, tooltip: lifecycle.tooltip))
            } else {
                let state = label(row.decision, size: 10.8, weight: .semibold, color: decisionColor(row.decision))
                state.alignment = .left
                state.translatesAutoresizingMaskIntoConstraints = false
                stack.addArrangedSubview(state)
            }
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 6),
                stack.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor, constant: -8),
                stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            return cell
        }

        let control = HoverPolicySwitch()
        control.selectedSegment = row.kind == "policy-deny-host" || row.kind == "policy-deny-read" || row.kind == "policy-deny-write" || row.decision == "deny" || row.decision == "review" ? 0 : 1
        control.target = self
        control.action = #selector(policySwitchChanged(_:))
        control.tag = rowIndex
        if let lifecycle = policyLifecycle(for: row), lifecycle.text != "live" {
            control.toolTip = "\(editable?.tooltip ?? "Allow or deny"). Applies on \(lifecycle.text)."
        } else {
            control.toolTip = editable?.tooltip ?? "Allow or deny"
        }
        stack.addArrangedSubview(control)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: cell.leadingAnchor, constant: 4),
            stack.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -26),
            stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    @objc func policySwitchChanged(_ sender: NSControl) {
        let row = sender.tag
        guard let activityRow = activityRow(atVisibleRow: row),
              let target = editablePolicyTarget(for: activityRow),
              let event = activityRow.event else { return }
        tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        let selectedSegment: Int
        if let policySwitch = sender as? HoverPolicySwitch {
            selectedSegment = policySwitch.selectedSegment
        } else if let segmented = sender as? NSSegmentedControl {
            selectedSegment = segmented.selectedSegment
        } else {
            selectedSegment = 1
        }
        if selectedSegment == 0 {
            setExclusiveRuleValue(target.value, event: event, allowField: target.allowField, denyField: target.denyField, allow: false)
        } else {
            setExclusiveRuleValue(target.value, event: event, allowField: target.allowField, denyField: target.denyField, allow: true)
        }
    }

    func editablePolicyTarget(for row: MonitorActivityRow) -> (value: String, allowField: String, denyField: String, tooltip: String)? {
        if row.kind == "destination", row.event?.host.isEmpty == false {
            return (row.event!.host, "network.allowedDomains", "network.deniedDomains", "Allow or deny this domain")
        }
        if row.kind == "policy-allow-host" || row.kind == "policy-deny-host" {
            return row.app.isEmpty ? nil : (row.app, "network.allowedDomains", "network.deniedDomains", "Allow or deny this domain")
        }
        if row.kind == "policy-read" || row.kind == "policy-deny-read" {
            return row.app.isEmpty ? nil : (row.app, "filesystem.allowRead", "filesystem.denyRead", "Allow or deny reads for this path")
        }
        if row.kind == "policy-write" || row.kind == "policy-deny-write" {
            return row.app.isEmpty ? nil : (row.app, "filesystem.allowWrite", "filesystem.denyWrite", "Allow or deny writes for this path")
        }
        return nil
    }

    func policyLifecycle(for row: MonitorActivityRow) -> (text: String, color: NSColor, tooltip: String)? {
        switch row.kind {
        case "destination", "policy-allow-host", "policy-deny-host":
            return ("live", .systemGreen, "Applies to new proxy decisions in this run.")
        case "policy-read", "policy-write", "policy-deny-read", "policy-deny-write":
            return ("next run", .secondaryLabelColor, "Filesystem sandbox rules are generated when a guarded run starts.")
        case "policy-raw-tcp", "policy-proxy-env", "policy-socks-env", "policy-loopback":
            return ("next run", .secondaryLabelColor, "Proxy environment and direct TCP exceptions are fixed for the current guarded run.")
        case "policy-http":
            return ("proxy reload", .systemOrange, "Deep HTTP rules are enforced by the proxy and require a proxy reload or the next run.")
        case "policy-tls":
            if row.destination == "off" {
                return ("setup", .systemBlue, "TLS inspection depends on proxy and certificate setup.")
            }
            return ("proxy reload", .systemOrange, "TLS inspection changes require proxy and certificate state to be refreshed.")
        default:
            return nil
        }
    }

    func policyLifecycleChip(_ text: String, color: NSColor, tooltip: String) -> NSView {
        let chip = CardView(fill: color.withAlphaComponent(0.10), border: color.withAlphaComponent(0.28))
        chip.layer?.cornerRadius = 5
        chip.toolTip = tooltip
        chip.translatesAutoresizingMaskIntoConstraints = false
        let title = label(text, size: 9.5, weight: .semibold, color: color)
        title.alignment = .center
        title.translatesAutoresizingMaskIntoConstraints = false
        chip.addSubview(title)
        NSLayoutConstraint.activate([
            title.leadingAnchor.constraint(equalTo: chip.leadingAnchor, constant: 6),
            title.trailingAnchor.constraint(equalTo: chip.trailingAnchor, constant: -6),
            title.centerYAnchor.constraint(equalTo: chip.centerYAnchor),
            chip.heightAnchor.constraint(equalToConstant: 20),
            chip.widthAnchor.constraint(greaterThanOrEqualToConstant: text.count > 8 ? 74 : 56)
        ])
        return chip
    }

    func decisionColor(_ text: String) -> NSColor {
        if text.contains("denied") || text == "deny" || text == "blocked" { return .systemRed }
        if text == "review" || text == "pending" { return .systemOrange }
        if text == "allow" || text == "allowed" || text == "active" { return .systemGreen }
        return .secondaryLabelColor
    }

    func ruleToggleSymbol(_ name: String, color: NSColor) -> NSView {
        let container = CardView(fill: color.withAlphaComponent(0.10), border: color.withAlphaComponent(0.35))
        container.layer?.cornerRadius = 5
        container.translatesAutoresizingMaskIntoConstraints = false
        container.widthAnchor.constraint(equalToConstant: 24).isActive = true
        container.heightAnchor.constraint(equalToConstant: 22).isActive = true
        let image = NSImageView()
        if #available(macOS 11.0, *) {
            image.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
            image.contentTintColor = color
        }
        image.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(image)
        NSLayoutConstraint.activate([
            image.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            image.centerYAnchor.constraint(equalTo: container.centerYAnchor),
            image.widthAnchor.constraint(equalToConstant: 12),
            image.heightAnchor.constraint(equalToConstant: 12)
        ])
        return container
    }

    func appCell(for row: MonitorActivityRow, rowIndex: Int) -> NSView {
        let cell = NSTableCellView()
        let stack = NSStackView()
        stack.orientation = .horizontal
        stack.alignment = .centerY
        stack.spacing = 5
        stack.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(stack)

        let imageView = NSImageView()
        imageView.image = iconForActivityRow(row)
        imageView.imageScaling = .scaleProportionallyUpOrDown
        if #available(macOS 11.0, *) {
            imageView.contentTintColor = row.kind == "destination"
                ? decisionColor(row.decision)
                : row.decision == "review" ? .systemOrange : .secondaryLabelColor
        }
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.widthAnchor.constraint(equalToConstant: 18).isActive = true
        imageView.heightAnchor.constraint(equalToConstant: 18).isActive = true
        stack.addArrangedSubview(imageView)

        let name = label(row.app, size: row.isGroup ? 12.6 : 12, weight: row.kind == "destination" ? .regular : .medium)
        name.lineBreakMode = .byTruncatingTail
        if row.kind == "destination" {
            name.textColor = .labelColor
        }
        stack.addArrangedSubview(name)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 3),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor, constant: -6),
            stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    @objc func toggleActivityGroupButton(_ sender: NSButton) {
        let row = sender.tag
        guard let activityRow = activityRow(atVisibleRow: row), activityRow.isGroup else { return }
        toggleActivityGroup(row: activityRow)
    }

    func toggleActivityGroup(named app: String) {
        if let row = activityRows.first(where: { $0.rowKey == app || ($0.kind == "app" && $0.app == app) }) {
            toggleActivityGroup(row: row)
            return
        }
        didAutoExpandActivityGroups = true
        let key = "app:\(app)"
        if expandedApps.contains(key) {
            expandedApps.remove(key)
        } else {
            expandedApps.insert(key)
        }
        rebuildActivityRows(keepSelection: false)
        _ = selectActivityRow(rowKey: key)
    }

    func toggleActivityGroup(row: MonitorActivityRow) {
        didAutoExpandActivityGroups = true
        if expandedApps.contains(row.rowKey) {
            expandedApps.remove(row.rowKey)
            tableView.collapseItem(row.rowKey)
        } else {
            expandedApps.insert(row.rowKey)
            tableView.expandItem(row.rowKey)
        }
        _ = selectActivityRow(rowKey: row.rowKey)
    }

    func descendantRange(in rows: [MonitorActivityRow], parentIndex: Int) -> Range<Int> {
        guard parentIndex >= 0 && parentIndex < rows.count else {
            return parentIndex..<parentIndex
        }
        let parentLevel = rows[parentIndex].level
        var end = parentIndex + 1
        while end < rows.count && rows[end].level > parentLevel {
            end += 1
        }
        return (parentIndex + 1)..<end
    }

    func iconForApp(_ app: String) -> NSImage? {
        let lower = app.lowercased()
        if #available(macOS 11.0, *) {
            let symbol: String
            if lower.contains("warp") || lower.contains("iterm") || lower.contains("terminal") || lower.contains("ghostty") {
                symbol = "terminal.fill"
            } else if lower.contains("packetsafari") || lower.contains("course") {
                symbol = "folder.fill"
            } else if lower.contains("node") || lower.contains("npm") || lower.contains("pnpm") {
                symbol = "terminal.fill"
            } else if lower.contains("python") {
                symbol = "chevron.left.forwardslash.chevron.right"
            } else if lower.contains("git") {
                symbol = "point.3.connected.trianglepath.dotted"
            } else if lower.contains("guard") {
                symbol = "shield.lefthalf.filled"
            } else {
                symbol = "app.fill"
            }
            let config = NSImage.SymbolConfiguration(pointSize: 19, weight: .semibold)
            return NSImage(systemSymbolName: symbol, accessibilityDescription: app)?.withSymbolConfiguration(config)
        }
        return NSImage(named: NSImage.applicationIconName)
    }

    func iconForActivityRow(_ row: MonitorActivityRow) -> NSImage? {
        if row.kind.hasPrefix("policy-") {
            if #available(macOS 11.0, *) {
                let symbol: String
                switch row.kind {
                case "policy-network": symbol = "network"
                case "policy-files": symbol = "folder.badge.gearshape"
                case "policy-proxy": symbol = "lock.shield"
                default: symbol = "list.bullet.rectangle"
                }
                let config = NSImage.SymbolConfiguration(pointSize: 17, weight: .semibold)
                return NSImage(systemSymbolName: symbol, accessibilityDescription: row.app)?.withSymbolConfiguration(config)
            }
            return NSImage(named: NSImage.infoName)
        }
        if row.kind == "destination" {
            if #available(macOS 11.0, *) {
                let symbol = row.decision == "deny" ? "xmark.circle.fill" : "globe"
                let config = NSImage.SymbolConfiguration(pointSize: 17, weight: .semibold)
                return NSImage(systemSymbolName: symbol, accessibilityDescription: row.app)?.withSymbolConfiguration(config)
            }
            return NSImage(named: NSImage.networkName)
        }
        if row.kind == "process" {
            if #available(macOS 11.0, *) {
                let lower = row.app.lowercased()
                let symbol = lower.contains("node") || lower.contains("pnpm") || lower.contains("npm") || lower.contains("python")
                    ? "terminal.fill"
                    : "app.fill"
                let config = NSImage.SymbolConfiguration(pointSize: 18, weight: .semibold)
                return NSImage(systemSymbolName: symbol, accessibilityDescription: row.app)?.withSymbolConfiguration(config)
            }
        }
        if row.kind == "event" {
            if #available(macOS 11.0, *) {
                let symbol = row.destination == "Filesystem policy" ? "folder.badge.gearshape" : "gearshape"
                let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
                return NSImage(systemSymbolName: symbol, accessibilityDescription: row.app)?.withSymbolConfiguration(config)
            }
        }
        return iconForApp(row.app)
    }

    func tableView(_ tableView: NSTableView, isGroupRow row: Int) -> Bool {
        false
    }

    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        let view = MonitorRowView()
        if let activityRow = activityRow(atVisibleRow: row) {
            view.group = activityRow.isGroup
            view.odd = row % 2 == 1
            view.denied = activityRow.isGroup && activityRow.decision == "review"
        }
        return view
    }

    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        activityRow(atVisibleRow: row)?.isGroup == true ? 30 : 23
    }

    func appLabel(_ label: String, decoratedWithLauncherFor event: GuardMonitorEvent) -> String {
        let launcher = event.launcherApp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !launcher.isEmpty else { return label }
        let launcherLower = launcher.lowercased()
        if launcherLower == "guard" || launcherLower == "node" || launcherLower == "zsh" || launcherLower == "bash" || launcherLower == "sh" {
            return label
        }
        let labelLower = label.lowercased()
        if labelLower.contains(" via ") || labelLower.contains(launcherLower) {
            return label
        }
        let commandLower = event.command.lowercased()
        let directCommand = commandLower.contains("curl") ||
            commandLower.contains("git") ||
            commandLower.contains("python") ||
            commandLower.contains("node") ||
            commandLower.contains("pnpm") ||
            commandLower.contains("npm")
        return directCommand ? "\(label) via \(launcher)" : label
    }

    func appLabel(for event: GuardMonitorEvent) -> String {
        let identity = event.command.isEmpty ? event.target : event.command
        let lower = identity.lowercased()
        if !event.projectDir.isEmpty {
            let project = projectDisplayName(event.projectDir)
            if lower.contains("-c frontend") || lower.contains(" frontend ") || lower.contains("/frontend") {
                return "\(project) Frontend"
            }
            if lower.contains("pnpm") || lower.contains("npm") || lower.contains("node") || lower.contains("python") {
                return project
            }
        }
        if lower.contains("pnpm") { return appLabel("pnpm", decoratedWithLauncherFor: event) }
        if lower.contains("npm") { return appLabel("npm", decoratedWithLauncherFor: event) }
        if lower.contains("node") { return appLabel("Node", decoratedWithLauncherFor: event) }
        if lower.contains("git") { return appLabel("Git", decoratedWithLauncherFor: event) }
        if lower.contains("curl") { return appLabel("curl", decoratedWithLauncherFor: event) }
        if lower.contains("python") { return appLabel("Python", decoratedWithLauncherFor: event) }
        if lower.contains("guard") { return appLabel("Guard", decoratedWithLauncherFor: event) }
        if !event.profile.isEmpty && event.profile != "guard" {
            return appLabel(event.profile, decoratedWithLauncherFor: event)
        }
        return appLabel(event.profile.isEmpty ? "Guarded command" : event.profile, decoratedWithLauncherFor: event)
    }

    func projectDisplayName(_ path: String) -> String {
        let raw = URL(fileURLWithPath: path).lastPathComponent
        if raw.lowercased() == "packetsafari" { return "PacketSafari" }
        return raw
            .split(separator: "-")
            .map { part in
                let lower = part.lowercased()
                return lower.prefix(1).uppercased() + lower.dropFirst()
            }
            .joined(separator: " ")
    }

    func activityLabel(for event: GuardMonitorEvent) -> String {
        if event.type == "network.decision" {
            if event.result == "allow" {
                return humanDecisionReason(event.detail, fallback: "Allowed connection")
            }
            return humanDecisionReason(event.detail, fallback: "Blocked connection")
        }
        if event.type == "proxy.started" { return "Proxy ready" }
        if event.type == "process.started" { return "Command started" }
        if event.type == "process.exited" {
            return event.result == "exit 0" ? "Command finished" : "Command failed"
        }
        if event.type == "guard.project.profile" { return "Inactive configuration" }
        if event.type == "sandbox.profile_written" { return "Sandbox applied" }
        if event.type == "guard.alert.pending" { return "Needs a decision" }
        if event.type == "guard.alert.decision" { return "Decision recorded" }
        return event.type.replacingOccurrences(of: ".", with: " ")
    }

    func humanDecisionReason(_ detail: String, fallback: String) -> String {
        let lower = detail.lowercased()
        if lower.contains("alloweddomains") { return "Allowed by domain rule" }
        if lower.contains("denieddomains") { return "Blocked by deny rule" }
        if lower.contains("default-deny") { return "Blocked by default policy" }
        if lower.contains("httprules") { return "Matched HTTP rule" }
        if lower.contains("session") { return "Allowed for this session" }
        if lower.contains("once") { return "Allowed once" }
        return fallback
    }

    func commandDisplay(_ command: String) -> String {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "Command" }
        if let identity = processIdentity(from: trimmed) {
            return identity
        }
        let lower = trimmed.lowercased()
        if lower.contains("pnpm") {
            if let range = trimmed.range(of: " run ") {
                return "pnpm run \(trimmed[range.upperBound...])"
            }
            return "pnpm"
        }
        if lower.contains("npm") {
            if let range = trimmed.range(of: " run ") {
                return "npm run \(trimmed[range.upperBound...])"
            }
            return "npm"
        }
        if lower.contains("node") {
            if trimmed.contains("--version") { return "node --version" }
            return "node"
        }
        if lower.contains("python") {
            return "python"
        }
        let parts = trimmed.split(separator: " ").map(String.init)
        guard let first = parts.first else { return "Command" }
        let executable = URL(fileURLWithPath: first).lastPathComponent
        return ([executable] + parts.dropFirst().prefix(2)).joined(separator: " ")
    }

    func shortTime(_ value: String) -> String {
        guard value.count >= 19 else { return value }
        let start = value.index(value.startIndex, offsetBy: 11)
        let end = value.index(value.startIndex, offsetBy: 19)
        return String(value[start..<end])
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard !suppressSelectionChange else { return }
        let row = tableView.selectedRow
        guard let activityRow = activityRow(atVisibleRow: row) else {
            selectedEventKey = nil
            selectedActivityRowKey = nil
            renderedInspectorRowKey = nil
            updateInspector(nil)
            return
        }
        selectedActivityRowKey = activityRow.rowKey
        if renderedInspectorRowKey == activityRow.rowKey {
            return
        }
        renderedInspectorRowKey = activityRow.rowKey
        if activityRow.kind == "app" {
            selectedEventKey = nil
            inspectorHelpLabel.stringValue = "Application Summary"
            inspectorTitleLabel.stringValue = activityRow.app
            renderGroupDetailsPanel(app: activityRow.app)
            inspectorSummaryStack.isHidden = false
            inspectorBodyLabel.isHidden = true
            inspectorBodyLabel.stringValue = ""
            inspectorRuleLabel.isHidden = false
            inspectorNoteLabel.isHidden = false
            inspectorRuleLabel.stringValue = "Select a process or destination row to review the exact policy scope."
            inspectorNoteLabel.stringValue = "Double-click app and process rows to expand or collapse recent activity."
            updateActionButtons(nil)
            return
        }
        if activityRow.kind == "process" {
            selectedEventKey = activityRow.event.map(eventKey)
            renderProcessDetailsPanel(row: activityRow)
            inspectorSummaryStack.isHidden = false
            inspectorBodyLabel.isHidden = true
            inspectorBodyLabel.stringValue = ""
            inspectorRuleLabel.isHidden = false
            inspectorNoteLabel.isHidden = false
            inspectorRuleLabel.stringValue = "Destinations under this process create the narrowest allow or deny rules."
            inspectorNoteLabel.stringValue = "Process identity is inferred from Guard events until binary metadata is available."
            updateActionButtons(nil)
            return
        }
        if activityRow.kind.hasPrefix("policy-") {
            selectedEventKey = nil
            inspectorHelpLabel.stringValue = "Configuration"
            inspectorTitleLabel.stringValue = activityRow.app
            renderGroupDetailsPanel(app: appLabelForRowKey(activityRow.rowKey))
            inspectorSummaryStack.isHidden = false
            inspectorBodyLabel.isHidden = true
            inspectorBodyLabel.stringValue = ""
            inspectorRuleLabel.isHidden = false
            inspectorNoteLabel.isHidden = false
            inspectorRuleLabel.stringValue = "This row is configuration from the active Guard profile, not a runtime event."
            inspectorNoteLabel.stringValue = "Use Rules to edit persistent domains, HTTP rules, raw TCP rules, and disabled rule state."
            updateActionButtons(nil)
            return
        }
        guard let event = activityRow.event else {
            selectedEventKey = nil
            renderedInspectorRowKey = nil
            updateInspector(nil)
            return
        }
        selectedEventKey = eventKey(event)
        if daemonConnected {
            loadDaemonPolicyState(profile: event.profile.isEmpty ? "guard" : event.profile)
        }
        updateInspector(event)
    }

    func renderSelectedInspectorIfNeeded(force: Bool) {
        let row = tableView.selectedRow
        guard let activityRow = activityRow(atVisibleRow: row) else {
            if force || renderedInspectorRowKey != nil {
                renderedInspectorRowKey = nil
                updateInspector(nil)
            }
            return
        }
        selectedActivityRowKey = activityRow.rowKey
        guard force || renderedInspectorRowKey != activityRow.rowKey else { return }
        renderedInspectorRowKey = nil
        tableViewSelectionDidChange(Notification(name: NSTableView.selectionDidChangeNotification, object: tableView))
    }

    func label(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor = .labelColor) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.systemFont(ofSize: size, weight: weight)
        label.textColor = color
        label.lineBreakMode = .byTruncatingTail
        label.maximumNumberOfLines = 1
        return label
    }
}

let app = NSApplication.shared
let appDelegate = GuardApplicationDelegate()
app.delegate = appDelegate
if runCliAskModeIfNeeded() {
    exit(0)
}

app.setActivationPolicy(.regular)
installMainMenu(appName: "Guard Monitor", delegate: appDelegate)
if let iconURL = Bundle.main.url(forResource: "GuardAppIcon", withExtension: "icns"),
   let bundledIcon = NSImage(contentsOf: iconURL) {
    app.applicationIconImage = bundledIcon
} else if #available(macOS 11.0, *) {
    app.applicationIconImage = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: "Guard")
}

do {
    let config = try loadConfig()
    if config.mode == "monitor" {
        let controller = MonitorWindowController(config: config)
        appDelegate.monitorController = controller
        appDelegate.statusController = GuardStatusItemController(monitor: controller)
        controller.show()
        app.run()
    } else {
        let summary = try loadSummary(config: config)
        let controller = LauncherWindowController(config: config, summary: summary)
        appDelegate.launcherController = controller
        controller.show()
        app.run()
    }
} catch {
    showError(error.localizedDescription)
}

import AppKit
import Foundation

struct GuardAppConfig: Decodable {
    let profile: String
    let displayName: String
    let guardPath: String
    let bundleIdentifier: String
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
    let deniedDomains: [String]
    let deniedDomainPresets: [String]
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
    process.terminationHandler = { _ in
        try? log.close()
        DispatchQueue.main.async {
            NSApp.terminate(nil)
        }
    }

    try process.run()
}

func showError(_ message: String) {
    let alert = NSAlert()
    alert.messageText = "Guard Launcher Failed"
    alert.informativeText = message
    alert.alertStyle = .critical
    alert.addButton(withTitle: "OK")
    alert.runModal()
}

final class CardView: NSView {
    init(fill: NSColor = NSColor.controlBackgroundColor.withAlphaComponent(0.42), border: NSColor = NSColor.separatorColor.withAlphaComponent(0.14)) {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.cornerRadius = 10
        layer?.cornerCurve = .continuous
        layer?.backgroundColor = fill.cgColor
        layer?.borderColor = border.cgColor
        layer?.borderWidth = 0.5
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

final class LauncherWindowController: NSObject, NSWindowDelegate {
    let config: GuardAppConfig
    let summary: GuardAppSummary
    var window: NSWindow?
    var disclosureTargets: [NSUserInterfaceItemIdentifier: NSView] = [:]

    init(config: GuardAppConfig, summary: GuardAppSummary) {
        self.config = config
        self.summary = summary
    }

    func show() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 540),
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
        background.material = .hudWindow
        background.blendingMode = .behindWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = background

        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 10
        root.edgeInsets = NSEdgeInsets(top: 18, left: 20, bottom: 16, right: 20)
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
            window?.orderOut(nil)
            NSApp.run()
        } catch {
            showError(error.localizedDescription)
        }
    }

    @objc func toggleDisclosure(_ sender: NSButton) {
        guard let identifier = sender.identifier, let target = disclosureTargets[identifier] else {
            return
        }
        target.isHidden.toggle()
        sender.title = target.isHidden ? "Show" : "Hide"
        window?.layoutIfNeeded()
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
            icon.widthAnchor.constraint(equalToConstant: 48),
            icon.heightAnchor.constraint(equalToConstant: 48)
        ])

        let title = label("Launch \(config.displayName) with Guard", size: 22, weight: .bold)
        let subtitle = label(
            summary.description.isEmpty ? "Review the locked sandbox before opening the app." : summary.description,
            size: 13,
            weight: .regular,
            color: .secondaryLabelColor
        )

        let titleStack = NSStackView(views: [title, subtitle, makeChipRow()])
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 5

        row.addArrangedSubview(icon)
        row.addArrangedSubview(titleStack)
        return row
    }

    func makeChipRow() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 6
        row.addArrangedSubview(chip("Locked", color: statusColor()))
        row.addArrangedSubview(chip(summary.risk.capitalized, color: riskColor()))
        row.addArrangedSubview(chip(summary.network.mode.capitalized, color: .controlAccentColor))
        if summary.findings.isEmpty {
            row.addArrangedSubview(chip("No warnings", color: .systemGreen))
        } else {
            row.addArrangedSubview(chip("\(summary.findings.count) warning\(summary.findings.count == 1 ? "" : "s")", color: .systemOrange))
        }
        return row
    }

    func makePolicyList() -> NSView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.borderType = .noBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: 330).isActive = true

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
            subtitle: "Only vendor domains are allowed through Guard.",
            values: summary.network.allowedDomains,
            tint: .systemGreen
        ))
        groupStack.addArrangedSubview(separator())
        groupStack.addArrangedSubview(settingsRow(
            symbol: "folder",
            title: "Read Access",
            subtitle: "App bundle and minimal support paths.",
            values: summary.filesystem.allowRead,
            tint: .systemBlue
        ))
        groupStack.addArrangedSubview(separator())
        groupStack.addArrangedSubview(settingsRow(
            symbol: "lock",
            title: "Protected Paths",
            subtitle: "Critical roots and secret writes stay blocked.",
            values: summary.filesystem.denyRead + summary.filesystem.denyWrite,
            tint: .systemOrange
        ))
        groupStack.addArrangedSubview(separator())
        groupStack.addArrangedSubview(settingsRow(
            symbol: summary.findings.isEmpty ? "checkmark.shield" : "exclamationmark.triangle",
            title: "Review",
            subtitle: reviewSubtitle(),
            values: reviewValues(),
            tint: summary.findings.isEmpty ? .systemGreen : .systemOrange,
            initiallyExpanded: true
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
        initiallyExpanded: Bool = true
    ) -> NSView {
        let rowContainer = NSView()
        let stack = paddedStack(in: rowContainer, inset: 12)
        stack.spacing = 7

        let header = NSStackView()
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 10

        let icon = symbolView(symbol, color: tint, size: 17)
        header.addArrangedSubview(icon)

        let labels = NSStackView()
        labels.orientation = .vertical
        labels.spacing = 1
        labels.alignment = .leading
        labels.addArrangedSubview(label(title, size: 14, weight: .semibold))
        labels.addArrangedSubview(label(subtitle, size: 11, weight: .regular, color: .secondaryLabelColor))
        header.addArrangedSubview(labels)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        header.addArrangedSubview(spacer)

        let details = NSStackView()
        details.orientation = .vertical
        details.alignment = .leading
        details.spacing = 5
        details.isHidden = !initiallyExpanded

        let button = NSButton(title: initiallyExpanded ? "Hide" : "Show", target: self, action: #selector(toggleDisclosure(_:)))
        button.bezelStyle = .rounded
        button.controlSize = .small
        let identifier = NSUserInterfaceItemIdentifier(UUID().uuidString)
        button.identifier = identifier
        details.identifier = identifier
        disclosureTargets[identifier] = details
        header.addArrangedSubview(button)

        stack.addArrangedSubview(header)

        let shown = values.isEmpty ? ["None"] : Array(values.prefix(6))
        for value in shown {
            details.addArrangedSubview(valueRow(value, muted: values.isEmpty))
        }
        if values.count > shown.count {
            details.addArrangedSubview(label("+ \(values.count - shown.count) more in the policy file", size: 11, weight: .regular, color: .tertiaryLabelColor))
        }

        let detailsRow = NSStackView()
        detailsRow.orientation = .horizontal
        detailsRow.alignment = .top
        detailsRow.spacing = 10
        let indent = NSView()
        indent.translatesAutoresizingMaskIntoConstraints = false
        indent.widthAnchor.constraint(equalToConstant: 17).isActive = true
        detailsRow.addArrangedSubview(indent)
        detailsRow.addArrangedSubview(details)
        stack.addArrangedSubview(detailsRow)
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

    func valueRow(_ text: String, muted: Bool) -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 6
        row.addArrangedSubview(label("•", size: 11, weight: .regular, color: muted ? .tertiaryLabelColor : .secondaryLabelColor))
        let textLabel = label(text, size: 11, weight: .regular, color: muted ? .tertiaryLabelColor : .labelColor)
        textLabel.lineBreakMode = .byTruncatingMiddle
        row.addArrangedSubview(textLabel)
        return row
    }

    func chip(_ text: String, color: NSColor) -> NSView {
        let view = CardView(fill: color.withAlphaComponent(0.14), border: color.withAlphaComponent(0.30))
        let textLabel = label(text, size: 11, weight: .semibold, color: color)
        textLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textLabel)
        NSLayoutConstraint.activate([
            textLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 8),
            textLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -8),
            textLabel.topAnchor.constraint(equalTo: view.topAnchor, constant: 4),
            textLabel.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -4)
        ])
        return view
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

    func label(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = NSFont.systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byWordWrapping
        return field
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
        return "\(summary.findings.count) policy warning\(summary.findings.count == 1 ? "" : "s") needs review."
    }

    func reviewValues() -> [String] {
        if summary.findings.isEmpty {
            return ["Ready to launch with the locked profile."]
        }
        return summary.findings.map { finding in
            "[\(finding.severity)] \(finding.message)"
        }
    }

}

let app = NSApplication.shared
app.setActivationPolicy(.regular)

do {
    let config = try loadConfig()
    let summary = try loadSummary(config: config)
    let controller = LauncherWindowController(config: config, summary: summary)
    controller.show()
    withExtendedLifetime(controller) {
        app.run()
    }
} catch {
    showError(error.localizedDescription)
}

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

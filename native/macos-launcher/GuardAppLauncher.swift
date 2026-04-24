import AppKit
import Foundation

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
}

struct GuardAskDecision: Encodable {
    let action: String
    let rule: GuardHttpPolicyRule?
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

func runAskNetworkPanel(input: GuardAskNetworkInput) -> GuardAskDecision {
    let target = input.target ?? "\(input.host)\(input.port.map { ":\($0)" } ?? "")"
    let alert = NSAlert()
    alert.messageText = "Allow Network Access?"
    alert.informativeText = "Allow this Guard run to connect to \(target)?\n\nThis decision is temporary for the current run."
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Deny")
    alert.addButton(withTitle: "Allow Once")
    NSApp.activate(ignoringOtherApps: true)
    let response = alert.runModal()
    return GuardAskDecision(action: response == .alertSecondButtonReturn ? "allow" : "deny", rule: nil)
}

func runAskHttpPolicyPanel(input: GuardAskHttpPolicyInput) -> GuardAskDecision {
    let request = input.request
    let alert = NSAlert()
    alert.messageText = "Allow HTTP Request?"
    alert.informativeText = "\(request.method) \(request.host)\(request.path)\n\nChoose the narrowest temporary rule that fits this run."
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Deny")
    alert.addButton(withTitle: "Allow Exact")
    alert.addButton(withTitle: "Allow Path")
    alert.addButton(withTitle: "Allow Domain")
    NSApp.activate(ignoringOtherApps: true)
    switch alert.runModal() {
    case .alertSecondButtonReturn:
        return GuardAskDecision(
            action: "allow",
            rule: GuardHttpPolicyRule(host: request.host, cidr: nil, methods: [request.method], paths: [request.path])
        )
    case .alertThirdButtonReturn:
        return GuardAskDecision(action: "allow", rule: input.suggestedRule)
    case NSApplication.ModalResponse(rawValue: NSApplication.ModalResponse.alertFirstButtonReturn.rawValue + 3):
        return GuardAskDecision(
            action: "allow",
            rule: GuardHttpPolicyRule(host: request.host, cidr: nil, methods: nil, paths: nil)
        )
    default:
        return GuardAskDecision(action: "deny", rule: nil)
    }
}

func runCliAskModeIfNeeded() -> Bool {
    guard CommandLine.arguments.count > 1 else { return false }
    let mode = CommandLine.arguments[1]
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
        emitDecision(GuardAskDecision(action: "deny", rule: nil))
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
    let at: String
    let type: String
    let profile: String
    let projectDir: String
    let host: String
    let target: String
    let result: String
    let detail: String
}

struct GuardDaemonResponse {
    let statusCode: Int
    let data: Data
}

final class GuardDaemonClient {
    let baseURL: URL
    let apiToken: String?
    let timeout: TimeInterval = 0.8

    init?() {
        let env = ProcessInfo.processInfo.environment
        let configured = env["GUARD_DAEMON_URL"] ?? env["GUARDD_URL"]
        let rawURL: String
        if let configured = configured, !configured.isEmpty {
            rawURL = configured
        } else {
            let host = env["GUARDD_HOST"]?.isEmpty == false ? env["GUARDD_HOST"]! : "127.0.0.1"
            let port = env["GUARDD_PORT"]?.isEmpty == false ? env["GUARDD_PORT"]! : "8765"
            rawURL = "http://\(host):\(port)"
        }
        guard let url = URL(string: rawURL) else { return nil }
        baseURL = url
        apiToken = env["GUARDD_API_TOKEN"]?.isEmpty == false ? env["GUARDD_API_TOKEN"] : nil
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

    func postRule(profile: String, field: String, value: String) -> GuardDaemonResponse? {
        request(
            path: "/profiles/\(profile.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? profile)/rules",
            method: "POST",
            body: ["action": "add", "field": field, "value": value]
        )
    }
}

enum MonitorInspectorTab: Int {
    case events = 0
    case rules = 1
    case settings = 2
}

final class MonitorWindowController: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    let config: GuardAppConfig
    var window: NSWindow?
    var events: [GuardMonitorEvent] = []
    var refreshTimer: Timer?
    var selectedEventKey: String?
    let daemonClient = GuardDaemonClient()
    var daemonConnected = false
    var daemonStatusText = "guardd offline"
    var profileSummaryText = "Profile rules unavailable until guardd is reachable."
    var templatesSummaryText = "Templates unavailable until guardd is reachable."
    let tableView = NSTableView()
    let statusLabel = NSTextField(labelWithString: "")
    let daemonStateLabel = NSTextField(labelWithString: "guardd offline")
    let inspectorTabs = NSSegmentedControl(labels: ["Events", "Rules", "Settings"], trackingMode: .selectOne, target: nil, action: nil)
    let inspectorHelpLabel = NSTextField(labelWithString: "Selected Event")
    let inspectorTitleLabel = NSTextField(labelWithString: "No event selected")
    let inspectorBodyLabel = NSTextField(labelWithString: "Select a monitor event to review the destination, result, and rule action that will be applied.")
    let inspectorRuleLabel = NSTextField(labelWithString: "Rule action: unavailable until a network event with a project profile is selected.")
    let inspectorNoteLabel = NSTextField(labelWithString: "Actions update the selected profile from the event project directory.")
    let allowDomainButton = NSButton()
    let denyDomainButton = NSButton()

    init(config: GuardAppConfig) {
        self.config = config
    }

    func show() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 640),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Monitor"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
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
        root.edgeInsets = NSEdgeInsets(top: 22, left: 24, bottom: 18, right: 24)
        root.translatesAutoresizingMaskIntoConstraints = false
        background.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: background.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: background.trailingAnchor),
            root.topAnchor.constraint(equalTo: background.topAnchor),
            root.bottomAnchor.constraint(equalTo: background.bottomAnchor)
        ])

        root.addArrangedSubview(makeHeader())
        root.addArrangedSubview(makeMonitorBody())
        root.addArrangedSubview(makeActionBar())

        self.window = window
        reloadEvents(nil)
        refreshTimer = Timer.scheduledTimer(timeInterval: 2.0, target: self, selector: #selector(reloadEvents(_:)), userInfo: nil, repeats: true)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) {
        refreshTimer?.invalidate()
        NSApp.terminate(nil)
    }

    func makeHeader() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 12

        let icon = NSImageView()
        if #available(macOS 11.0, *) {
            icon.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil)
            icon.contentTintColor = .systemBlue
        } else {
            icon.image = NSImage(named: NSImage.networkName)
        }
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 38),
            icon.heightAnchor.constraint(equalToConstant: 38)
        ])

        let title = label("Guard Monitor", size: 22, weight: .bold)
        let subtitle = label(eventLogPath(), size: 12, weight: .regular, color: .secondaryLabelColor)
        subtitle.lineBreakMode = .byTruncatingMiddle
        daemonStateLabel.font = NSFont.systemFont(ofSize: 11, weight: .medium)
        daemonStateLabel.textColor = .tertiaryLabelColor
        daemonStateLabel.maximumNumberOfLines = 1
        daemonStateLabel.lineBreakMode = .byTruncatingTail
        let labels = NSStackView(views: [title, subtitle, daemonStateLabel])
        labels.orientation = .vertical
        labels.alignment = .leading
        labels.spacing = 3

        row.addArrangedSubview(icon)
        row.addArrangedSubview(labels)
        return row
    }

    func makeMonitorBody() -> NSView {
        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.translatesAutoresizingMaskIntoConstraints = false
        split.heightAnchor.constraint(greaterThanOrEqualToConstant: 460).isActive = true

        let table = makeTable()
        let inspector = makeInspector()
        split.addArrangedSubview(table)
        split.addArrangedSubview(inspector)
        table.widthAnchor.constraint(greaterThanOrEqualToConstant: 650).isActive = true
        inspector.widthAnchor.constraint(equalToConstant: 260).isActive = true
        return split
    }

    func makeTable() -> NSView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.borderType = .lineBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        tableView.headerView = NSTableHeaderView()
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowHeight = 28
        tableView.dataSource = self
        tableView.delegate = self
        tableView.addTableColumn(column("time", title: "Time", width: 170))
        tableView.addTableColumn(column("profile", title: "Profile", width: 90))
        tableView.addTableColumn(column("type", title: "Event", width: 150))
        tableView.addTableColumn(column("target", title: "Target", width: 250))
        tableView.addTableColumn(column("result", title: "Result", width: 90))
        tableView.addTableColumn(column("detail", title: "Detail", width: 220))
        scroll.documentView = tableView
        return scroll
    }

    func makeInspector() -> NSView {
        let card = CardView(fill: NSColor.controlBackgroundColor.withAlphaComponent(0.58), border: NSColor.separatorColor.withAlphaComponent(0.16))
        card.layer?.cornerRadius = 10
        card.layer?.borderWidth = 0.5
        card.translatesAutoresizingMaskIntoConstraints = false

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: card.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: card.trailingAnchor),
            stack.topAnchor.constraint(equalTo: card.topAnchor),
            stack.bottomAnchor.constraint(equalTo: card.bottomAnchor)
        ])

        inspectorTitleLabel.font = NSFont.systemFont(ofSize: 14, weight: .semibold)
        inspectorTitleLabel.textColor = .labelColor
        inspectorTitleLabel.lineBreakMode = .byTruncatingMiddle
        inspectorTitleLabel.maximumNumberOfLines = 2

        inspectorBodyLabel.font = NSFont.systemFont(ofSize: 12)
        inspectorBodyLabel.textColor = .secondaryLabelColor
        inspectorBodyLabel.lineBreakMode = .byWordWrapping
        inspectorBodyLabel.maximumNumberOfLines = 0

        inspectorRuleLabel.font = NSFont.systemFont(ofSize: 12, weight: .medium)
        inspectorRuleLabel.textColor = .secondaryLabelColor
        inspectorRuleLabel.lineBreakMode = .byWordWrapping
        inspectorRuleLabel.maximumNumberOfLines = 0

        inspectorTabs.selectedSegment = MonitorInspectorTab.events.rawValue
        inspectorTabs.target = self
        inspectorTabs.action = #selector(switchInspectorTab(_:))
        inspectorTabs.segmentStyle = .texturedRounded
        inspectorTabs.translatesAutoresizingMaskIntoConstraints = false

        inspectorHelpLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        inspectorHelpLabel.textColor = .tertiaryLabelColor
        inspectorHelpLabel.lineBreakMode = .byTruncatingTail
        inspectorHelpLabel.maximumNumberOfLines = 1

        stack.addArrangedSubview(inspectorTabs)
        stack.addArrangedSubview(inspectorHelpLabel)
        stack.addArrangedSubview(inspectorTitleLabel)
        stack.addArrangedSubview(inspectorBodyLabel)
        stack.addArrangedSubview(separator())
        stack.addArrangedSubview(inspectorRuleLabel)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .vertical)
        stack.addArrangedSubview(spacer)

        inspectorNoteLabel.font = NSFont.systemFont(ofSize: 11)
        inspectorNoteLabel.textColor = .tertiaryLabelColor
        inspectorNoteLabel.maximumNumberOfLines = 0
        inspectorNoteLabel.lineBreakMode = .byWordWrapping
        stack.addArrangedSubview(inspectorNoteLabel)
        return card
    }

    func makeActionBar() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let refresh = NSButton(title: "Refresh", target: self, action: #selector(reloadEvents(_:)))
        refresh.bezelStyle = .rounded
        refresh.keyEquivalent = "r"

        let openLog = NSButton(title: "Reveal Log", target: self, action: #selector(revealLog(_:)))
        openLog.bezelStyle = .rounded

        allowDomainButton.title = "Allow Domain in Profile"
        allowDomainButton.target = self
        allowDomainButton.action = #selector(allowSelectedDomain(_:))
        allowDomainButton.bezelStyle = .rounded
        allowDomainButton.toolTip = "Add the selected host to network.allowedDomains for the selected event profile."

        denyDomainButton.title = "Deny Domain in Profile"
        denyDomainButton.target = self
        denyDomainButton.action = #selector(denySelectedDomain(_:))
        denyDomainButton.bezelStyle = .rounded
        denyDomainButton.toolTip = "Add the selected host to network.deniedDomains for the selected event profile."

        row.addArrangedSubview(statusLabel)
        row.addArrangedSubview(denyDomainButton)
        row.addArrangedSubview(allowDomainButton)
        row.addArrangedSubview(openLog)
        row.addArrangedSubview(refresh)
        updateInspector(nil)
        return row
    }

    @objc func switchInspectorTab(_ sender: NSSegmentedControl) {
        updateInspector(currentSelectedEvent())
    }

    func column(_ identifier: String, title: String, width: CGFloat) -> NSTableColumn {
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
        column.title = title
        column.width = width
        column.minWidth = 60
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

    func eventLogPath() -> String {
        if let path = config.eventLogPath, !path.isEmpty {
            return path
        }
        return NSString(string: "~/Library/Application Support/guard/events.jsonl").expandingTildeInPath
    }

    func selectedInspectorTab() -> MonitorInspectorTab {
        MonitorInspectorTab(rawValue: inspectorTabs.selectedSegment) ?? .events
    }

    func currentSelectedEvent() -> GuardMonitorEvent? {
        let row = tableView.selectedRow
        guard row >= 0 && row < events.count else { return nil }
        return events[row]
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
            "Event log: \(eventLogPath())",
            "Ask UI: native AppKit panels for this launcher",
            "Daemon: \(daemonStatusText)",
            "Daemon URL: \(daemonURLHint())",
            "TLS inspection: \(tlsInspectionStatus())",
            "Templates: \(templatesSummaryText)"
        ].joined(separator: "\n")
    }

    @objc func revealLog(_ sender: Any?) {
        let url = URL(fileURLWithPath: eventLogPath())
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    @objc func allowSelectedDomain(_ sender: Any?) {
        addSelectedDomain(to: "network.allowedDomains")
    }

    @objc func denySelectedDomain(_ sender: Any?) {
        addSelectedDomain(to: "network.deniedDomains")
    }

    func selectedNetworkEvent() -> GuardMonitorEvent? {
        let row = tableView.selectedRow
        guard row >= 0 && row < events.count else {
            statusLabel.stringValue = "Select a network event first."
            return nil
        }
        let event = events[row]
        guard !event.host.isEmpty else {
            statusLabel.stringValue = "Selected event has no domain."
            return nil
        }
        guard daemonConnected || !event.projectDir.isEmpty else {
            statusLabel.stringValue = "Selected event has no project profile."
            return nil
        }
        return event
    }

    func eventKey(_ event: GuardMonitorEvent) -> String {
        [event.at, event.type, event.profile, event.target, event.result, event.detail].joined(separator: "|")
    }

    func ruleReady(_ event: GuardMonitorEvent?) -> Bool {
        guard let event = event else { return false }
        return !event.host.isEmpty && (daemonConnected || !event.projectDir.isEmpty)
    }

    func updateInspector(_ event: GuardMonitorEvent?) {
        if selectedInspectorTab() == .settings {
            inspectorHelpLabel.stringValue = "Settings"
            inspectorTitleLabel.stringValue = "Monitor Status"
            inspectorBodyLabel.stringValue = settingsBodyText()
            inspectorRuleLabel.stringValue = "Simple per-run mode remains usable without a daemon. Guard.app and guardd can add persistent rules, richer alerts, and shared event history when installed."
            inspectorNoteLabel.stringValue = "Read-only status from launcher config, environment, and recent monitor events."
            allowDomainButton.isEnabled = false
            denyDomainButton.isEnabled = false
            return
        }

        if selectedInspectorTab() == .rules {
            inspectorHelpLabel.stringValue = "Rules"
            inspectorTitleLabel.stringValue = event?.target.isEmpty == false ? event?.target ?? "No event selected" : "No event selected"
            if let event = event {
                inspectorBodyLabel.stringValue = [
                    "Profile: \(event.profile.isEmpty ? "guard" : event.profile)",
                    "Destination: \(event.host.isEmpty ? "none" : event.host)",
                    "Project: \(event.projectDir.isEmpty ? "not recorded" : event.projectDir)",
                    "Loaded rules: \(profileSummaryText)"
                ].joined(separator: "\n")
            } else {
                inspectorBodyLabel.stringValue = [
                    "Select a network event to preview the profile rule actions.",
                    "Loaded rules: \(profileSummaryText)"
                ].joined(separator: "\n")
            }
            if ruleReady(event), let event = event {
                inspectorRuleLabel.stringValue = "Available actions: allow or deny \(event.host) in the selected profile."
                inspectorNoteLabel.stringValue = daemonConnected ? "Actions update the selected profile through guardd." : "Actions update the selected profile from the event project directory."
                allowDomainButton.isEnabled = true
                denyDomainButton.isEnabled = true
            } else {
                inspectorRuleLabel.stringValue = "Rule actions need a selected event with both a destination host and project directory."
                inspectorNoteLabel.stringValue = "Select a complete event before changing profile rules."
                allowDomainButton.isEnabled = false
                denyDomainButton.isEnabled = false
            }
            return
        }

        inspectorHelpLabel.stringValue = "Selected Event"
        inspectorNoteLabel.stringValue = "Actions update the selected profile from the event project directory."
        guard let event = event else {
            inspectorTitleLabel.stringValue = "No event selected"
            inspectorBodyLabel.stringValue = "Select a monitor event to review the destination, result, and rule action that will be applied."
            inspectorRuleLabel.stringValue = "Rule action: unavailable until a network event with a project profile is selected."
            allowDomainButton.isEnabled = false
            denyDomainButton.isEnabled = false
            return
        }

        inspectorTitleLabel.stringValue = event.target.isEmpty ? event.type : event.target
        inspectorBodyLabel.stringValue = [
            "Time: \(event.at.isEmpty ? "unknown" : event.at)",
            "Event: \(event.type)",
            "Profile: \(event.profile.isEmpty ? "guard" : event.profile)",
            "Result: \(event.result.isEmpty ? "not recorded" : event.result)",
            "Detail: \(event.detail.isEmpty ? "none" : event.detail)"
        ].joined(separator: "\n")

        if ruleReady(event) {
            inspectorRuleLabel.stringValue = daemonConnected
                ? "Rule action: add \(event.host) to the selected profile through guardd."
                : "Rule action: add \(event.host) to the selected profile from \(event.projectDir)."
            allowDomainButton.isEnabled = true
            denyDomainButton.isEnabled = true
        } else if event.host.isEmpty {
            inspectorRuleLabel.stringValue = "Rule action: unavailable because this event has no destination host."
            allowDomainButton.isEnabled = false
            denyDomainButton.isEnabled = false
        } else {
            inspectorRuleLabel.stringValue = "Rule action: unavailable because this event has no project directory."
            allowDomainButton.isEnabled = false
            denyDomainButton.isEnabled = false
        }
    }

    func addSelectedDomain(to field: String) {
        guard let event = selectedNetworkEvent() else { return }
        let profile = event.profile.isEmpty ? "guard" : event.profile
        if daemonConnected, let response = daemonClient?.postRule(profile: profile, field: field, value: event.host) {
            if (200..<300).contains(response.statusCode) {
                statusLabel.stringValue = "Added \(event.host) to \(field) via guardd."
                loadDaemonPolicyState(profile: profile)
                updateInspector(event)
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
            event.host
        ]
        let stderr = Pipe()
        process.standardError = stderr
        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                statusLabel.stringValue = "Added \(event.host) to \(field) via guard CLI."
            } else {
                let data = stderr.fileHandleForReading.readDataToEndOfFile()
                let message = String(data: data, encoding: .utf8) ?? "Rule update failed."
                statusLabel.stringValue = message.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        } catch {
            statusLabel.stringValue = error.localizedDescription
        }
    }

    @objc func reloadEvents(_ sender: Any?) {
        let previousKey = selectedEventKey
        let loaded = loadEvents()
        events = Array(loaded.prefix(250))
        tableView.reloadData()
        if let previousKey = previousKey, let index = events.firstIndex(where: { eventKey($0) == previousKey }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            updateInspector(events[index])
        } else {
            selectedEventKey = nil
            updateInspector(nil)
        }
        statusLabel.stringValue = "\(events.count) recent event\(events.count == 1 ? "" : "s") · \(daemonStatusText) · auto-refresh on"
    }

    func loadEvents() -> [GuardMonitorEvent] {
        if let daemonEvents = loadDaemonEvents() {
            return daemonEvents
        }
        daemonConnected = false
        daemonStatusText = "guardd offline; showing local JSONL"
        daemonStateLabel.stringValue = daemonStatusText
        daemonStateLabel.textColor = .tertiaryLabelColor
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
        daemonStatusText = "guardd connected"
        daemonStateLabel.stringValue = daemonStatusText
        daemonStateLabel.textColor = .systemGreen
        loadDaemonPolicyState(profile: config.profile)
        return rawEvents.map { event(from: $0) }
    }

    func loadDaemonPolicyState(profile: String) {
        guard daemonConnected, let client = daemonClient else {
            profileSummaryText = "Profile rules unavailable until guardd is reachable."
            templatesSummaryText = "Templates unavailable until guardd is reachable."
            return
        }

        if let profileJSON = client.getJSON(path: "/profiles/\(profile.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? profile)") {
            profileSummaryText = summarizeProfile(profileJSON)
        } else {
            profileSummaryText = "Profile \(profile) not loaded from guardd."
        }

        if let templatesJSON = client.getJSON(path: "/templates") {
            templatesSummaryText = summarizeTemplates(templatesJSON)
        } else {
            templatesSummaryText = "Template list not loaded from guardd."
        }
    }

    func summarizeProfile(_ json: [String: Any]) -> String {
        let config = json["config"] as? [String: Any] ?? json
        let network = config["network"] as? [String: Any] ?? [:]
        let allowed = network["allowedDomains"] as? [Any] ?? []
        let denied = network["deniedDomains"] as? [Any] ?? []
        let httpRules = network["httpRules"] as? [Any] ?? []
        let source = json["source"] as? String ?? "profile"
        return "\(source): \(allowed.count) allowed, \(denied.count) denied, \(httpRules.count) HTTP rule\(httpRules.count == 1 ? "" : "s")"
    }

    func summarizeTemplates(_ json: [String: Any]) -> String {
        guard let templates = json["templates"] as? [[String: Any]] else {
            return "no templates reported"
        }
        let names = templates.compactMap { $0["name"] as? String }.prefix(3).joined(separator: ", ")
        let suffix = templates.count > 3 ? ", +\(templates.count - 3) more" : ""
        return templates.isEmpty ? "no templates reported" : "\(templates.count) available: \(names)\(suffix)"
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
        let target = host.isEmpty ? command : "\(host)\(port.isEmpty ? "" : ":\(port)")"
        let result: String
        if type == "network.decision" {
            result = (json["allowed"] as? Bool ?? false) ? "allow" : "deny"
        } else if let code = json["code"] {
            result = "exit \(code)"
        } else {
            result = ""
        }
        let detailParts = [
            json["backend"] as? String,
            json["reason"] as? String,
            json["method"] as? String,
            json["path"] as? String
        ].compactMap { $0 }.filter { !$0.isEmpty }
        return GuardMonitorEvent(
            at: json["at"] as? String ?? "",
            type: type,
            profile: json["profile"] as? String ?? "",
            projectDir: json["projectDir"] as? String ?? "",
            host: host,
            target: target,
            result: result,
            detail: detailParts.joined(separator: " ")
        )
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        events.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < events.count else { return nil }
        let event = events[row]
        let id = tableColumn?.identifier.rawValue ?? ""
        let text: String
        switch id {
        case "time": text = event.at
        case "profile": text = event.profile
        case "type": text = event.type
        case "target": text = event.target
        case "result": text = event.result
        case "detail": text = event.detail
        default: text = ""
        }
        let cell = NSTableCellView()
        let label = NSTextField(labelWithString: text)
        label.lineBreakMode = .byTruncatingMiddle
        label.font = NSFont.systemFont(ofSize: 12)
        if id == "result" {
            label.textColor = text == "deny" ? .systemRed : text == "allow" ? .systemGreen : .secondaryLabelColor
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

    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = tableView.selectedRow
        guard row >= 0 && row < events.count else {
            selectedEventKey = nil
            updateInspector(nil)
            return
        }
        let event = events[row]
        selectedEventKey = eventKey(event)
        if daemonConnected {
            loadDaemonPolicyState(profile: event.profile.isEmpty ? "guard" : event.profile)
        }
        updateInspector(event)
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
app.setActivationPolicy(.regular)

if runCliAskModeIfNeeded() {
    exit(0)
}

do {
    let config = try loadConfig()
    if config.mode == "monitor" {
        let controller = MonitorWindowController(config: config)
        controller.show()
        withExtendedLifetime(controller) {
            app.run()
        }
    } else {
        let summary = try loadSummary(config: config)
        let controller = LauncherWindowController(config: config, summary: summary)
        controller.show()
        withExtendedLifetime(controller) {
            app.run()
        }
    }
} catch {
    showError(error.localizedDescription)
}

import AppKit
import Darwin
import Foundation

extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
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

final class GuardApplicationDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

func installMainMenu(appName: String) {
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
    fileItem.submenu = fileMenu
    mainMenu.addItem(fileItem)

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
    var selectedChoice: GuardPromptChoice = .deny
    var detailsView: NSView?
    var detailsButton: NSButton?

    init(
        titleText: String,
        actor: String,
        destination: String,
        context: String,
        scopeRows: [(String, String)],
        detailRows: [(String, String)],
        actions: [(String, GuardPromptChoice, Bool)]
    ) {
        self.titleText = titleText
        self.actor = actor
        self.destination = destination
        self.context = context
        self.scopeRows = scopeRows
        self.detailRows = detailRows
        self.actions = actions
    }

    func run() -> GuardPromptChoice {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 430),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.title = "Guard Connection"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.delegate = self

        let background = NSVisualEffectView()
        background.material = .hudWindow
        background.blendingMode = .behindWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView = background

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .width
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 20, left: 24, bottom: 18, right: 24)
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
        NSApp.stopModal()
    }

    @objc func toggleDetails(_ sender: NSButton) {
        guard let detailsView else { return }
        detailsView.isHidden.toggle()
        sender.title = detailsView.isHidden ? "Details" : "Hide Details"
    }

    func makeHeader() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 14

        let iconWrap = NSView()
        iconWrap.wantsLayer = true
        iconWrap.layer?.cornerRadius = 10
        iconWrap.layer?.cornerCurve = .continuous
        iconWrap.layer?.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.16).cgColor
        iconWrap.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            iconWrap.widthAnchor.constraint(equalToConstant: 46),
            iconWrap.heightAnchor.constraint(equalToConstant: 46)
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
            icon.widthAnchor.constraint(equalToConstant: 24),
            icon.heightAnchor.constraint(equalToConstant: 24)
        ])

        let title = promptLabel(titleText, size: 20, weight: .bold)
        let subtitle = promptLabel(context, size: 12, weight: .regular, color: .secondaryLabelColor)
        subtitle.maximumNumberOfLines = 2

        let actorLine = makeKeyValueLine("Actor", actor, strong: true)
        let targetLine = makeKeyValueLine("Destination", destination, strong: true)

        let text = NSStackView(views: [title, subtitle, actorLine, targetLine])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 5

        row.addArrangedSubview(iconWrap)
        row.addArrangedSubview(text)
        return row
    }

    func makeScopePanel() -> NSView {
        let container = promptCard()
        let stack = paddedPromptStack(in: container, inset: 12)
        stack.spacing = 8

        let heading = promptLabel("Rule Preview", size: 12, weight: .semibold, color: .secondaryLabelColor)
        stack.addArrangedSubview(heading)
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
        row.spacing = 8

        let details = NSButton(title: "Details", target: self, action: #selector(toggleDetails(_:)))
        details.bezelStyle = .rounded
        detailsButton = details
        row.addArrangedSubview(details)

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)

        for (index, action) in actions.enumerated() {
            let button = NSButton(title: action.0, target: self, action: #selector(chooseAction(_:)))
            button.bezelStyle = .rounded
            button.tag = index
            button.setContentHuggingPriority(.required, for: .horizontal)
            if action.2 {
                button.keyEquivalent = "\r"
            }
            if action.1 == .deny {
                button.hasDestructiveAction = true
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
        keyLabel.widthAnchor.constraint(equalToConstant: 86).isActive = true

        let valueLabel = promptLabel(value.isEmpty ? "Unknown" : value, size: strong ? 13 : 12, weight: strong ? .semibold : .regular)
        valueLabel.lineBreakMode = .byTruncatingMiddle
        valueLabel.maximumNumberOfLines = 1

        row.addArrangedSubview(keyLabel)
        row.addArrangedSubview(valueLabel)
        return row
    }

    func promptCard() -> NSView {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.cornerRadius = 10
        view.layer?.cornerCurve = .continuous
        view.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.58).cgColor
        view.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.18).cgColor
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
    let actor = input.command?.isEmpty == false ? input.command! : "Guard run"
    let controller = GuardConnectionPromptController(
        titleText: "Connection Request",
        actor: actor,
        destination: target,
        context: "A guarded process wants to open a network connection. This prompt only affects the current run.",
        scopeRows: [
            ("Action", "Allow or deny this exact connection"),
            ("Lifetime", "Once for this run"),
            ("Profile", input.profile ?? "guard")
        ],
        detailRows: [
            ("Host", input.host),
            ("Port", input.port.map { "\($0)" } ?? "default"),
            ("Project", input.projectDir ?? "Unknown"),
            ("Run", input.runDir ?? "Unknown")
        ],
        actions: [
            ("Deny", .deny, false),
            ("Allow Once", .allowOnce, true)
        ]
    )
    return GuardAskDecision(action: controller.run() == .allowOnce ? "allow" : "deny", rule: nil)
}

func runAskHttpPolicyPanel(input: GuardAskHttpPolicyInput) -> GuardAskDecision {
    let request = input.request
    let actor = input.command?.isEmpty == false ? input.command! : "Guard run"
    let suggestedPaths = input.suggestedRule.paths?.joined(separator: ", ") ?? "Any path"
    let suggestedMethods = input.suggestedRule.methods?.joined(separator: ", ") ?? "Any method"
    let controller = GuardConnectionPromptController(
        titleText: "HTTP Policy Request",
        actor: actor,
        destination: "\(request.method) \(request.host)\(request.path)",
        context: "The proxy intercepted an HTTP request that needs a policy decision. Choose the narrowest rule that fits this workflow.",
        scopeRows: [
            ("Exact", "\(request.method) \(request.path) on \(request.host)"),
            ("Path Rule", "\(suggestedMethods) \(suggestedPaths)"),
            ("Domain Rule", "Any HTTP request to \(request.host)"),
            ("Lifetime", "Temporary for this run")
        ],
        detailRows: [
            ("Host", request.host),
            ("Method", request.method),
            ("Path", request.path),
            ("Profile", input.profile ?? "guard"),
            ("Project", input.projectDir ?? "Unknown"),
            ("Run", input.runDir ?? "Unknown")
        ],
        actions: [
            ("Deny", .deny, false),
            ("Allow Exact", .allowExact, true),
            ("Allow Path", .allowPath, false),
            ("Allow Domain", .allowDomain, false)
        ]
    )
    switch controller.run() {
    case .allowExact:
        return GuardAskDecision(
            action: "allow",
            rule: GuardHttpPolicyRule(host: request.host, cidr: nil, methods: [request.method], paths: [request.path])
        )
    case .allowPath:
        return GuardAskDecision(action: "allow", rule: input.suggestedRule)
    case .allowDomain:
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
        widthAnchor.constraint(equalToConstant: 54).isActive = true
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
        let symbolColor = selected ? NSColor.white : color
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

    func postAlertDecision(profile: String, host: String, port: Int = 0, action: String, duration: String, ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = [
            "profile": profile,
            "host": host,
            "port": port,
            "action": action,
            "duration": duration,
            "reason": "monitor-alert-action"
        ]
        if let ifMatch, !ifMatch.isEmpty { body["ifMatch"] = ifMatch }
        return request(path: "/alerts/decision", method: "POST", body: body)
    }

    func resolvePendingAlert(alertId: String, action: String, duration: String, ifMatch: String? = nil) -> GuardDaemonResponse? {
        var body: [String: Any] = [
            "action": action,
            "duration": duration,
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
    let kind: String
    let action: String
    let scope: String
    let detail: String
    let enabled: Bool
    let source: String
    let field: String
    let value: Any
}

struct MonitorTemplateRow {
    let name: String
    let description: String
    let detail: String
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
        heightAnchor.constraint(equalToConstant: 42).isActive = true
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

final class RulesWindowController: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    weak var parent: MonitorWindowController?
    let client: GuardDaemonClient?
    let tableView = NSTableView()
    let searchField = NSSearchField()
    let profilePopup = NSPopUpButton()
    let filterControl = NSSegmentedControl(labels: ["All", "Allow", "Deny", "HTTP", "Off"], trackingMode: .selectOne, target: nil, action: nil)
    let statusLabel = NSTextField(labelWithString: "")
    var window: NSWindow?
    var profileNames: [String]
    var selectedProfile: String
    var rows: [MonitorRuleRow]
    var renderedRows: [MonitorRuleRow] = []

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
        window.titlebarAppearsTransparent = true
        window.delegate = self
        window.center()

        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 8
        root.edgeInsets = NSEdgeInsets(top: 12, left: 10, bottom: 8, right: 10)
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

        root.addArrangedSubview(makeHeader())
        root.addArrangedSubview(makeToolbar())
        root.addArrangedSubview(makeTable())
        root.addArrangedSubview(makeActionBar())

        self.window = window
        syncProfilePopup()
        renderRows()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowWillClose(_ notification: Notification) {
        parent?.rulesWindowController = nil
    }

    func makeHeader() -> NSView {
        let title = NSTextField(labelWithString: "Rules")
        title.font = NSFont.systemFont(ofSize: 22, weight: .bold)
        let subtitle = NSTextField(labelWithString: "Profile rules, disabled rules, HTTP filters, and rule sources.")
        subtitle.font = NSFont.systemFont(ofSize: 12)
        subtitle.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [title, subtitle])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        return stack
    }

    func makeToolbar() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8

        searchField.placeholderString = "Search rules"
        searchField.target = self
        searchField.action = #selector(filterChanged(_:))
        searchField.translatesAutoresizingMaskIntoConstraints = false
        searchField.widthAnchor.constraint(equalToConstant: 260).isActive = true

        profilePopup.addItems(withTitles: profileNames)
        profilePopup.selectItem(withTitle: selectedProfile)
        profilePopup.target = self
        profilePopup.action = #selector(profileChanged(_:))

        filterControl.selectedSegment = 0
        filterControl.target = self
        filterControl.action = #selector(filterChanged(_:))

        let refresh = NSButton(title: "Refresh", target: self, action: #selector(refresh(_:)))
        refresh.bezelStyle = .rounded

        row.addArrangedSubview(searchField)
        row.addArrangedSubview(profilePopup)
        row.addArrangedSubview(filterControl)
        row.addArrangedSubview(refresh)
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
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
        scroll.borderType = .lineBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 430).isActive = true
        tableView.headerView = NSTableHeaderView()
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.allowsMultipleSelection = true
        tableView.rowHeight = 30
        tableView.dataSource = self
        tableView.delegate = self
        tableView.addTableColumn(column("state", "State", 70))
        tableView.addTableColumn(column("action", "Action", 80))
        tableView.addTableColumn(column("kind", "Kind", 90))
        tableView.addTableColumn(column("scope", "Scope", 260))
        tableView.addTableColumn(column("detail", "Detail", 300))
        tableView.addTableColumn(column("source", "Source", 120))
        scroll.documentView = tableView
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

    @objc func filterChanged(_ sender: Any?) {
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
            return matchesSearch && matchesFilter
        }
        tableView.reloadData()
        statusLabel.stringValue = "\(renderedRows.count) visible of \(rows.count) rules."
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
        window?.close()
    }

    func mutateSelected(action: String) {
        mutateRules(selectedRules(), action: action)
    }

    func mutateRules(_ targetRows: [MonitorRuleRow], action: String) {
        guard !targetRows.isEmpty, let client = client else {
            statusLabel.stringValue = "guardd must be connected before editing rules."
            return
        }
        var changed = 0
        for row in targetRows {
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
        statusLabel.stringValue = "\(action.capitalized) \(changed) rule\(changed == 1 ? "" : "s")."
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
        case "source": text = rule.source
        default: text = ""
        }
        let cell = NSTableCellView()
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
}

final class MonitorWindowController: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    let config: GuardAppConfig
    var window: NSWindow?
    var events: [GuardMonitorEvent] = []
    var activityRows: [MonitorActivityRow] = []
    var refreshTimer: Timer?
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
    var recentAllowedCount = 0
    var recentDeniedCount = 0
    var recentTopHost = "-"
    var pendingAlertCount = 0
    var pendingAlertSummaryText = "Pending alerts unavailable until guardd is reachable."
    var profileRiskLabel = "risk unknown"
    var expandedApps = Set<String>()
    var didAutoExpandActivityGroups = false
    var rulesWindowController: RulesWindowController?
    let trafficSparkline = TrafficSparklineView()
    let tableView = NSTableView()
    let monitorSearchField = NSSearchField()
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
    var templatesWindow: NSWindow?
    var logWindow: NSWindow?
    var logTextView: NSTextView?
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
        window.isMovableByWindowBackground = true
        window.minSize = NSSize(width: 700, height: 440)
        window.isRestorable = false
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
        root.alignment = .width
        root.spacing = 8
        root.edgeInsets = NSEdgeInsets(top: 44, left: 12, bottom: 8, right: 12)
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
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillTerminate(_:)),
            name: NSApplication.willTerminateNotification,
            object: nil
        )
        autoStartDaemonIfNeeded()
        reloadEvents(nil)
        refreshTimer = Timer.scheduledTimer(timeInterval: 2.0, target: self, selector: #selector(reloadEvents(_:)), userInfo: nil, repeats: true)
        applyPreferredWindowFrame(window)
        window.makeKeyAndOrderFront(nil)
        DispatchQueue.main.async {
            self.applyPreferredWindowFrame(window)
        }
        NSApp.activate(ignoringOtherApps: true)
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
        stopManagedDaemon()
    }

    func windowDidResize(_ notification: Notification) {
        resizeActivityColumns()
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
        container.heightAnchor.constraint(equalToConstant: 76).isActive = true

        let rates = NSStackView()
        rates.orientation = .horizontal
        rates.alignment = .centerY
        rates.spacing = 8
        footerAllowedRateLabel.stringValue = "allowed \(recentAllowedCount)"
        footerDeniedRateLabel.stringValue = "denied \(recentDeniedCount)"
        rates.addArrangedSubview(ratePill(symbol: "arrow.up", field: footerAllowedRateLabel, tint: .systemPurple))
        rates.addArrangedSubview(ratePill(symbol: "xmark", field: footerDeniedRateLabel, tint: .systemRed))

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        rates.addArrangedSubview(spacer)
        let windowLabel = label("Policy decisions", size: 11, weight: .medium, color: .tertiaryLabelColor)
        rates.addArrangedSubview(windowLabel)

        container.addArrangedSubview(rates)
        container.addArrangedSubview(trafficSparkline)
        return container
    }

    func makeMonitorToolbar() -> NSView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8

        monitorSearchField.placeholderString = "Search"
        monitorSearchField.target = self
        monitorSearchField.action = #selector(filterMonitorRows(_:))
        monitorSearchField.controlSize = .small
        monitorSearchField.font = NSFont.systemFont(ofSize: 12)
        monitorSearchField.translatesAutoresizingMaskIntoConstraints = false
        monitorSearchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
        monitorSearchField.sendsSearchStringImmediately = true

        monitorFilterControl.selectedSegment = 0
        monitorFilterControl.target = self
        monitorFilterControl.action = #selector(filterMonitorRows(_:))
        monitorFilterControl.segmentStyle = .texturedRounded
        monitorFilterControl.controlSize = .small
        monitorFilterControl.setToolTip("Show all recent activity", forSegment: 0)
        monitorFilterControl.setToolTip("Show network decisions and alerts", forSegment: 1)
        monitorFilterControl.setToolTip("Show denied traffic", forSegment: 2)
        monitorFilterControl.setToolTip("Show filesystem and sandbox activity", forSegment: 3)
        monitorFilterControl.setToolTip("Show pending and resolved alert decisions", forSegment: 4)

        row.addArrangedSubview(monitorSearchField)
        row.addArrangedSubview(monitorFilterControl)
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        row.addArrangedSubview(spacer)
        return row
    }

    func makeTable() -> NSView {
        let scroll = NSScrollView()
        configureOverlayScrollView(scroll)
        scroll.translatesAutoresizingMaskIntoConstraints = false

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
        tableView.addTableColumn(column("app", title: "App / Command", width: 260))
        tableView.addTableColumn(column("destination", title: "Destination", width: 280))
        tableView.addTableColumn(column("activity", title: "Policy", width: 360))
        tableView.addTableColumn(column("decision", title: "State", width: 76))
        scroll.documentView = tableView
        DispatchQueue.main.async {
            self.resizeActivityColumns()
        }
        return scroll
    }

    func resizeActivityColumns() {
        guard tableView.numberOfColumns >= 4 else { return }
        let available = tableView.enclosingScrollView?.contentView.bounds.width ?? tableView.bounds.width
        guard available > 0 else { return }

        let decisionWidth: CGFloat = available < 760 ? 66 : 74
        var appWidth = min(max(available * 0.24, 190), 300)
        var destinationWidth = min(max(available * 0.24, 190), 340)
        let activityMinimum: CGFloat = available < 760 ? 170 : 260
        var activityWidth = available - appWidth - destinationWidth - decisionWidth

        if activityWidth < activityMinimum {
            var deficit = activityMinimum - activityWidth
            let appReduction = min(deficit * 0.55, max(0, appWidth - 165))
            appWidth -= appReduction
            deficit -= appReduction
            let destinationReduction = min(deficit, max(0, destinationWidth - 160))
            destinationWidth -= destinationReduction
            activityWidth = max(activityMinimum, available - appWidth - destinationWidth - decisionWidth)
        }

        if appWidth + destinationWidth + activityWidth + decisionWidth > available {
            activityWidth = max(120, available - appWidth - destinationWidth - decisionWidth)
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
            column.minWidth = min(width, column.identifier.rawValue == "activity" ? 160 : 90)
        }
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
            scroll.topAnchor.constraint(equalTo: sidebar.topAnchor, constant: 12),
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
            ("PID", event.pid > 0 ? "\(event.pid)" : "Not recorded"),
            ("Path", event.processPath.isEmpty ? "Not recorded" : event.processPath),
            ("Command", event.command.isEmpty ? "Unknown" : event.command),
            ("Project", event.projectDir.isEmpty ? "Not recorded" : event.projectDir),
            ("Profile", event.profile.isEmpty ? "guard" : event.profile)
        ]))

        inspectorSummaryStack.addArrangedSubview(inspectorSection("Internet Access Policy"))
        inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
            ("Outcome", decisionLabel(for: event).isEmpty ? "managed" : decisionLabel(for: event)),
            ("Reason", humanDecisionReason(event.detail, fallback: activityLabel(for: event))),
            ("Rule Scope", event.host.isEmpty ? "No destination host" : ruleScopePreview(for: event)),
            ("Lifetime", event.expiresAt.isEmpty ? "Current profile/session" : "Expires \(event.expiresAt)")
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
        let summary = projectSummary(for: groupEvents)
        let network = groupEvents.filter { $0.type == "network.decision" || $0.type.hasPrefix("guard.alert.") }
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
                ("Network", summary.network.allowedDomains.isEmpty ? "no allowlist" : "\(summary.network.allowedDomains.count) allowed domains"),
                ("Filesystem", "\(summary.filesystem.allowRead.count) read allows, \(summary.filesystem.allowWrite.count) write allows"),
                ("Protections", "\(summary.filesystem.denyRead.count + summary.filesystem.denyWrite.count) deny rules")
            ], valueTint: summary.findings.isEmpty ? .secondaryLabelColor : .systemOrange))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Allowed Network"))
            for domain in summary.network.allowedDomains.prefix(8) {
                inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "network", text: domain))
            }
            if summary.network.allowedDomains.isEmpty {
                inspectorSummaryStack.addArrangedSubview(detailBlock(["No allowed domains configured."], tint: .tertiaryLabelColor))
            }
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Filesystem Scope"))
            inspectorSummaryStack.addArrangedSubview(detailKeyValueBlock([
                ("Read", compactPolicyList(summary.filesystem.allowRead)),
                ("Write", compactPolicyList(summary.filesystem.allowWrite)),
                ("Denied", compactPolicyList(summary.filesystem.denyRead + summary.filesystem.denyWrite))
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
        let shown = values.prefix(limit).joined(separator: ", ")
        let remaining = values.count - min(values.count, limit)
        return remaining > 0 ? "\(shown), +\(remaining) more" : shown
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
        let summary = projectSummary(for: processEvents)
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
                ("Network", summary.network.allowedDomains.isEmpty ? "no network allowlist" : "\(summary.network.allowedDomains.count) allowed domains"),
                ("Read", compactPolicyList(summary.filesystem.allowRead, limit: 3)),
                ("Write", compactPolicyList(summary.filesystem.allowWrite, limit: 3)),
                ("Protected", compactPolicyList(summary.filesystem.denyRead + summary.filesystem.denyWrite, limit: 3))
            ], valueTint: summary.findings.isEmpty ? .secondaryLabelColor : .systemOrange))
            inspectorSummaryStack.addArrangedSubview(inspectorSection("Allowed Domains"))
            for domain in summary.network.allowedDomains.prefix(6) {
                inspectorSummaryStack.addArrangedSubview(summaryListItem(symbol: "network", text: domain))
            }
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

    func projectSummary(for events: [GuardMonitorEvent]) -> GuardAppSummary? {
        guard let event = events.first(where: { !$0.projectDir.isEmpty }) else { return nil }
        let profile = event.profile.isEmpty ? config.profile : event.profile
        let key = "\(profile)|\(event.projectDir)"
        if let cached = projectSummaryCache[key] {
            return cached
        }
        if let localSummary = projectConfigSummary(for: event) {
            projectSummaryCache[key] = localSummary
            return localSummary
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
                projectSummaryCache[key] = fallback
                return fallback
            }
            let data = stdout.fileHandleForReading.readDataToEndOfFile()
            let summary = try decodeAppSummary(data)
            projectSummaryCache[key] = summary
            return summary
        } catch {
            let fallback = projectConfigSummary(for: event)
            projectSummaryCache[key] = fallback
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
                deniedDomains: network["deniedDomains"] as? [String] ?? [],
                deniedDomainPresets: network["deniedDomainPresets"] as? [String] ?? []
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
                deniedDomains: network["deniedDomains"] as? [String] ?? [],
                deniedDomainPresets: network["deniedDomainPresets"] as? [String] ?? []
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

    func policyTableSummary(_ summary: GuardAppSummary?) -> String? {
        guard let summary else { return nil }
        let network = summary.network.allowedDomains.count
        let read = summary.filesystem.allowRead.count
        let write = summary.filesystem.allowWrite.count
        let protected = summary.filesystem.denyRead.count + summary.filesystem.denyWrite.count
        var parts: [String] = []
        if network > 0 { parts.append("\(network) network rules") }
        if read > 0 || write > 0 { parts.append("\(read) read · \(write) write") }
        if protected > 0 { parts.append("\(protected) protected") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    func isRunLifecycleActivity(_ event: GuardMonitorEvent) -> Bool {
        event.type == "proxy.started" ||
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
        return (status, authority, teamId, identifier)
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
            value.lineBreakMode = .byTruncatingMiddle
            value.maximumNumberOfLines = 2
            value.alignment = .left
            value.toolTip = row.1
            value.translatesAutoresizingMaskIntoConstraints = false
            value.widthAnchor.constraint(lessThanOrEqualToConstant: 330).isActive = true
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

        let refresh = NSButton(title: "Refresh", target: self, action: #selector(reloadEvents(_:)))
        refresh.bezelStyle = .rounded
        refresh.keyEquivalent = "r"
        refresh.controlSize = .small

        let openLog = NSButton(title: "Log", target: self, action: #selector(revealLog(_:)))
        openLog.bezelStyle = .rounded
        openLog.controlSize = .small
        openLog.toolTip = "Open recent Guard event log entries."

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
        row.addArrangedSubview(openLog)
        row.addArrangedSubview(refresh)

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
        statusLabel.stringValue = "\(events.count) recent event\(events.count == 1 ? "" : "s") · \(activityRows.count) visible row\(activityRows.count == 1 ? "" : "s") · \(daemonStatusText)"
    }

    @objc func toggleSelectedActivityGroup(_ sender: Any?) {
        let row = tableView.clickedRow >= 0 ? tableView.clickedRow : tableView.selectedRow
        guard row >= 0, row < activityRows.count, activityRows[row].isGroup else { return }
        toggleActivityGroup(named: activityRows[row].app)
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
        guard row >= 0 && row < activityRows.count else { return nil }
        return activityRows[row].event
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
        let window = utilityWindow(existing: logWindow, title: "Event Log", width: 760, height: 540)
        logWindow = window
        let root = utilityRoot(in: window)
        root.addArrangedSubview(utilityTitle("Event Log", subtitle: eventLogPath()))

        let textView = NSTextView()
        textView.isEditable = false
        textView.isRichText = false
        textView.usesFindBar = true
        textView.drawsBackground = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.textColor = .labelColor
        textView.string = logWindowText()
        logTextView = textView

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.borderType = .lineBorder
        scroll.documentView = textView
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 380).isActive = true
        root.addArrangedSubview(scroll)

        let actions = NSStackView()
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 8
        let status = label("\(events.count) loaded events", size: 12, weight: .regular, color: .secondaryLabelColor)
        status.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let refresh = NSButton(title: "Refresh", target: self, action: #selector(refreshLogWindow(_:)))
        let reveal = NSButton(title: "Reveal File", target: self, action: #selector(revealLogFile(_:)))
        for button in [refresh, reveal] {
            button.bezelStyle = .rounded
            button.controlSize = .small
        }
        actions.addArrangedSubview(status)
        actions.addArrangedSubview(refresh)
        actions.addArrangedSubview(reveal)
        root.addArrangedSubview(actions)

        window.makeKeyAndOrderFront(nil)
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
        let window = utilityWindow(existing: settingsWindow, title: "Settings", width: 620, height: 500)
        settingsWindow = window
        let root = utilityRoot(in: window)
        root.addArrangedSubview(utilityTitle("Settings", subtitle: "Daemon, TLS, Network Extension, and monitor status."))

        let text = NSTextView()
        text.isEditable = false
        text.drawsBackground = false
        text.font = NSFont.systemFont(ofSize: 12)
        text.textColor = .secondaryLabelColor
        text.string = settingsBodyText()
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .lineBorder
        scroll.documentView = text
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true
        root.addArrangedSubview(scroll)

        let actions = NSStackView()
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 8
        for button in [startDaemonButton, stopDaemonButton, enableTLSButton, disableTLSButton, generateTLSCAButton, rotateTLSCAButton, revokeTLSCAButton, syncExtensionButton, invalidateExtensionButton] {
            button.isHidden = false
            actions.addArrangedSubview(button)
        }
        root.addArrangedSubview(actions)
        window.makeKeyAndOrderFront(nil)
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
        guard row >= 0 && row < activityRows.count, let event = activityRows[row].event else {
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
        case "proxy.started": return "proxy ready"
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
        let apps = Set(events.map { appLabel(for: $0) }).count
        let domains = Set(events.compactMap { $0.host.isEmpty ? nil : $0.host }).count
        return "\(apps) app\(apps == 1 ? "" : "s"), \(domains) destination\(domains == 1 ? "" : "s")"
    }

    func monitorSummaryText() -> String {
        let network = events.filter { $0.type == "network.decision" || $0.type.hasPrefix("guard.alert.") }
        let fileEvents = events.filter { isFileActivity($0) }
        let pending = events.filter { $0.type == "guard.alert.pending" || $0.status == "pending" }.count
        let topApps = topCounts(events.map { appLabel(for: $0) }, limit: 4)
        let topHosts = topCounts(events.compactMap { $0.host.isEmpty ? nil : $0.host }, limit: 4)
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
        let profile = event.profile.isEmpty ? "guard" : event.profile
        if daemonConnected, let response = daemonClient?.postRule(profile: profile, field: field, value: event.host, ifMatch: profileVersionText) {
            if (200..<300).contains(response.statusCode) {
                statusLabel.stringValue = "Added \(event.host) to \(field) via guardd."
                loadDaemonPolicyState(profile: profile)
                updateInspector(event)
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
                ifMatch: duration == "forever" ? profileVersionText : nil
            )
        } else {
            response = client.postAlertDecision(
                profile: profile.isEmpty ? "guard" : profile,
                host: event.host,
                port: port,
                action: action,
                duration: duration,
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

    @objc func reloadEvents(_ sender: Any?) {
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
        if let previousRowKey = previousRowKey, let index = activityRows.firstIndex(where: { $0.rowKey == previousRowKey }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            selectedActivityRowKey = activityRows[index].rowKey
            selectedEventKey = activityRows[index].event.map(eventKey)
        } else if let previousKey = previousKey, let index = activityRows.firstIndex(where: { $0.event.map(eventKey) == previousKey }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            selectedActivityRowKey = activityRows[index].rowKey
            selectedEventKey = activityRows[index].event.map(eventKey)
        } else {
            selectedEventKey = nil
            selectedActivityRowKey = nil
            tableView.deselectAll(nil)
        }
        suppressSelectionChange = false
        renderSelectedInspectorIfNeeded(force: sender != nil && !(sender is Timer))
        statusLabel.stringValue = "\(events.count) recent event\(events.count == 1 ? "" : "s") · \(daemonStatusText) · auto-refresh on"
    }

    func rebuildActivityRows(keepSelection: Bool) {
        let previousKey = keepSelection ? selectedEventKey : nil
        let previousRowKey = keepSelection ? selectedActivityRowKey : nil
        activityRows = buildActivityRows(from: filteredEventsForMonitor())
        suppressSelectionChange = true
        tableView.reloadData()
        if let previousRowKey = previousRowKey, let index = activityRows.firstIndex(where: { $0.rowKey == previousRowKey }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            selectedActivityRowKey = activityRows[index].rowKey
            selectedEventKey = activityRows[index].event.map(eventKey)
        } else if let previousKey = previousKey, let index = activityRows.firstIndex(where: { $0.event.map(eventKey) == previousKey }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            selectedActivityRowKey = activityRows[index].rowKey
            selectedEventKey = activityRows[index].event.map(eventKey)
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
        return events.filter { event in
            let filterMatches: Bool
            switch selectedFilter {
            case 1:
                filterMatches = event.type == "network.decision" || event.type.hasPrefix("guard.alert.")
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
            guard !query.isEmpty else { return true }
            let haystack = [
                appLabel(for: event),
                event.host,
                event.target,
                event.type,
                event.result,
                event.detail,
                event.profile,
                event.projectDir
            ].joined(separator: " ").lowercased()
            return haystack.contains(query)
        }
    }

    func updateTrafficSummary() {
        let networkEvents = events.filter { $0.type == "network.decision" }
        recentAllowedCount = networkEvents.filter { $0.result == "allow" }.count
        recentDeniedCount = networkEvents.filter { $0.result == "deny" }.count
        var counts: [String: Int] = [:]
        for event in networkEvents where !event.host.isEmpty {
            counts[event.host, default: 0] += 1
        }
        recentTopHost = counts.sorted { lhs, rhs in lhs.value == rhs.value ? lhs.key < rhs.key : lhs.value > rhs.value }.first?.key ?? "-"
        trafficSummaryLabel.stringValue = "\(recentAllowedCount) allowed · \(recentDeniedCount) denied · \(pendingAlertCount) pending"
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
            return daemonEvents
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
        if let health = client.getJSON(path: "/health") {
            daemonHealthText = summarizeHealth(health)
        }
        loadPendingAlertState(client: client)
        daemonStatusText = managedDaemon == nil ? "guardd connected" : "guardd managed by monitor"
        daemonStateLabel.stringValue = daemonStatusText
        daemonStateLabel.textColor = .systemGreen
        loadDaemonPolicyState(profile: selectedProfileName.isEmpty ? config.profile : selectedProfileName)
        return rawEvents.map { event(from: $0) }
    }

    func loadPendingAlertState(client: GuardDaemonClient) {
        guard let pendingJSON = client.pendingAlerts(limit: 20) else {
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
        let network = config["network"] as? [String: Any] ?? [:]
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
        let target = host.isEmpty ? command : "\(host)\(port.isEmpty ? "" : ":\(port)")"
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
            pid: Int("\(json["pid"] ?? 0)") ?? 0,
            bundleIdentifier: json["bundleIdentifier"] as? String ?? json["bundleId"] as? String ?? "",
            bytesSent: Int("\(json["bytesSent"] ?? json["sentBytes"] ?? json["uploadBytes"] ?? 0)") ?? 0,
            bytesReceived: Int("\(json["bytesReceived"] ?? json["receivedBytes"] ?? json["downloadBytes"] ?? 0)") ?? 0,
            host: host,
            target: target,
            result: result,
            detail: detailParts.joined(separator: " "),
            status: status,
            expiresAt: json["expiresAt"] as? String ?? ""
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
            let summary = projectSummary(for: groupEvents)
            let network = groupEvents.filter { !$0.host.isEmpty }
            let denied = network.filter { $0.result == "deny" }.count
            let allowed = network.filter { $0.result == "allow" }.count
            let domains = Set(network.map { $0.host }).count
            let fileLike = groupEvents.filter { isFileActivity($0) }.count
            let summaryParts = [
                domains == 0 ? nil : "\(domains) destination\(domains == 1 ? "" : "s")",
                network.isEmpty ? nil : "\(allowed) allowed",
                denied == 0 ? nil : "\(denied) denied",
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
            if !expandedApps.contains(appKey) {
                continue
            }

            let visibleEvents = showingFiles
                ? groupEvents
                : groupEvents.filter { !$0.host.isEmpty || $0.type.hasPrefix("guard.alert.") || isRunLifecycleActivity($0) }
            let processGroups = Dictionary(grouping: visibleEvents, by: { processLabel(for: $0) })
            for process in processGroups.keys.sorted(by: sortProcessNames) {
                let processEvents = processGroups[process] ?? []
                let processNetwork = processEvents.filter { !$0.host.isEmpty }
                let hasRunPolicy = processEvents.contains(where: isRunLifecycleActivity)
                if processNetwork.isEmpty && !showingFiles && !hasRunPolicy {
                    continue
                }
                let processDenied = processNetwork.filter { $0.result == "deny" }.count
                let processAllowed = processNetwork.filter { $0.result == "allow" }.count
                let processSummary = projectSummary(for: processEvents) ?? summary
                let processKey = "\(appKey)/process:\(process)"
                rows.append(MonitorActivityRow(
                    isGroup: true,
                    kind: "process",
                    level: 1,
                    rowKey: processKey,
                    app: process,
                    destination: topDestinationSummary(for: processEvents),
                    activity: [
                        processNetwork.isEmpty ? nil : "\(processAllowed) allowed",
                        processDenied == 0 ? nil : "\(processDenied) denied",
                        processSummary.map { "policy: \(policyTableSummary($0) ?? "loaded")" },
                        showingFiles && processEvents.contains(where: isFileActivity) ? "filesystem policy" : nil,
                        processEvents.contains { $0.type == "proxy.started" || !$0.host.isEmpty } ? "proxy/TLS managed" : nil
                    ].compactMap { $0 }.joined(separator: " · "),
                    decision: processDenied > 0 ? "review" : "active",
                    time: shortTime(processEvents.first?.at ?? ""),
                    event: processEvents.first
                ))

                if !expandedApps.contains(processKey) {
                    continue
                }

                let hosts = Dictionary(grouping: processNetwork, by: { hostListLabel(for: $0) })
                for host in hosts.keys.sorted() {
                    let hostEvents = hosts[host] ?? []
                    let hostDenied = hostEvents.contains { $0.result == "deny" }
                    let hostAllowed = hostEvents.filter { $0.result == "allow" }.count
                    let hostBlocked = hostEvents.filter { $0.result == "deny" }.count
                    let representative = hostEvents.first
                    rows.append(MonitorActivityRow(
                        isGroup: false,
                        kind: "destination",
                        level: 2,
                        rowKey: "\(processKey)/host:\(host)",
                        app: host,
                        destination: hostPortLabel(for: representative ?? hostEvents[0]),
                        activity: hostDenied
                            ? "Blocked by network policy · \(hostBlocked) denied"
                            : "Allowed by network policy · \(hostAllowed) allowed",
                        decision: hostDenied ? "deny" : "allow",
                        time: shortTime(representative?.at ?? ""),
                        event: representative
                    ))
                }

                let nonNetwork = showingFiles
                    ? processEvents.filter { $0.host.isEmpty && isFileActivity($0) }
                    : []
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
                    rows.append(MonitorActivityRow(
                        isGroup: false,
                        kind: "destination",
                        level: 1,
                        rowKey: "\(appKey)/host:\(host)",
                        app: host,
                        destination: host,
                        activity: hostDenied ? "Blocked by network policy" : "Allowed by network policy",
                        decision: hostDenied ? "deny" : "allow",
                        time: shortTime(representative?.at ?? ""),
                        event: representative
                    ))
                }
            }
        }
        return rows
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
        let network = groupEvents.filter { $0.type == "network.decision" || $0.type.hasPrefix("guard.alert.") }
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

    func numberOfRows(in tableView: NSTableView) -> Int {
        activityRows.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < activityRows.count else { return nil }
        let activityRow = activityRows[row]
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
        label.lineBreakMode = .byTruncatingMiddle
        label.font = activityRow.isGroup
            ? NSFont.systemFont(ofSize: 12.6, weight: .semibold)
            : NSFont.systemFont(ofSize: 11.5)
        if id == "decision" {
            label.textColor = decisionColor(text)
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

        let canEditNetworkRule = row.kind == "destination" && row.event?.host.isEmpty == false
        if !canEditNetworkRule {
            let state = label(row.decision, size: 10.8, weight: .semibold, color: decisionColor(row.decision))
            state.alignment = .left
            state.translatesAutoresizingMaskIntoConstraints = false
            stack.addArrangedSubview(state)
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 6),
                stack.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor, constant: -8),
                stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            return cell
        }

        let control = HoverPolicySwitch()
        control.selectedSegment = row.decision == "deny" || row.decision == "review" ? 0 : 1
        control.target = self
        control.action = #selector(policySwitchChanged(_:))
        control.tag = rowIndex
        control.toolTip = "Allow or deny this domain"
        stack.addArrangedSubview(control)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: cell.leadingAnchor, constant: 4),
            stack.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -14),
            stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    @objc func policySwitchChanged(_ sender: NSControl) {
        let row = sender.tag
        guard row >= 0, row < activityRows.count, let event = activityRows[row].event, !event.host.isEmpty else { return }
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
            addSelectedDomain(to: "network.deniedDomains")
        } else {
            addSelectedDomain(to: "network.allowedDomains")
        }
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
        stack.spacing = 7
        stack.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(stack)

        let disclosure = NSButton()
        disclosure.title = ""
        disclosure.target = self
        disclosure.action = #selector(toggleActivityGroupButton(_:))
        disclosure.bezelStyle = .disclosure
        disclosure.setButtonType(.pushOnPushOff)
        let expandable = row.isGroup
        disclosure.state = expandedApps.contains(row.rowKey) ? .on : .off
        disclosure.tag = rowIndex
        disclosure.isBordered = true
        disclosure.controlSize = .small
        disclosure.toolTip = expandedApps.contains(row.rowKey) ? "Collapse \(row.app)" : "Expand \(row.app)"
        disclosure.isHidden = !expandable
        disclosure.translatesAutoresizingMaskIntoConstraints = false
        disclosure.widthAnchor.constraint(equalToConstant: 16).isActive = true
        disclosure.heightAnchor.constraint(equalToConstant: 16).isActive = true
        stack.addArrangedSubview(disclosure)

        let imageView = NSImageView()
        imageView.image = iconForActivityRow(row)
        imageView.imageScaling = .scaleProportionallyUpOrDown
        if #available(macOS 11.0, *) {
            imageView.contentTintColor = row.kind == "destination"
                ? decisionColor(row.decision)
                : row.decision == "review" ? .systemOrange : .secondaryLabelColor
        }
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.widthAnchor.constraint(equalToConstant: 20).isActive = true
        imageView.heightAnchor.constraint(equalToConstant: 20).isActive = true
        stack.addArrangedSubview(imageView)

        let name = label(row.app, size: row.isGroup ? 12.8 : 12, weight: row.kind == "destination" ? .medium : .semibold)
        name.lineBreakMode = .byTruncatingTail
        if row.kind == "destination" {
            name.textColor = .labelColor
        }
        stack.addArrangedSubview(name)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 7 + CGFloat(row.level * 22)),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor, constant: -6),
            stack.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    @objc func toggleActivityGroupButton(_ sender: NSButton) {
        let row = sender.tag
        guard row >= 0, row < activityRows.count, activityRows[row].isGroup else { return }
        toggleActivityGroup(row: activityRows[row])
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
        if let index = activityRows.firstIndex(where: { $0.rowKey == key }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        }
    }

    func toggleActivityGroup(row: MonitorActivityRow) {
        didAutoExpandActivityGroups = true
        if expandedApps.contains(row.rowKey) {
            expandedApps.remove(row.rowKey)
        } else {
            expandedApps.insert(row.rowKey)
        }
        rebuildActivityRows(keepSelection: false)
        if let index = activityRows.firstIndex(where: { $0.rowKey == row.rowKey }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        }
    }

    func iconForApp(_ app: String) -> NSImage? {
        let lower = app.lowercased()
        if #available(macOS 11.0, *) {
            let symbol: String
            if lower.contains("packetsafari") || lower.contains("course") {
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
        if row < activityRows.count {
            let activityRow = activityRows[row]
            view.group = activityRow.isGroup
            view.odd = row % 2 == 1
            view.denied = activityRow.isGroup && activityRow.decision == "review"
        }
        return view
    }

    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        row < activityRows.count && activityRows[row].isGroup ? 30 : 23
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
        if lower.contains("pnpm") { return "pnpm" }
        if lower.contains("npm") { return "npm" }
        if lower.contains("node") { return "Node" }
        if lower.contains("git") { return "Git" }
        if lower.contains("curl") { return "curl" }
        if lower.contains("python") { return "Python" }
        if lower.contains("guard") { return "Guard" }
        if !event.profile.isEmpty && event.profile != "guard" {
            return event.profile
        }
        return event.profile.isEmpty ? "Guarded command" : event.profile
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
        guard row >= 0 && row < activityRows.count else {
            selectedEventKey = nil
            selectedActivityRowKey = nil
            renderedInspectorRowKey = nil
            updateInspector(nil)
            return
        }
        let activityRow = activityRows[row]
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
        guard row >= 0 && row < activityRows.count else {
            if force || renderedInspectorRowKey != nil {
                renderedInspectorRowKey = nil
                updateInspector(nil)
            }
            return
        }
        let activityRow = activityRows[row]
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
app.setActivationPolicy(.regular)
installMainMenu(appName: "Guard Monitor")
if let iconURL = Bundle.main.url(forResource: "GuardAppIcon", withExtension: "icns"),
   let bundledIcon = NSImage(contentsOf: iconURL) {
    app.applicationIconImage = bundledIcon
} else if #available(macOS 11.0, *) {
    app.applicationIconImage = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: "Guard")
}

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

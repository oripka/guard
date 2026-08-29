import AppKit
import SwiftUI

private struct GuardMonitorRuntimeConfig: Decodable {
    var guardPath: String
}

enum GuardAccountLoginAction {
    static func scriptContents(guardPath: String, accountId: String) -> String {
        """
        #!/bin/zsh
        action_script="$0"
        trap '/bin/rm -f "$action_script"' EXIT
        \(shellQuote(guardPath)) account login \(shellQuote(accountId))
        exit $?
        """
    }

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

final class AccountsWindowController: NSWindowController {
    private let model: AccountMonitorViewModel

    init() {
        let guardPath = Self.resolveGuardPath()
        self.model = AccountMonitorViewModel(guardPath: guardPath)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 840, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Accounts"
        window.subtitle = "Local account sessions"
        window.setFrameAutosaveName("dev.guard.accounts.window")
        window.titlebarAppearsTransparent = true
        super.init(window: window)
        let root = AccountsView(model: model) { [weak self] account in
            self?.confirmLogin(account)
        }
        window.contentViewController = NSHostingController(rootView: root)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func confirmLogin(_ account: GuardAccountSnapshot) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let preview = try self.model.loginPreview(id: account.id)
                DispatchQueue.main.async {
                    let environmentKeys = preview.environmentKeys.joined(separator: ", ")
                    let alert = NSAlert()
                    alert.alertStyle = .informational
                    alert.messageText = "Login again to \(preview.label)?"
                    alert.informativeText = "Target: \(preview.target.label)\n\n\(preview.argv.joined(separator: " "))\n\nEnvironment values remain hidden; keys: \(environmentKeys.isEmpty ? "none" : environmentKeys)."
                    alert.addButton(withTitle: "Open Terminal")
                    alert.addButton(withTitle: "Cancel")
                    guard alert.runModal() == .alertFirstButtonReturn else { return }
                    do {
                        try self.openLoginTerminal(accountId: account.id)
                    } catch {
                        self.showError(error.localizedDescription)
                    }
                }
            } catch {
                DispatchQueue.main.async { self.showError(error.localizedDescription) }
            }
        }
    }

    private func openLoginTerminal(accountId: String) throws {
        let stateRoot = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Guard/account-actions", isDirectory: true)
        try FileManager.default.createDirectory(at: stateRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stateRoot.path)
        let script = stateRoot.appendingPathComponent("login-\(UUID().uuidString).command")
        let contents = GuardAccountLoginAction.scriptContents(guardPath: model.guardPath, accountId: accountId)
        try contents.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        guard NSWorkspace.shared.open(script) else {
            try? FileManager.default.removeItem(at: script)
            throw NSError(
                domain: "dev.guard.accounts",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "macOS could not open the supervised login terminal."]
            )
        }
    }

    private func showError(_ message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Guard account action failed"
        alert.informativeText = message
        alert.runModal()
    }

    private static func resolveGuardPath() -> String {
        if let url = Bundle.main.url(forResource: "GuardAppConfig", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let config = try? JSONDecoder().decode(GuardMonitorRuntimeConfig.self, from: data),
           FileManager.default.isExecutableFile(atPath: config.guardPath) {
            return config.guardPath
        }
        if let configured = ProcessInfo.processInfo.environment["GUARD_EXECUTABLE"],
           FileManager.default.isExecutableFile(atPath: configured) {
            return configured
        }
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let candidates = [
            cwd.appendingPathComponent("bin/guard").path,
            cwd.appendingPathComponent("../../bin/guard").standardized.path,
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/guard").path
        ]
        return candidates.first(where: FileManager.default.isExecutableFile(atPath:)) ?? "/usr/local/bin/guard"
    }

}

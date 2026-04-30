import AppKit

final class MonitorWindowController: NSWindowController {
    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Guard Monitor"
        window.setFrameAutosaveName("dev.guard.monitor.window")
        super.init(window: window)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func showRules() {
        // Migrated from native/macos-launcher/GuardAppLauncher.swift in phases.
    }

    func showSettings() {
        // Migrated from native/macos-launcher/GuardAppLauncher.swift in phases.
    }
}

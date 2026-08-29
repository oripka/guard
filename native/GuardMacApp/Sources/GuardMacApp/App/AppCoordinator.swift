import AppKit

final class AppCoordinator {
    private let monitorWindowController = MonitorWindowController()
    private lazy var accountsWindowController = AccountsWindowController()
    private lazy var statusItemController = StatusItemController(coordinator: self)

    func startMenuBarOnly() {
        _ = statusItemController
    }

    func showMonitor() {
        _ = statusItemController
        monitorWindowController.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func showRules() {
        monitorWindowController.showRules()
    }

    func showSettings() {
        monitorWindowController.showSettings()
    }

    func showAccounts() {
        accountsWindowController.showWindow(nil)
        accountsWindowController.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

import AppKit

final class StatusItemController {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private weak var coordinator: AppCoordinator?

    init(coordinator: AppCoordinator) {
        self.coordinator = coordinator
        statusItem.button?.title = " Guard"
        statusItem.button?.target = self
        statusItem.button?.action = #selector(openMonitor)
        if #available(macOS 11.0, *) {
            statusItem.button?.image = NSImage(
                systemSymbolName: "network.badge.shield.half.filled",
                accessibilityDescription: "Guard"
            )
        }
    }

    @objc private func openMonitor() {
        coordinator?.showMonitor()
    }
}

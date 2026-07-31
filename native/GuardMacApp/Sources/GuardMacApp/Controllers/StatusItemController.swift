import AppKit

final class StatusItemController {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private weak var coordinator: AppCoordinator?

    init(coordinator: AppCoordinator) {
        self.coordinator = coordinator
        statusItem.button?.title = ""
        statusItem.button?.toolTip = "Guard"
        statusItem.button?.target = self
        statusItem.button?.action = #selector(openMonitor)
        if #available(macOS 11.0, *) {
            let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
                let path = NSBezierPath()
                path.move(to: NSPoint(x: rect.midX, y: rect.maxY - 1.2))
                path.line(to: NSPoint(x: rect.maxX - 3.2, y: rect.maxY - 3.7))
                path.line(to: NSPoint(x: rect.maxX - 3.2, y: rect.midY + 0.7))
                path.curve(
                    to: NSPoint(x: rect.midX, y: rect.minY + 1.1),
                    controlPoint1: NSPoint(x: rect.maxX - 3.2, y: rect.minY + 4.7),
                    controlPoint2: NSPoint(x: rect.midX + 2.2, y: rect.minY + 1.7)
                )
                path.curve(
                    to: NSPoint(x: rect.minX + 3.2, y: rect.midY + 0.7),
                    controlPoint1: NSPoint(x: rect.midX - 2.2, y: rect.minY + 1.7),
                    controlPoint2: NSPoint(x: rect.minX + 3.2, y: rect.minY + 4.7)
                )
                path.line(to: NSPoint(x: rect.minX + 3.2, y: rect.maxY - 3.7))
                path.close()
                path.lineWidth = 1.8
                path.lineJoinStyle = .round
                NSColor.white.setStroke()
                path.stroke()
                return true
            }
            image.isTemplate = false
            statusItem.button?.image = image
            statusItem.button?.imagePosition = .imageOnly
            statusItem.button?.contentTintColor = .white
        }
    }

    @objc private func openMonitor() {
        coordinator?.showMonitor()
    }
}

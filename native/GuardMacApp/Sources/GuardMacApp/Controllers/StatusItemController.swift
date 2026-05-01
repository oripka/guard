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
            statusItem.button?.image = Self.whiteShieldImage()
            statusItem.button?.imagePosition = .imageOnly
            statusItem.button?.contentTintColor = .white
        }
    }

    private static func whiteShieldImage() -> NSImage {
        let image = NSImage(size: NSSize(width: 17, height: 17))
        image.lockFocus()
        NSColor.white.setStroke()
        let path = NSBezierPath()
        path.lineWidth = 1.7
        path.lineJoinStyle = .round
        path.lineCapStyle = .round
        path.move(to: NSPoint(x: 8.5, y: 15.0))
        path.curve(to: NSPoint(x: 3.6, y: 12.8), controlPoint1: NSPoint(x: 6.9, y: 14.4), controlPoint2: NSPoint(x: 5.2, y: 13.7))
        path.line(to: NSPoint(x: 3.6, y: 8.0))
        path.curve(to: NSPoint(x: 8.5, y: 2.0), controlPoint1: NSPoint(x: 3.6, y: 5.0), controlPoint2: NSPoint(x: 6.0, y: 3.0))
        path.curve(to: NSPoint(x: 13.4, y: 8.0), controlPoint1: NSPoint(x: 11.0, y: 3.0), controlPoint2: NSPoint(x: 13.4, y: 5.0))
        path.line(to: NSPoint(x: 13.4, y: 12.8))
        path.curve(to: NSPoint(x: 8.5, y: 15.0), controlPoint1: NSPoint(x: 11.8, y: 13.7), controlPoint2: NSPoint(x: 10.1, y: 14.4))
        path.close()
        path.stroke()
        image.unlockFocus()
        image.isTemplate = false
        return image
    }

    @objc private func openMonitor() {
        coordinator?.showMonitor()
    }
}

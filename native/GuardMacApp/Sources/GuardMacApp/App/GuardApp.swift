import AppKit

@main
final class GuardApp: NSObject, NSApplicationDelegate {
    private var coordinator: AppCoordinator?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let coordinator = AppCoordinator()
        self.coordinator = coordinator
        NSApp.setActivationPolicy(.accessory)
        coordinator.startMenuBarOnly()
    }
}

import Foundation
import NetworkExtension

final class GuardNetworkExtensionProvider: NEFilterDataProvider {
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // The production provider will consult guardd policy here and emit the
        // shared schemaVersion:1 JSONL event contract documented in this folder.
        return .allow()
    }
}


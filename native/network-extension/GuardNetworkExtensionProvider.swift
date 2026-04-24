import Foundation
import CryptoKit
import Network
import NetworkExtension

private let eventSchemaVersion = 1
private let backendName = "network-extension"
private let defaultAppGroupIdentifier = "TEAMID.dev.guard"
private let defaultMaxPolicyAgeSeconds: TimeInterval = 30
private let defaultMaxEventBacklogBytes: UInt64 = 1024 * 1024
private let defaultHeartbeatInterval: TimeInterval = 5
private let defaultReconnectGraceSeconds: TimeInterval = 10
private let tlsClientHelloPeekBytes = 4096

final class GuardNetworkExtensionProvider: NEFilterDataProvider {
    private let policyStore = PolicyStore()
    private let eventWriter = EventWriter()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        policyStore.reloadIfNeeded(force: true)
        eventWriter.configure(sync: policyStore.syncState, force: true)
        eventWriter.emitHeartbeat(policy: policyStore.snapshotMetadata, force: true)
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        eventWriter.configure(sync: policyStore.syncState, force: true)
        eventWriter.emitLifecycle(reason: "stopFilter", detail: "\(reason.rawValue)")
        eventWriter.emitHeartbeat(policy: policyStore.snapshotMetadata, force: true)
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        policyStore.reloadIfNeeded(force: false)
        eventWriter.configure(sync: policyStore.syncState, force: false)

        let context = FlowContext(flow: flow)
        let decision = policyStore.decide(context)
        eventWriter.emitDecision(context: context, decision: decision, policy: policyStore.snapshotMetadata)

        if decision.allowed, let inspection = policyStore.tlsInspection(for: context) {
            eventWriter.emitTLSInspectionRequest(
                context: context,
                inspection: inspection,
                policy: policyStore.snapshotMetadata
            )
            eventWriter.emitHeartbeat(policy: policyStore.snapshotMetadata, force: false)

            if inspection.requiresDataPeek {
                return NEFilterNewFlowVerdict.filterDataVerdict(
                    withFilterInbound: false,
                    peekInboundBytes: 0,
                    filterOutbound: true,
                    peekOutboundBytes: tlsClientHelloPeekBytes
                )
            }
            eventWriter.emitTLSInspectionDecision(
                context: context,
                inspection: inspection,
                policy: policyStore.snapshotMetadata
            )
        }

        eventWriter.emitHeartbeat(policy: policyStore.snapshotMetadata, force: false)

        return decision.allowed ? .allow() : .drop()
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        policyStore.reloadIfNeeded(force: false)
        eventWriter.configure(sync: policyStore.syncState, force: false)

        let context = FlowContext(flow: flow)
        let metadata = TLSClientHelloMetadata(data: readBytes)
        let inspection = policyStore.tlsInspection(for: context)
            ?? TLSInspectionDecision.passthrough(context: context, reason: "tlsInspection-no-active-policy")
        let finalInspection = inspection.withObservedClientHello(metadata, offset: offset)

        eventWriter.emitTLSInspectionDecision(
            context: context,
            inspection: finalInspection,
            policy: policyStore.snapshotMetadata
        )
        eventWriter.emitHeartbeat(policy: policyStore.snapshotMetadata, force: false)

        return finalInspection.allowed ? .allow() : .drop()
    }

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        return .allow()
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        return .allow()
    }
}

private struct PolicySnapshot: Decodable {
    struct Metadata: Decodable {
        let profile: String?
        let projectDir: String?
    }

    struct NetworkPolicy: Decodable {
        let backend: String?
        let allowedDomains: [String]?
        let deniedDomains: [String]?
        let httpRules: [HTTPRule]?
        let tlsInspection: TLSInspection?
    }

    struct HTTPRule: Decodable {
        let id: String?
        let ruleId: String?
        let description: String?
        let host: String?
        let hosts: [String]?
        let methods: [String]?
        let paths: [String]?
        let headers: [String: String]?
        let action: String?

        var effectiveRuleId: String {
            id ?? ruleId ?? stableRuleId(parts: [host, hosts?.joined(separator: ","), methods?.joined(separator: ","), paths?.joined(separator: ",")])
        }

        func matches(_ context: FlowContext) -> Bool {
            guard let host = context.host, hostMatchesAny(host, hostPatterns) else {
                return false
            }
            if let methods, !methods.isEmpty {
                guard let method = context.method?.uppercased(), methods.map({ $0.uppercased() }).contains(method) else {
                    return false
                }
            }
            if let paths, !paths.isEmpty {
                guard let path = context.path else {
                    return false
                }
                return paths.contains { wildcardMatch(path, pattern: $0) }
            }
            return true
        }

        func matchesHost(_ host: String) -> Bool {
            hostMatchesAny(host, hostPatterns)
        }

        private var hostPatterns: [String] {
            var patterns: [String] = []
            if let host {
                patterns.append(host)
            }
            if let hosts {
                patterns.append(contentsOf: hosts)
            }
            return patterns
        }
    }

    struct TLSInspection: Decodable {
        let enabled: Bool?
        let explicit: Bool?
        let mode: String?
        let caScope: String?
        let trustedBy: [String]?
        let userApprovalRequired: Bool?
        let allowWithoutInspection: Bool?
        let failClosedWithoutDecryption: Bool?
        let inspectHosts: [String]?
        let excludeHosts: [String]?

        var effectiveEnabled: Bool {
            enabled == true
        }
    }

    let metadata: Metadata?
    let syncVersion: Int?
    let sequence: Int?
    let generatedAt: String?
    let version: String?
    let profile: String?
    let projectDir: String?
    let network: NetworkPolicy?
}

private struct SyncManifest: Decodable {
    struct Paths: Decodable {
        let policyPath: String
        let eventLogPath: String
        let heartbeatPath: String?
        let daemonEventLogPath: String?
    }

    struct Fallback: Decodable {
        let unavailable: String?
        let stalePolicy: String?
        let eventBackpressure: String?
    }

    let syncVersion: Int
    let sequence: Int
    let generatedAt: String
    let profile: String
    let mode: String?
    let maxPolicyAgeSeconds: Double?
    let maxEventBacklogBytes: UInt64?
    let fallback: Fallback?
    let paths: Paths
    let version: String?
    let policyDigest: String?
    let invalidatedAt: String?
    let invalidateReason: String?
}

private enum PolicyLoadError: LocalizedError {
    case digestMismatch(expected: String, actual: String)

    var errorDescription: String? {
        switch self {
        case .digestMismatch(let expected, let actual):
            return "policy digest mismatch: expected \(expected), actual \(actual)"
        }
    }
}

private struct SnapshotMetadata {
    let profile: String
    let projectDir: String
    let policyPath: String
    let loaded: Bool
    let loadError: String?
    let sequence: Int?
    let stale: Bool
    let fallbackReason: String?
}

private struct RuntimeSyncState {
    let manifestURL: URL?
    let manifestSequence: Int?
    let eventLogURL: URL?
    let heartbeatURL: URL?
    let maxEventBacklogBytes: UInt64
    let fallbackEventBackpressure: String?
}

private struct FlowContext {
    let host: String?
    let port: Int?
    let method: String?
    let path: String?
    let url: String?
    let direction: String
    let flowProtocol: String
    let appBundleIdentifier: String?
    let processPath: String?
    let pid: Int?

    var isHTTPS: Bool {
        flowProtocol == "https" || port == 443
    }

    var hasHTTPRequestMetadata: Bool {
        method != nil || path != nil || url != nil
    }

    init(flow: NEFilterFlow) {
        if let request = FlowContext.value(flow, keys: ["request"]) as? URLRequest {
            let url = request.url
            self.host = normalizeHost(url?.host)
            self.port = url?.port ?? defaultPort(for: url?.scheme)
            self.method = request.httpMethod
            self.path = url?.path.isEmpty == false ? url?.path : "/"
            self.url = url?.absoluteString
            self.flowProtocol = url?.scheme?.lowercased() ?? "http"
        } else {
            let endpoint = FlowContext.remoteEndpoint(from: flow)
            self.host = normalizeHost(endpoint.host)
            self.port = endpoint.port
            self.method = nil
            self.path = nil
            self.url = nil
            self.flowProtocol = FlowContext.socketProtocol(from: flow, port: endpoint.port)
        }

        self.direction = FlowContext.trafficDirection(from: flow)
        self.appBundleIdentifier = FlowContext.stringValue(flow, keys: ["sourceAppIdentifier", "appBundleIdentifier"])
        self.processPath = FlowContext.stringValue(flow, keys: ["sourceAppPath", "processPath"])
        self.pid = FlowContext.intValue(flow, keys: ["sourceAppPid", "pid"])
    }

    private static func remoteEndpoint(from flow: NEFilterFlow) -> (host: String?, port: Int?) {
        guard let raw = value(flow, keys: ["remoteEndpoint", "remoteHostEndpoint"]) else {
            return (nil, nil)
        }
        if let endpoint = raw as? Network.NWEndpoint {
            switch endpoint {
            case .hostPort(let host, let port):
                return ("\(host)", Int(port.rawValue))
            default:
                return (nil, nil)
            }
        }
        return parseEndpointDescription("\(raw)")
    }

    private static func socketProtocol(from flow: NEFilterFlow, port: Int?) -> String {
        if let value = stringValue(flow, keys: ["socketProtocol", "protocol"]), !value.isEmpty {
            return value.lowercased()
        }
        switch port {
        case 80:
            return "http"
        case 443:
            return "https"
        default:
            return "tcp"
        }
    }

    private static func trafficDirection(from flow: NEFilterFlow) -> String {
        guard let value = value(flow, keys: ["direction"]) else {
            return "outbound"
        }
        if let number = value as? NSNumber {
            return number.intValue == NETrafficDirection.inbound.rawValue ? "inbound" : "outbound"
        }
        let description = "\(value)".lowercased()
        return description.contains("inbound") ? "inbound" : "outbound"
    }

    private static func value(_ object: NSObject, keys: [String]) -> Any? {
        for key in keys {
            if object.responds(to: NSSelectorFromString(key)) {
                return object.value(forKey: key)
            }
        }
        return nil
    }

    private static func stringValue(_ object: NSObject, keys: [String]) -> String? {
        guard let raw = value(object, keys: keys) else {
            return nil
        }
        if let data = raw as? Data {
            return String(data: data, encoding: .utf8)
        }
        let text = "\(raw)"
        return text.isEmpty ? nil : text
    }

    private static func intValue(_ object: NSObject, keys: [String]) -> Int? {
        guard let raw = value(object, keys: keys) else {
            return nil
        }
        if let number = raw as? NSNumber {
            return number.intValue
        }
        return Int("\(raw)")
    }
}

private struct Decision {
    let allowed: Bool
    let reason: String
    let ruleId: String?
}

private struct TLSInspectionDecision {
    let requested: Bool
    let allowed: Bool
    let classification: String
    let reason: String
    let mode: String
    let caScope: String
    let trustedBy: [String]
    let userApprovalRequired: Bool
    let requiresDataPeek: Bool
    let decryptedRequestAvailable: Bool
    let httpRulesCount: Int
    let candidateRuleIds: [String]
    let sni: String?
    let tlsVersion: String?
    let clientHelloOffset: Int?

    static func passthrough(context: FlowContext, reason: String) -> TLSInspectionDecision {
        TLSInspectionDecision(
            requested: false,
            allowed: true,
            classification: "passthrough",
            reason: reason,
            mode: "off",
            caScope: "none",
            trustedBy: [],
            userApprovalRequired: false,
            requiresDataPeek: false,
            decryptedRequestAvailable: context.hasHTTPRequestMetadata,
            httpRulesCount: 0,
            candidateRuleIds: [],
            sni: nil,
            tlsVersion: nil,
            clientHelloOffset: nil
        )
    }

    func withObservedClientHello(_ metadata: TLSClientHelloMetadata, offset: Int) -> TLSInspectionDecision {
        let nextClassification = metadata.isTLSClientHello
            ? "https-client-hello-observed"
            : "https-client-hello-unavailable"
        let nextReason = metadata.isTLSClientHello
            ? reason
            : "tlsInspection-client-hello-unavailable"
        return TLSInspectionDecision(
            requested: requested,
            allowed: allowed,
            classification: nextClassification,
            reason: nextReason,
            mode: mode,
            caScope: caScope,
            trustedBy: trustedBy,
            userApprovalRequired: userApprovalRequired,
            requiresDataPeek: false,
            decryptedRequestAvailable: decryptedRequestAvailable,
            httpRulesCount: httpRulesCount,
            candidateRuleIds: candidateRuleIds,
            sni: metadata.serverName,
            tlsVersion: metadata.recordVersion,
            clientHelloOffset: offset
        )
    }
}

private final class PolicyStore {
    private let lock = NSLock()
    private var snapshot: PolicySnapshot?
    private var manifest: SyncManifest?
    private var manifestURLCache: URL?
    private var manifestModified: Date?
    private var manifestLoadError: String?
    private var lastManifestSeenAt: Date?
    private var policyURLCache: URL?
    private var lastModified: Date?
    private var loadError: String?
    private var stalePolicy = false
    private var fallbackReason: String?
    private var lastPolicySequence: Int?

    var snapshotMetadata: SnapshotMetadata {
        lock.lock()
        defer { lock.unlock() }
        return SnapshotMetadata(
            profile: snapshot?.profile ?? snapshot?.metadata?.profile ?? "",
            projectDir: snapshot?.projectDir ?? snapshot?.metadata?.projectDir ?? "",
            policyPath: policyURLLocked()?.path ?? "",
            loaded: snapshot != nil,
            loadError: manifestLoadError ?? loadError,
            sequence: manifest?.sequence ?? snapshot?.sequence ?? lastPolicySequence,
            stale: stalePolicy,
            fallbackReason: fallbackReason
        )
    }

    var syncState: RuntimeSyncState {
        lock.lock()
        defer { lock.unlock() }
        return RuntimeSyncState(
            manifestURL: manifestURLCache ?? manifestURL(),
            manifestSequence: manifest?.sequence,
            eventLogURL: manifest.map { URL(fileURLWithPath: $0.paths.eventLogPath) },
            heartbeatURL: manifest?.paths.heartbeatPath.map { URL(fileURLWithPath: $0) },
            maxEventBacklogBytes: manifest?.maxEventBacklogBytes ?? defaultMaxEventBacklogBytes,
            fallbackEventBackpressure: manifest?.fallback?.eventBackpressure
        )
    }

    func reloadIfNeeded(force: Bool) {
        lock.lock()
        defer { lock.unlock() }

        let manifestChanged = loadManifestIfNeededLocked(force: force)
        if manifest?.invalidatedAt != nil {
            loadError = "extension sync invalidated"
            stalePolicy = true
            fallbackReason = "sync-invalidated:\(manifest?.invalidateReason ?? "manual-invalidation")"
            return
        }
        guard let url = policyURLLocked() else {
            markSyncUnavailableLocked(error: "policy path not configured")
            return
        }

        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let modified = attributes[.modificationDate] as? Date
            let policyPathChanged = policyURLCache != url
            let policySequenceChanged = manifest?.sequence != nil && manifest?.sequence != lastPolicySequence
            if !force, !manifestChanged, !policyPathChanged, !policySequenceChanged, let modified, modified == lastModified {
                updateFreshnessLocked()
                return
            }
            let data = try Data(contentsOf: url)
            if let expectedDigest = manifest?.policyDigest {
                let actualDigest = sha256Digest(data)
                if actualDigest != expectedDigest {
                    throw PolicyLoadError.digestMismatch(expected: expectedDigest, actual: actualDigest)
                }
            }
            snapshot = try JSONDecoder().decode(PolicySnapshot.self, from: data)
            policyURLCache = url
            lastModified = modified
            loadError = nil
            lastPolicySequence = manifest?.sequence ?? snapshot?.sequence ?? lastPolicySequence
            updateFreshnessLocked()
        } catch {
            if snapshot == nil {
                lastModified = nil
            }
            lastModified = nil
            loadError = error.localizedDescription
            stalePolicy = true
            fallbackReason = snapshot == nil ? "policy-load-error" : "policy-reload-error"
        }
    }

    func decide(_ context: FlowContext) -> Decision {
        lock.lock()
        let currentSnapshot = snapshot
        let currentManifest = manifest
        let currentLoadError = loadError
        let currentStale = stalePolicy
        lock.unlock()

        if currentStale, currentManifest?.fallback?.stalePolicy == "strict-deny" {
            return Decision(allowed: false, reason: "stale-policy", ruleId: nil)
        }
        guard let network = currentSnapshot?.network else {
            let strict = currentManifest?.fallback?.unavailable == "strict-deny"
            return Decision(allowed: !strict, reason: currentLoadError == nil ? "no-policy" : "policy-load-error", ruleId: nil)
        }

        guard let host = context.host else {
            return Decision(allowed: true, reason: "no-host", ruleId: nil)
        }

        if let denied = firstMatch(host: host, patterns: network.deniedDomains) {
            return Decision(allowed: false, reason: "deniedDomains", ruleId: stableRuleId(parts: ["network.deniedDomains", denied]))
        }

        let httpRules = network.httpRules ?? []
        if !httpRules.isEmpty, context.method != nil || context.path != nil {
            if let rule = httpRules.first(where: { $0.matches(context) }) {
                let allowed = rule.action?.lowercased() != "deny"
                return Decision(allowed: allowed, reason: allowed ? "httpRules" : "httpRules-deny", ruleId: rule.effectiveRuleId)
            }
            return Decision(allowed: false, reason: "httpRules-default-deny", ruleId: nil)
        }

        if let allowed = firstMatch(host: host, patterns: network.allowedDomains) {
            return Decision(allowed: true, reason: "allowedDomains", ruleId: stableRuleId(parts: ["network.allowedDomains", allowed]))
        }

        if let allowedDomains = network.allowedDomains, !allowedDomains.isEmpty {
            return Decision(allowed: false, reason: "default-deny", ruleId: nil)
        }

        return Decision(allowed: true, reason: "default-allow", ruleId: nil)
    }

    func tlsInspection(for context: FlowContext) -> TLSInspectionDecision? {
        lock.lock()
        let currentSnapshot = snapshot
        let currentManifest = manifest
        let currentStale = stalePolicy
        lock.unlock()

        guard currentStale == false || currentManifest?.fallback?.stalePolicy != "strict-deny",
              let network = currentSnapshot?.network,
              context.isHTTPS,
              let host = context.host else {
            return nil
        }

        let settings = network.tlsInspection
        let httpRules = network.httpRules ?? []
        let candidateRules = httpRules.filter { $0.matchesHost(host) }
        let hasDeepHTTPPolicy = !candidateRules.isEmpty
        let enabled = settings?.effectiveEnabled == true
            || network.backend == "iron-proxy"
            || hasDeepHTTPPolicy

        guard enabled else {
            return nil
        }
        if let excluded = firstMatch(host: host, patterns: settings?.excludeHosts) {
            return TLSInspectionDecision(
                requested: false,
                allowed: true,
                classification: "tlsInspection-excluded-host",
                reason: "tlsInspection-excluded:\(excluded)",
                mode: settings?.mode ?? "off",
                caScope: settings?.caScope ?? "none",
                trustedBy: settings?.trustedBy ?? [],
                userApprovalRequired: settings?.userApprovalRequired ?? false,
                requiresDataPeek: false,
                decryptedRequestAvailable: context.hasHTTPRequestMetadata,
                httpRulesCount: httpRules.count,
                candidateRuleIds: candidateRules.map(\.effectiveRuleId),
                sni: nil,
                tlsVersion: nil,
                clientHelloOffset: nil
            )
        }
        if let inspectHosts = settings?.inspectHosts, !inspectHosts.isEmpty, firstMatch(host: host, patterns: inspectHosts) == nil {
            return nil
        }

        let decryptedAvailable = context.hasHTTPRequestMetadata
        let allowWithoutInspection = settings?.allowWithoutInspection ?? true
        let failClosed = settings?.failClosedWithoutDecryption ?? false
        let shouldDrop = !decryptedAvailable && failClosed && !allowWithoutInspection
        let classification: String
        let reason: String
        if decryptedAvailable {
            classification = "decrypted-request-metadata-available"
            reason = "tlsInspection-http-metadata"
        } else if hasDeepHTTPPolicy {
            classification = "https-needs-proxy-decrypt"
            reason = shouldDrop ? "tlsInspection-required-deny" : "tlsInspection-handoff"
        } else {
            classification = "https-tls-metadata-only"
            reason = "tlsInspection-metadata"
        }

        return TLSInspectionDecision(
            requested: true,
            allowed: !shouldDrop,
            classification: classification,
            reason: reason,
            mode: settings?.mode ?? (network.backend == "iron-proxy" ? "ephemeral-run-ca" : "network-extension-metadata"),
            caScope: settings?.caScope ?? (network.backend == "iron-proxy" ? "guarded-process-env" : "none"),
            trustedBy: settings?.trustedBy ?? [],
            userApprovalRequired: settings?.userApprovalRequired ?? true,
            requiresDataPeek: !decryptedAvailable,
            decryptedRequestAvailable: decryptedAvailable,
            httpRulesCount: httpRules.count,
            candidateRuleIds: candidateRules.map(\.effectiveRuleId),
            sni: nil,
            tlsVersion: nil,
            clientHelloOffset: nil
        )
    }

    private func policyURLLocked() -> URL? {
        let environment = ProcessInfo.processInfo.environment
        if let configured = environment["GUARD_NE_POLICY_PATH"], !configured.isEmpty {
            return URL(fileURLWithPath: configured)
        }
        if let manifest {
            return URL(fileURLWithPath: manifest.paths.policyPath)
        }
        let groupIdentifier = environment["GUARD_APP_GROUP_ID"] ?? defaultAppGroupIdentifier
        return FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
            .appendingPathComponent("Library/Application Support/Guard/policy.json")
    }

    private func manifestURL() -> URL? {
        let environment = ProcessInfo.processInfo.environment
        if let configured = environment["GUARD_NE_SYNC_MANIFEST_PATH"], !configured.isEmpty {
            return URL(fileURLWithPath: configured)
        }
        let groupIdentifier = environment["GUARD_APP_GROUP_ID"] ?? defaultAppGroupIdentifier
        return FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
            .appendingPathComponent("Library/Application Support/Guard/network-extension/manifest.json")
    }

    private func loadManifestIfNeededLocked(force: Bool) -> Bool {
        let url = manifestURL()
        manifestURLCache = url
        guard let url, FileManager.default.fileExists(atPath: url.path) else {
            manifestLoadError = nil
            if manifest != nil {
                manifest = nil
                manifestModified = nil
                fallbackReason = reconnectFallbackReasonLocked()
                updateFreshnessLocked()
                return true
            }
            fallbackReason = reconnectFallbackReasonLocked()
            updateFreshnessLocked()
            return false
        }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let modified = attributes[.modificationDate] as? Date
            if !force, let modified, modified == manifestModified {
                lastManifestSeenAt = Date()
                updateFreshnessLocked()
                return false
            }
            let data = try Data(contentsOf: url)
            let nextManifest = try JSONDecoder().decode(SyncManifest.self, from: data)
            if nextManifest.invalidatedAt != nil {
                let changed = manifest?.sequence != nextManifest.sequence
                manifest = nextManifest
                manifestModified = modified
                manifestLoadError = nil
                lastManifestSeenAt = Date()
                stalePolicy = true
                fallbackReason = "sync-invalidated:\(nextManifest.invalidateReason ?? "manual-invalidation")"
                return changed
            }
            let changed = manifest?.sequence != nextManifest.sequence || manifest?.paths.policyPath != nextManifest.paths.policyPath
            manifest = nextManifest
            manifestModified = modified
            manifestLoadError = nil
            lastManifestSeenAt = Date()
            updateFreshnessLocked()
            return changed
        } catch {
            manifestLoadError = "manifest: \(error.localizedDescription)"
            fallbackReason = "manifest-load-error"
            updateFreshnessLocked()
            return false
        }
    }

    private func updateFreshnessLocked() {
        stalePolicy = isPolicyStaleLocked(snapshot)
        if stalePolicy {
            fallbackReason = fallbackReason ?? "stale-policy"
        } else if manifestLoadError == nil && loadError == nil {
            fallbackReason = reconnectFallbackReasonLocked()
        }
    }

    private func markSyncUnavailableLocked(error: String) {
        if snapshot == nil {
            lastModified = nil
            loadError = error
        }
        fallbackReason = reconnectFallbackReasonLocked()
        updateFreshnessLocked()
    }

    private func reconnectFallbackReasonLocked() -> String? {
        guard manifest == nil, snapshot != nil else {
            return nil
        }
        guard let lastManifestSeenAt else {
            return "sync-unavailable"
        }
        let age = Date().timeIntervalSince(lastManifestSeenAt)
        return age > defaultReconnectGraceSeconds ? "sync-unavailable" : "sync-reconnecting"
    }

    private func isPolicyStaleLocked(_ snapshot: PolicySnapshot?) -> Bool {
        let generatedAt = manifest?.generatedAt ?? snapshot?.generatedAt
        guard let generatedAt,
              let generatedDate = ISO8601DateFormatter().date(from: generatedAt) else {
            return false
        }
        let maxAge = manifest?.maxPolicyAgeSeconds ?? defaultMaxPolicyAgeSeconds
        return Date().timeIntervalSince(generatedDate) > maxAge
    }
}

private final class EventWriter {
    private let lock = NSLock()
    private var eventLogURL: URL?
    private var heartbeatURL: URL?
    private var manifestURL: URL?
    private var manifestSequence: Int?
    private var maxEventBacklogBytes: UInt64 = defaultMaxEventBacklogBytes
    private var fallbackEventBackpressure: String?
    private var backpressureActive = false
    private var droppedEventCount: UInt64 = 0
    private var lastHeartbeatAt: Date?

    func configure(sync: RuntimeSyncState, force: Bool) {
        lock.lock()
        defer { lock.unlock() }

        if !force,
           manifestURL == sync.manifestURL,
           manifestSequence == sync.manifestSequence,
           eventLogURL == (sync.eventLogURL ?? configuredEventLogURLLocked()),
           heartbeatURL == sync.heartbeatURL {
            return
        }
        manifestURL = sync.manifestURL
        manifestSequence = sync.manifestSequence
        eventLogURL = sync.eventLogURL ?? configuredEventLogURLLocked()
        heartbeatURL = sync.heartbeatURL
        maxEventBacklogBytes = sync.maxEventBacklogBytes
        fallbackEventBackpressure = sync.fallbackEventBackpressure
    }

    func emitLifecycle(reason: String, detail: String) {
        append([
            "schemaVersion": eventSchemaVersion,
            "at": isoNow(),
            "type": "network.extension.lifecycle",
            "backend": backendName,
            "reason": reason,
            "detail": detail,
        ])
    }

    func emitDecision(context: FlowContext, decision: Decision, policy: SnapshotMetadata) {
        append([
            "schemaVersion": eventSchemaVersion,
            "at": isoNow(),
            "type": "network.decision",
            "backend": backendName,
            "profile": policy.profile,
            "projectDir": policy.projectDir,
            "host": context.host ?? "",
            "port": context.port ?? 0,
            "protocol": context.flowProtocol,
            "direction": context.direction,
            "method": context.method ?? "",
            "path": context.path ?? "",
            "url": context.url ?? "",
            "appBundleIdentifier": context.appBundleIdentifier ?? "",
            "processPath": context.processPath ?? "",
            "pid": context.pid ?? 0,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "ruleId": decision.ruleId ?? "",
            "policyPath": policy.policyPath,
            "policyLoaded": policy.loaded,
            "policyLoadError": policy.loadError ?? "",
            "policySequence": policy.sequence ?? 0,
            "policyStale": policy.stale,
            "fallbackReason": policy.fallbackReason ?? "",
        ])
    }

    func emitTLSInspectionRequest(context: FlowContext, inspection: TLSInspectionDecision, policy: SnapshotMetadata) {
        append(tlsInspectionEvent(
            type: "network.tlsInspection.request",
            context: context,
            inspection: inspection,
            policy: policy
        ))
    }

    func emitTLSInspectionDecision(context: FlowContext, inspection: TLSInspectionDecision, policy: SnapshotMetadata) {
        append(tlsInspectionEvent(
            type: "network.tlsInspection.decision",
            context: context,
            inspection: inspection,
            policy: policy
        ))
    }

    private func tlsInspectionEvent(
        type: String,
        context: FlowContext,
        inspection: TLSInspectionDecision,
        policy: SnapshotMetadata
    ) -> [String: Any] {
        [
            "schemaVersion": eventSchemaVersion,
            "at": isoNow(),
            "type": type,
            "backend": backendName,
            "profile": policy.profile,
            "projectDir": policy.projectDir,
            "host": context.host ?? "",
            "port": context.port ?? 0,
            "protocol": context.flowProtocol,
            "direction": context.direction,
            "method": context.method ?? "",
            "path": context.path ?? "",
            "url": context.url ?? "",
            "appBundleIdentifier": context.appBundleIdentifier ?? "",
            "processPath": context.processPath ?? "",
            "pid": context.pid ?? 0,
            "requested": inspection.requested,
            "allowed": inspection.allowed,
            "classification": inspection.classification,
            "reason": inspection.reason,
            "mode": inspection.mode,
            "caScope": inspection.caScope,
            "trustedBy": inspection.trustedBy,
            "userApprovalRequired": inspection.userApprovalRequired,
            "requiresDataPeek": inspection.requiresDataPeek,
            "decryptedRequestAvailable": inspection.decryptedRequestAvailable,
            "httpRulesCount": inspection.httpRulesCount,
            "candidateRuleIds": inspection.candidateRuleIds,
            "sni": inspection.sni ?? "",
            "tlsVersion": inspection.tlsVersion ?? "",
            "clientHelloOffset": inspection.clientHelloOffset ?? -1,
            "policyPath": policy.policyPath,
            "policyLoaded": policy.loaded,
            "policyLoadError": policy.loadError ?? "",
            "policySequence": policy.sequence ?? 0,
            "policyStale": policy.stale,
            "fallbackReason": policy.fallbackReason ?? "",
        ]
    }

    func emitHeartbeat(policy: SnapshotMetadata, force: Bool) {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()
        if !force, let lastHeartbeatAt, now.timeIntervalSince(lastHeartbeatAt) < defaultHeartbeatInterval {
            return
        }
        lastHeartbeatAt = now

        guard let heartbeatURL else {
            return
        }
        let heartbeat: [String: Any] = [
            "schemaVersion": eventSchemaVersion,
            "at": ISO8601DateFormatter().string(from: now),
            "service": "GuardNetworkExtensionProvider",
            "backend": backendName,
            "pid": ProcessInfo.processInfo.processIdentifier,
            "policyPath": policy.policyPath,
            "policyLoaded": policy.loaded,
            "policySequence": policy.sequence ?? 0,
            "policyStale": policy.stale,
            "fallbackReason": policy.fallbackReason ?? "",
            "eventLogPath": eventLogURL?.path ?? "",
            "eventBackpressure": backpressureActive,
            "eventBackpressureMode": fallbackEventBackpressure ?? "",
            "droppedEventCount": droppedEventCount,
        ]
        do {
            try FileManager.default.createDirectory(
                at: heartbeatURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let data = try JSONSerialization.data(withJSONObject: heartbeat, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: heartbeatURL, options: .atomic)
        } catch {
            NSLog("guard network extension: failed to write heartbeat: \(error.localizedDescription)")
        }
    }

    private func configuredEventLogURL() -> URL? {
        lock.lock()
        defer { lock.unlock() }
        return configuredEventLogURLLocked()
    }

    private func configuredEventLogURLLocked() -> URL? {
        let environment = ProcessInfo.processInfo.environment
        if let configured = environment["GUARD_NE_EVENT_LOG_PATH"], !configured.isEmpty {
            return URL(fileURLWithPath: configured)
        }
        if let manifestURL = manifestURL ?? configuredManifestURL(),
           let data = try? Data(contentsOf: manifestURL),
           let manifest = try? JSONDecoder().decode(SyncManifest.self, from: data) {
            return URL(fileURLWithPath: manifest.paths.eventLogPath)
        }
        let groupIdentifier = environment["GUARD_APP_GROUP_ID"] ?? defaultAppGroupIdentifier
        return FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
            .appendingPathComponent("Library/Application Support/Guard/network-extension-events.jsonl")
    }

    private func append(_ event: [String: Any]) {
        lock.lock()
        defer { lock.unlock() }

        guard let eventLogURL else {
            return
        }
        do {
            try FileManager.default.createDirectory(
                at: eventLogURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if isBackpressureActiveLocked(eventLogURL) {
                droppedEventCount += 1
                if !backpressureActive {
                    backpressureActive = true
                    lastHeartbeatAt = nil
                    NSLog("guard network extension: event log backpressure active")
                }
                return
            }
            if backpressureActive {
                backpressureActive = false
                lastHeartbeatAt = nil
                var recovery = event
                recovery["type"] = "network.extension.lifecycle"
                recovery["reason"] = "event-backpressure-recovered"
                recovery["droppedEventCount"] = droppedEventCount
                appendUnlocked(recovery, to: eventLogURL)
                droppedEventCount = 0
            }
            appendUnlocked(event, to: eventLogURL)
        } catch {
            NSLog("guard network extension: failed to append event: \(error.localizedDescription)")
        }
    }

    private func appendUnlocked(_ event: [String: Any], to eventLogURL: URL) {
        do {
            backpressureActive = false
            let data = try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys])
            if FileManager.default.fileExists(atPath: eventLogURL.path) {
                let handle = try FileHandle(forWritingTo: eventLogURL)
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
                try handle.write(contentsOf: Data("\n".utf8))
                try handle.close()
            } else {
                try (data + Data("\n".utf8)).write(to: eventLogURL, options: .atomic)
            }
        } catch {
            NSLog("guard network extension: failed to append event: \(error.localizedDescription)")
        }
    }

    private func isBackpressureActiveLocked(_ url: URL) -> Bool {
        let maxBytes = maxEventBacklogBytes
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attributes[.size] as? NSNumber else {
            return false
        }
        return size.uint64Value > maxBytes
    }
}

private struct TLSClientHelloMetadata {
    let isTLSClientHello: Bool
    let serverName: String?
    let recordVersion: String?

    init(data: Data) {
        guard data.count >= 6,
              data[0] == 0x16,
              data[5] == 0x01 else {
            self.isTLSClientHello = false
            self.serverName = nil
            self.recordVersion = nil
            return
        }

        self.isTLSClientHello = true
        self.recordVersion = "0x\(hexByte(data[1]))\(hexByte(data[2]))"
        self.serverName = TLSClientHelloMetadata.parseServerName(data)
    }

    private static func parseServerName(_ data: Data) -> String? {
        var cursor = 5
        guard cursor + 4 <= data.count else {
            return nil
        }
        cursor += 4

        guard cursor + 2 <= data.count else {
            return nil
        }
        cursor += 2

        guard cursor + 32 <= data.count else {
            return nil
        }
        cursor += 32

        guard cursor < data.count else {
            return nil
        }
        let sessionIDLength = Int(data[cursor])
        cursor += 1 + sessionIDLength

        guard cursor + 2 <= data.count else {
            return nil
        }
        let cipherSuitesLength = Int(data[cursor]) << 8 | Int(data[cursor + 1])
        cursor += 2 + cipherSuitesLength

        guard cursor < data.count else {
            return nil
        }
        let compressionMethodsLength = Int(data[cursor])
        cursor += 1 + compressionMethodsLength

        guard cursor + 2 <= data.count else {
            return nil
        }
        let extensionsLength = Int(data[cursor]) << 8 | Int(data[cursor + 1])
        cursor += 2
        let extensionsEnd = min(cursor + extensionsLength, data.count)

        while cursor + 4 <= extensionsEnd {
            let extensionType = Int(data[cursor]) << 8 | Int(data[cursor + 1])
            let extensionLength = Int(data[cursor + 2]) << 8 | Int(data[cursor + 3])
            cursor += 4
            let extensionEnd = cursor + extensionLength
            guard extensionEnd <= extensionsEnd else {
                return nil
            }

            if extensionType == 0 {
                return parseServerNameExtension(data, start: cursor, end: extensionEnd)
            }
            cursor = extensionEnd
        }
        return nil
    }

    private static func parseServerNameExtension(_ data: Data, start: Int, end: Int) -> String? {
        var cursor = start
        guard cursor + 2 <= end else {
            return nil
        }
        let listLength = Int(data[cursor]) << 8 | Int(data[cursor + 1])
        cursor += 2
        let listEnd = min(cursor + listLength, end)

        while cursor + 3 <= listEnd {
            let nameType = data[cursor]
            let nameLength = Int(data[cursor + 1]) << 8 | Int(data[cursor + 2])
            cursor += 3
            guard cursor + nameLength <= listEnd else {
                return nil
            }
            if nameType == 0 {
                let nameData = data.subdata(in: cursor..<(cursor + nameLength))
                return normalizeHost(String(data: nameData, encoding: .utf8))
            }
            cursor += nameLength
        }
        return nil
    }
}

private func configuredManifestURL() -> URL? {
    let environment = ProcessInfo.processInfo.environment
    if let configured = environment["GUARD_NE_SYNC_MANIFEST_PATH"], !configured.isEmpty {
        return URL(fileURLWithPath: configured)
    }
    let groupIdentifier = environment["GUARD_APP_GROUP_ID"] ?? defaultAppGroupIdentifier
    return FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
        .appendingPathComponent("Library/Application Support/Guard/network-extension/manifest.json")
}

private func normalizeHost(_ value: String?) -> String? {
    guard var host = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !host.isEmpty else {
        return nil
    }
    if host.hasPrefix("[") && host.hasSuffix("]") {
        host.removeFirst()
        host.removeLast()
    }
    if host.hasSuffix(".") {
        host.removeLast()
    }
    return host
}

private func firstMatch(host: String, patterns: [String]?) -> String? {
    patterns?.first { hostMatchesPattern(host, $0) }
}

private func hostMatchesAny(_ host: String, _ patterns: [String]) -> Bool {
    patterns.contains { hostMatchesPattern(host, $0) }
}

private func hostMatchesPattern(_ host: String, _ pattern: String) -> Bool {
    guard let normalizedHost = normalizeHost(host), let normalizedPattern = normalizeHost(pattern) else {
        return false
    }
    if !normalizedPattern.contains("*") {
        return normalizedHost == normalizedPattern
    }
    return wildcardMatch(normalizedHost, pattern: normalizedPattern)
}

private func wildcardMatch(_ value: String, pattern: String) -> Bool {
    let escaped = NSRegularExpression.escapedPattern(for: pattern).replacingOccurrences(of: "\\*", with: ".*")
    return value.range(of: "^\(escaped)$", options: .regularExpression) != nil
}

private func defaultPort(for scheme: String?) -> Int? {
    switch scheme?.lowercased() {
    case "http":
        return 80
    case "https":
        return 443
    default:
        return nil
    }
}

private func parseEndpointDescription(_ value: String) -> (host: String?, port: Int?) {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("[") {
        let parts = trimmed.split(separator: "]", maxSplits: 1).map(String.init)
        guard parts.count == 2 else {
            return (trimmed, nil)
        }
        let host = parts[0].dropFirst()
        let port = parts[1].drop(while: { $0 == ":" })
        return (String(host), Int(port))
    }
    let parts = trimmed.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
    if parts.count == 2 {
        return (parts[0], Int(parts[1]))
    }
    return (trimmed.isEmpty ? nil : trimmed, nil)
}

private func stableRuleId(parts: [String?]) -> String {
    let joined = parts.compactMap { $0 }.joined(separator: "\u{1f}")
    return "rule_\(fnv1a64(joined))"
}

private func fnv1a64(_ value: String) -> String {
    var hash: UInt64 = 0xcbf29ce484222325
    for byte in value.utf8 {
        hash ^= UInt64(byte)
        hash = hash &* 0x100000001b3
    }
    return String(format: "%016llx", hash)
}

private func hexByte(_ value: UInt8) -> String {
    String(format: "%02x", value)
}

private func sha256Digest(_ data: Data) -> String {
    let digest = SHA256.hash(data: data)
    return "sha256:" + digest.map { String(format: "%02x", $0) }.joined()
}

private func isoNow() -> String {
    ISO8601DateFormatter().string(from: Date())
}

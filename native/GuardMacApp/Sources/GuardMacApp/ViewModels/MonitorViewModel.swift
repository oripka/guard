import Foundation

struct MonitorViewModel {
    var allowedCount = 0
    var deniedCount = 0
    var pendingAlertCount = 0
}

struct GuardDecisionSubject: Codable, Equatable {
    var kind: String = "process"
    var executablePath: String = ""
    var commandLine: String = ""
    var bundleId: String = ""
    var teamId: String = ""
    var signingStatus: String = "unknown"
    var projectDir: String = ""
    var profile: String = "guard"
    var parentChain: String = ""
}

struct GuardDecisionOperation: Codable, Equatable {
    var kind: String
    var direction: String = ""
    var intent: String = ""
}

struct GuardDecisionResource: Codable, Equatable {
    var kind: String
    var host: String?
    var port: Int?
    var method: String?
    var path: String?
    var tlsInspection: String?
}

struct GuardDecisionRequest: Codable, Equatable {
    var schemaVersion: Int = 1
    var contractVersion: Int = 1
    var source: String
    var mode: String
    var subject: GuardDecisionSubject
    var operation: GuardDecisionOperation
    var resource: GuardDecisionResource
    var recommendedScopes: [String]
    var defaultAction: String = "ask"
}

struct GuardAlertPresentation: Equatable {
    var title: String
    var subtitle: String
    var primaryResource: String
    var consequence: String
    var scopes: [String]
}

struct GuardUnifiedRule: Codable, Identifiable, Equatable {
    var id: String
    var action: String
    var lifetime: String
    var subject: GuardDecisionSubject
    var operation: GuardDecisionOperation
    var resource: GuardDecisionResource
    var enabled: Bool
    var approvalState: String

    var displayScope: String {
        switch resource.kind {
        case "http":
            return "\(resource.method ?? "*") \(resource.host ?? "")\(resource.path ?? "")"
        default:
            return resource.host ?? resource.path ?? ""
        }
    }
}

struct RulesEditorViewModel {
    var rules: [GuardUnifiedRule] = []

    var networkRules: [GuardUnifiedRule] {
        rules.filter { $0.operation.kind.hasPrefix("network.") || $0.operation.kind == "http.request" || $0.operation.kind == "tls.inspect" }
    }

    mutating func upsert(_ rule: GuardUnifiedRule) {
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
    }
}

extension GuardDecisionRequest {
    func alertPresentation() -> GuardAlertPresentation {
        switch operation.kind {
        case "http.request":
            let method = resource.method?.isEmpty == false ? "\(resource.method ?? "") " : ""
            return GuardAlertPresentation(
                title: "\(actorName) wants network access",
                subtitle: "\(method)\(resource.host ?? "")\(resource.path ?? "")",
                primaryResource: resource.host ?? "",
                consequence: resource.tlsInspection == "active" ? "HTTP path can be inspected" : "Destination rule",
                scopes: recommendedScopes
            )
        default:
            return GuardAlertPresentation(
                title: "\(actorName) wants network access",
                subtitle: resource.host ?? resource.path ?? "",
                primaryResource: resource.host ?? "",
                consequence: "Network rule",
                scopes: recommendedScopes
            )
        }
    }

    private var actorName: String {
        if !subject.bundleId.isEmpty { return subject.bundleId }
        if !subject.executablePath.isEmpty { return URL(fileURLWithPath: subject.executablePath).lastPathComponent }
        if !subject.commandLine.isEmpty { return subject.commandLine.split(separator: " ").first.map(String.init) ?? "Process" }
        return "Process"
    }
}

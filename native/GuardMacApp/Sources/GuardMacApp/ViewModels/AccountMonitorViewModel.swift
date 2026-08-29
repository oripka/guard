import Foundation

struct GuardAccountTarget: Codable, Equatable {
    var type: String
    var label: String
}

struct GuardAccountSnapshot: Codable, Identifiable, Equatable {
    var schemaVersion: Int
    var id: String
    var label: String
    var providerLabel: String
    var target: GuardAccountTarget
    var state: String
    var identity: String
    var lastUsedAt: String
    var lastUsedSource: String
    var expiresAt: String
    var checkedAt: String
    var stale: Bool
    var reasonCode: String
    var loginAvailable: Bool
    var expiryWarningSeconds: Int

    var isExpiring: Bool {
        guard state == "signedIn", let expiry = Self.parseDate(expiresAt) else { return false }
        return expiry.timeIntervalSinceNow > 0 && expiry.timeIntervalSinceNow <= TimeInterval(expiryWarningSeconds)
    }

    var statusLabel: String {
        if isExpiring { return "Expiring soon" }
        switch state {
        case "signedIn": return "Signed in"
        case "signedOut": return "Signed out"
        case "expired": return "Expired"
        case "unavailable": return "Unavailable"
        case "error": return "Check failed"
        default: return "Unknown"
        }
    }

    var sortRank: Int {
        if state == "expired" || isExpiring { return 0 }
        if state == "error" || state == "unavailable" { return 1 }
        if state == "signedOut" { return 2 }
        if state == "signedIn" { return 3 }
        return 4
    }

    static func parseDate(_ value: String) -> Date? {
        guard !value.isEmpty else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) { return date }
        return ISO8601DateFormatter().date(from: value)
    }
}

struct GuardAccountListPayload: Codable {
    var configPath: String
    var errors: [String]
    var warnings: [String]
    var accounts: [GuardAccountSnapshot]
}

struct GuardAccountLoginPreview: Codable, Equatable {
    var id: String
    var label: String
    var providerLabel: String
    var target: GuardAccountTarget
    var presentation: String
    var argv: [String]
    var cwd: String
    var environmentKeys: [String]
}

private struct GuardAccountPreviewPayload: Codable {
    var schemaVersion: Int
    var preview: GuardAccountLoginPreview
}

enum GuardAccountCommandError: LocalizedError {
    case launch(String)
    case failed(Int32, String)
    case invalidResponse(String)

    var errorDescription: String? {
        switch self {
        case .launch(let message): return message
        case .failed(let status, let message): return message.isEmpty ? "Guard exited with status \(status)." : message
        case .invalidResponse(let message): return message
        }
    }
}

final class AccountMonitorViewModel: ObservableObject {
    @Published private(set) var accounts: [GuardAccountSnapshot] = []
    @Published private(set) var isRefreshing = false
    @Published private(set) var errorMessage = ""
    @Published private(set) var configPath = ""

    let guardPath: String

    init(guardPath: String) {
        self.guardPath = guardPath
    }

    func loadCached() {
        run(arguments: ["account", "list", "--json"])
    }

    func refresh(id: String? = nil) {
        var arguments = ["account", "refresh"]
        if let id, !id.isEmpty { arguments.append(id) }
        arguments.append("--json")
        run(arguments: arguments)
    }

    func loginPreview(id: String) throws -> GuardAccountLoginPreview {
        let data = try Self.runGuard(path: guardPath, arguments: ["account", "preview", id, "--json"])
        do {
            return try JSONDecoder().decode(GuardAccountPreviewPayload.self, from: data).preview
        } catch {
            throw GuardAccountCommandError.invalidResponse("Guard returned an invalid login preview.")
        }
    }

    private func run(arguments: [String]) {
        guard !isRefreshing else { return }
        isRefreshing = true
        errorMessage = ""
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let data = try Self.runGuard(path: self.guardPath, arguments: arguments)
                let payload = try JSONDecoder().decode(GuardAccountListPayload.self, from: data)
                DispatchQueue.main.async {
                    self.accounts = payload.accounts.sorted {
                        $0.sortRank == $1.sortRank ? $0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending : $0.sortRank < $1.sortRank
                    }
                    self.configPath = payload.configPath
                    self.errorMessage = payload.errors.first ?? ""
                    self.isRefreshing = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isRefreshing = false
                }
            }
        }
    }

    static func runGuard(path: String, arguments: [String]) throws -> Data {
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
        } catch {
            throw GuardAccountCommandError.launch("Could not launch Guard at \(path).")
        }
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = errors.fileHandleForReading.readDataToEndOfFile()
        if process.terminationStatus != 0 {
            let message = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw GuardAccountCommandError.failed(process.terminationStatus, message)
        }
        return data
    }
}

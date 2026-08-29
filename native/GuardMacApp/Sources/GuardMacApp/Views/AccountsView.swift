import SwiftUI

struct AccountsView: View {
    @ObservedObject var model: AccountMonitorViewModel
    var onLogin: (GuardAccountSnapshot) -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if model.accounts.isEmpty && !model.isRefreshing {
                emptyState
            } else {
                TimelineView(.periodic(from: .now, by: 30)) { _ in
                    ScrollView {
                        LazyVStack(spacing: 10) {
                            ForEach(model.accounts) { account in
                                AccountRow(account: account, isRefreshing: model.isRefreshing, onRefresh: {
                                    model.refresh(id: account.id)
                                }, onLogin: {
                                    onLogin(account)
                                })
                            }
                        }
                        .padding(16)
                    }
                }
            }
            if !model.errorMessage.isEmpty {
                Text(model.errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color.red.opacity(0.08))
            }
        }
        .frame(minWidth: 760, minHeight: 520)
        .background(.ultraThinMaterial)
        .onAppear { model.loadCached() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Accounts")
                    .font(.system(size: 24, weight: .semibold))
                Text("Local sign-in state, observed use, and credential expiry")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.isRefreshing { ProgressView().controlSize(.small) }
            Button("Refresh All") { model.refresh() }
                .disabled(model.isRefreshing)
                .keyboardShortcut("r", modifiers: .command)
        }
        .padding(18)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "person.crop.circle.badge.questionmark")
                .font(.system(size: 38))
                .foregroundStyle(.secondary)
            Text("No account monitors configured")
                .font(.headline)
            Text("Run “guard account setup” or add accountMonitoring.monitors to Guard’s user config.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

private struct AccountRow: View {
    var account: GuardAccountSnapshot
    var isRefreshing: Bool
    var onRefresh: () -> Void
    var onLogin: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: iconName)
                .font(.system(size: 21, weight: .medium))
                .foregroundStyle(statusColor)
                .frame(width: 34, height: 34)
                .background(statusColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Text(account.label).font(.headline)
                    Text(account.statusLabel)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(statusColor)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(statusColor.opacity(0.12), in: Capsule())
                    if account.stale {
                        Text("Stale").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text([account.providerLabel, account.target.label, account.identity].filter { !$0.isEmpty }.joined(separator: "  •  "))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                HStack(spacing: 20) {
                    metadata("Last used", value: relative(account.lastUsedAt, empty: "Not observed"), detail: timestampDetail(account.lastUsedAt, suffix: account.lastUsedSource))
                    metadata("Expires", value: relative(account.expiresAt, empty: "Not exposed"), detail: account.expiresAt)
                    metadata("Checked", value: relative(account.checkedAt, empty: "Never"), detail: timestampDetail(account.checkedAt, suffix: reasonLabel))
                }
                if account.state == "unavailable" || account.state == "error" {
                    Text(reasonLabel).font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 8) {
                Button("Refresh", action: onRefresh).disabled(isRefreshing)
                if account.loginAvailable {
                    Button("Login Again", action: onLogin)
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(14)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.08)))
        .accessibilityElement(children: .contain)
    }

    private func metadata(_ label: String, value: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label.uppercased()).font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
            Text(value).font(.caption).help(detail)
            if !detail.isEmpty { Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(1) }
        }
    }

    private func timestampDetail(_ timestamp: String, suffix: String) -> String {
        [timestamp, suffix].filter { !$0.isEmpty }.joined(separator: " • ")
    }

    private var reasonLabel: String {
        switch account.reasonCode {
        case "command-not-found": return "Command not found — review the configured binary"
        case "docker-target-unavailable": return "Docker or the configured container is unavailable"
        case "docker-command-not-found": return "The configured command is missing in the Docker container"
        case "probe-timeout": return "Status check timed out — retry or review the probe"
        case "probe-output-truncated": return "Status output exceeded Guard’s safe limit"
        case "manual-probe-not-run": return "Manual status check required"
        default:
            if account.state == "unavailable" { return "Target unavailable — refresh or review its configuration" }
            return account.reasonCode
        }
    }

    private func relative(_ value: String, empty: String) -> String {
        guard let date = GuardAccountSnapshot.parseDate(value) else { return empty }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    private var statusColor: Color {
        if account.state == "expired" || account.state == "signedOut" || account.state == "error" { return .red }
        if account.isExpiring || account.state == "unavailable" { return .orange }
        if account.state == "signedIn" { return .green }
        return .secondary
    }

    private var iconName: String {
        switch account.target.type {
        case "docker": return "shippingbox"
        default: return "person.crop.circle.badge.checkmark"
        }
    }
}

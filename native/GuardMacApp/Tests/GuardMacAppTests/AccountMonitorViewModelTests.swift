import XCTest
@testable import GuardMacApp

final class AccountMonitorViewModelTests: XCTestCase {
    private func snapshot(state: String, expiresAt: String = "") -> GuardAccountSnapshot {
        GuardAccountSnapshot(
            schemaVersion: 1,
            id: "fixture",
            label: "Fixture",
            providerLabel: "Provider",
            target: GuardAccountTarget(type: "host", label: "This Mac"),
            state: state,
            identity: "",
            lastUsedAt: "",
            lastUsedSource: "",
            expiresAt: expiresAt,
            checkedAt: "",
            stale: false,
            reasonCode: "fixture",
            loginAvailable: true,
            expiryWarningSeconds: 1800
        )
    }

    func testStatusLabelsAreHumanReadable() {
        XCTAssertEqual(snapshot(state: "signedIn").statusLabel, "Signed in")
        XCTAssertEqual(snapshot(state: "signedOut").statusLabel, "Signed out")
        XCTAssertEqual(snapshot(state: "expired").statusLabel, "Expired")
        XCTAssertEqual(snapshot(state: "unavailable").statusLabel, "Unavailable")
    }

    func testExpiredAndUnavailableAccountsSortBeforeHealthyAccounts() {
        XCTAssertLessThan(snapshot(state: "expired").sortRank, snapshot(state: "signedIn").sortRank)
        XCTAssertLessThan(snapshot(state: "unavailable").sortRank, snapshot(state: "signedIn").sortRank)
    }

    func testMissingExpiryDoesNotClaimAccountIsExpiring() {
        XCTAssertFalse(snapshot(state: "signedIn").isExpiring)
    }

    func testTerminalActionInvokesOnlyGuardAccountLoginAndSelfDeletes() {
        let script = GuardAccountLoginAction.scriptContents(
            guardPath: "/fixture/guard",
            accountId: "codex-worker"
        )
        XCTAssertTrue(script.contains("'/fixture/guard' account login 'codex-worker'"))
        XCTAssertTrue(script.contains("trap '/bin/rm -f \"$action_script\"' EXIT"))
        XCTAssertFalse(script.contains("device-auth"))
        XCTAssertFalse(script.contains("docker exec"))
    }
}

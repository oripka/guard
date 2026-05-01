import XCTest
@testable import GuardMacApp

final class MonitorViewModelTests: XCTestCase {
    func testDefaultCountsStartAtZero() {
        let model = MonitorViewModel()
        XCTAssertEqual(model.allowedCount, 0)
        XCTAssertEqual(model.deniedCount, 0)
        XCTAssertEqual(model.pendingAlertCount, 0)
    }

    func testHTTPDecisionPresentation() {
        let request = GuardDecisionRequest(
            source: "iron-proxy",
            mode: "system",
            subject: GuardDecisionSubject(executablePath: "/usr/bin/curl", commandLine: "curl"),
            operation: GuardDecisionOperation(kind: "http.request", direction: "outbound", intent: "connect"),
            resource: GuardDecisionResource(
                kind: "http",
                host: "api.openai.com",
                port: 443,
                method: "POST",
                path: "/v1/responses",
                tlsInspection: "active"
            ),
            recommendedScopes: ["exact", "path", "domain"]
        )

        let presentation = request.alertPresentation()
        XCTAssertEqual(presentation.title, "curl wants network access")
        XCTAssertEqual(presentation.subtitle, "POST api.openai.com/v1/responses")
        XCTAssertEqual(presentation.consequence, "HTTP path can be inspected")
    }

    func testRulesEditorGroupsNetworkRules() {
        var model = RulesEditorViewModel()
        model.upsert(GuardUnifiedRule(
            id: "http",
            action: "allow",
            lifetime: "persistent",
            subject: GuardDecisionSubject(),
            operation: GuardDecisionOperation(kind: "http.request"),
            resource: GuardDecisionResource(kind: "http", host: "api.openai.com", method: "POST", path: "/v1/responses"),
            enabled: true,
            approvalState: "approved"
        ))

        XCTAssertEqual(model.networkRules.count, 1)
        XCTAssertEqual(model.networkRules[0].displayScope, "POST api.openai.com/v1/responses")
    }
}

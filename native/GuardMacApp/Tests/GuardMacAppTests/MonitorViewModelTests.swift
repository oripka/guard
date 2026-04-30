import XCTest
@testable import GuardMacApp

final class MonitorViewModelTests: XCTestCase {
    func testDefaultCountsStartAtZero() {
        let model = MonitorViewModel()
        XCTAssertEqual(model.allowedCount, 0)
        XCTAssertEqual(model.deniedCount, 0)
        XCTAssertEqual(model.pendingAlertCount, 0)
    }
}

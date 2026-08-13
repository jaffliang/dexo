import XCTest
@testable import dexo

final class GuestContentLoadFailureTests: XCTestCase {
    func testChallengeRequiredUsesLocalizedCopy() {
        let error = DiscourseAPIError(
            messages: ["Cloudflare challenge required"],
            errorType: "challenge_required"
        )
        let failure = GuestContentLoadFailure(error)
        XCTAssertTrue(failure.requiresChallenge)
        XCTAssertFalse(failure.requiresLogin)
        XCTAssertEqual(failure.message, String(localized: "challenge.empty.message"))
        XCTAssertNotEqual(failure.message, "Cloudflare challenge required")
    }

    func testNotLoggedInStillRequiresLogin() {
        let error = DiscourseAPIError(
            messages: ["You need to log in"],
            errorType: "not_logged_in"
        )
        let failure = GuestContentLoadFailure(error)
        XCTAssertTrue(failure.requiresLogin)
        XCTAssertFalse(failure.requiresChallenge)
        XCTAssertEqual(failure.message, "You need to log in")
    }

    func testGenericErrorKeepsLocalizedDescription() {
        let error = DiscourseAPIError(messages: ["Rate limit"], errorType: nil)
        let failure = GuestContentLoadFailure(error)
        XCTAssertFalse(failure.requiresLogin)
        XCTAssertFalse(failure.requiresChallenge)
        XCTAssertEqual(failure.message, "Rate limit")
    }
}

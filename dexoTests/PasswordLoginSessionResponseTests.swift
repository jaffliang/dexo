import XCTest
@testable import dexo

final class PasswordLoginSessionResponseTests: XCTestCase {
    func testOnlyCsrf403RetriesCloudflareChallenge() {
        XCTAssertTrue(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(phase: "csrf", status: 403))
        XCTAssertFalse(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(phase: "csrf", status: 200))
        XCTAssertFalse(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(phase: "evaluate", status: 0))
        XCTAssertFalse(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(phase: "evaluate", status: 403))
        XCTAssertFalse(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(phase: "session", status: 403))
        XCTAssertFalse(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(phase: "exception", status: 0))
    }

    func testHTTP200WithUserIsSignedIn() {
        let body = #"{"user":{"id":42,"username":"jeff"}}"#
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: 200, body: body),
            .signedIn
        )
    }

    func testHTTP200WithInvalidCredentialsReason() {
        let body = #"{"error":"Incorrect username, email or password","reason":"invalid_credentials"}"#
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: 200, body: body),
            .invalidCredentials
        )
    }

    func testHTTP200WithSecondFactorReason() {
        let body = #"{"error":"Invalid second factor","reason":"invalid_second_factor"}"#
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: 200, body: body),
            .needsSecondFactor
        )
    }

    func testHTTP200WithErrorAndUnknownReasonSurfacesBody() {
        let body = #"{"error":"Account suspended.","reason":"suspended"}"#
        switch PasswordLoginSessionResponse.interpret(status: 200, body: body) {
        case .failed(let status, let text):
            XCTAssertEqual(status, 200)
            XCTAssertTrue(text.contains("Account suspended"))
            XCTAssertTrue(text.contains("suspended"))
        default:
            XCTFail("expected failed outcome with body")
        }
    }

    func testNon200SurfacesRawBody() {
        let body = "<html>cf challenge blocked csrf</html>"
        switch PasswordLoginSessionResponse.interpret(status: 403, body: body) {
        case .failed(let status, let text):
            XCTAssertEqual(status, 403)
            XCTAssertEqual(text, body)
        default:
            XCTFail("expected failed outcome with raw body")
        }
    }

    func testNon200InvalidCredentialsReasonStillMaps() {
        let body = #"{"reason":"invalid_credentials","error":"nope"}"#
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: 403, body: body),
            .invalidCredentials
        )
    }

    func testHTTP200EmptyJSONTreatsAsSignedIn() {
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: 200, body: "{}"),
            .signedIn
        )
    }

    func testHTTP200HTMLIsNotTreatedAsSuccess() {
        let body = "<html>Just a moment...</html>"
        switch PasswordLoginSessionResponse.interpret(status: 200, body: body) {
        case .failed(let status, let text):
            XCTAssertEqual(status, 200)
            XCTAssertTrue(text.contains("Just a moment"))
        default:
            XCTFail("HTML 200 must surface the body, not look like a session")
        }
    }
}

final class PasswordLoginErrorTests: XCTestCase {
    func testUnexpectedDescriptionIncludesPhaseStatusAndBody() {
        let error = PasswordLoginError.unexpected(
            status: 403,
            phase: "csrf",
            body: "<html>Just a moment...</html>"
        )
        let description = error.errorDescription ?? ""
        XCTAssertTrue(description.contains("csrf"), description)
        XCTAssertTrue(description.contains("403"), description)
        XCTAssertTrue(description.contains("Just a moment"), description)
        XCTAssertNotEqual(description, String(localized: "password_login.error.unknown"))
    }
}

final class PasswordLoginJavaScriptProtocolTests: XCTestCase {
    func testLinuxDoKeepsBothHCaptchaCreateEndpointsInOrder() throws {
        XCTAssertEqual(
            PasswordLoginConfig.linuxDo.hCaptchaCreateEndpoints,
            [
                "/captcha/hcaptcha/create.json",
                "/hcaptcha/create.json",
            ]
        )
        let encoded = try XCTUnwrap(
            String(data: JSONEncoder().encode(PasswordLoginConfig.linuxDo.hCaptchaCreateEndpoints), encoding: .utf8)
        )
        let js = PasswordLoginWebSession.loginJavaScript(config: .linuxDo)
        XCTAssertTrue(js.contains(encoded), "login JS must embed both create endpoints in order: \(encoded)")
    }

    func testLoginJavaScriptUsesCredentialsIncludeWithoutManualCookieHeaders() {
        let js = PasswordLoginWebSession.loginJavaScript(config: .linuxDo)
        XCTAssertTrue(js.contains("credentials: 'include'"))
        XCTAssertTrue(js.contains("/session/csrf"))
        XCTAssertTrue(js.contains("/session.json"))
        XCTAssertTrue(js.contains("/captcha/hcaptcha/create.json"))
        XCTAssertTrue(js.contains("/hcaptcha/create.json"))
        XCTAssertTrue(js.contains("X-Requested-With"))
        XCTAssertTrue(js.contains("X-CSRF-Token"))
        XCTAssertFalse(js.contains("'Cookie'"))
        XCTAssertFalse(js.contains("\"Cookie\""))
        XCTAssertFalse(js.contains("User-Agent"))
        XCTAssertFalse(js.contains("'Origin'"))
        XCTAssertFalse(js.contains("\"Origin\""))
    }
}

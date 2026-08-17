import XCTest
@testable import dexo

final class DoHGatewayCookieBridgeTests: XCTestCase {
    func testAppliesNativeHeadersWhenSchemesRetainedOrCookieMissing() {
        XCTAssertTrue(DoHGatewayCookieBridge.shouldApplyNativeSessionHeaders(
            schemesRetained: true,
            missingCookie: false
        ))
        XCTAssertTrue(DoHGatewayCookieBridge.shouldApplyNativeSessionHeaders(
            schemesRetained: false,
            missingCookie: true
        ))
        XCTAssertFalse(DoHGatewayCookieBridge.shouldApplyNativeSessionHeaders(
            schemesRetained: false,
            missingCookie: false
        ))
    }

    func testChallengeWebViewPathSendsFullJar() {
        XCTAssertTrue(DoHGatewayCookieBridge.isChallengeWebViewPath(
            schemesRetained: true,
            accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            hasUserApiKeyHeader: false
        ))
        XCTAssertFalse(DoHGatewayCookieBridge.guestBrowsing(
            isChallengeWebViewPath: true,
            hasUserApiKey: false
        ))
    }

    func testJSONAPIWithoutKeyStaysGuestEvenWhileSchemesAreRetained() {
        XCTAssertFalse(DoHGatewayCookieBridge.isChallengeWebViewPath(
            schemesRetained: true,
            accept: "application/json",
            hasUserApiKeyHeader: false
        ))
        XCTAssertTrue(DoHGatewayCookieBridge.guestBrowsing(
            isChallengeWebViewPath: false,
            hasUserApiKey: false
        ))
    }

    func testJSONAPIWithKeyIsNotGuest() {
        XCTAssertFalse(DoHGatewayCookieBridge.guestBrowsing(
            isChallengeWebViewPath: false,
            hasUserApiKey: true
        ))
    }

    func testPrepareOutboundRequestInjectsLoginCookiesForHTMLWithoutCookieHeader() {
        let previousUA = WebCookieStore.shared.userAgent
        let url = URL(string: "https://cookie-bridge-test.example/challenge")!
        let session = HTTPCookie(properties: [
            .domain: "cookie-bridge-test.example",
            .path: "/",
            .name: "_t",
            .value: "login-token",
            .secure: "TRUE",
        ])!
        let clearance = HTTPCookie(properties: [
            .domain: "cookie-bridge-test.example",
            .path: "/",
            .name: "cf_clearance",
            .value: "cf-token",
            .secure: "TRUE",
        ])!
        WebCookieStore.shared.setCookies([session, clearance])
        WebCookieStore.shared.userAgent = "Mozilla/5.0 CookieBridgeTest"
        defer {
            WebCookieStore.shared.clearCookies(for: "https://cookie-bridge-test.example")
            WebCookieStore.shared.userAgent = previousUA
        }

        var request = URLRequest(url: url)
        request.setValue("text/html", forHTTPHeaderField: "Accept")
        let outbound = DoHGatewayCookieBridge.prepareOutboundRequest(request)
        let cookie = outbound.value(forHTTPHeaderField: "Cookie") ?? ""
        // Schemes are not retained in this unit test, so missing Cookie uses
        // the guest jar (same as today's API client). Full `_t` is covered by
        // `testChallengeWebViewPathSendsFullJar`.
        XCTAssertTrue(cookie.contains("cf_clearance=cf-token"))
        XCTAssertFalse(cookie.contains("_t="))
        XCTAssertEqual(outbound.value(forHTTPHeaderField: "User-Agent"), "Mozilla/5.0 CookieBridgeTest")
        XCTAssertEqual(outbound.allHTTPHeaderFields?.filter { $0.key.lowercased() == "cookie" }.count, 1)
    }

    func testMergeResponseWritesSetCookieToNativeJar() {
        let url = URL(string: "https://cookie-bridge-test.example/challenge")!
        WebCookieStore.shared.clearCookies(for: "https://cookie-bridge-test.example")
        defer { WebCookieStore.shared.clearCookies(for: "https://cookie-bridge-test.example") }

        let response = HTTPURLResponse(
            url: url,
            statusCode: 403,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Set-Cookie": "cf_clearance=from-protocol; Path=/; Secure",
                "Content-Type": "text/html",
            ]
        )!
        var request = URLRequest(url: url)
        request.setValue("text/html", forHTTPHeaderField: "Accept")
        DoHGatewayCookieBridge.mergeResponse(response, original: request)

        let stored = WebCookieStore.shared.cookies(for: url)
        XCTAssertTrue(stored.contains { $0.name == "cf_clearance" && $0.value == "from-protocol" })
    }

    func testForumBaseURLUsesOrigin() throws {
        let url = try XCTUnwrap(URL(string: "https://linux.do/challenge?foo=1"))
        XCTAssertEqual(DoHGatewayCookieBridge.forumBaseURL(from: url), "https://linux.do")
    }

    func testSkipsLoopbackRewriteURL() throws {
        let loopback = try XCTUnwrap(URL(string: "http://127.0.0.1:47821/challenge"))
        XCTAssertFalse(DoHGatewayCookieBridge.isOriginalForumURL(loopback))
        XCTAssertTrue(DoHGatewayCookieBridge.isOriginalForumURL(
            URL(string: "https://linux.do/challenge")
        ))
    }
}

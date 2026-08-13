import XCTest
@testable import dexo

final class WebCookieStoreTests: XCTestCase {
    func testDomainCookieRequiresDotBoundary() {
        XCTAssertTrue(WebCookieStore.cookieDomain(".example.com", matchesHost: "forum.example.com"))
        XCTAssertTrue(WebCookieStore.cookieDomain(".example.com", matchesHost: "example.com"))
        XCTAssertFalse(WebCookieStore.cookieDomain(".example.com", matchesHost: "notexample.com"))
        XCTAssertFalse(WebCookieStore.cookieDomain(".example.com", matchesHost: "example.com.evil.test"))
    }

    func testHostOnlyCookieRequiresExactHost() {
        XCTAssertTrue(WebCookieStore.cookieDomain("forum.example.com", matchesHost: "forum.example.com"))
        XCTAssertFalse(WebCookieStore.cookieDomain("forum.example.com", matchesHost: "sub.forum.example.com"))
    }

    func testDomainMatchingIsCaseInsensitive() {
        XCTAssertTrue(WebCookieStore.cookieDomain(".Example.COM", matchesHost: "Forum.Example.com"))
    }

    func testApplySessionHeadersAttachesClearanceAndUserAgentForGuestRequest() {
        let previousUA = WebCookieStore.shared.userAgent
        let url = URL(string: "https://guest-cf-test.example/latest.json")!
        let clearance = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "cf_clearance",
            .value: "guest-token",
            .secure: "TRUE",
        ])!
        let botManagement = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "__cf_bm",
            .value: "bm-token",
            .secure: "TRUE",
        ])!
        let session = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "_t",
            .value: "should-not-go-out-as-guest",
            .secure: "TRUE",
        ])!
        let otherCf = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "cf_other",
            .value: "must-not-go-out",
            .secure: "TRUE",
        ])!
        WebCookieStore.shared.setCookies([clearance, botManagement, session, otherCf])
        WebCookieStore.shared.userAgent = "Mozilla/5.0 GuestChallengeTest"
        defer {
            WebCookieStore.shared.clearCookies(for: "https://guest-cf-test.example")
            WebCookieStore.shared.userAgent = previousUA
        }

        // Alamofire always stamps a default User-Agent before the interceptor.
        var request = URLRequest(url: url)
        request.setValue("Dexo/1.0 (iPhone; iOS 15.0) Alamofire/5.0", forHTTPHeaderField: "User-Agent")
        WebCookieStore.shared.applySessionHeaders(to: &request, guestBrowsing: true)

        let cookie = request.value(forHTTPHeaderField: "Cookie") ?? ""
        XCTAssertTrue(cookie.contains("cf_clearance=guest-token"))
        XCTAssertTrue(cookie.contains("__cf_bm=bm-token"))
        XCTAssertFalse(cookie.contains("_t="))
        XCTAssertFalse(cookie.contains("cf_other="))
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "Mozilla/5.0 GuestChallengeTest")
        XCTAssertEqual(cookieHeaderCount(in: request), 1)
    }

    func testApplySessionHeadersSendsSessionCookieWhenNotGuestBrowsing() {
        let previousUA = WebCookieStore.shared.userAgent
        let url = URL(string: "https://guest-cf-test.example/latest.json")!
        let clearance = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "cf_clearance",
            .value: "guest-token",
            .secure: "TRUE",
        ])!
        let session = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "_t",
            .value: "web-session",
            .secure: "TRUE",
        ])!
        WebCookieStore.shared.setCookies([clearance, session])
        WebCookieStore.shared.userAgent = "Mozilla/5.0 GuestChallengeTest"
        defer {
            WebCookieStore.shared.clearCookies(for: "https://guest-cf-test.example")
            WebCookieStore.shared.userAgent = previousUA
        }

        var request = URLRequest(url: url)
        WebCookieStore.shared.applySessionHeaders(to: &request, guestBrowsing: false)

        let cookie = request.value(forHTTPHeaderField: "Cookie") ?? ""
        XCTAssertTrue(cookie.contains("cf_clearance=guest-token"))
        XCTAssertTrue(cookie.contains("_t=web-session"))
        XCTAssertEqual(cookieHeaderCount(in: request), 1)
    }

    func testApplySessionHeadersReplacesCookieAndUserAgentWithoutDuplicating() {
        let previousUA = WebCookieStore.shared.userAgent
        let url = URL(string: "https://guest-cf-test.example/latest.json")!
        let cookie = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "cf_clearance",
            .value: "guest-token",
            .secure: "TRUE",
        ])!
        WebCookieStore.shared.setCookies([cookie])
        WebCookieStore.shared.userAgent = "Mozilla/5.0 GuestChallengeTest"
        defer {
            WebCookieStore.shared.clearCookies(for: "https://guest-cf-test.example")
            WebCookieStore.shared.userAgent = previousUA
        }

        var request = URLRequest(url: url)
        request.setValue("existing=1", forHTTPHeaderField: "Cookie")
        request.addValue("stale-clearance", forHTTPHeaderField: "Cookie")
        request.setValue("CustomUA", forHTTPHeaderField: "User-Agent")
        WebCookieStore.shared.applySessionHeaders(to: &request, guestBrowsing: true)

        XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), "cf_clearance=guest-token")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "Mozilla/5.0 GuestChallengeTest")
        XCTAssertEqual(cookieHeaderCount(in: request), 1)
    }

    func testGuestCloudflareCookieNameDetection() {
        XCTAssertTrue(WebCookieStore.isGuestCloudflareCookieName("cf_clearance"))
        XCTAssertTrue(WebCookieStore.isGuestCloudflareCookieName("__cf_bm"))
        XCTAssertFalse(WebCookieStore.isGuestCloudflareCookieName("cf_other"))
        XCTAssertFalse(WebCookieStore.isGuestCloudflareCookieName("_t"))
        XCTAssertFalse(WebCookieStore.isGuestCloudflareCookieName("_forum_session"))
    }

    func testRemoveClearanceCookiesDropsOnlyCfClearance() {
        let url = URL(string: "https://guest-cf-test.example/")!
        let clearance = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "cf_clearance",
            .value: "stale",
            .secure: "TRUE",
        ])!
        let botManagement = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "__cf_bm",
            .value: "keep",
            .secure: "TRUE",
        ])!
        let session = HTTPCookie(properties: [
            .domain: "guest-cf-test.example",
            .path: "/",
            .name: "_t",
            .value: "keep-session",
            .secure: "TRUE",
        ])!
        WebCookieStore.shared.setCookies([clearance, botManagement, session])
        defer { WebCookieStore.shared.clearCookies(for: "https://guest-cf-test.example") }

        WebCookieStore.shared.removeClearanceCookies(matching: url)

        let remaining = Set(WebCookieStore.shared.cookies(for: url).map(\.name))
        XCTAssertFalse(remaining.contains("cf_clearance"))
        XCTAssertTrue(remaining.contains("__cf_bm"))
        XCTAssertTrue(remaining.contains("_t"))
    }

    private func cookieHeaderCount(in request: URLRequest) -> Int {
        request.allHTTPHeaderFields?.keys.filter { $0.caseInsensitiveCompare("Cookie") == .orderedSame }.count ?? 0
    }
}

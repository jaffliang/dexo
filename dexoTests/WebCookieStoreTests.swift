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
        WebCookieStore.shared.applySessionHeaders(to: &request)

        XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), "cf_clearance=guest-token")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "Mozilla/5.0 GuestChallengeTest")
    }

    func testApplySessionHeadersDoesNotOverwriteExistingCookieOrUserAgent() {
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
        request.setValue("CustomUA", forHTTPHeaderField: "User-Agent")
        WebCookieStore.shared.applySessionHeaders(to: &request)

        XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), "existing=1")
        XCTAssertEqual(request.value(forHTTPHeaderField: "User-Agent"), "CustomUA")
    }
}

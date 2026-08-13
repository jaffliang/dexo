import XCTest
@testable import dexo

final class ExternalLinkOpenerTests: XCTestCase {
    private let linuxDo = URL(string: "https://linux.do/")!
    private let coee = URL(string: "https://api.coee.ccwu.cc/")!
    private let cdk = URL(string: "https://cdk.linux.do/")!

    override func tearDown() {
        WebCookieStore.shared.clearCookies(for: "https://linux.do")
        super.tearDown()
    }

    func testTypedNonFamilyHTTPSUsesAuthenticatedWebViewWhenTExists() {
        installLinuxDoToken()
        XCTAssertEqual(
            ExternalLinkOpener.destinationForTypedURL(coee),
            .authenticatedWebView
        )
        XCTAssertEqual(
            ExternalLinkOpener.destinationForTypedURL(linuxDo),
            .authenticatedWebView
        )
    }

    func testTypedURLWithoutTShowsMissingSession() {
        XCTAssertEqual(
            ExternalLinkOpener.destinationForTypedURL(coee),
            .missingSession
        )
        XCTAssertEqual(
            ExternalLinkOpener.destinationForTypedURL(cdk),
            .missingSession
        )
    }

    func testLinkTapKeepsNonFamilyOnSafariEvenWhenTExists() {
        installLinuxDoToken()
        XCTAssertEqual(ExternalLinkOpener.destinationForLinkTap(coee), .safari)
        XCTAssertEqual(
            ExternalLinkOpener.destinationForLinkTap(cdk),
            .authenticatedWebView
        )
    }

    func testLinkTapFamilyWithoutTShowsMissingSession() {
        XCTAssertEqual(
            ExternalLinkOpener.destinationForLinkTap(cdk),
            .missingSession
        )
    }

    private func installLinuxDoToken() {
        let token = HTTPCookie(properties: [
            .domain: "linux.do",
            .path: "/",
            .name: "_t",
            .value: "typed-url-session",
            .secure: "TRUE",
            .expires: Date(timeIntervalSince1970: 1_900_000_000),
        ])!
        WebCookieStore.shared.setCookies([token])
    }
}

import XCTest
@testable import dexo

final class WebViewDoHTunnelPolicyTests: XCTestCase {
    func testCloudflareChallengeHostUsesEndToEndTLS() {
        XCTAssertTrue(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "challenges.cloudflare.com"))
        XCTAssertTrue(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "CHALLENGES.CLOUDFLARE.COM"))
    }

    func testHCaptchaHostsUseEndToEndTLS() {
        XCTAssertTrue(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "hcaptcha.com"))
        XCTAssertTrue(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "newassets.hcaptcha.com"))
        XCTAssertTrue(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "imgs.hcaptcha.com"))
    }

    func testForumHostsStayOnMITM() {
        XCTAssertFalse(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "linux.do"))
        XCTAssertFalse(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "idcflare.com"))
        XCTAssertFalse(WebViewDoHTunnelPolicy.usesEndToEndTLS(host: "cdnjs.cloudflare.com"))
    }

    func testPrefaceRoundTrip() throws {
        let original = WebViewDoHTunnelPolicy.Preface(
            usesEndToEndTLS: true,
            host: "challenges.cloudflare.com",
            port: 443
        )
        let encoded = WebViewDoHTunnelPolicy.encodePreface(original)
        let parsed = try XCTUnwrap(WebViewDoHTunnelPolicy.splitPreface(encoded))
        XCTAssertEqual(parsed.0, original)
        XCTAssertTrue(parsed.1.isEmpty)
    }

    func testPrefaceSplitsRemainder() throws {
        var buffer = WebViewDoHTunnelPolicy.encodePreface(
            .init(usesEndToEndTLS: false, host: "linux.do", port: 443)
        )
        buffer.append(Data("GET /challenge HTTP/1.1\r\n".utf8))
        let parsed = try XCTUnwrap(WebViewDoHTunnelPolicy.splitPreface(buffer))
        XCTAssertFalse(parsed.0.usesEndToEndTLS)
        XCTAssertEqual(parsed.0.host, "linux.do")
        XCTAssertEqual(String(data: parsed.1, encoding: .utf8), "GET /challenge HTTP/1.1\r\n")
    }

    func testPrefaceIncompleteUntilCRLF() {
        let partial = Data("X-Dexo-Tunnel: mitm linux.do 443".utf8)
        XCTAssertNil(WebViewDoHTunnelPolicy.splitPreface(partial))
    }

    func testMITMSessionUsesDoHGatewayProtocol() {
        let configuration = WebViewDoHMITMTunnel.makeSessionConfiguration()
        XCTAssertTrue(
            configuration.protocolClasses?.contains(where: { $0 == DoHGatewayURLProtocol.self }) == true
        )
        XCTAssertNil(configuration.httpCookieStorage)
        XCTAssertFalse(configuration.httpShouldSetCookies)
    }
}

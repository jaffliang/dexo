import WebKit
import XCTest
@testable import dexo

final class WebViewLegacyChallengeDoHTests: XCTestCase {
    func testIsolatedStoreRejectsZeroPort() {
        let shared = WebCookieStore.shared.websiteDataStore
        XCTAssertThrowsError(try WebViewDoHConfigurator.makeIsolatedProxiedDataStore(port: 0)) { error in
            guard let challenge = error as? WebViewLegacyChallengeError else {
                return XCTFail("expected WebViewLegacyChallengeError, got \(error)")
            }
            XCTAssertEqual(challenge, .isolatedStoreFailed("isolated store port is 0"))
        }
        XCTAssertTrue(WebCookieStore.shared.websiteDataStore === shared)
        XCTAssertTrue(shared !== WKWebsiteDataStore.default())
    }

    func testIsolatedStoreRejectsOutOfRangePort() {
        XCTAssertThrowsError(try WebViewDoHConfigurator.makeIsolatedProxiedDataStore(port: 70_000)) { error in
            guard case .isolatedStoreFailed(let reason) = error as? WebViewLegacyChallengeError else {
                return XCTFail("expected isolatedStoreFailed, got \(error)")
            }
            XCTAssertTrue(reason.contains("70000"), reason)
        }
    }

    func testSchemeRegistrationIsRefCounted() {
        let before = WebViewCustomProtocolSchemes.registrationCount
        guard WebViewCustomProtocolSchemes.isAvailable else {
            XCTAssertEqual(before, 0)
            return
        }

        var first = WebViewCustomProtocolSchemes.acquire()
        XCTAssertNotNil(first)
        XCTAssertEqual(WebViewCustomProtocolSchemes.registrationCount, before + 1)

        var second = WebViewCustomProtocolSchemes.acquire()
        XCTAssertNotNil(second)
        XCTAssertEqual(WebViewCustomProtocolSchemes.registrationCount, before + 2)

        first = nil
        XCTAssertEqual(WebViewCustomProtocolSchemes.registrationCount, before + 1)
        second = nil
        XCTAssertEqual(WebViewCustomProtocolSchemes.registrationCount, before)
    }

    func testRecoveryDoesNotStartConnectListener() {
        WebViewLegacyProxyRecovery.clearLeakedProxies()
        if #available(iOS 17.0, *) {
            XCTAssertTrue(WKWebsiteDataStore.default().proxyConfigurations.isEmpty)
            XCTAssertTrue(WebCookieStore.shared.websiteDataStore.proxyConfigurations.isEmpty)
        }
    }

    func testAttachLegacyRoutingIsNoOpWhenDoHIsOff() async {
        let previous = AppSettings.shared.dohEnabled
        AppSettings.shared.dohEnabled = false
        defer { AppSettings.shared.dohEnabled = previous }

        let configuration = WKWebViewConfiguration()
        let original = configuration.websiteDataStore
        let lease = await WebViewDoHConfigurator.attachLegacyChallengeRouting(configuration)
        XCTAssertNil(lease)
        XCTAssertTrue(configuration.websiteDataStore === original)
        XCTAssertNil(WebViewDoHConfigurator.legacyAttachWarning(from: lease))
    }

    func testGatewayInactiveWarningKeepsSharedStore() async throws {
        let previous = AppSettings.shared.dohEnabled
        AppSettings.shared.dohEnabled = true
        defer { AppSettings.shared.dohEnabled = previous }

        guard !DoHGatewayRuntime.shared.currentConfiguration.isProxyActive else {
            throw XCTSkip("gateway is already listening in this process")
        }

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = WebCookieStore.shared.websiteDataStore
        let lease = await WebViewDoHConfigurator.attachLegacyChallengeRouting(configuration)
        XCTAssertNotNil(lease)
        XCTAssertTrue(configuration.websiteDataStore === WebCookieStore.shared.websiteDataStore)
        guard let warning = WebViewDoHConfigurator.legacyAttachWarning(from: lease) as? WebViewLegacyChallengeError else {
            return XCTFail("expected gatewayInactive warning")
        }
        XCTAssertEqual(warning, .gatewayInactive)
        (lease as? WebViewLegacyChallengeSession)?.release()
    }

    func testRelaySessionDoesNotInstallProxyOrRecurse() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = []
        XCTAssertEqual(configuration.protocolClasses?.count, 0)
        XCTAssertNil(configuration.connectionProxyDictionary)
        if #available(iOS 17.0, *) {
            XCTAssertTrue(configuration.proxyConfigurations.isEmpty)
        }
    }

    func testErrorDetailIncludesURLErrorDomain() {
        let error = URLError(.timedOut)
        let detail = WebViewChallengeDoHDiagnostics.detail(for: error)
        XCTAssertTrue(detail.contains(NSURLErrorDomain), detail)
        XCTAssertTrue(detail.contains("-1001") || detail.contains("\(URLError.timedOut.rawValue)"), detail)
    }
}

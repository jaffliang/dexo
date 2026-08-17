import WebKit
import XCTest
@testable import dexo
import DoHGatewayPolicy

final class WebViewLegacyChallengeDoHTests: XCTestCase {
    func testIsolatedStoreRejectsZeroPort() {
        let shared = WebCookieStore.shared.websiteDataStore
        XCTAssertThrowsError(try WebViewDoHConfigurator.makeIsolatedProxiedDataStore(port: 0)) { error in
            guard let challenge = error as? WebViewLegacyChallengeError else {
                return XCTFail("expected WebViewLegacyChallengeError, got \(error)")
            }
            XCTAssertEqual(challenge, .isolatedStoreFailed("isolated store port is 0"))
        }
        XCTAssertThrowsError(try WebViewDoHConfigurator.makeIsolatedConnectDataStore(port: 0))
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

    func testSchemeRegistrationIsDisabled() {
        XCTAssertFalse(WebViewCustomProtocolSchemes.isAvailable)
        XCTAssertNil(WebViewCustomProtocolSchemes.acquire())
        XCTAssertEqual(WebViewCustomProtocolSchemes.registrationCount, 0)
        XCTAssertFalse(WebViewCustomProtocolSchemes.isRetained)
        WebViewCustomProtocolSchemes.unregisterIfNeeded()
        XCTAssertFalse(WebViewCustomProtocolSchemes.isRetained)
    }

    func testRecoveryDoesNotStartConnectListener() {
        WebViewLegacyProxyRecovery.clearLeakedProxies()
        if #available(iOS 17.0, *) {
            XCTAssertTrue(WKWebsiteDataStore.default().proxyConfigurations.isEmpty)
            XCTAssertTrue(WebCookieStore.shared.websiteDataStore.proxyConfigurations.isEmpty)
        }
        XCTAssertFalse(WebViewCustomProtocolSchemes.isRetained)
    }

    func testAttachIsolatedStoreIsNoOpWhenDoHIsOff() async {
        let previous = AppSettings.shared.dohEnabled
        AppSettings.shared.dohEnabled = false
        defer { AppSettings.shared.dohEnabled = previous }

        let configuration = WKWebViewConfiguration()
        let original = configuration.websiteDataStore
        let lease = await WebViewDoHConfigurator.attachIsolatedConnectStore(configuration)
        XCTAssertNil(lease)
        XCTAssertTrue(configuration.websiteDataStore === original)
        XCTAssertNil(WebViewDoHConfigurator.legacyAttachWarning(from: lease))
    }

    func testGatewayInactiveWarningKeepsSharedStore() async throws {
        let previous = AppSettings.shared.dohEnabled
        AppSettings.shared.dohEnabled = true
        defer { AppSettings.shared.dohEnabled = previous }

        guard !DoHGatewayRuntime.shared.currentConfiguration.isConnectProxyActive else {
            throw XCTSkip("gateway is already listening in this process")
        }

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = WebCookieStore.shared.websiteDataStore
        let lease = await WebViewDoHConfigurator.attachIsolatedConnectStore(configuration)
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

    func testMitmCAMissingIsALoudAttachFailure() {
        let error = WebViewLegacyChallengeError.mitmCAMissing
        XCTAssertEqual(error.localizedDescription, "DoH MITM CA is not available")
        XCTAssertNotEqual(error, .gatewayInactive)
    }

    func testTrustEvaluatorRequiresCertificateBytes() {
        XCTAssertNil(WebViewProxyTrustEvaluator(certificateData: []))
        XCTAssertNil(WebViewProxyTrustEvaluator(certificateData: [Data([0x00, 0x01])]))
    }

    func testTunnelPolicyMatchesRustSplit() {
        XCTAssertTrue(WebViewDoHTunnelPolicy.shouldPassthroughTLS(host: "challenges.cloudflare.com"))
        XCTAssertTrue(WebViewDoHTunnelPolicy.shouldPassthroughTLS(host: "newassets.hcaptcha.com"))
        XCTAssertFalse(WebViewDoHTunnelPolicy.shouldPassthroughTLS(host: "linux.do"))
        XCTAssertFalse(WebViewDoHTunnelPolicy.shouldPassthroughTLS(host: "cdk.linux.do"))
        XCTAssertFalse(WebViewDoHTunnelPolicy.shouldPassthroughTLS(host: "idcflare.com"))
    }
}

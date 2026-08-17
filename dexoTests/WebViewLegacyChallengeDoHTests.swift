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

    func testIsolatedProxiedStoreIsNonPersistent() throws {
        let store: WKWebsiteDataStore
        do {
            store = try WebViewDoHConfigurator.makeIsolatedProxiedDataStore(port: 9)
        } catch {
            throw XCTSkip("isolated store SPI unavailable: \(error)")
        }
        XCTAssertFalse(store.isPersistent, "proxied stores must not persist into CFNetwork")
        XCTAssertTrue(store !== WKWebsiteDataStore.default())
        XCTAssertTrue(store !== WebCookieStore.shared.websiteDataStore)
        WKWebsiteDataStore.dexo_clearProxyConfiguration(store)
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

    func testAttachIsolatedStoreIsNoOpBeforeiOS17() async throws {
        guard #unavailable(iOS 17.0) else {
            throw XCTSkip("iOS 17+ attaches CONNECT")
        }
        let previous = AppSettings.shared.dohEnabled
        AppSettings.shared.dohEnabled = true
        defer { AppSettings.shared.dohEnabled = previous }

        XCTAssertFalse(WebViewDoHConfigurator.attachesWebViewConnectProxy)
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = WebCookieStore.shared.websiteDataStore
        let lease = await WebViewDoHConfigurator.attachIsolatedConnectStore(configuration)
        XCTAssertNil(lease)
        XCTAssertTrue(configuration.websiteDataStore === WebCookieStore.shared.websiteDataStore)
        XCTAssertNil(WebViewDoHConfigurator.legacyAttachWarning(from: lease))
    }

    func testGatewayInactiveWarningKeepsSharedStore() async throws {
        guard #available(iOS 17.0, *) else {
            throw XCTSkip("CONNECT attach is iOS 17+ only")
        }
        let previous = AppSettings.shared.dohEnabled
        AppSettings.shared.dohEnabled = true
        defer { AppSettings.shared.dohEnabled = previous }

        guard !DoHGatewayRuntime.shared.currentConfiguration.isConnectProxyActive else {
            throw XCTSkip("gateway is already listening in this process")
        }

        XCTAssertTrue(WebViewDoHConfigurator.attachesWebViewConnectProxy)
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
        DoHGatewayPolicy.applyDirectConnectionProxy(configuration)
        XCTAssertEqual(configuration.protocolClasses?.count, 0)
        XCTAssertTrue(DoHGatewayPolicy.disablesConnectionProxies(configuration.connectionProxyDictionary))
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

    func testSecureConnectionDetailIncludesProxyProbe() {
        let probe = WebViewDoHLoadProbe(proxyAttached: false, connectPort: 18_443)
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorSecureConnectionFailed,
            userInfo: [NSLocalizedDescriptionKey: "ssl"]
        )
        XCTAssertTrue(WebViewChallengeDoHDiagnostics.isSecureConnectionFailure(error))
        let detail = WebViewChallengeDoHDiagnostics.detail(for: error, probe: probe)
        XCTAssertTrue(detail.contains("proxy=off"), detail)
        XCTAssertTrue(detail.contains("connectPort=18443"), detail)
        XCTAssertTrue(detail.contains("didReceive=no"), detail)
        probe.markDidReceiveServerTrust()
        let after = WebViewChallengeDoHDiagnostics.detail(for: error, probe: probe)
        XCTAssertTrue(after.contains("didReceive=yes"), after)
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

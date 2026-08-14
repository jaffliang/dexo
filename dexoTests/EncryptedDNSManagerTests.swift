import DoHGatewayPolicy
import WebKit
import XCTest
@testable import dexo

final class EncryptedDNSManagerTests: XCTestCase {
    func testNormalizationAddsHTTPSScheme() {
        XCTAssertEqual(
            EncryptedDNSManager.normalizedServerURL(" dns.example.com/dns-query ")?.absoluteString,
            "https://dns.example.com/dns-query"
        )
    }

    func testNormalizationPreservesHTTPSPathPortAndQuery() {
        XCTAssertEqual(
            EncryptedDNSManager.normalizedServerURL(
                "https://dns.example.com:8443/dns-query?token=value"
            )?.absoluteString,
            "https://dns.example.com:8443/dns-query?token=value"
        )
    }

    func testNormalizationRejectsUnsafeOrMalformedEndpoints() {
        XCTAssertNil(EncryptedDNSManager.normalizedServerURL(""))
        XCTAssertNil(EncryptedDNSManager.normalizedServerURL("http://dns.example.com/dns-query"))
        XCTAssertNil(EncryptedDNSManager.normalizedServerURL("https://user:password@dns.example.com/dns-query"))
        XCTAssertNil(EncryptedDNSManager.normalizedServerURL("https://dns.example.com/dns-query#fragment"))
        XCTAssertNil(EncryptedDNSManager.normalizedServerURL("https://"))
    }

    func testApplyCurrentSettingsReturnsWithoutWaitingForProbe() {
        let startedAt = Date()
        EncryptedDNSManager.shared.applyCurrentSettings()
        XCTAssertLessThan(Date().timeIntervalSince(startedAt), 0.5)
    }

    func testClearLeftoverWebKitHTTPProxiesTargetsDefaultAndCookieStores() {
        let defaultStore = WKWebsiteDataStore.default()
        let cookieStore = WebCookieStore.shared.websiteDataStore
        XCTAssertTrue(cookieStore !== defaultStore)
        EncryptedDNSManager.shared.clearLeftoverWebKitHTTPProxies()
        WKWebsiteDataStore.dexo_clearProxyConfiguration(defaultStore)
        WKWebsiteDataStore.dexo_clearProxyConfiguration(cookieStore)
    }

    func testApplyAsyncInvalidURLCompletesWithoutHanging() {
        let finished = expectation(description: "applyAsync")
        let startedAt = Date()
        EncryptedDNSManager.shared.applyAsync(
            enabled: true,
            serverURLString: "http://dns.example.com/dns-query"
        ) { ok in
            XCTAssertFalse(ok)
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertTrue(DoHGatewayPolicy.shouldDisableDoHAfterLaunchStart(ok))
            XCTAssertLessThan(Date().timeIntervalSince(startedAt), 2)
            finished.fulfill()
        }
        wait(for: [finished], timeout: 2)
    }
}

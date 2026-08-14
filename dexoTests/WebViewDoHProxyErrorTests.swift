import XCTest
@testable import dexo

final class WebViewDoHProxyErrorTests: XCTestCase {
    func testProxyErrorDetailIncludesCaseName() {
        let error = WebViewDoHProxy.ProxyError.unavailablePort
        XCTAssertEqual(
            WebViewDoHProxyDiagnostics.detail(for: error),
            "ProxyError.unavailablePort: CONNECT listener has no port"
        )
    }

    func testLegacyAttachFailureIncludesReason() {
        let error = WebViewDoHProxy.ProxyError.legacyProxyAttachFailed(
            "_setProxyConfiguration: not available"
        )
        let detail = WebViewDoHProxyDiagnostics.detail(for: error)
        XCTAssertTrue(detail.hasPrefix("ProxyError.legacyProxyAttachFailed:"))
        XCTAssertTrue(detail.contains("_setProxyConfiguration: not available"))
    }

    func testInvalidDoHConfigurationDetail() {
        let error = WebViewDoHProxy.ProxyError.invalidDoHConfiguration
        XCTAssertEqual(
            WebViewDoHProxyDiagnostics.detail(for: error),
            "ProxyError.invalidDoHConfiguration: DoH is on but the selected server URL is missing or invalid"
        )
    }
}

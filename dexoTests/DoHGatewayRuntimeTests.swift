import XCTest
@testable import dexo

final class DoHGatewayRuntimeTests: XCTestCase {
    func testPrepareInsertsGatewayURLProtocol() {
        let configuration = URLSessionConfiguration.ephemeral
        DoHGatewayRuntime.prepare(configuration)
        XCTAssertTrue(
            configuration.protocolClasses?.contains(where: { $0 == DoHGatewayURLProtocol.self }) == true
        )
    }

    func testURLProtocolDoesNotInterceptWhenGatewayIsOff() throws {
        DoHGatewayRuntime.shared.stop()
        let request = URLRequest(url: try XCTUnwrap(URL(string: "https://linux.do/latest.json")))
        XCTAssertFalse(DoHGatewayURLProtocol.canInit(with: request))
        XCTAssertFalse(DoHGatewayRuntime.shared.currentConfiguration.isConnectProxyActive)
        XCTAssertEqual(DoHGatewayRuntime.shared.currentConfiguration.connectPort, 0)
        XCTAssertNil(DoHGatewayRuntime.shared.mitmCACertificateData)
    }

    func testBuiltInDoHServersUsePublicHTTPSEndpoints() {
        XCTAssertEqual(AppSettings.builtInDoHServers.count, 3)
        XCTAssertEqual(
            AppSettings.builtInDoHServers.map(\.urlString),
            [
                "https://cloudflare-dns.com/dns-query",
                "https://dns.alidns.com/dns-query",
                "https://doh.pub/dns-query",
            ]
        )
        for server in AppSettings.builtInDoHServers {
            XCTAssertNotNil(EncryptedDNSManager.normalizedServerURL(server.urlString))
        }
    }

    func testECHCompiledIsExposed() {
        XCTAssertTrue(
            DoHGatewayRuntime.echCompiled,
            "libdexo_doh_gateway.a must be built with --features ech"
        )
        XCTAssertFalse(DoHGatewayRuntime.echCompiledLabel.isEmpty)
    }

    func testInvalidDoHURLRecordsStartError() {
        XCTAssertFalse(DoHGatewayRuntime.shared.setEnabled(true, serverURLString: "http://dns.example.com/dns-query"))
        let reason = DoHGatewayRuntime.shared.lastError ?? ""
        XCTAssertFalse(reason.isEmpty)
        XCTAssertTrue(reason.localizedCaseInsensitiveContains("https"), reason)
    }

    func testApplyAsyncInvalidURLCompletesWithoutHanging() {
        let finished = expectation(description: "applyAsync")
        let startedAt = Date()
        DoHGatewayRuntime.shared.applyAsync(
            enabled: true,
            serverURLString: "http://dns.example.com/dns-query"
        ) { ok in
            XCTAssertFalse(ok)
            XCTAssertLessThan(Date().timeIntervalSince(startedAt), 2)
            let reason = DoHGatewayRuntime.shared.lastError ?? ""
            XCTAssertTrue(reason.localizedCaseInsensitiveContains("https"), reason)
            finished.fulfill()
        }
        wait(for: [finished], timeout: 2)
    }
}

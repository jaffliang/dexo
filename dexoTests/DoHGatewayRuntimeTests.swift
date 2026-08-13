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
}

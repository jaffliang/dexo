import DoHGatewayPolicy
import XCTest

final class DoHGatewayPolicyTests: XCTestCase {
    private let active = DoHGatewayPolicy.Configuration(
        isEnabled: true,
        gatewayPort: 47821,
        dohHost: "cloudflare-dns.com"
    )

    func testRewritesHTTPSForumURLToLoopbackGateway() throws {
        let original = try XCTUnwrap(URL(string: "https://linux.do/latest.json?page=1"))
        var request = URLRequest(url: original)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let rewritten = try XCTUnwrap(DoHGatewayPolicy.rewrittenRequest(request, configuration: active))
        XCTAssertEqual(rewritten.url?.scheme, "http")
        XCTAssertEqual(rewritten.url?.host, "127.0.0.1")
        XCTAssertEqual(rewritten.url?.port, 47821)
        XCTAssertEqual(rewritten.url?.path, "/latest.json")
        XCTAssertEqual(rewritten.url?.query, "page=1")
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: DoHGatewayPolicy.upstreamHostHeader), "linux.do")
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: DoHGatewayPolicy.upstreamPortHeader), "443")
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: DoHGatewayPolicy.upstreamSchemeHeader), "https")
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: "Host"), "linux.do")
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: "Accept"), "application/json")
    }

    func testDoesNotRewriteWhenProxyDisabledOrPortMissing() throws {
        let url = try XCTUnwrap(URL(string: "https://linux.do/latest.json"))
        let request = URLRequest(url: url)
        XCTAssertNil(DoHGatewayPolicy.rewrittenRequest(
            request,
            configuration: .init(isEnabled: false, gatewayPort: 47821, dohHost: "cloudflare-dns.com")
        ))
        XCTAssertNil(DoHGatewayPolicy.rewrittenRequest(
            request,
            configuration: .init(isEnabled: true, gatewayPort: 0, dohHost: "cloudflare-dns.com")
        ))
    }

    func testHostPolicySkipsLoopbackIPAndDoHResolver() throws {
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(
            try XCTUnwrap(URL(string: "https://127.0.0.1/latest.json")),
            configuration: active
        ))
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(
            try XCTUnwrap(URL(string: "https://localhost/latest.json")),
            configuration: active
        ))
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(
            try XCTUnwrap(URL(string: "https://1.1.1.1/dns-query")),
            configuration: active
        ))
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(
            try XCTUnwrap(URL(string: "https://cloudflare-dns.com/dns-query")),
            configuration: active
        ))
        XCTAssertTrue(DoHGatewayPolicy.shouldRewrite(
            try XCTUnwrap(URL(string: "https://idcflare.com/latest.json")),
            configuration: active
        ))
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(
            try XCTUnwrap(URL(string: "http://linux.do/latest.json")),
            configuration: active
        ))
    }

    func testDoesNotRewriteAlreadyProxiedOrSkippedRequests() throws {
        let url = try XCTUnwrap(URL(string: "https://linux.do/latest.json"))
        var skipped = URLRequest(url: url)
        skipped.setValue("1", forHTTPHeaderField: DoHGatewayPolicy.skipHeader)
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(skipped, configuration: active))

        var alreadyRewritten = URLRequest(url: try XCTUnwrap(URL(string: "http://127.0.0.1:47821/latest.json")))
        alreadyRewritten.setValue("linux.do", forHTTPHeaderField: DoHGatewayPolicy.upstreamHostHeader)
        XCTAssertFalse(DoHGatewayPolicy.shouldRewrite(alreadyRewritten, configuration: active))
    }

    func testProxyEnablementRequiresHTTPSDoHURL() {
        XCTAssertTrue(DoHGatewayPolicy.isProxyEnablementAllowed(isEnabled: false, serverURLString: ""))
        XCTAssertTrue(DoHGatewayPolicy.isProxyEnablementAllowed(
            isEnabled: true,
            serverURLString: "cloudflare-dns.com/dns-query"
        ))
        XCTAssertFalse(DoHGatewayPolicy.isProxyEnablementAllowed(
            isEnabled: true,
            serverURLString: "http://dns.example.com/dns-query"
        ))
        XCTAssertEqual(
            DoHGatewayPolicy.normalizedDoHURL(" dns.alidns.com/dns-query ")?.absoluteString,
            "https://dns.alidns.com/dns-query"
        )
        XCTAssertEqual(DoHGatewayPolicy.dohHost(from: "https://dns.google/dns-query"), "dns.google")
    }

    func testRewrittenPOSTPreservesBodyAndForcesContentLength() throws {
        let original = try XCTUnwrap(URL(string: "https://linux.do/session.json"))
        var request = URLRequest(url: original)
        request.httpMethod = "POST"
        let body = Data("login=jeff&password=p%40ss".utf8)
        request.httpBody = body
        request.setValue("chunked", forHTTPHeaderField: "Transfer-Encoding")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let rewritten = try XCTUnwrap(DoHGatewayPolicy.rewrittenRequest(request, configuration: active))
        XCTAssertEqual(rewritten.httpBody, body)
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: "Content-Length"), String(body.count))
        XCTAssertNil(rewritten.value(forHTTPHeaderField: "Transfer-Encoding"))
        XCTAssertEqual(rewritten.value(forHTTPHeaderField: "Content-Type"), "application/x-www-form-urlencoded")
        XCTAssertEqual(rewritten.url?.path, "/session.json")
    }

    func testMaterializeHTTPBodyReadsStream() {
        let body = Data("token=abc".utf8)
        var request = URLRequest(url: URL(string: "https://linux.do/hcaptcha/create.json")!)
        request.httpMethod = "POST"
        request.httpBodyStream = InputStream(data: body)

        let materialized = DoHGatewayPolicy.materializeHTTPBody(request)
        XCTAssertEqual(materialized.httpBody, body)
        XCTAssertEqual(materialized.value(forHTTPHeaderField: "Content-Length"), String(body.count))
        XCTAssertNil(materialized.value(forHTTPHeaderField: "Transfer-Encoding"))
    }
}

import Foundation
import XCTest
@testable import dexo

final class PasswordLoginAPIClientTests: XCTestCase {
    func testSessionAndCSRFURLsStayOnForumOrigin() throws {
        let base = try XCTUnwrap(URL(string: "https://linux.do"))
        XCTAssertEqual(
            PasswordLoginAPIClient.sessionURL(baseURL: base),
            URL(string: "https://linux.do/session.json")
        )
        XCTAssertEqual(
            PasswordLoginAPIClient.csrfURLs(baseURL: base),
            [
                URL(string: "https://linux.do/session/csrf")!,
                URL(string: "https://linux.do/session/csrf.json")!,
            ]
        )
        XCTAssertEqual(
            PasswordLoginAPIClient.hCaptchaCreateURLs(
                baseURL: base,
                endpoints: PasswordLoginConfig.linuxDo.hCaptchaCreateEndpoints
            ),
            [
                URL(string: "https://linux.do/captcha/hcaptcha/create.json")!,
                URL(string: "https://linux.do/hcaptcha/create.json")!,
            ]
        )
    }

    func testSessionFormMatchesLoginJavaScriptEncoding() {
        XCTAssertEqual(
            PasswordLoginAPIClient.sessionFormBody(
                identifier: "jeff",
                password: "secret",
                secondFactorToken: nil
            ),
            "login=jeff&password=secret"
        )
        XCTAssertEqual(
            PasswordLoginAPIClient.sessionFormBody(
                identifier: "jeff+do",
                password: "p@ss&word 1",
                secondFactorToken: nil
            ),
            "login=jeff%2Bdo&password=p%40ss%26word%201"
        )
        XCTAssertEqual(
            PasswordLoginAPIClient.sessionFormBody(
                identifier: "jeff",
                password: "secret",
                secondFactorToken: "123456"
            ),
            "login=jeff&password=secret&second_factor_token=123456&second_factor_method=1"
        )
        XCTAssertEqual(
            PasswordLoginAPIClient.hCaptchaFormBody(token: "tok en"),
            "token=tok%20en"
        )
        XCTAssertEqual(PasswordLoginAPIClient.encodeURIComponent("密码"), "%E5%AF%86%E7%A0%81")
    }

    func testLoginSessionConfigurationUsesDoHGatewayAndDisablesCookieJar() {
        let configuration = PasswordLoginAPIClient.makeSessionConfiguration()
        XCTAssertTrue(
            configuration.protocolClasses?.contains(where: { $0 == DoHGatewayURLProtocol.self }) == true
        )
        XCTAssertEqual(configuration.httpCookieAcceptPolicy, .never)
        XCTAssertFalse(configuration.httpShouldSetCookies)
        XCTAssertNil(configuration.httpCookieStorage)
    }

    func testLoginUsesURLSessionForCSRFHCaptchaAndSession() async throws {
        let host = "password-login-api.test"
        let base = try XCTUnwrap(URL(string: "https://\(host)"))
        let previousUA = WebCookieStore.shared.userAgent
        WebCookieStore.shared.clearCookies(for: base.absoluteString)
        WebCookieStore.shared.userAgent = "Mozilla/5.0 PasswordLoginAPITest"
        let clearance = HTTPCookie(properties: [
            .domain: host,
            .path: "/",
            .name: "cf_clearance",
            .value: "cf-token",
            .secure: "TRUE",
        ])!
        WebCookieStore.shared.setCookies([clearance])
        PasswordLoginAPIStubURLProtocol.reset()
        PasswordLoginAPIStubURLProtocol.handler = { request in
            let path = request.url?.path ?? ""
            switch (request.httpMethod, path) {
            case ("GET", "/session/csrf"):
                return (200, [:], Data(#"{"csrf":"csrf-token"}"#.utf8))
            case ("POST", "/captcha/hcaptcha/create.json"):
                return (404, [:], Data("missing".utf8))
            case ("POST", "/hcaptcha/create.json"):
                return (200, [:], Data("{}".utf8))
            case ("POST", "/session.json"):
                return (
                    200,
                    ["Set-Cookie": "_t=native-session; Path=/; Secure; HttpOnly"],
                    Data(#"{"user":{"id":1,"username":"jeff"}}"#.utf8)
                )
            default:
                return (500, [:], Data("unexpected \(path)".utf8))
            }
        }
        defer {
            PasswordLoginAPIStubURLProtocol.reset()
            WebCookieStore.shared.clearCookies(for: base.absoluteString)
            WebCookieStore.shared.userAgent = previousUA
        }

        let result = await PasswordLoginAPIClient.login(
            baseURL: base,
            config: .linuxDo,
            identifier: "jeff",
            password: "p@ss",
            hCaptchaToken: "captcha-token",
            secondFactorToken: nil,
            urlSession: makeStubSession()
        )

        XCTAssertEqual(result.phase, "session")
        XCTAssertEqual(result.status, 200)
        XCTAssertTrue(result.body.contains("\"username\":\"jeff\""))

        let exchanges = PasswordLoginAPIStubURLProtocol.exchanges
        XCTAssertEqual(exchanges.map(\.path), [
            "/session/csrf",
            "/captcha/hcaptcha/create.json",
            "/hcaptcha/create.json",
            "/session.json",
        ])
        XCTAssertEqual(exchanges[0].method, "GET")
        XCTAssertEqual(exchanges[1].body, "token=captcha-token")
        XCTAssertEqual(exchanges[1].csrf, "csrf-token")
        XCTAssertEqual(exchanges[2].csrf, "csrf-token")
        XCTAssertEqual(exchanges[3].body, "login=jeff&password=p%40ss")
        XCTAssertEqual(exchanges[3].csrf, "csrf-token")
        XCTAssertTrue(exchanges[0].cookie?.contains("cf_clearance=cf-token") == true)
        XCTAssertEqual(exchanges[0].userAgent, "Mozilla/5.0 PasswordLoginAPITest")

        let cookies = WebCookieStore.shared.cookies(for: base)
        XCTAssertTrue(cookies.contains { $0.name == "_t" && $0.value == "native-session" })
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: result.status, body: result.body),
            .signedIn
        )
    }

    func testCSRF403IsReturnedForCloudflareRetry() async throws {
        let host = "password-login-csrf.test"
        let base = try XCTUnwrap(URL(string: "https://\(host)"))
        WebCookieStore.shared.clearCookies(for: base.absoluteString)
        PasswordLoginAPIStubURLProtocol.reset()
        PasswordLoginAPIStubURLProtocol.handler = { _ in
            return (403, [:], Data("<html>cf</html>".utf8))
        }
        defer {
            PasswordLoginAPIStubURLProtocol.reset()
            WebCookieStore.shared.clearCookies(for: base.absoluteString)
        }

        let result = await PasswordLoginAPIClient.login(
            baseURL: base,
            config: .linuxDo,
            identifier: "jeff",
            password: "secret",
            hCaptchaToken: "token",
            secondFactorToken: nil,
            urlSession: makeStubSession()
        )
        XCTAssertEqual(result.phase, "csrf")
        XCTAssertEqual(result.status, 403)
        XCTAssertTrue(PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(
            phase: result.phase,
            status: result.status
        ))
        XCTAssertEqual(PasswordLoginAPIStubURLProtocol.exchanges.map(\.path), ["/session/csrf"])
    }

    func testSecondFactorFormIsOmittedUntilTokenIsPresent() async throws {
        let host = "password-login-2fa.test"
        let base = try XCTUnwrap(URL(string: "https://\(host)"))
        WebCookieStore.shared.clearCookies(for: base.absoluteString)
        PasswordLoginAPIStubURLProtocol.reset()
        PasswordLoginAPIStubURLProtocol.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("GET", "/session/csrf"):
                return (200, [:], Data(#"{"csrf":"csrf"}"#.utf8))
            case ("POST", "/session.json"):
                return (
                    200,
                    [:],
                    Data(#"{"error":"Invalid second factor","reason":"invalid_second_factor"}"#.utf8)
                )
            default:
                return (404, [:], Data())
            }
        }
        defer {
            PasswordLoginAPIStubURLProtocol.reset()
            WebCookieStore.shared.clearCookies(for: base.absoluteString)
        }

        let first = await PasswordLoginAPIClient.login(
            baseURL: base,
            config: .linuxDo,
            identifier: "jeff",
            password: "secret",
            hCaptchaToken: nil,
            secondFactorToken: nil,
            urlSession: makeStubSession()
        )
        XCTAssertEqual(
            PasswordLoginSessionResponse.interpret(status: first.status, body: first.body),
            .needsSecondFactor
        )
        XCTAssertEqual(PasswordLoginAPIStubURLProtocol.exchanges.last?.body, "login=jeff&password=secret")

        PasswordLoginAPIStubURLProtocol.reset()
        PasswordLoginAPIStubURLProtocol.handler = { request in
            switch (request.httpMethod, request.url?.path) {
            case ("GET", "/session/csrf"):
                return (200, [:], Data(#"{"csrf":"csrf"}"#.utf8))
            case ("POST", "/session.json"):
                return (200, [:], Data(#"{"user":{"id":1,"username":"jeff"}}"#.utf8))
            default:
                return (404, [:], Data())
            }
        }
        let second = await PasswordLoginAPIClient.login(
            baseURL: base,
            config: .linuxDo,
            identifier: "jeff",
            password: "secret",
            hCaptchaToken: nil,
            secondFactorToken: "654321",
            urlSession: makeStubSession()
        )
        XCTAssertEqual(second.phase, "session")
        XCTAssertEqual(
            PasswordLoginAPIStubURLProtocol.exchanges.last?.body,
            "login=jeff&password=secret&second_factor_token=654321&second_factor_method=1"
        )
    }

    private func makeStubSession() -> URLSession {
        let configuration = PasswordLoginAPIClient.makeSessionConfiguration()
        var classes = configuration.protocolClasses ?? []
        classes.insert(PasswordLoginAPIStubURLProtocol.self, at: 0)
        configuration.protocolClasses = classes
        return URLSession(configuration: configuration)
    }
}

nonisolated final class PasswordLoginAPIStubURLProtocol: URLProtocol, @unchecked Sendable {
    struct Exchange: Equatable {
        var method: String
        var path: String
        var body: String
        var csrf: String?
        var cookie: String?
        var userAgent: String?
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var storedExchanges: [Exchange] = []
    nonisolated(unsafe) private static var storedHandler: ((URLRequest) -> (Int, [String: String], Data))?

    static var exchanges: [Exchange] {
        lock.lock()
        defer { lock.unlock() }
        return storedExchanges
    }

    static var handler: ((URLRequest) -> (Int, [String: String], Data))? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return storedHandler
        }
        set {
            lock.lock()
            storedHandler = newValue
            lock.unlock()
        }
    }

    static func reset() {
        lock.lock()
        storedExchanges = []
        storedHandler = nil
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool {
        handler != nil && request.url?.host?.hasSuffix(".test") == true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let materialized = materializeBody(request)
        let body = String(data: materialized.httpBody ?? Data(), encoding: .utf8) ?? ""
        let exchange = Exchange(
            method: materialized.httpMethod ?? "GET",
            path: materialized.url?.path ?? "",
            body: body,
            csrf: materialized.value(forHTTPHeaderField: "X-CSRF-Token"),
            cookie: materialized.value(forHTTPHeaderField: "Cookie"),
            userAgent: materialized.value(forHTTPHeaderField: "User-Agent")
        )
        Self.lock.lock()
        Self.storedExchanges.append(exchange)
        let handler = Self.storedHandler
        Self.lock.unlock()

        let (status, headers, data) = handler?(materialized) ?? (500, [:], Data("no handler".utf8))
        let url = materialized.url ?? URL(string: "https://password-login-api.test/")!
        let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !data.isEmpty {
            client?.urlProtocol(self, didLoad: data)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private nonisolated func materializeBody(_ request: URLRequest) -> URLRequest {
    if request.httpBody != nil {
        return request
    }
    guard let stream = request.httpBodyStream else {
        return request
    }
    if stream.streamStatus == .notOpen {
        stream.open()
    }
    defer {
        if stream.streamStatus != .closed {
            stream.close()
        }
    }
    var data = Data()
    let bufferSize = 4096
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }
    while stream.hasBytesAvailable {
        let read = stream.read(buffer, maxLength: bufferSize)
        if read <= 0 { break }
        data.append(buffer, count: read)
    }
    var copy = request
    copy.httpBody = data
    return copy
}

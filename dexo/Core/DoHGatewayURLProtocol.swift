import DoHGatewayPolicy
import Foundation

/// Rewrites HTTPS URLSession requests onto the app-local HTTP gateway.
/// WKWebView does not consult `URLProtocol` unless http/https are registered
/// with `WKBrowsingContextController` (iOS 15 challenge / password-login).
nonisolated final class DoHGatewayURLProtocol: URLProtocol, @unchecked Sendable {
    private static let relay = Relay()
    private var relayTask: URLSessionDataTask?

    static func register(on configuration: URLSessionConfiguration) {
        var classes = configuration.protocolClasses ?? []
        if !classes.contains(where: { $0 == DoHGatewayURLProtocol.self }) {
            classes.insert(DoHGatewayURLProtocol.self, at: 0)
            configuration.protocolClasses = classes
        }
    }

    override class func canInit(with request: URLRequest) -> Bool {
        DoHGatewayPolicy.shouldRewrite(
            request,
            configuration: DoHGatewayRuntime.shared.currentConfiguration
        )
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let configuration = DoHGatewayRuntime.shared.currentConfiguration
        let outbound = DoHGatewayCookieBridge.prepareOutboundRequest(request)
        guard var rewritten = DoHGatewayPolicy.rewrittenRequest(
            outbound,
            configuration: configuration
        ) else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        rewritten.setValue("1", forHTTPHeaderField: DoHGatewayPolicy.skipHeader)
        if outbound.value(forHTTPHeaderField: "Accept")?
            .localizedCaseInsensitiveContains("text/html") == true
        {
            rewritten.setValue("1", forHTTPHeaderField: DoHGatewayPolicy.passHTMLHeader)
        }
        #if DEBUG
        if let original = outbound.url?.absoluteString, let proxied = rewritten.url?.absoluteString {
            print("[DoHGateway] \(request.httpMethod ?? "GET") \(original) -> \(proxied)")
        }
        #endif
        relayTask = Self.relay.start(rewritten, owner: self)
    }

    override func stopLoading() {
        relayTask?.cancel()
        relayTask = nil
        Self.relay.cancel(self)
    }
}

private nonisolated final class Relay: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var protocols: [Int: DoHGatewayURLProtocol] = [:]
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = []
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    func start(_ request: URLRequest, owner urlProtocol: DoHGatewayURLProtocol) -> URLSessionDataTask {
        let task = session.dataTask(with: request)
        lock.lock()
        protocols[task.taskIdentifier] = urlProtocol
        lock.unlock()
        task.resume()
        return task
    }

    func cancel(_ urlProtocol: DoHGatewayURLProtocol) {
        lock.lock()
        protocols = protocols.filter { $0.value !== urlProtocol }
        lock.unlock()
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let urlProtocol = owner(for: dataTask) else {
            completionHandler(.cancel)
            return
        }
        DoHGatewayCookieBridge.mergeResponse(response, original: urlProtocol.request)
        let mapped = mappedResponse(response, original: urlProtocol.request)
        urlProtocol.client?.urlProtocol(urlProtocol, didReceive: mapped, cacheStoragePolicy: .notAllowed)
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let urlProtocol = owner(for: dataTask) else { return }
        urlProtocol.client?.urlProtocol(urlProtocol, didLoad: data)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Do not follow Location on this session (`protocolClasses = []`).
        // Announce the redirect to the outer client (protocol + ForumRedirectHandler)
        // with hop headers stripped so the next URL is rewritten again.
        if DoHGatewayPolicy.relayFollowsHTTPRedirects {
            completionHandler(newRequest)
            return
        }
        guard let urlProtocol = owner(for: task) else {
            completionHandler(nil)
            return
        }
        DoHGatewayCookieBridge.mergeResponse(response, original: urlProtocol.request)
        let mapped = mappedResponse(response, original: urlProtocol.request)
        let next = DoHGatewayPolicy.requestForOuterRedirect(newRequest)
        urlProtocol.client?.urlProtocol(urlProtocol, wasRedirectedTo: next, redirectResponse: mapped)
        cancel(urlProtocol)
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let urlProtocol = owner(for: task) else { return }
        if let error {
            urlProtocol.client?.urlProtocol(urlProtocol, didFailWithError: mappedRelayError(error))
        } else {
            urlProtocol.client?.urlProtocolDidFinishLoading(urlProtocol)
        }
        cancel(urlProtocol)
    }

    private func owner(for task: URLSessionTask) -> DoHGatewayURLProtocol? {
        lock.lock()
        defer { lock.unlock() }
        return protocols[task.taskIdentifier]
    }

    /// Relay only speaks HTTP to 127.0.0.1. An iOS SSL error here means the
    /// inner session followed an https Location (visible SNI). Do not surface
    /// that as `URLError.secureConnectionFailed`; gateway TLS failures stay
    /// on the JSON 502 / `dexo_doh_gateway_last_error` path.
    private func mappedRelayError(_ error: Error) -> Error {
        let code = (error as? URLError)?.code
        switch code {
        case .secureConnectionFailed,
             .serverCertificateUntrusted,
             .serverCertificateHasBadDate,
             .serverCertificateNotYetValid,
             .clientCertificateRejected,
             .clientCertificateRequired:
            break
        default:
            return error
        }
        let text = DoHGatewayRuntime.shared.lastError
            ?? "DoH gateway: inner relay refused a visible-SNI TLS hop"
        return URLError(
            .cannotConnectToHost,
            userInfo: [
                NSLocalizedDescriptionKey: text,
                NSUnderlyingErrorKey: error,
            ]
        )
    }

    private func mappedResponse(_ response: URLResponse, original: URLRequest) -> URLResponse {
        guard let http = response as? HTTPURLResponse, let originalURL = original.url else {
            return response
        }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String {
                headers[key] = String(describing: value)
            }
        }
        return HTTPURLResponse(
            url: originalURL,
            statusCode: http.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        ) ?? http
    }
}

/// Injects the native cookie jar onto URLProtocol requests and writes
/// `Set-Cookie` back. WKWebView custom-scheme requests often arrive without
/// `WKHTTPCookieStore` cookies, and the Relay session does not store them.
nonisolated enum DoHGatewayCookieBridge {
    static func prepareOutboundRequest(_ request: URLRequest) -> URLRequest {
        guard isOriginalForumURL(request.url) else { return request }
        let schemesRetained = WebViewCustomProtocolSchemes.isRetained
        let cookieHeader = request.value(forHTTPHeaderField: "Cookie")
        let missingCookie = cookieHeader == nil || cookieHeader?.isEmpty == true
        let isChallengeWebViewPath = isChallengeWebViewPath(
            schemesRetained: schemesRetained,
            accept: request.value(forHTTPHeaderField: "Accept"),
            hasUserApiKeyHeader: request.value(forHTTPHeaderField: "User-Api-Key") != nil
        )
        guard shouldApplyNativeSessionHeaders(
            schemesRetained: schemesRetained,
            missingCookie: missingCookie
        ) else {
            return request
        }

        return onMain {
            var outbound = request
            let hasKey = hasUserApiKey(for: request.url)
            let guestBrowsing = guestBrowsing(
                isChallengeWebViewPath: isChallengeWebViewPath,
                hasUserApiKey: hasKey
            )
            WebCookieStore.shared.applySessionHeaders(to: &outbound, guestBrowsing: guestBrowsing)
            return outbound
        }
    }

    static func mergeResponse(_ response: URLResponse, original request: URLRequest) {
        guard let http = response as? HTTPURLResponse,
              let originalURL = request.url,
              isOriginalForumURL(originalURL)
        else {
            return
        }
        onMain {
            WebCookieStore.shared.mergeProtocolResponse(http, for: originalURL)
        }
    }

    static func shouldApplyNativeSessionHeaders(
        schemesRetained: Bool,
        missingCookie: Bool
    ) -> Bool {
        schemesRetained || missingCookie
    }

    /// Challenge / password-login WKWebView traffic (schemes registered, not a
    /// JSON API Accept). Forum list/login JSON stays on the guest cookie policy
    /// when no User-Api-Key is present.
    static func isChallengeWebViewPath(
        schemesRetained: Bool,
        accept: String?,
        hasUserApiKeyHeader: Bool
    ) -> Bool {
        guard schemesRetained, !hasUserApiKeyHeader else { return false }
        let accept = accept?.lowercased() ?? ""
        if accept.contains("application/json"), !accept.contains("text/html") {
            return false
        }
        return true
    }

    static func guestBrowsing(isChallengeWebViewPath: Bool, hasUserApiKey: Bool) -> Bool {
        !isChallengeWebViewPath && !hasUserApiKey
    }

    static func forumBaseURL(from url: URL) -> String? {
        guard let scheme = url.scheme, let host = url.host, !host.isEmpty else { return nil }
        return "\(scheme)://\(host)"
    }

    /// Cookie work is for the forum origin, never the loopback rewrite.
    static func isOriginalForumURL(_ url: URL?) -> Bool {
        guard let host = url?.host?.lowercased(), !host.isEmpty else { return false }
        return host != "127.0.0.1" && host != "localhost" && host != "::1"
    }

    private static func hasUserApiKey(for url: URL?) -> Bool {
        guard let url, let baseURL = forumBaseURL(from: url) else { return false }
        return KeychainHelper.getUserApiKey(for: baseURL) != nil
    }

    @discardableResult
    private static func onMain<T>(_ work: @MainActor () -> T) -> T {
        if Thread.isMainThread {
            return MainActor.assumeIsolated(work)
        }
        return DispatchQueue.main.sync {
            MainActor.assumeIsolated(work)
        }
    }
}

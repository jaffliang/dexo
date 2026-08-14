import Foundation

/// Discourse password login over URLSession so csrf / hCaptcha create /
/// `POST /session.json` use the iOS 15 DoH loopback gateway.
///
/// WKWebView: iOS 17 skips CONNECT MITM (Turnstile / hCaptcha stay
/// end-to-end). iOS 15 reuses the URLSession DoH gateway via custom schemes.
enum PasswordLoginAPIClient {
    private static let requestTimeout: TimeInterval = 30

    static func makeSessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = requestTimeout
        DoHGatewayRuntime.prepare(configuration)
        return configuration
    }

    static func csrfURLs(baseURL: URL) -> [URL] {
        ["/session/csrf", "/session/csrf.json"].compactMap { absoluteURL(baseURL: baseURL, path: $0) }
    }

    static func sessionURL(baseURL: URL) -> URL? {
        absoluteURL(baseURL: baseURL, path: "/session.json")
    }

    static func hCaptchaCreateURLs(baseURL: URL, endpoints: [String]) -> [URL] {
        endpoints.compactMap { absoluteURL(baseURL: baseURL, path: $0) }
    }

    static func absoluteURL(baseURL: URL, path: String) -> URL? {
        let root = baseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let suffix = path.hasPrefix("/") ? path : "/" + path
        return URL(string: root + suffix)
    }

    /// Matches `encodeURIComponent` used by the injected login JS.
    static func encodeURIComponent(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.!~*'()")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    static func sessionFormBody(
        identifier: String,
        password: String,
        secondFactorToken: String?
    ) -> String {
        var form = "login=\(encodeURIComponent(identifier))&password=\(encodeURIComponent(password))"
        if let secondFactorToken, !secondFactorToken.isEmpty {
            form += "&second_factor_token=\(encodeURIComponent(secondFactorToken))&second_factor_method=1"
        }
        return form
    }

    static func hCaptchaFormBody(token: String) -> String {
        "token=\(encodeURIComponent(token))"
    }

    static func login(
        baseURL: URL,
        config: PasswordLoginConfig,
        identifier: String,
        password: String,
        hCaptchaToken: String?,
        secondFactorToken: String?,
        urlSession: URLSession? = nil
    ) async -> PasswordLoginBridgeResult {
        let ownedSession: URLSession?
        let session: URLSession
        if let urlSession {
            session = urlSession
            ownedSession = nil
        } else {
            let created = URLSession(
                configuration: makeSessionConfiguration(),
                delegate: PasswordLoginAPIRedirectRejector(),
                delegateQueue: nil
            )
            session = created
            ownedSession = created
        }
        defer { ownedSession?.finishTasksAndInvalidate() }

        let origin = originString(for: baseURL)
        let csrfResult = await fetchCSRF(baseURL: baseURL, origin: origin, session: session)
        switch csrfResult {
        case .failure(let result):
            return result
        case .success(let csrf):
            if let hCaptchaToken, !hCaptchaToken.isEmpty {
                if let failure = await submitHCaptcha(
                    baseURL: baseURL,
                    origin: origin,
                    endpoints: config.hCaptchaCreateEndpoints,
                    csrf: csrf,
                    token: hCaptchaToken,
                    session: session
                ) {
                    return failure
                }
            }
            return await submitSession(
                baseURL: baseURL,
                origin: origin,
                csrf: csrf,
                identifier: identifier,
                password: password,
                secondFactorToken: secondFactorToken,
                session: session
            )
        }
    }

    private enum CSRFResult {
        case success(String)
        case failure(PasswordLoginBridgeResult)
    }

    private static func fetchCSRF(
        baseURL: URL,
        origin: String,
        session: URLSession
    ) async -> CSRFResult {
        let urls = csrfURLs(baseURL: baseURL)
        var lastFailure = PasswordLoginBridgeResult(phase: "csrf", status: 0, body: "missing csrf url")
        for (index, url) in urls.enumerated() {
            if Task.isCancelled {
                return .failure(PasswordLoginBridgeResult(phase: "csrf", status: 0, body: "canceled"))
            }
            do {
                var request = URLRequest(url: url)
                request.httpMethod = "GET"
                applyCommonHeaders(to: &request, origin: origin, csrf: nil)
                let (data, http) = try await perform(request, session: session, cookieURL: url)
                let body = String(data: data, encoding: .utf8) ?? ""
                lastFailure = PasswordLoginBridgeResult(phase: "csrf", status: http.statusCode, body: body)
                if http.statusCode == 403 {
                    return .failure(lastFailure)
                }
                if http.statusCode == 200, let token = parseCSRF(data), !token.isEmpty {
                    return .success(token)
                }
                let canFallback = index + 1 < urls.count && (http.statusCode == 404 || http.statusCode == 200)
                if canFallback {
                    continue
                }
                return .failure(lastFailure)
            } catch is CancellationError {
                return .failure(PasswordLoginBridgeResult(phase: "csrf", status: 0, body: "canceled"))
            } catch {
                lastFailure = PasswordLoginBridgeResult(
                    phase: "exception",
                    status: 0,
                    body: error.localizedDescription
                )
                if index + 1 < urls.count {
                    continue
                }
                return .failure(lastFailure)
            }
        }
        return .failure(lastFailure)
    }

    private static func submitHCaptcha(
        baseURL: URL,
        origin: String,
        endpoints: [String],
        csrf: String,
        token: String,
        session: URLSession
    ) async -> PasswordLoginBridgeResult? {
        let urls = hCaptchaCreateURLs(baseURL: baseURL, endpoints: endpoints)
        var last: (endpoint: String, status: Int, body: String)?
        for url in urls {
            if Task.isCancelled {
                return PasswordLoginBridgeResult(phase: "hcaptcha", status: 0, body: "canceled")
            }
            do {
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                applyCommonHeaders(to: &request, origin: origin, csrf: csrf)
                request.setValue(
                    "application/x-www-form-urlencoded",
                    forHTTPHeaderField: "Content-Type"
                )
                let bodyData = Data(hCaptchaFormBody(token: token).utf8)
                request.httpBody = bodyData
                request.setValue(String(bodyData.count), forHTTPHeaderField: "Content-Length")
                let (data, http) = try await perform(request, session: session, cookieURL: url)
                let bodyText = String(data: data, encoding: .utf8) ?? ""
                last = (url.path, http.statusCode, bodyText)
                if http.statusCode == 200 {
                    return nil
                }
                if http.statusCode != 404 {
                    break
                }
            } catch {
                last = (url.path, 0, error.localizedDescription)
            }
        }
        let payload: String
        if let last, let data = try? JSONSerialization.data(withJSONObject: [
            "endpoint": last.endpoint,
            "status": last.status,
            "body": last.body,
        ]), let text = String(data: data, encoding: .utf8) {
            payload = text
        } else {
            payload = last?.body ?? ""
        }
        return PasswordLoginBridgeResult(phase: "hcaptcha", status: last?.status ?? 0, body: payload)
    }

    private static func submitSession(
        baseURL: URL,
        origin: String,
        csrf: String,
        identifier: String,
        password: String,
        secondFactorToken: String?,
        session: URLSession
    ) async -> PasswordLoginBridgeResult {
        guard let url = sessionURL(baseURL: baseURL) else {
            return PasswordLoginBridgeResult(phase: "session", status: 0, body: "missing session url")
        }
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            applyCommonHeaders(to: &request, origin: origin, csrf: csrf)
            request.setValue(
                "application/x-www-form-urlencoded",
                forHTTPHeaderField: "Content-Type"
            )
            let bodyData = Data(
                sessionFormBody(
                    identifier: identifier,
                    password: password,
                    secondFactorToken: secondFactorToken
                ).utf8
            )
            request.httpBody = bodyData
            request.setValue(String(bodyData.count), forHTTPHeaderField: "Content-Length")
            let (data, http) = try await perform(request, session: session, cookieURL: url)
            let bodyText = String(data: data, encoding: .utf8) ?? ""
            return PasswordLoginBridgeResult(phase: "session", status: http.statusCode, body: bodyText)
        } catch {
            return PasswordLoginBridgeResult(
                phase: "exception",
                status: 0,
                body: error.localizedDescription
            )
        }
    }

    private static func perform(
        _ request: URLRequest,
        session: URLSession,
        cookieURL: URL
    ) async throws -> (Data, HTTPURLResponse) {
        try Task.checkCancellation()
        var request = request
        WebCookieStore.shared.applySessionHeaders(to: &request)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        WebCookieStore.shared.mergeResponseHeaders(http.allHeaderFields, for: cookieURL)
        return (data, http)
    }

    private static func applyCommonHeaders(to request: inout URLRequest, origin: String, csrf: String?) {
        request.setValue("XMLHttpRequest", forHTTPHeaderField: "X-Requested-With")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue(origin, forHTTPHeaderField: "Origin")
        request.setValue(origin + "/", forHTTPHeaderField: "Referer")
        if let csrf, !csrf.isEmpty {
            request.setValue(csrf, forHTTPHeaderField: "X-CSRF-Token")
        }
    }

    private static func originString(for url: URL) -> String {
        var components = URLComponents()
        components.scheme = url.scheme
        components.host = url.host
        components.port = url.port
        return components.string ?? url.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private static func parseCSRF(_ data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let token = (json["csrf"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        return token?.isEmpty == false ? token : nil
    }
}

private nonisolated final class PasswordLoginAPIRedirectRejector: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

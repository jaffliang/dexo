import Foundation
import Network

private nonisolated final class WebViewMITMRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// Receives either decrypted HTTP/1.1 (MITM) or raw TLS (end-to-end) after
/// the CONNECT preface. MITM requests are forwarded with a URLSession that
/// uses the DoH gateway. Cloudflare / hCaptcha hosts are byte-copied so the
/// widget keeps a real certificate and TLS fingerprint.
nonisolated final class WebViewDoHMITMTunnel: @unchecked Sendable {
    private static let receiveBufferSize = 64 * 1024
    private static let hopByHopHeaders: Set<String> = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]

    private let id: UUID
    private let client: NWConnection
    private let queue: DispatchQueue
    private let onStop: @Sendable () -> Void
    private let redirectDelegate = WebViewMITMRedirectDelegate()
    private let session: URLSession

    private var parser = HTTPProxyRequestParser()
    private var activeTask: URLSessionDataTask?
    private var isStopped = false
    private var isForwarding = false
    private var receivedBytes = 0
    private var sentBytes = 0
    private var prefaceBuffer = Data()
    private var didReadPreface = false
    private var upstream: NWConnection?
    private var isPlainTunnel = false
    private var isReceivingFromClient = false
    private var isReceivingFromUpstream = false

    init(
        id: UUID,
        client: NWConnection,
        queue: DispatchQueue,
        onStop: @escaping @Sendable () -> Void
    ) {
        self.id = id
        self.client = client
        self.queue = queue
        self.onStop = onStop

        session = URLSession(
            configuration: Self.makeSessionConfiguration(),
            delegate: redirectDelegate,
            delegateQueue: nil
        )
    }

    /// Ephemeral session that still hits the DoH/ECH loopback gateway. Cookies
    /// stay in WKWebView; this session only carries the decrypted HTTP bytes.
    static func makeSessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 120
        DoHGatewayRuntime.prepare(configuration)
        return configuration
    }

    func start() {
        client.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.log("local connection ready; waiting for tunnel preface")
                self.receivePrefaceBytes()
            case .waiting(let error):
                self.log("local connection waiting: \(error)")
            case .failed(let error):
                self.log("local connection failed: \(error)")
                self.stop()
            case .cancelled:
                self.stop()
            default:
                break
            }
        }
        client.start(queue: queue)
    }

    func cancel() {
        queue.async { [weak self] in self?.stop() }
    }

    private func receivePrefaceBytes() {
        guard !isStopped, !didReadPreface else { return }
        if let parsed = WebViewDoHTunnelPolicy.splitPreface(prefaceBuffer) {
            handlePreface(parsed.0, remainder: parsed.1)
            return
        }
        if prefaceBuffer.count > 1_024 {
            log("missing tunnel preface; treating bytes as MITM HTTP")
            didReadPreface = true
            do {
                try parser.append(prefaceBuffer)
            } catch {
                handleParserError(error)
                return
            }
            prefaceBuffer = Data()
            receiveRequestBytes()
            return
        }

        client.receive(minimumIncompleteLength: 1, maximumLength: Self.receiveBufferSize) { [weak self] data, _, complete, error in
            guard let self, !self.isStopped else { return }
            guard error == nil else {
                self.log("preface receive failed: \(String(describing: error))")
                self.stop()
                return
            }
            if let data, !data.isEmpty {
                self.receivedBytes += data.count
                self.prefaceBuffer.append(data)
            }
            if complete, WebViewDoHTunnelPolicy.splitPreface(self.prefaceBuffer) == nil {
                self.stop()
                return
            }
            self.receivePrefaceBytes()
        }
    }

    private func handlePreface(_ preface: WebViewDoHTunnelPolicy.Preface, remainder: Data) {
        didReadPreface = true
        prefaceBuffer = Data()
        log(
            preface.usesEndToEndTLS
                ? "end-to-end tunnel \(preface.host):\(preface.port)"
                : "MITM HTTP \(preface.host):\(preface.port)"
        )
        if preface.usesEndToEndTLS {
            startPlainTunnel(host: preface.host, port: preface.port, initialData: remainder)
            return
        }
        if !remainder.isEmpty {
            do {
                try parser.append(remainder)
            } catch {
                handleParserError(error)
                return
            }
        }
        receiveRequestBytes()
    }

    private func startPlainTunnel(host: String, port: UInt16, initialData: Data) {
        guard !isStopped else { return }
        isPlainTunnel = true
        let endpoint = NWEndpoint.hostPort(
            host: .name(host, nil),
            port: NWEndpoint.Port(rawValue: port) ?? 443
        )
        let upstream = NWConnection(to: endpoint, using: .tcp)
        self.upstream = upstream
        upstream.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.log("plain upstream ready \(host):\(port)")
                if !initialData.isEmpty {
                    self.sendPlain(initialData, to: upstream, then: { [weak self] in
                        self?.receivePlainFromClient()
                    })
                } else {
                    self.receivePlainFromClient()
                }
                self.receivePlainFromUpstream()
            case .waiting(let error):
                self.log("plain upstream waiting: \(error)")
            case .failed(let error):
                self.log("plain upstream failed: \(error)")
                self.stop()
            case .cancelled:
                self.stop()
            default:
                break
            }
        }
        upstream.start(queue: queue)
    }

    private func receivePlainFromClient() {
        guard !isStopped, !isReceivingFromClient else { return }
        isReceivingFromClient = true
        client.receive(minimumIncompleteLength: 1, maximumLength: Self.receiveBufferSize) { [weak self] data, _, complete, error in
            guard let self, !self.isStopped else { return }
            self.isReceivingFromClient = false
            guard error == nil else {
                self.stop()
                return
            }
            if let data, !data.isEmpty {
                self.receivedBytes += data.count
                self.sendPlain(data, to: self.upstream, then: { [weak self] in
                    if complete {
                        self?.stop()
                    } else {
                        self?.receivePlainFromClient()
                    }
                })
                return
            }
            complete ? self.stop() : self.receivePlainFromClient()
        }
    }

    private func receivePlainFromUpstream() {
        guard !isStopped, let upstream, !isReceivingFromUpstream else { return }
        isReceivingFromUpstream = true
        upstream.receive(minimumIncompleteLength: 1, maximumLength: Self.receiveBufferSize) { [weak self] data, _, complete, error in
            guard let self, !self.isStopped else { return }
            self.isReceivingFromUpstream = false
            guard error == nil else {
                self.stop()
                return
            }
            if let data, !data.isEmpty {
                self.sendPlain(data, to: self.client, then: { [weak self] in
                    if complete {
                        self?.stop()
                    } else {
                        self?.receivePlainFromUpstream()
                    }
                })
                return
            }
            complete ? self.stop() : self.receivePlainFromUpstream()
        }
    }

    private func sendPlain(_ data: Data, to connection: NWConnection?, then completion: @escaping () -> Void) {
        guard let connection else {
            stop()
            return
        }
        sentBytes += data.count
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self, !self.isStopped else { return }
            if error != nil {
                self.stop()
                return
            }
            completion()
        })
    }

    private func receiveRequestBytes() {
        guard !isStopped, !isForwarding, !isPlainTunnel else { return }
        do {
            if let request = try parser.nextRequest() {
                forward(request)
                return
            }
        } catch {
            handleParserError(error)
            return
        }

        client.receive(minimumIncompleteLength: 1, maximumLength: Self.receiveBufferSize) { [weak self] data, _, complete, error in
            guard let self, !self.isStopped else { return }
            guard error == nil else {
                self.log("HTTP receive failed: \(String(describing: error))")
                self.stop()
                return
            }
            if let data, !data.isEmpty {
                self.receivedBytes += data.count
                do {
                    try self.parser.append(data)
                } catch {
                    self.handleParserError(error)
                    return
                }
            }
            if complete {
                self.stop()
            } else {
                self.receiveRequestBytes()
            }
        }
    }

    private func forward(_ request: HTTPProxyRequestParser.Request) {
        guard !isStopped else { return }
        guard request.values(forHeader: "Upgrade").allSatisfy({ $0.isEmpty }) else {
            sendErrorResponse(statusCode: 501, reason: "Not Implemented")
            return
        }

        let forwarded: URLRequest
        do {
            forwarded = try makeURLRequest(from: request)
        } catch {
            log("request rejected: \(error)")
            sendErrorResponse(statusCode: 400, reason: "Bad Request")
            return
        }

        isForwarding = true
        let closeAfterResponse = request.values(forHeader: "Connection")
            .flatMap { $0.split(separator: ",") }
            .contains { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "close" }

        log("\(request.method) \(forwarded.url?.absoluteString ?? request.target)")
        logCapturedRequest(request, url: forwarded.url)
        let task = session.dataTask(with: forwarded) { [weak self] data, response, error in
            guard let self else { return }
            self.queue.async {
                guard !self.isStopped else { return }
                self.activeTask = nil
                guard error == nil, let response = response as? HTTPURLResponse else {
                    self.log("URLSession failed: \(String(describing: error))")
                    self.sendErrorResponse(statusCode: 502, reason: "Bad Gateway")
                    return
                }
                self.send(
                    response: response,
                    body: data ?? Data(),
                    closeAfterResponse: closeAfterResponse
                )
            }
        }
        activeTask = task
        task.resume()
    }

    private func makeURLRequest(from request: HTTPProxyRequestParser.Request) throws -> URLRequest {
        enum RequestError: Error { case invalidAuthority, invalidTarget }

        let hosts = request.values(forHeader: "Host")
        guard hosts.count == 1 else { throw RequestError.invalidAuthority }
        let authority = hosts[0].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !authority.isEmpty,
              !authority.contains("/"),
              !authority.contains("@"),
              let origin = URL(string: "https://\(authority)"),
              let originHost = origin.host,
              !originHost.isEmpty
        else {
            throw RequestError.invalidAuthority
        }

        let pathAndQuery: String
        if request.target.hasPrefix("/") {
            pathAndQuery = request.target
        } else if request.target == "*" {
            pathAndQuery = "/"
        } else if let absolute = URL(string: request.target),
                  absolute.scheme?.lowercased() == "https",
                  absolute.host?.lowercased() == originHost.lowercased()
        {
            var components = URLComponents(url: absolute, resolvingAgainstBaseURL: false)
            components?.scheme = nil
            components?.host = nil
            components?.port = nil
            components?.user = nil
            components?.password = nil
            pathAndQuery = components?.string ?? "/"
        } else {
            throw RequestError.invalidTarget
        }

        guard let url = URL(string: pathAndQuery, relativeTo: origin)?.absoluteURL,
              url.scheme?.lowercased() == "https",
              url.host?.lowercased() == originHost.lowercased()
        else {
            throw RequestError.invalidTarget
        }

        var forwarded = URLRequest(
            url: url,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: 60
        )
        forwarded.httpMethod = request.method
        forwarded.httpBody = request.body.isEmpty ? nil : request.body
        forwarded.httpShouldHandleCookies = false

        let connectionNamedHeaders = Set(
            request.values(forHeader: "Connection")
                .flatMap { $0.split(separator: ",") }
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        )
        for header in request.headers {
            let lowercaseName = header.name.lowercased()
            guard lowercaseName != "host",
                  lowercaseName != "content-length",
                  lowercaseName != "accept-encoding",
                  !Self.hopByHopHeaders.contains(lowercaseName),
                  !connectionNamedHeaders.contains(lowercaseName)
            else {
                continue
            }
            forwarded.addValue(header.value, forHTTPHeaderField: header.name)
        }
        return forwarded
    }

    private func send(response: HTTPURLResponse, body: Data, closeAfterResponse: Bool) {
        guard !isStopped else { return }
        logCapturedResponse(response, body: body)
        var data = Data("HTTP/1.1 \(response.statusCode) \(Self.reasonPhrase(response.statusCode))\r\n".utf8)
        for (rawName, rawValue) in response.allHeaderFields {
            let name = String(describing: rawName)
            let lowercaseName = name.lowercased()
            guard !Self.hopByHopHeaders.contains(lowercaseName),
                  lowercaseName != "alt-svc",
                  lowercaseName != "content-length",
                  lowercaseName != "content-encoding"
            else {
                continue
            }

            let values = (rawValue as? [String]) ?? [String(describing: rawValue)]
            if lowercaseName == "set-cookie" {
                let cookieHeaders = values.flatMap(HTTPProxyResponseHeader.splitCombinedSetCookieHeader)
                let cookieNames = cookieHeaders.compactMap(HTTPProxyResponseHeader.cookieName)
                if !cookieNames.isEmpty {
                    log("forwarding Set-Cookie: \(cookieNames.joined(separator: ", "))")
                }
                for value in cookieHeaders {
                    guard !value.contains("\r"), !value.contains("\n") else { continue }
                    data.append(Data("Set-Cookie: \(value)\r\n".utf8))
                }
                continue
            }
            for value in values {
                guard !name.contains("\r"), !name.contains("\n"),
                      !value.contains("\r"), !value.contains("\n")
                else { continue }
                data.append(Data("\(name): \(value)\r\n".utf8))
            }
        }
        data.append(Data("Content-Length: \(body.count)\r\n".utf8))
        data.append(Data("Connection: \(closeAfterResponse ? "close" : "keep-alive")\r\n\r\n".utf8))
        data.append(body)

        sentBytes += data.count
        client.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self, !self.isStopped else { return }
            guard error == nil else {
                self.log("HTTP response send failed: \(String(describing: error))")
                self.stop()
                return
            }
            self.log("response \(response.statusCode), body=\(body.count) bytes")
            self.isForwarding = false
            closeAfterResponse ? self.stop() : self.receiveRequestBytes()
        })
    }

    private func handleParserError(_ error: Error) {
        log("HTTP parse failed: \(error)")
        switch error {
        case HTTPProxyRequestParser.ParseError.headerTooLarge,
             HTTPProxyRequestParser.ParseError.bodyTooLarge:
            sendErrorResponse(statusCode: 413, reason: "Content Too Large")
        case HTTPProxyRequestParser.ParseError.unsupportedTransferEncoding:
            sendErrorResponse(statusCode: 501, reason: "Not Implemented")
        default:
            sendErrorResponse(statusCode: 400, reason: "Bad Request")
        }
    }

    private func sendErrorResponse(statusCode: Int, reason: String) {
        guard !isStopped else { return }
        isForwarding = true
        let body = Data("\(statusCode) \(reason)\n".utf8)
        var response = Data("HTTP/1.1 \(statusCode) \(reason)\r\n".utf8)
        response.append(Data("Content-Type: text/plain; charset=utf-8\r\n".utf8))
        response.append(Data("Content-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8))
        response.append(body)
        client.send(content: response, completion: .contentProcessed { [weak self] _ in self?.stop() })
    }

    private func stop() {
        guard !isStopped else { return }
        isStopped = true
        activeTask?.cancel()
        activeTask = nil
        session.invalidateAndCancel()
        upstream?.stateUpdateHandler = nil
        upstream?.cancel()
        upstream = nil
        client.stateUpdateHandler = nil
        client.cancel()
        log("stopping; decrypted received=\(receivedBytes), sent=\(sentBytes)")
        onStop()
    }

    private func log(_ message: String) {
        #if DEBUG
        print("[WebViewDoHProxy \(id.uuidString.prefix(8))] \(message)")
        #endif
    }

    private func logCapturedRequest(_ request: HTTPProxyRequestParser.Request, url: URL?) {
        #if DEBUG
        let sensitiveHeaders: Set<String> = ["authorization", "cookie", "proxy-authorization"]
        let headerText = request.headers.map { header in
            let value = sensitiveHeaders.contains(header.name.lowercased()) ? "<redacted>" : header.value
            return "\(header.name): \(value)"
        }.joined(separator: "\n")
        let bodyPreview = Self.textPreview(request.body)
        print(
            "[WebViewProxyCapture] >>> \(request.method) \(url?.absoluteString ?? request.target)\n"
                + "\(headerText)\n"
                + "body-bytes=\(request.body.count)\(bodyPreview)"
        )
        #endif
    }

    private func logCapturedResponse(_ response: HTTPURLResponse, body: Data) {
        #if DEBUG
        let headers = response.allHeaderFields.map {
            "\(String(describing: $0.key)): \(String(describing: $0.value))"
        }.sorted().joined(separator: "\n")
        print(
            "[WebViewProxyCapture] <<< \(response.statusCode) \(response.url?.absoluteString ?? "")\n"
                + "\(headers)\n"
                + "body-bytes=\(body.count)\(Self.textPreview(body))"
        )
        #endif
    }

    private static func textPreview(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }
        let prefix = data.prefix(4_096)
        guard let text = String(data: prefix, encoding: .utf8) else {
            return "\n<binary>"
        }
        return "\n" + text
    }

    private static func reasonPhrase(_ statusCode: Int) -> String {
        switch statusCode {
        case 100: "Continue"
        case 200: "OK"
        case 201: "Created"
        case 202: "Accepted"
        case 204: "No Content"
        case 206: "Partial Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 303: "See Other"
        case 304: "Not Modified"
        case 307: "Temporary Redirect"
        case 308: "Permanent Redirect"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 408: "Request Timeout"
        case 409: "Conflict"
        case 410: "Gone"
        case 413: "Content Too Large"
        case 415: "Unsupported Media Type"
        case 422: "Unprocessable Content"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        case 504: "Gateway Timeout"
        default: "HTTP Response"
        }
    }
}

/// Normalizes response fields that URLSession exposes in a flattened form.
nonisolated enum HTTPProxyResponseHeader {
    /// Split only at a comma followed by a new cookie name. The comma inside
    /// an Expires date and commas inside quoted values are preserved.
    static func splitCombinedSetCookieHeader(_ value: String) -> [String] {
        var headers: [String] = []
        var start = value.startIndex
        var index = value.startIndex
        var isQuoted = false
        var isEscaped = false

        while index < value.endIndex {
            let character = value[index]
            if isEscaped {
                isEscaped = false
            } else if character == "\\", isQuoted {
                isEscaped = true
            } else if character == "\"" {
                isQuoted.toggle()
            } else if character == ",", !isQuoted {
                let candidateStart = value.index(after: index)
                if looksLikeCookieStart(value[candidateStart...]) {
                    let header = value[start..<index].trimmingCharacters(in: .whitespacesAndNewlines)
                    if !header.isEmpty {
                        headers.append(header)
                    }
                    start = candidateStart
                }
            }
            index = value.index(after: index)
        }

        let finalHeader = value[start...].trimmingCharacters(in: .whitespacesAndNewlines)
        if !finalHeader.isEmpty {
            headers.append(finalHeader)
        }
        return headers
    }

    private static func looksLikeCookieStart(_ substring: Substring) -> Bool {
        let candidate = substring.drop(while: { $0 == " " || $0 == "\t" })
        guard let first = candidate.first,
              first != "=", first != ";", first != ","
        else {
            return false
        }

        for character in candidate {
            if character == "=" { return true }
            if character == ";" || character == "," || character.isWhitespace { return false }
        }
        return false
    }

    static func cookieName(from header: String) -> String? {
        guard let equals = header.firstIndex(of: "=") else { return nil }
        let name = header[..<equals].trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? nil : name
    }
}

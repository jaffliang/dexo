import Foundation
import Network
import Security

nonisolated final class WebViewMITMFramerContext: NSObject, @unchecked Sendable {
    let certificateAuthority: WebViewProxyCertificateAuthority

    init(certificateAuthority: WebViewProxyCertificateAuthority) {
        self.certificateAuthority = certificateAuthority
    }
}

/// Parses the plaintext HTTP CONNECT preface, replies with 200, and then
/// either inserts Apple's TLS protocol (MITM) or passes the bytes through
/// (end-to-end TLS for Cloudflare / hCaptcha widgets).
nonisolated final class HTTPConnectMITMFramer: NWProtocolFramerImplementation, @unchecked Sendable {
    static let label = "Dexo HTTP CONNECT MITM"
    static let definition = NWProtocolFramer.Definition(implementation: HTTPConnectMITMFramer.self)

    private static let contextKey = "dexo.webview.mitm.context"
    private static let headerDelimiter = Data("\r\n\r\n".utf8)
    private static let maximumHeaderSize = 64 * 1024

    private let context: WebViewMITMFramerContext?
    private var didUpgradeToTLS = false
    private var didBecomePassThrough = false

    required init(framer: NWProtocolFramer.Instance) {
        context = framer.options[Self.contextKey] as? WebViewMITMFramerContext
    }

    static func options(context: WebViewMITMFramerContext) -> NWProtocolFramer.Options {
        let options = NWProtocolFramer.Options(definition: definition)
        options[contextKey] = context
        return options
    }

    func start(framer: NWProtocolFramer.Instance) -> NWProtocolFramer.StartResult {
        .willMarkReady
    }

    func handleInput(framer: NWProtocolFramer.Instance) -> Int {
        if didUpgradeToTLS || didBecomePassThrough {
            framer.passThroughInput()
            return 0
        }

        var request: HTTPConnectRequestParser.Request?
        var headerLength = 0
        let parsed = framer.parseInput(
            minimumIncompleteLength: 1,
            maximumLength: Self.maximumHeaderSize
        ) { buffer, isComplete in
            guard let buffer, !buffer.isEmpty else { return 0 }
            let available = Data(buffer)
            guard let delimiterRange = available.range(of: Self.headerDelimiter) else {
                if isComplete || available.count >= Self.maximumHeaderSize {
                    headerLength = -1
                    return available.count
                }
                return 0
            }

            headerLength = delimiterRange.upperBound
            request = try? HTTPConnectRequestParser.parse(Data(available[..<headerLength]))
            return headerLength
        }

        guard parsed else { return 1 }
        guard headerLength > 0, let request, let context else {
            fail(framer: framer, statusCode: 400, reason: "Bad Request")
            return 0
        }

        let usesEndToEndTLS = WebViewDoHTunnelPolicy.usesEndToEndTLS(host: request.host)
        #if DEBUG
        print(
            "[WebViewDoHProxy] CONNECT \(request.host):\(request.port); "
                + (usesEndToEndTLS ? "end-to-end TLS" : "upgrading to native TLS")
        )
        #endif

        let preface = WebViewDoHTunnelPolicy.encodePreface(
            .init(usesEndToEndTLS: usesEndToEndTLS, host: request.host, port: request.port)
        )
        let established = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)

        if usesEndToEndTLS {
            framer.writeOutput(data: established)
            didBecomePassThrough = true
            framer.passThroughInput()
            framer.passThroughOutput()
            framer.markReady()
            deliverPreface(preface, framer: framer)
            return 0
        }

        let identity: WebViewProxyTLSIdentity
        do {
            identity = try context.certificateAuthority.identity(for: request.host)
        } catch {
            #if DEBUG
            print("[WebViewDoHProxy] failed to sign certificate for \(request.host): \(error)")
            #endif
            fail(framer: framer, statusCode: 502, reason: "Certificate Error")
            return 0
        }

        #if DEBUG
        print("[WebViewDoHProxy] dynamically signed leaf certificate for \(identity.host)")
        #endif

        let tlsOptions = NWProtocolTLS.Options()
        let securityOptions = tlsOptions.securityProtocolOptions
        sec_protocol_options_set_local_identity(securityOptions, identity.networkIdentity)
        sec_protocol_options_set_peer_authentication_required(securityOptions, false)
        sec_protocol_options_add_tls_application_protocol(securityOptions, "http/1.1")
        sec_protocol_options_set_min_tls_protocol_version(securityOptions, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(securityOptions, .TLSv13)

        do {
            framer.writeOutput(data: established)
            try framer.prependApplicationProtocol(options: tlsOptions)
            didUpgradeToTLS = true
            framer.passThroughInput()
            framer.passThroughOutput()
            framer.markReady()
            deliverPreface(preface, framer: framer)
        } catch {
            #if DEBUG
            print("[WebViewDoHProxy] failed to prepend native TLS: \(error)")
            #endif
            framer.markFailed(error: NWError.posix(.EPROTO))
        }
        return 0
    }

    func handleOutput(
        framer: NWProtocolFramer.Instance,
        message: NWProtocolFramer.Message,
        messageLength: Int,
        isComplete: Bool
    ) {
        if didUpgradeToTLS || didBecomePassThrough {
            framer.passThroughOutput()
        }
    }

    func wakeup(framer: NWProtocolFramer.Instance) {}

    func stop(framer: NWProtocolFramer.Instance) -> Bool {
        true
    }

    func cleanup(framer: NWProtocolFramer.Instance) {}

    private func deliverPreface(_ preface: Data, framer: NWProtocolFramer.Instance) {
        let message = NWProtocolFramer.Message(definition: Self.definition)
        framer.deliverInput(data: preface, message: message, isComplete: false)
    }

    private func fail(framer: NWProtocolFramer.Instance, statusCode: Int, reason: String) {
        let body = "\(statusCode) \(reason)\n"
        let response = """
        HTTP/1.1 \(statusCode) \(reason)\r
        Content-Type: text/plain; charset=utf-8\r
        Content-Length: \(body.utf8.count)\r
        Connection: close\r
        \r
        \(body)
        """
        framer.writeOutput(data: Data(response.utf8))
        framer.markFailed(error: NWError.posix(.EPROTO))
    }
}

nonisolated enum HTTPConnectRequestParser {
    struct Request: Equatable {
        let host: String
        let port: UInt16
    }

    enum ParseError: Error, Equatable {
        case malformedRequest
        case unsupportedMethod
        case invalidAuthority
    }

    static func parse(_ headerData: Data) throws -> Request {
        guard let header = String(data: headerData, encoding: .utf8),
              let requestLine = header.components(separatedBy: "\r\n").first
        else {
            throw ParseError.malformedRequest
        }

        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count == 3,
              parts[2] == "HTTP/1.0" || parts[2] == "HTTP/1.1"
        else {
            throw ParseError.malformedRequest
        }
        guard parts[0].uppercased() == "CONNECT" else {
            throw ParseError.unsupportedMethod
        }

        return try parseAuthority(String(parts[1]))
    }

    private static func parseAuthority(_ authority: String) throws -> Request {
        let host: String
        let portString: String

        if authority.hasPrefix("[") {
            guard let closingBracket = authority.firstIndex(of: "]"),
                  authority.index(after: closingBracket) < authority.endIndex,
                  authority[authority.index(after: closingBracket)] == ":"
            else {
                throw ParseError.invalidAuthority
            }
            host = String(authority[authority.index(after: authority.startIndex)..<closingBracket])
            portString = String(authority[authority.index(closingBracket, offsetBy: 2)...])
        } else {
            guard let colon = authority.lastIndex(of: ":"),
                  !authority[..<colon].contains(":")
            else {
                throw ParseError.invalidAuthority
            }
            host = String(authority[..<colon])
            portString = String(authority[authority.index(after: colon)...])
        }

        guard !host.isEmpty,
              host.count <= 253,
              !host.contains(where: { $0.isWhitespace || $0.isNewline || $0 == "/" }),
              let port = UInt16(portString),
              port > 0
        else {
            throw ParseError.invalidAuthority
        }
        return Request(host: host, port: port)
    }
}

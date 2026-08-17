import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Pure URL rewrite / host-policy helpers for the iOS 15 loopback DoH gateway.
///
/// The app's `URLProtocol` uses these so Alamofire and URLSession keep the
/// original HTTPS URL for cookies, redirects, and `ForumURLPolicy`, while the
/// bytes go to `http://127.0.0.1:<port>/...`.
public enum DoHGatewayPolicy {
    public static let skipHeader = "X-Dexo-Gateway-Skip"
    public static let upstreamHostHeader = "X-Dexo-Gateway-Host"
    public static let upstreamPortHeader = "X-Dexo-Gateway-Port"
    public static let upstreamSchemeHeader = "X-Dexo-Gateway-Scheme"
    /// Challenge WKWebView only. Tells the loopback gateway to pass through
    /// Cloudflare interstitial HTML instead of turning it into a JSON 502.
    public static let passHTMLHeader = "X-Dexo-Pass-HTML"

    /// Inner `URLProtocol` relay must return 3xx to the client. Following
    /// `Location: https://…` on a session with `protocolClasses = []` does
    /// visible-SNI TLS and surfaces `URLError.secureConnectionFailed`.
    public static let relayFollowsHTTPRedirects = false

    /// `NWParameters.PrivacyContext` is encrypted DNS only (visible SNI).
    /// On iOS 15 the loopback gateway is the only ECH path — keep this off
    /// while the gateway is active so leaked URLSessions fail closed.
    public static let enablePrivacyContextWhileGatewayActive = false

    public struct Configuration: Equatable, Sendable {
        public var isEnabled: Bool
        public var gatewayPort: Int
        public var dohHost: String?
        /// Isolated WKWebView CONNECT listener. 0 when the gateway is down.
        public var connectPort: Int

        public init(isEnabled: Bool, gatewayPort: Int, dohHost: String?, connectPort: Int = 0) {
            self.isEnabled = isEnabled
            self.gatewayPort = gatewayPort
            self.dohHost = dohHost
            self.connectPort = connectPort
        }

        public var isProxyActive: Bool {
            isEnabled && gatewayPort > 0
        }

        public var isConnectProxyActive: Bool {
            isEnabled && connectPort > 0
        }
    }

    public static func shouldRewrite(_ url: URL, configuration: Configuration) -> Bool {
        guard configuration.isProxyActive else { return false }
        guard url.scheme?.lowercased() == "https" else { return false }
        guard let host = url.host, !host.isEmpty else { return false }
        if isLoopbackHost(host) || isIPAddress(host) {
            return false
        }
        if let dohHost = configuration.dohHost, host.caseInsensitiveCompare(dohHost) == .orderedSame {
            return false
        }
        return true
    }

    public static func shouldRewrite(_ request: URLRequest, configuration: Configuration) -> Bool {
        if request.value(forHTTPHeaderField: skipHeader) != nil {
            return false
        }
        if request.value(forHTTPHeaderField: upstreamHostHeader) != nil {
            return false
        }
        guard let url = request.url else { return false }
        return shouldRewrite(url, configuration: configuration)
    }

    public static func rewrittenRequest(
        _ request: URLRequest,
        configuration: Configuration
    ) -> URLRequest? {
        guard shouldRewrite(request, configuration: configuration),
              let url = request.url,
              var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        else {
            return nil
        }

        let originalHost = url.host ?? ""
        let originalPort = url.port ?? 443
        components.scheme = "http"
        components.host = "127.0.0.1"
        components.port = configuration.gatewayPort

        guard let rewrittenURL = components.url else { return nil }
        var rewritten = materializeHTTPBody(request)
        rewritten.url = rewrittenURL
        rewritten.setValue(originalHost, forHTTPHeaderField: upstreamHostHeader)
        rewritten.setValue(String(originalPort), forHTTPHeaderField: upstreamPortHeader)
        rewritten.setValue("https", forHTTPHeaderField: upstreamSchemeHeader)
        rewritten.setValue(originalHost, forHTTPHeaderField: "Host")
        return rewritten
    }

    /// URLSession often exposes `POST` bodies only as `httpBodyStream` inside
    /// `URLProtocol`. The loopback gateway requires `Content-Length` and rejects
    /// chunked requests, so login `/session.json` must be materialized here.
    public static func materializeHTTPBody(_ request: URLRequest) -> URLRequest {
        var copy = request
        let body: Data
        if let existing = copy.httpBody {
            body = existing
        } else if let stream = copy.httpBodyStream {
            body = readHTTPBodyStream(stream)
            copy.httpBody = body
        } else {
            return request
        }
        copy.setValue(nil, forHTTPHeaderField: "Transfer-Encoding")
        copy.setValue(String(body.count), forHTTPHeaderField: "Content-Length")
        return copy
    }

    private static func readHTTPBodyStream(_ stream: InputStream) -> Data {
        if stream.streamStatus == .notOpen {
            stream.open()
        }
        defer {
            if stream.streamStatus != .closed {
                stream.close()
            }
        }
        var data = Data()
        let bufferSize = 16 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }

    public static func isLoopbackHost(_ host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        return normalized == "localhost"
            || normalized == "127.0.0.1"
            || normalized == "::1"
            || normalized == "0.0.0.0"
            || normalized.hasPrefix("127.")
    }

    public static func isIPAddress(_ host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var ipv4 = in_addr()
        if inet_pton(AF_INET, normalized, &ipv4) == 1 {
            return true
        }
        var ipv6 = in6_addr()
        return inet_pton(AF_INET6, normalized, &ipv6) == 1
    }

    public static func dohHost(from serverURLString: String) -> String? {
        normalizedDoHURL(serverURLString)?.host
    }

    /// Mirrors `EncryptedDNSManager.normalizedServerURL` so policy tests do not
    /// need to import the app target.
    public static func normalizedDoHURL(_ input: String) -> URL? {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }
        if !value.contains("://") {
            value = "https://" + value
        }
        guard let components = URLComponents(string: value),
              components.scheme?.lowercased() == "https",
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              let url = components.url
        else {
            return nil
        }
        return url
    }

    /// Strip hop headers from an inner-session redirect so the outer
    /// URLSession re-issues a normal `https://` URL and we rewrite again.
    /// Leaving `X-Dexo-Gateway-Skip` on `Location` would skip the protocol
    /// and handshake TLS with visible SNI.
    public static func requestForOuterRedirect(_ newRequest: URLRequest) -> URLRequest {
        var request = newRequest
        request.setValue(nil, forHTTPHeaderField: skipHeader)
        request.setValue(nil, forHTTPHeaderField: upstreamHostHeader)
        request.setValue(nil, forHTTPHeaderField: upstreamPortHeader)
        request.setValue(nil, forHTTPHeaderField: upstreamSchemeHeader)
        request.setValue(nil, forHTTPHeaderField: passHTMLHeader)
        return request
    }

    public static func isProxyEnablementAllowed(isEnabled: Bool, serverURLString: String) -> Bool {
        guard isEnabled else { return true }
        return normalizedDoHURL(serverURLString) != nil
    }

    /// Outcome of switching the default DoH server (or toggling enablement).
    /// Persist a new default only after a successful start when DoH is on.
    public struct SettingsSwitch: Equatable, Sendable {
        public var commitNewDefault: Bool
        public var restorePreviousDefault: Bool
        public var keepEnabled: Bool

        public init(commitNewDefault: Bool, restorePreviousDefault: Bool, keepEnabled: Bool) {
            self.commitNewDefault = commitNewDefault
            self.restorePreviousDefault = restorePreviousDefault
            self.keepEnabled = keepEnabled
        }

        /// `dohWasEnabled` is the toggle state before this start attempt.
        /// When DoH is off, changing the default is just a preference write.
        public static func afterStart(dohWasEnabled: Bool, startSucceeded: Bool) -> SettingsSwitch {
            if !dohWasEnabled {
                return SettingsSwitch(
                    commitNewDefault: true,
                    restorePreviousDefault: false,
                    keepEnabled: false
                )
            }
            if startSucceeded {
                return SettingsSwitch(
                    commitNewDefault: true,
                    restorePreviousDefault: false,
                    keepEnabled: true
                )
            }
            return SettingsSwitch(
                commitNewDefault: false,
                restorePreviousDefault: true,
                keepEnabled: true
            )
        }
    }

    /// Cold launch must not retry a resolver that just failed to start.
    public static func shouldDisableDoHAfterLaunchStart(_ startSucceeded: Bool) -> Bool {
        !startSucceeded
    }

    public static func persistedDefaultServerID<ID: Equatable>(
        previous: ID?,
        candidate: ID,
        dohWasEnabled: Bool,
        startSucceeded: Bool
    ) -> ID? {
        let decision = SettingsSwitch.afterStart(
            dohWasEnabled: dohWasEnabled,
            startSucceeded: startSucceeded
        )
        if decision.commitNewDefault {
            return candidate
        }
        return previous
    }
}

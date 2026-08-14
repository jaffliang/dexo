import Foundation

/// CONNECT-proxy policy shared by the iOS 15/17 WKWebView DoH path.
///
/// Forum hosts (linux.do / idcflare) must be MITM'd so upstream TLS can use
/// the DoH/ECH gateway. Cloudflare Turnstile and hCaptcha must stay
/// end-to-end: MITM changes the certificate and TLS fingerprint and those
/// widgets render blank.
nonisolated enum WebViewDoHTunnelPolicy {
    struct Preface: Equatable, Sendable {
        var usesEndToEndTLS: Bool
        var host: String
        var port: UInt16
    }

    static func usesEndToEndTLS(host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .lowercased()
        if normalized == "challenges.cloudflare.com" {
            return true
        }
        if normalized == "hcaptcha.com" || normalized.hasSuffix(".hcaptcha.com") {
            return true
        }
        return false
    }

    static func encodePreface(_ preface: Preface) -> Data {
        let mode = preface.usesEndToEndTLS ? "e2e" : "mitm"
        return Data("X-Dexo-Tunnel: \(mode) \(preface.host) \(preface.port)\r\n".utf8)
    }

    /// Splits a complete preface line from `buffer`. Returns nil until `\r\n`
    /// arrives or the buffer is clearly not a preface.
    static func splitPreface(_ buffer: Data) -> (Preface, Data)? {
        guard let separator = buffer.range(of: Data("\r\n".utf8)) else {
            return nil
        }
        let line = buffer[buffer.startIndex..<separator.lowerBound]
        let remainder = Data(buffer[separator.upperBound...])
        guard let text = String(data: line, encoding: .utf8),
              let preface = parsePrefaceLine(text)
        else {
            return nil
        }
        return (preface, remainder)
    }

    static func parsePrefaceLine(_ line: String) -> Preface? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count == 4,
              parts[0] == "X-Dexo-Tunnel:",
              parts[1] == "e2e" || parts[1] == "mitm",
              let port = UInt16(parts[3]),
              port > 0
        else {
            return nil
        }
        let host = String(parts[2])
        guard !host.isEmpty, !host.contains("/") else { return nil }
        return Preface(usesEndToEndTLS: parts[1] == "e2e", host: host, port: port)
    }
}

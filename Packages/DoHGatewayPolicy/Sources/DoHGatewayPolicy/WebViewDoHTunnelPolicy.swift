import Foundation

/// CONNECT-path host split for WKWebView DoH.
///
/// `challenges.cloudflare.com` and `*.hcaptcha.com` must be a raw TCP tunnel
/// so WebKit does end-to-end Safari TLS. MITM/rustls JA3 makes Turnstile
/// refuse the widget. Forum hosts stay on CONNECT MITM + ECH.
public enum WebViewDoHTunnelPolicy {
    public static func shouldPassthroughTLS(host: String) -> Bool {
        let host = host.trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !host.isEmpty else { return false }
        return host == "challenges.cloudflare.com"
            || host.hasSuffix(".challenges.cloudflare.com")
            || host == "hcaptcha.com"
            || host.hasSuffix(".hcaptcha.com")
    }
}

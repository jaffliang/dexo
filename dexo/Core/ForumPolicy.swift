import Foundation

/// Per-forum UI/feature toggles that depend on the connected Discourse instance.
/// Centralizes host-specific decisions so call sites don't sprinkle string checks.
enum ForumPolicy {
    /// Hosts where the like affordance should be suppressed in post cells.
    private static let likeButtonSuppressedHosts: Set<String> = []

    /// Hosts where read timing uploads are opt-in because repeated POSTs may
    /// trigger site-side anti-bot protection.
    private static let readTimingsOptInHosts: Set<String> = ["linux.do"]

    /// linux.do and sister sites that share Cloudflare guest/password handling.
    /// Do not send idcflare users to linux.do/challenge — that host's
    /// `/challenge` is 404; use each forum's own interstitial URL.
    private static let linuxDoFamilyHosts: Set<String> = ["linux.do", "idcflare.com"]

    /// True when posts on this forum should hide the heart / like button.
    static func hidesLikeButton(baseURL: String) -> Bool {
        matches(baseURL: baseURL, hosts: likeButtonSuppressedHosts)
    }

    /// True when this forum opts out of `/topics/timings` reporting.
    static func tracksReadTimings(baseURL: String) -> Bool {
        guard matches(baseURL: baseURL, hosts: readTimingsOptInHosts) else {
            return true
        }
        return AppSettings.shared.linuxDoReadTimingsEnabled
    }

    static func isLinuxDoFamily(baseURL: String) -> Bool {
        matches(baseURL: baseURL, hosts: linuxDoFamilyHosts)
    }

    /// linux.do-only circuit breaker for `/topics/timings`. Do not reuse the
    /// family set: flipping `linuxDoReadTimingsEnabled` while browsing
    /// idcflare would clobber the linux.do setting.
    static func usesLinuxDoReadTimingsGuard(baseURL: String) -> Bool {
        matches(baseURL: baseURL, hosts: readTimingsOptInHosts)
    }

    /// URL to load in the guest/password CF WebView. linux.do uses `/challenge`;
    /// idcflare's `/challenge` is 404, so use `/login` (Cloudflare interstitial
    /// on origin, not linux.do).
    static func cloudflareInterstitialURL(for baseURL: String) -> URL? {
        PasswordLoginConfig.config(for: baseURL)?.challengeURL
    }

    /// Host check that also matches subdomains (e.g. `meta.linux.do` for `linux.do`).
    private static func matches(baseURL: String, hosts: Set<String>) -> Bool {
        guard let host = URL(string: baseURL)?.host?.lowercased() else { return false }
        return hosts.contains(where: { host == $0 || host.hasSuffix(".\($0)") })
    }
}

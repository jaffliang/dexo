import Foundation

/// Per-forum UI/feature toggles that depend on the connected Discourse instance.
/// Centralizes host-specific decisions so call sites don't sprinkle string checks.
enum ForumPolicy {
    /// Hosts where the like affordance should be suppressed in post cells.
    private static let likeButtonSuppressedHosts: Set<String> = []

    /// Hosts where read timing uploads are opt-in because repeated POSTs may
    /// trigger site-side anti-bot protection.
    private static let readTimingsOptInHosts: Set<String> = ["linux.do"]

    /// True when posts on this forum should hide the heart / like button.
    static func hidesLikeButton(baseURL: String) -> Bool {
        matches(baseURL: baseURL, hosts: likeButtonSuppressedHosts)
    }

    /// True when this forum should POST `/topics/timings`.
    static func tracksReadTimings(baseURL: String) -> Bool {
        switch readTimingsSite(baseURL: baseURL) {
        case .linuxDo:
            return AppSettings.shared.linuxDoReadTimingsEnabled
        case .idcflare:
            return AppSettings.shared.idcflareReadTimingsEnabled
        case .other:
            return true
        }
    }

    enum ReadTimingsSite: Equatable {
        case linuxDo
        case idcflare
        case other
    }

    static func readTimingsSite(baseURL: String) -> ReadTimingsSite {
        guard let host = host(fromBaseURL: baseURL),
              let registrable = linuxDoFamilyRegistrableHost(forHost: host)
        else { return .other }
        switch registrable {
        case "linux.do": return .linuxDo
        case "idcflare.com": return .idcflare
        default: return .other
        }
    }

    static func readTimingsActivationGeneration(baseURL: String) -> Int {
        switch readTimingsSite(baseURL: baseURL) {
        case .linuxDo: return AppSettings.shared.linuxDoReadTimingsActivationGeneration
        case .idcflare: return AppSettings.shared.idcflareReadTimingsActivationGeneration
        case .other: return 0
        }
    }

    /// Turns off only the switch for this site. Other forums are unchanged.
    static func disableReadTimingsReporting(baseURL: String) {
        switch readTimingsSite(baseURL: baseURL) {
        case .linuxDo:
            AppSettings.shared.linuxDoReadTimingsEnabled = false
        case .idcflare:
            AppSettings.shared.idcflareReadTimingsEnabled = false
        case .other:
            break
        }
    }

    /// linux.do and sister sites that share Cloudflare guest/password handling.
    /// Do not send idcflare users to linux.do/challenge — that host's
    /// `/challenge` is 404; use each forum's own interstitial URL.
    static func isLinuxDoFamily(baseURL: String) -> Bool {
        guard let host = host(fromBaseURL: baseURL) else { return false }
        return linuxDoFamilyRegistrableHost(forHost: host) != nil
    }

    nonisolated static func isLinuxDoFamily(url: URL) -> Bool {
        guard let host = url.host ?? host(fromBaseURL: url.absoluteString) else { return false }
        return linuxDoFamilyRegistrableHost(forHost: host) != nil
    }

    /// Host from a stored forum URL. DiscourseAPI trims trailing slashes;
    /// some saved rows omit a scheme, so `URL.host` can be nil.
    nonisolated static func host(fromBaseURL baseURL: String) -> String? {
        let trimmed = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if let host = URL(string: trimmed)?.host, !host.isEmpty {
            return host.lowercased()
        }
        if !trimmed.contains("://"),
           let host = URL(string: "https://\(trimmed)")?.host,
           !host.isEmpty
        {
            return host.lowercased()
        }
        return nil
    }

    /// `linux.do` or `idcflare.com` when `host` is that site, a subdomain, or
    /// a nearby registrable form (last two labels / a label containing the brand).
    nonisolated static func linuxDoFamilyRegistrableHost(forHost host: String) -> String? {
        let host = host.lowercased()
        if host == "linux.do" || host.hasSuffix(".linux.do") { return "linux.do" }
        if host == "idcflare.com" || host.hasSuffix(".idcflare.com") { return "idcflare.com" }
        let labels = host.split(separator: ".").map(String.init)
        let lastTwo = labels.suffix(2).joined(separator: ".")
        if lastTwo.contains("idcflare") || labels.contains(where: { $0.contains("idcflare") }) {
            return "idcflare.com"
        }
        if lastTwo.contains("linux.do")
            || (labels.contains(where: { $0.contains("linux") }) && labels.contains(where: { $0 == "do" }))
        {
            return "linux.do"
        }
        return nil
    }

    /// Default URL for the in-app browser prompt. linux.do defaults to CDK
    /// because that site's login UI is incompatible with iOS 15.
    static func defaultInAppBrowserURL(for baseURL: String) -> URL? {
        guard let forumURL = URL(string: baseURL),
              let host = forumURL.host,
              let registrable = linuxDoFamilyRegistrableHost(forHost: host)
        else { return URL(string: baseURL) }
        if registrable == "linux.do" {
            return URL(string: "https://cdk.linux.do/")
        }
        var components = URLComponents()
        components.scheme = forumURL.scheme ?? "https"
        components.host = host
        components.path = "/"
        return components.url
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
        guard let host = host(fromBaseURL: baseURL) else { return false }
        if hosts.contains(where: { host == $0 || host.hasSuffix(".\($0)") }) { return true }
        if let registrable = linuxDoFamilyRegistrableHost(forHost: host), hosts.contains(registrable) {
            return true
        }
        return false
    }
}

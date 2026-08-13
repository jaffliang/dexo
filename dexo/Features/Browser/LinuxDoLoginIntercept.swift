import Foundation

/// Skips Discourse `/login` on linux.do family hosts when the WK store already
/// has host-only `_t`. That SPA spins forever on iOS 15 instead of completing
/// OAuth/SSO to `connect.linux.do`.
nonisolated enum LinuxDoLoginIntercept: Sendable {
    static let redirectQueryKeys = ["redirect", "return_path", "redirect_url"]

    /// Cheap path check for WK callbacks that may run off the main actor.
    nonisolated static func looksLikeLoginPath(_ url: URL) -> Bool {
        let path = url.path.lowercased()
        return path == "/login" || path == "/login/"
    }

    static func isLoginPage(_ url: URL) -> Bool {
        looksLikeLoginPath(url) && ForumPolicy.isLinuxDoFamily(url: url)
    }

    /// Replacement to load instead of the broken `/login` SPA.
    ///
    /// Prefers a family https redirect (`connect.linux.do/oauth2/…`). Otherwise
    /// loads the registrable origin so host-only `_t` is sent. `previouslyLoaded`
    /// prevents login → OAuth → login loops.
    static func replacementURL(for url: URL, previouslyLoaded: Set<String> = []) -> URL? {
        guard isLoginPage(url) else { return nil }
        let origin = forumOrigin(for: url)
        if let redirect = familyHTTPSRedirect(from: url) {
            if isLoginPage(redirect) || previouslyLoaded.contains(canonicalKey(redirect)) {
                return origin
            }
            return redirect
        }
        return origin
    }

    static func forumOrigin(for url: URL) -> URL {
        guard let host = url.host,
              let registrable = ForumPolicy.linuxDoFamilyRegistrableHost(forHost: host),
              let origin = URL(string: "https://\(registrable)/")
        else {
            return URL(string: "https://linux.do/")!
        }
        return origin
    }

    static func canonicalKey(_ url: URL) -> String {
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        components?.fragment = nil
        return components?.url?.absoluteString ?? url.absoluteString
    }

    static func familyHTTPSRedirect(from url: URL) -> URL? {
        guard let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else {
            return nil
        }
        for key in redirectQueryKeys {
            guard let raw = items.first(where: { $0.name.lowercased() == key })?.value?
                .trimmingCharacters(in: .whitespacesAndNewlines),
                  !raw.isEmpty,
                  let resolved = resolveRedirect(raw, relativeTo: url)
            else { continue }
            if isAllowedBypassTarget(resolved) {
                return resolved
            }
        }
        return nil
    }

    private static func resolveRedirect(_ raw: String, relativeTo loginURL: URL) -> URL? {
        if let absolute = URL(string: raw), let scheme = absolute.scheme, !scheme.isEmpty {
            return absolute
        }
        return URL(string: raw, relativeTo: loginURL)?.absoluteURL
    }

    private static func isAllowedBypassTarget(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https",
              ForumPolicy.isLinuxDoFamily(url: url),
              !isLoginPage(url)
        else { return false }
        return true
    }
}

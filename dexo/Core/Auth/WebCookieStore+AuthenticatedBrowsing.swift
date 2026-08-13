import Foundation
import WebKit

extension WebCookieStore {
    /// Session / clearance cookies that linux.do-family SSO needs on subdomains.
    static let subdomainSSOCookieNames: Set<String> = ["_t", "_forum_session", "cf_clearance"]

    func hasDiscourseSessionCookies(for baseURL: String) -> Bool {
        guard let url = URL(string: baseURL) else { return false }
        return hasAuthTokenCookie(for: url)
    }

    /// API-key login via `ASWebAuthenticationSession` never stores `_t`.
    /// Password / web login do. Look up the registrable origin so a host-only
    /// `linux.do` `_t` still counts when opening `cdk.linux.do`.
    func hasAuthTokenCookie(for url: URL) -> Bool {
        cookies(for: Self.cookieEditorExportURL(for: url)).contains { $0.name == "_t" }
    }

    /// Jar cookies that apply to `url`, plus Domain=.<registrable> copies of
    /// host-only linux.do-family SSO cookies when the target is a subdomain.
    func cookiesForAuthenticatedBrowsing(for url: URL) -> [HTTPCookie] {
        let matching = cookies(for: url)
        let extras = subdomainSSOCookies(for: url)
        var seen = Set(matching.map { Self.cookieIdentity($0) })
        var result = matching
        for cookie in extras where seen.insert(Self.cookieIdentity($0)).inserted {
            result.append(cookie)
        }
        return result
    }

    /// Host-only `_t` / `_forum_session` / `cf_clearance` on `linux.do` do not
    /// match `cdk.linux.do`. Build Domain=.<registrable> copies for WKWebView
    /// priming without deleting the host-only jar entries used by the API client.
    func subdomainSSOCookies(for url: URL) -> [HTTPCookie] {
        guard let host = url.host?.lowercased(),
              let registrable = ForumPolicy.linuxDoFamilyRegistrableHost(forHost: host),
              host != registrable
        else { return [] }

        let matchingNames = Set(
            cookies(for: url)
                .filter { Self.subdomainSSOCookieNames.contains($0.name) }
                .map(\.name)
        )
        var excluded = jarIdentities()
        for name in matchingNames {
            excluded.insert(".\(registrable)|\(name)|/")
        }

        return domainCopies(
            of: hostOnlySSOCookies(onRegistrableHost: registrable),
            registrable: registrable,
            excluding: excluded
        )
        .filter { !matchingNames.contains($0.name) }
    }

    /// Cookie-Editor import JSON for the current forum, including both host-only
    /// cookies and Domain=.<parent> SSO copies so Safari can apply them to CDK.
    func cookieEditorJSON(for url: URL) throws -> String {
        let objects = cookieEditorItems(for: url).map(\.jsonObject)
        guard JSONSerialization.isValidJSONObject(objects),
              let data = try? JSONSerialization.data(
                withJSONObject: objects,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let json = String(data: data, encoding: .utf8)
        else {
            throw CookieEditorExportError.serializationFailed
        }
        return json
    }

    func cookieEditorItems(for url: URL) -> [CookieEditorItem] {
        let exportURL = Self.cookieEditorExportURL(for: url)
        var items = cookies(for: exportURL).map { CookieEditorItem(cookie: $0) }
        var seen = Set(items.map(\.identity))
        guard let host = exportURL.host,
              let registrable = ForumPolicy.linuxDoFamilyRegistrableHost(forHost: host)
        else { return items }

        let copies = domainCopies(
            of: hostOnlySSOCookies(onRegistrableHost: registrable),
            registrable: registrable,
            excluding: seen
        )
        for cookie in copies {
            let item = CookieEditorItem(
                cookie: cookie,
                domain: ".\(registrable)",
                hostOnly: false
            )
            if seen.insert(item.identity).inserted {
                items.append(item)
            }
        }
        return items
    }

    /// linux.do-family pages export the registrable origin jar so host-only
    /// `_t` cookies are included even when the current page is a subdomain.
    static func cookieEditorExportURL(for url: URL) -> URL {
        guard let host = url.host,
              let registrable = ForumPolicy.linuxDoFamilyRegistrableHost(forHost: host),
              let origin = URL(string: "https://\(registrable)/")
        else { return url }
        return origin
    }

    // MARK: - Internals

    private func hostOnlySSOCookies(onRegistrableHost registrable: String) -> [HTTPCookie] {
        guard let origin = URL(string: "https://\(registrable)/") else { return [] }
        return cookies(for: origin).filter { cookie in
            Self.subdomainSSOCookieNames.contains(cookie.name)
                && Self.isHostOnly(cookie)
                && cookie.domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) == registrable
        }
    }

    private func domainCopies(
        of cookies: [HTTPCookie],
        registrable: String,
        excluding identities: Set<String>
    ) -> [HTTPCookie] {
        let dotted = ".\(registrable)"
        return cookies.compactMap { cookie in
            guard let copy = Self.makeDomainCookie(from: cookie, domain: dotted) else { return nil }
            let intended = CookieEditorItem(cookie: copy, domain: dotted, hostOnly: false).identity
            if identities.contains(Self.cookieIdentity(copy)) || identities.contains(intended) {
                return nil
            }
            return copy
        }
    }

    static func isHostOnly(_ cookie: HTTPCookie) -> Bool {
        !cookie.domain.hasPrefix(".")
    }

    static func cookieIdentity(_ cookie: HTTPCookie) -> String {
        "\(cookie.domain)|\(cookie.name)|\(cookie.path)"
    }

    static func makeDomainCookie(from cookie: HTTPCookie, domain: String) -> HTTPCookie? {
        var props: [HTTPCookiePropertyKey: Any] = [
            .name: cookie.name,
            .value: cookie.value,
            .domain: domain,
            .path: "/",
        ]
        if cookie.isSecure {
            props[.secure] = "TRUE"
        }
        if cookie.isHTTPOnly {
            props[HTTPCookiePropertyKey("HttpOnly")] = "TRUE"
        }
        if let expires = cookie.expiresDate {
            props[.expires] = expires
        }
        if let policy = cookie.sameSitePolicy {
            props[.sameSitePolicy] = policy
        }
        return HTTPCookie(properties: props)
    }

    static func cookieEditorSameSite(for cookie: HTTPCookie) -> String {
        guard let policy = cookie.sameSitePolicy else { return "unspecified" }
        switch policy {
        case .none:
            return "no_restriction"
        case .lax:
            return "lax"
        case .strict:
            return "strict"
        default:
            let raw = policy.rawValue.lowercased()
            if raw == "none" { return "no_restriction" }
            if raw == "lax" || raw == "strict" { return raw }
            return "unspecified"
        }
    }
}

enum CookieEditorExportError: Error {
    case serializationFailed
}

struct CookieEditorItem: Equatable {
    var name: String
    var value: String
    var domain: String
    var hostOnly: Bool
    var path: String
    var secure: Bool
    var httpOnly: Bool
    var session: Bool
    var expirationDate: Int?
    var sameSite: String

    var identity: String {
        "\(domain.lowercased())|\(name)|\(path)"
    }

    init(cookie: HTTPCookie, domain: String? = nil, hostOnly: Bool? = nil) {
        name = cookie.name
        value = cookie.value
        let resolvedDomain = domain ?? cookie.domain
        self.domain = resolvedDomain
        self.hostOnly = hostOnly ?? !resolvedDomain.hasPrefix(".")
        path = cookie.path.isEmpty ? "/" : cookie.path
        secure = cookie.isSecure
        httpOnly = cookie.isHTTPOnly
        session = cookie.expiresDate == nil
        expirationDate = cookie.expiresDate.map { Int($0.timeIntervalSince1970) }
        sameSite = WebCookieStore.cookieEditorSameSite(for: cookie)
    }

    var jsonObject: [String: Any] {
        var dict: [String: Any] = [
            "name": name,
            "value": value,
            "domain": domain,
            "hostOnly": NSNumber(value: hostOnly),
            "path": path,
            "secure": NSNumber(value: secure),
            "httpOnly": NSNumber(value: httpOnly),
            "session": NSNumber(value: session),
            "sameSite": sameSite,
        ]
        if let expirationDate {
            dict["expirationDate"] = NSNumber(value: expirationDate)
        }
        return dict
    }
}

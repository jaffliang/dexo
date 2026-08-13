import Foundation
import WebKit

extension WebCookieStore {
    func hasDiscourseSessionCookies(for baseURL: String) -> Bool {
        guard let url = URL(string: baseURL) else { return false }
        return hasAuthTokenCookie(for: url)
    }

    /// API-key login via `ASWebAuthenticationSession` never stores `_t`.
    /// Password / web login do. Look up the registrable origin so a host-only
    /// `linux.do` `_t` still counts when opening `cdk.linux.do`.
    func hasAuthTokenCookie(for url: URL) -> Bool {
        cookies(for: Self.familyOriginURL(for: url)).contains { $0.name == "_t" }
    }

    /// Cookies to write into the shared WK store before load.
    ///
    /// Includes cookies that already apply to `url` (e.g. `Domain=.linux.do`
    /// `cf_clearance`) plus host-only `_t` / `_forum_session` on the
    /// registrable origin so a CDK → linux.do SSO redirect can send them.
    /// Never rewrites `_t` to `Domain=.linux.do`.
    func cookiesForAuthenticatedBrowsing(for url: URL) -> [HTTPCookie] {
        var result: [HTTPCookie] = []
        var seen = Set<String>()
        func append(_ cookies: [HTTPCookie]) {
            for cookie in cookies where seen.insert(Self.cookieIdentity(cookie)).inserted {
                result.append(cookie)
            }
        }
        append(cookies(for: url))
        let origin = Self.familyOriginURL(for: url)
        if origin.host?.lowercased() != url.host?.lowercased() {
            append(cookies(for: origin))
        }
        return result
    }

    /// Cookie-Editor import JSON for the forum origin. Exports jar cookies
    /// as stored — no invented `Domain=.linux.do` copies of `_t`.
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
        cookies(for: Self.familyOriginURL(for: url)).map { CookieEditorItem(cookie: $0) }
    }

    /// Prefer linux.do, then idcflare, when Settings has no current-forum context.
    func cookieEditorExportURLFromJar() -> URL? {
        for host in ["linux.do", "idcflare.com"] {
            if let url = URL(string: "https://\(host)/"), hasAuthTokenCookie(for: url) {
                return url
            }
        }
        return nil
    }

    /// linux.do-family URLs map to the registrable origin so host-only `_t`
    /// is visible when the page host is a subdomain.
    static func familyOriginURL(for url: URL) -> URL {
        guard let host = url.host,
              let registrable = ForumPolicy.linuxDoFamilyRegistrableHost(forHost: host),
              let origin = URL(string: "https://\(registrable)/")
        else { return url }
        return origin
    }

    /// Stock WK `navigator.userAgent` omits `Version/x.y` and `Safari/604.1`,
    /// which Cloudflare treats as a WebView. Append those tokens to the stored
    /// login UA instead of substituting a different string than the API client.
    static func safariCompatibleUserAgent(_ stored: String?) -> String? {
        guard var ua = stored?.trimmingCharacters(in: .whitespacesAndNewlines), !ua.isEmpty else {
            return nil
        }
        if ua.range(of: #"Version/\d"#, options: .regularExpression) == nil {
            ua += " Version/15.6.1"
        }
        if ua.range(of: #"Safari/\d"#, options: .regularExpression) == nil {
            ua += " Safari/604.1"
        }
        return ua
    }

    static func cookieIdentity(_ cookie: HTTPCookie) -> String {
        "\(cookie.domain)|\(cookie.name)|\(cookie.path)"
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

    init(cookie: HTTPCookie) {
        name = cookie.name
        value = cookie.value
        domain = cookie.domain
        hostOnly = !cookie.domain.hasPrefix(".")
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

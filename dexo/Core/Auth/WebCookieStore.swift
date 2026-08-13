import Foundation
import WebKit

/// In-memory + persisted cookie store used for web-login sessions.
/// Cookies are keyed by "domain|name|path" for deduplication.
final class WebCookieStore {
    static let shared = WebCookieStore()

    private var jar: [String: HTTPCookie] = [:]
    private let lock = NSLock()
    private let filePath: URL

    /// The User-Agent captured from the WKWebView that completed login.
    var userAgent: String? {
        didSet { saveUserAgent() }
    }

    /// Long-lived WebKit jar shared by Cloudflare challenge and password-login
    /// WKWebViews. Copying `cf_clearance` into a fresh `.nonPersistent()` store
    /// does not preserve TLS/JA3, so both flows must use this instance.
    @MainActor
    private(set) lazy var websiteDataStore: WKWebsiteDataStore = .nonPersistent()

    private let userAgentPath: URL

    private init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        filePath = dir.appendingPathComponent("dexo_web_cookies.json")
        userAgentPath = dir.appendingPathComponent("dexo_web_ua.txt")
        load()
        userAgent = loadUserAgent()
    }

    // MARK: - Read / Write

    func setCookies(_ cookies: [HTTPCookie]) {
        let now = Date()
        lock.lock()
        for c in cookies {
            // Drop already-expired cookies instead of letting them overwrite a still-valid entry.
            if let expires = c.expiresDate, expires <= now {
                jar.removeValue(forKey: key(for: c))
            } else {
                jar[key(for: c)] = c
            }
        }
        lock.unlock()
        save()
    }

    func cookies(for url: URL) -> [HTTPCookie] {
        let now = Date()
        lock.lock()
        defer { lock.unlock() }
        guard let host = url.host?.lowercased() else { return [] }
        let path = url.path.isEmpty ? "/" : url.path
        return jar.values.filter { cookie in
            // Skip expired cookies so a stale/expired `_t` left in the jar never gets sent.
            if let expires = cookie.expiresDate, expires <= now { return false }
            return Self.cookieDomain(cookie.domain, matchesHost: host)
                && path.hasPrefix(cookie.path)
        }
    }

    func cookieHeader(for url: URL) -> String {
        cookies(for: url).map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
    }

    /// Cloudflare cookies that guest (no User-Api-Key) requests may send.
    /// Never include `_t` / `_forum_session` — those would impersonate a login.
    static let guestCloudflareCookieNames: Set<String> = ["cf_clearance", "__cf_bm"]

    static func isGuestCloudflareCookieName(_ name: String) -> Bool {
        guestCloudflareCookieNames.contains(name)
    }

    /// Attaches stored cookies and the challenge WKWebView User-Agent.
    ///
    /// Always `setValue`s (never `addValue`) so Alamofire's default User-Agent
    /// is replaced and a second `Cookie` header is never created.
    ///
    /// Pass `guestBrowsing: true` when there is no User-Api-Key: only
    /// `cf_clearance` and `__cf_bm` are sent.
    func applySessionHeaders(to request: inout URLRequest, guestBrowsing: Bool = false) {
        guard let url = request.url else { return }
        let matching = cookies(for: url).filter { cookie in
            !guestBrowsing || Self.isGuestCloudflareCookieName(cookie.name)
        }
        let header = matching.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
        if !header.isEmpty {
            request.setValue(header, forHTTPHeaderField: "Cookie")
        }
        if let ua = userAgent, !ua.isEmpty {
            request.setValue(ua, forHTTPHeaderField: "User-Agent")
        }
    }

    /// Drops stale `cf_clearance` for this host so Cloudflare will show the
    /// challenge widget instead of silently skipping it.
    func removeClearanceCookies(matching url: URL) {
        guard let host = url.host?.lowercased() else { return }
        lock.lock()
        jar = jar.filter { _, cookie in
            !(cookie.name == "cf_clearance" && Self.cookieDomain(cookie.domain, matchesHost: host))
        }
        lock.unlock()
        save()
    }

    @MainActor
    func removeClearanceCookies(from dataStore: WKWebsiteDataStore, matching url: URL) async {
        guard let host = url.host?.lowercased() else { return }
        let store = dataStore.httpCookieStore
        let all = await withCheckedContinuation { cont in
            store.getAllCookies { cont.resume(returning: $0) }
        }
        for cookie in all where cookie.name == "cf_clearance"
            && Self.cookieDomain(cookie.domain, matchesHost: host)
        {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                store.delete(cookie) { cont.resume() }
            }
        }
    }

    func mergeResponseHeaders(_ headers: [AnyHashable: Any], for url: URL) {
        var stringHeaders: [String: String] = [:]
        for (k, v) in headers { stringHeaders["\(k)"] = "\(v)" }
        let newCookies = HTTPCookie.cookies(withResponseHeaderFields: stringHeaders, for: url)
        if !newCookies.isEmpty { setCookies(newCookies) }
    }

    @MainActor
    func syncFromWebView(_ dataStore: WKWebsiteDataStore, for url: URL) async {
        let cookies = await withCheckedContinuation { cont in
            dataStore.httpCookieStore.getAllCookies { cont.resume(returning: $0) }
        }
        guard let host = url.host?.lowercased() else { return }

        // Treat WebKit as authoritative for this forum. A challenge may
        // delete or rotate cf_clearance without returning the expired cookie
        // from getAllCookies; merge-only syncing would leave that stale value
        // in the native jar and send it again on the next topic request.
        let now = Date()
        let currentForumCookies = cookies.filter {
            Self.cookieDomain($0.domain, matchesHost: host)
                && ($0.expiresDate.map { $0 > now } ?? true)
        }
        lock.lock()
        jar = jar.filter { _, cookie in
            !Self.cookieDomain(cookie.domain, matchesHost: host)
        }
        for cookie in currentForumCookies {
            jar[key(for: cookie)] = cookie
        }
        lock.unlock()
        save()
    }

    func clearAll() {
        lock.lock()
        jar.removeAll()
        lock.unlock()
        userAgent = nil
        try? FileManager.default.removeItem(at: filePath)
    }

    func clearCookies(for baseURL: String) {
        guard let host = URL(string: baseURL)?.host?.lowercased() else { return }
        lock.lock()
        jar = jar.filter { _, cookie in
            !Self.cookieDomain(cookie.domain, matchesHost: host)
        }
        lock.unlock()
        save()
    }

    /// Returns whether a cookie's domain applies to a host. Domain cookies
    /// require a dot boundary, so `.example.com` matches `forum.example.com`
    /// but never `notexample.com`. Host-only cookies remain exact matches.
    static func cookieDomain(_ cookieDomain: String, matchesHost host: String) -> Bool {
        let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let rawDomain = cookieDomain.lowercased()
        let normalizedDomain = rawDomain.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !normalizedHost.isEmpty, !normalizedDomain.isEmpty else { return false }
        if normalizedHost == normalizedDomain { return true }
        return rawDomain.hasPrefix(".") && normalizedHost.hasSuffix("." + normalizedDomain)
    }

    // MARK: - Persistence

    func jarIdentities() -> Set<String> {
        lock.lock()
        defer { lock.unlock() }
        return Set(jar.keys)
    }

    private func key(for cookie: HTTPCookie) -> String {
        "\(cookie.domain)|\(cookie.name)|\(cookie.path)"
    }

    private func save() {
        let serializable: [[String: Any]] = jar.values.compactMap { cookie in
            guard let props = cookie.properties else { return nil }
            var dict: [String: Any] = [:]
            for (k, v) in props {
                if let date = v as? Date {
                    dict[k.rawValue] = date.timeIntervalSinceReferenceDate
                } else {
                    dict[k.rawValue] = v
                }
            }
            return dict
        }
        guard JSONSerialization.isValidJSONObject(serializable),
              let data = try? JSONSerialization.data(withJSONObject: serializable)
        else { return }
        try? data.write(to: filePath, options: .atomic)
    }

    private func load() {
        guard let data = try? Data(contentsOf: filePath),
              let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return }
        let now = Date()
        let cookies: [HTTPCookie] = array.compactMap { dict in
            var props: [HTTPCookiePropertyKey: Any] = [:]
            for (k, v) in dict {
                let key = HTTPCookiePropertyKey(k)
                if (key == .expires || key == HTTPCookiePropertyKey("Max-Age")),
                   let ti = v as? TimeInterval {
                    props[key] = Date(timeIntervalSinceReferenceDate: ti)
                } else {
                    props[key] = v
                }
            }
            return HTTPCookie(properties: props)
        }.filter {
            $0.expiresDate.map { $0 > now } ?? true
        }
        for c in cookies { jar[key(for: c)] = c }
    }

    private func saveUserAgent() {
        if let ua = userAgent {
            try? ua.write(to: userAgentPath, atomically: true, encoding: .utf8)
        } else {
            try? FileManager.default.removeItem(at: userAgentPath)
        }
    }

    private func loadUserAgent() -> String? {
        try? String(contentsOf: userAgentPath, encoding: .utf8)
    }
}

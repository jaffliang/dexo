import Foundation
import WebKit

extension WebCookieStore {
    static let discourseSessionCookieNames: Set<String> = ["_t", "_forum_session"]

    func hasValidClearance(for baseURL: String) -> Bool {
        guard let url = URL(string: baseURL) else { return false }
        return cookies(for: url).contains { $0.name == "cf_clearance" }
    }

    /// Writes jar cookies into a WKWebView data store with full attributes.
    @MainActor
    func primeToWebView(
        _ dataStore: WKWebsiteDataStore,
        for url: URL,
        excludingNames: Set<String> = []
    ) async {
        await prime(into: dataStore, for: url, excludingNames: excludingNames)
    }

    @MainActor
    func exportCookies(
        from dataStore: WKWebsiteDataStore,
        matchingHost host: String
    ) async -> [HTTPCookie] {
        let all = await withCheckedContinuation { cont in
            dataStore.httpCookieStore.getAllCookies { cont.resume(returning: $0) }
        }
        let now = Date()
        return all.filter {
            Self.cookieDomain($0.domain, matchesHost: host.lowercased())
                && ($0.expiresDate.map { $0 > now } ?? true)
        }
    }
}

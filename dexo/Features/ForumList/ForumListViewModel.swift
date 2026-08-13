import Foundation

import Perception

@Perceptible
final class ForumListViewModel {
    var forums: [ForumInstance] = []
    var isLoading = false
    var errorMessage: String?

    func loadForums() {
        isLoading = true
        errorMessage = nil
        do {
            forums = try DatabaseManager.shared.fetchAllForums()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
        Task {
            await ForumNotificationMetadataSynchronizer.syncAll()
        }
    }

    func deleteForum(at index: Int) {
        guard index < forums.count else { return }
        let forum = forums[index]
        Task {
            do {
                if ForumURLPolicy.isSecure(forum.baseURL) {
                    let coordinator = PushSubscriptionCoordinator(
                        api: DiscourseAPI(forum: forum)
                    )
                    if let username = AuthManager.shared.username(for: forum.baseURL)
                        ?? forum.username
                    {
                        await coordinator.disableForLogout(username: username)
                    } else {
                        coordinator.retireLocalSubscriptions()
                    }
                    AuthManager.shared.logout(forum: forum)
                } else {
                    // Never attempt server-side revocation for a blocked legacy URL.
                    AuthManager.shared.clearLocalAuthentication(for: forum.baseURL)
                }
                try DatabaseManager.shared.deleteForum(forum)
                if let currentIndex = forums.firstIndex(where: { $0.id == forum.id }) {
                    forums.remove(at: currentIndex)
                }
                await ForumNotificationMetadataSynchronizer.syncAll()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    func moveForum(from sourceIndex: Int, to destinationIndex: Int) {
        guard sourceIndex != destinationIndex,
              sourceIndex >= 0, sourceIndex < forums.count,
              destinationIndex >= 0, destinationIndex < forums.count else { return }
        let moved = forums.remove(at: sourceIndex)
        forums.insert(moved, at: destinationIndex)
        for i in forums.indices {
            forums[i].sortOrder = i
        }
        do {
            try DatabaseManager.shared.updateForumOrder(forums)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Probes the HTTPS equivalent anonymously, then migrates the saved forum
    /// and removes credentials associated with the legacy HTTP address.
    func upgradeForumToHTTPS(_ forum: ForumInstance) async throws -> ForumInstance {
        let candidate = try ForumURLPolicy.httpsUpgradeCandidate(from: forum.baseURL)
        let info = try await fetchBasicInfoAnonymously(baseURL: candidate)

        var updated = forum
        updated.baseURL = candidate
        if !info.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            updated.title = info.title
        }
        updated.iconURL = secureIconURL(baseURL: candidate, info: info)
        updated.apiKey = nil
        updated.apiUsername = nil
        updated.username = nil

        try DatabaseManager.shared.saveForum(&updated)
        // Credential keys are URL-based. Clear both the legacy address and
        // the HTTPS candidate so an unrelated/stale candidate credential can
        // never make the migrated record appear logged in automatically.
        AuthManager.shared.clearLocalAuthentication(for: candidate)
        AuthManager.shared.clearLocalAuthentication(for: forum.baseURL)

        if let index = forums.firstIndex(where: { $0.id == forum.id }) {
            forums[index] = updated
        }
        return updated
    }

    private func fetchBasicInfoAnonymously(baseURL: String) async throws -> DiscourseBasicInfo {
        guard let url = URL(string: baseURL + "/site/basic-info.json") else {
            throw URLError(.badURL)
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        DoHGatewayRuntime.prepare(configuration)

        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200 ..< 300).contains(httpResponse.statusCode),
              let responseURL = httpResponse.url,
              Self.hasSameHTTPSOrigin(responseURL, as: url)
        else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(DiscourseBasicInfo.self, from: data)
    }

    /// Anonymous upgrade probes may follow same-origin redirects (for example
    /// to add a trailing slash), but must not silently turn a saved forum into
    /// a cross-origin redirector that later receives authenticated requests.
    private static func hasSameHTTPSOrigin(_ lhs: URL, as rhs: URL) -> Bool {
        guard lhs.scheme?.lowercased() == "https",
              rhs.scheme?.lowercased() == "https",
              lhs.host?.lowercased() == rhs.host?.lowercased()
        else { return false }

        return (lhs.port ?? 443) == (rhs.port ?? 443)
    }

    private func secureIconURL(baseURL: String, info: DiscourseBasicInfo) -> String? {
        guard let path = info.appleTouchIconURL ?? info.logoURL ?? info.faviconURL else {
            return nil
        }

        let value: String
        if path.hasPrefix("//") {
            value = "https:" + path
        } else if let url = URL(string: path), url.scheme != nil {
            value = url.absoluteString
        } else {
            value = path.hasPrefix("/") ? baseURL + path : baseURL + "/" + path
        }

        guard let url = URL(string: value), url.scheme?.lowercased() == "https" else {
            return nil
        }
        return url.absoluteString
    }
}

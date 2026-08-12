import UIKit

enum CloudflareClearanceGate {
    /// Ensures `cf_clearance` exists for the forum. May present the challenge UI.
    /// Pass `force: true` to re-run the challenge even when a clearance cookie
    /// is already present (used after a CSRF 403 retry).
    @MainActor
    static func ensureClearance(
        for forum: ForumInstance,
        config: PasswordLoginConfig,
        from presenter: UIViewController,
        force: Bool = false
    ) async throws {
        let baseURL = forum.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if !force, WebCookieStore.shared.hasValidClearance(for: baseURL) {
            return
        }
        guard let challengeURL = config.challengeURL else {
            throw PasswordLoginError.cloudflareFailed
        }
        await ChallengeViewController.presentAndWait(
            from: presenter,
            challengeURL: challengeURL
        )
        // ChallengeViewController syncs cookies on navigation/dismiss; allow flush.
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        if !WebCookieStore.shared.hasValidClearance(for: baseURL) {
            try? await Task.sleep(nanoseconds: 800_000_000)
        }
        guard WebCookieStore.shared.hasValidClearance(for: baseURL) else {
            throw PasswordLoginError.cloudflareFailed
        }
    }
}

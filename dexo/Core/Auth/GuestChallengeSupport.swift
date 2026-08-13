import UIKit

/// Maps a content-load error into the empty-state flags used by guest list
/// screens (home, categories, search, topic detail).
struct GuestContentLoadFailure {
    let message: String
    let requiresLogin: Bool
    let requiresChallenge: Bool

    init(_ error: Error) {
        if let apiError = error as? DiscourseAPIError, apiError.isChallengeRequired {
            message = String(localized: "challenge.empty.message")
            requiresLogin = false
            requiresChallenge = true
        } else if let apiError = error as? DiscourseAPIError,
                  apiError.isNotLoggedIn || apiError.isForbidden
        {
            message = error.localizedDescription
            requiresLogin = true
            requiresChallenge = false
        } else {
            message = error.localizedDescription
            requiresLogin = false
            requiresChallenge = false
        }
    }
}

/// Coalesces concurrent `challenge_required` failures into a single
/// Cloudflare interstitial sheet. Password-login runs the forum's own
/// interstitial URL in its WKWebView (linux.do `/challenge`, idcflare `/login`).
enum GuestChallengePresenter {
    @MainActor
    private static var isPresenting = false
    @MainActor
    private static var waiters: [CheckedContinuation<Bool, Never>] = []
    @MainActor
    private static var didAutoPresentThisSession = false

    /// Presents one challenge sheet (or joins an in-flight one). Returns
    /// whether `cf_clearance` is present after dismiss.
    @MainActor
    static func presentAndWaitForClearance(
        from presenter: UIViewController,
        api: DiscourseAPI
    ) async -> Bool {
        guard api.isLinuxDoFamily,
              let challengeURL = ForumPolicy.cloudflareInterstitialURL(for: api.baseURL)
        else { return false }
        if isPresenting {
            return await withCheckedContinuation { waiters.append($0) }
        }
        isPresenting = true
        await ChallengeViewController.presentAndWait(from: presenter, challengeURL: challengeURL)
        let cleared = WebCookieStore.shared.hasValidClearance(for: api.baseURL)
        let pending = waiters
        waiters = []
        isPresenting = false
        pending.forEach { $0.resume(returning: cleared) }
        return cleared
    }

    @MainActor
    static func consumeHomeAutoPresent() -> Bool {
        guard !didAutoPresentThisSession else { return false }
        didAutoPresentThisSession = true
        return true
    }

    #if DEBUG
    @MainActor
    static func resetForTesting() {
        didAutoPresentThisSession = false
        isPresenting = false
        waiters = []
    }
    #endif
}

enum GuestChallengeUI {
    static func makePassButton() -> UIButton {
        var config = UIButton.Configuration.filled()
        config.title = String(localized: "challenge.pass_button")
        config.cornerStyle = .medium
        let button = UIButton(configuration: config)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.isHidden = true
        return button
    }
}

extension UIViewController {
    /// Presents the forum's Cloudflare interstitial sheet (coalesced), then
    /// retries only when a valid `cf_clearance` cookie is present.
    func presentGuestChallengeThenRetry(
        on api: DiscourseAPI,
        retry: @escaping () async -> Void
    ) {
        guard api.isLinuxDoFamily else { return }
        Task { @MainActor in
            let cleared = await GuestChallengePresenter.presentAndWaitForClearance(
                from: self,
                api: api
            )
            if cleared {
                await retry()
            }
        }
    }

    /// Auto-presents the challenge sheet once per session when the home feed
    /// first hits `challenge_required`. Cancel still leaves the empty-state
    /// button in place.
    func presentGuestChallengeAutomaticallyIfNeeded(
        on api: DiscourseAPI,
        isChallengeRequired: Bool,
        retry: @escaping () async -> Void
    ) async {
        guard api.isLinuxDoFamily,
              isChallengeRequired,
              view.window != nil,
              GuestChallengePresenter.consumeHomeAutoPresent()
        else { return }
        let cleared = await GuestChallengePresenter.presentAndWaitForClearance(
            from: self,
            api: api
        )
        if cleared {
            await retry()
        }
    }
}

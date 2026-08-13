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

enum GuestChallengeAutoPresent {
    @MainActor
    private static var didPresentThisSession = false

    /// Returns true once per process for the home-feed auto-present path.
    @MainActor
    static func consume() -> Bool {
        guard !didPresentThisSession else { return false }
        didPresentThisSession = true
        return true
    }

    #if DEBUG
    @MainActor
    static func resetForTesting() {
        didPresentThisSession = false
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
    /// Presents the linux.do Cloudflare challenge sheet, then retries.
    func presentGuestChallengeThenRetry(
        on api: DiscourseAPI,
        retry: @escaping () async -> Void
    ) {
        guard api.isLinuxDo else { return }
        Task { @MainActor in
            await ChallengeViewController.presentAndWait(from: self)
            await retry()
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
        guard api.isLinuxDo,
              isChallengeRequired,
              view.window != nil,
              presentedViewController == nil,
              GuestChallengeAutoPresent.consume()
        else { return }
        await ChallengeViewController.presentAndWait(from: self)
        await retry()
    }
}

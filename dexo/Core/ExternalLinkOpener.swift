import SafariServices
import UIKit

/// Destination for a URL the native topic/category/user router cannot handle.
enum ExternalLinkDestination: Equatable {
    case authenticatedWebView
    case safari
    case systemOpen
    case missingSession
}

/// Topic link taps vs explicit “打开网页” URLs must not share one policy:
/// Safari cannot see App `_t`, so a linux.do OAuth site opened from the prompt
/// has to stay in the authenticated WKWebView.
enum ExternalLinkOpener {
    /// Live call site: `VirtualizedTopicDetailViewController.handleLink`.
    /// Family hosts use the authenticated WKWebView when the jar has `_t`.
    /// Non-family HTTP(S) stays in Safari.
    static func open(_ url: URL, from presenter: UIViewController) {
        present(destinationForLinkTap(url), url: url, from: presenter)
    }

    /// User-typed URL from Me / Settings “打开网页”. Any HTTP(S) host uses the
    /// authenticated WKWebView when the jar has `_t` (so `api.coee.ccwu.cc`
    /// can OAuth to `connect.linux.do`). Never Safari.
    static func openTypedURL(_ url: URL, from presenter: UIViewController) {
        present(destinationForTypedURL(url), url: url, from: presenter)
    }

    static func destinationForLinkTap(_ url: URL) -> ExternalLinkDestination {
        let scheme = url.scheme?.lowercased()
        guard scheme == "http" || scheme == "https" else { return .systemOpen }
        if ForumPolicy.isLinuxDoFamily(url: url) {
            return WebCookieStore.shared.hasAuthTokenCookie(for: url)
                ? .authenticatedWebView
                : .missingSession
        }
        return .safari
    }

    static func destinationForTypedURL(_ url: URL) -> ExternalLinkDestination {
        let scheme = url.scheme?.lowercased()
        guard scheme == "http" || scheme == "https" else { return .systemOpen }
        guard WebCookieStore.shared.hasAnyAuthTokenCookie() else { return .missingSession }
        return .authenticatedWebView
    }

    private static func present(
        _ destination: ExternalLinkDestination,
        url: URL,
        from presenter: UIViewController
    ) {
        switch destination {
        case .authenticatedWebView:
            AuthenticatedWebViewController.present(url, from: presenter)
        case .safari:
            presenter.present(SFSafariViewController(url: url), animated: true)
        case .systemOpen:
            UIApplication.shared.open(url)
        case .missingSession:
            presentMissingSessionAlert(from: presenter)
        }
    }

    static func presentMissingSessionAlert(from presenter: UIViewController) {
        let alert = UIAlertController(
            title: String(localized: "browser.missing_session.title"),
            message: String(localized: "browser.missing_session.message"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default))
        presenter.present(alert, animated: true)
    }
}

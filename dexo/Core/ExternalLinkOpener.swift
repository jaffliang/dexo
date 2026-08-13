import SafariServices
import UIKit

/// Destination for a URL the native topic/category/user router cannot handle.
enum ExternalLinkDestination: Equatable {
    case authenticatedWebView
    case safari
    case systemOpen
    case missingSession
}

/// HTTP(S) links use the authenticated WKWebView whenever the jar has `_t`,
/// including post taps to third-party linux.do OAuth sites. Safari cannot see
/// App cookies. Custom schemes still go to the system.
enum ExternalLinkOpener {
    /// Live call site: `VirtualizedTopicDetailViewController.handleLink`.
    static func open(_ url: URL, from presenter: UIViewController) {
        present(destinationForLinkTap(url), url: url, from: presenter)
    }

    /// User-typed URL from Me / Settings “打开网页”.
    static func openTypedURL(_ url: URL, from presenter: UIViewController) {
        present(destinationForTypedURL(url), url: url, from: presenter)
    }

    static func destinationForLinkTap(_ url: URL) -> ExternalLinkDestination {
        destinationForAuthenticatedHTTP(url, missingFamilySession: true)
    }

    static func destinationForTypedURL(_ url: URL) -> ExternalLinkDestination {
        destinationForAuthenticatedHTTP(url, missingFamilySession: false)
    }

    /// - Parameter missingFamilySession: Topic taps to linux.do family without
    ///   `_t` show the missing-session alert. Typed URLs always alert without `_t`.
    ///   Non-family taps without `_t` still use Safari.
    private static func destinationForAuthenticatedHTTP(
        _ url: URL,
        missingFamilySession: Bool
    ) -> ExternalLinkDestination {
        let scheme = url.scheme?.lowercased()
        guard scheme == "http" || scheme == "https" else { return .systemOpen }
        if WebCookieStore.shared.hasAnyAuthTokenCookie() {
            return .authenticatedWebView
        }
        if !missingFamilySession || ForumPolicy.isLinuxDoFamily(url: url) {
            return .missingSession
        }
        return .safari
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

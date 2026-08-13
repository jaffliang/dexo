import SafariServices
import UIKit

/// Single entry point for opening URLs the native topic/category/user router
/// cannot handle. Live call site: `VirtualizedTopicDetailViewController.handleLink`.
///
/// linux.do-family HTTP(S) uses the authenticated WKWebView when the JSON jar
/// has `_t` from password/web login. Safari cannot see App cookies, so family
/// hosts never go to `SFSafariViewController`. API-key login does not store
/// `_t`; show a message instead of a logged-out WebView.
enum ExternalLinkOpener {
    static func open(_ url: URL, from presenter: UIViewController) {
        let scheme = url.scheme?.lowercased()
        guard scheme == "http" || scheme == "https" else {
            UIApplication.shared.open(url)
            return
        }
        if ForumPolicy.isLinuxDoFamily(url: url) {
            guard WebCookieStore.shared.hasAuthTokenCookie(for: url) else {
                presentMissingSessionAlert(from: presenter)
                return
            }
            AuthenticatedWebViewController.present(url, from: presenter)
            return
        }
        presenter.present(SFSafariViewController(url: url), animated: true)
    }

    private static func presentMissingSessionAlert(from presenter: UIViewController) {
        let alert = UIAlertController(
            title: String(localized: "browser.missing_session.title"),
            message: String(localized: "browser.missing_session.message"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default))
        presenter.present(alert, animated: true)
    }
}

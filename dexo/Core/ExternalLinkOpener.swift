import SafariServices
import UIKit

/// Single entry point for opening URLs the native topic/category/user router
/// cannot handle. Live call site: `VirtualizedTopicDetailViewController.handleLink`
/// (legacy leftover: `LegacyTopicDetailViewController.handleLink`).
///
/// linux.do-family HTTP(S) uses the authenticated WKWebView when the JSON jar
/// has `_t` from password/web login. API-key login does not store `_t`; show
/// a message instead of a logged-out WebView. Unrelated hosts stay on
/// `SFSafariViewController`.
enum ExternalLinkOpener {
    static func open(_ url: URL, from presenter: UIViewController) {
        let scheme = url.scheme?.lowercased()
        guard scheme == "http" || scheme == "https" else {
            UIApplication.shared.open(url)
            return
        }
        if ForumPolicy.isLinuxDoFamily(url: url) {
            guard WebCookieStore.shared.hasAuthTokenCookie(for: url) else {
                presentMissingSessionAlert(for: url, from: presenter)
                return
            }
            AuthenticatedWebViewController.present(url, from: presenter)
            return
        }
        presenter.present(SFSafariViewController(url: url), animated: true)
    }

    private static func presentMissingSessionAlert(for url: URL, from presenter: UIViewController) {
        let alert = UIAlertController(
            title: String(localized: "browser.missing_session.title"),
            message: String(localized: "browser.missing_session.message"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(
            title: String(localized: "browser.open_in_safari"),
            style: .default
        ) { _ in
            DispatchQueue.main.async {
                presenter.present(SFSafariViewController(url: url), animated: true)
            }
        })
        presenter.present(alert, animated: true)
    }
}

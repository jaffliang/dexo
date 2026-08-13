import SafariServices
import UIKit

/// Single entry point for opening URLs tapped in the app.
/// linux.do-family HTTP(S) links use the authenticated in-app WKWebView so
/// primed session cookies apply; everything else stays on system Safari.
enum ExternalLinkOpener {
    static func open(_ url: URL, from presenter: UIViewController) {
        let scheme = url.scheme?.lowercased()
        guard scheme == "http" || scheme == "https" else {
            UIApplication.shared.open(url)
            return
        }
        if ForumPolicy.isLinuxDoFamily(url: url) {
            AuthenticatedWebViewController.present(url, from: presenter)
            return
        }
        presenter.present(SFSafariViewController(url: url), animated: true)
    }
}

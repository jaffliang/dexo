import UIKit

enum CookieExportPresenter {
    static func confirmAndCopy(from presenter: UIViewController, url: URL) {
        let json: String
        do {
            json = try WebCookieStore.shared.cookieEditorJSON(for: url)
        } catch {
            let alert = UIAlertController(
                title: String(localized: "me.copy_cookies"),
                message: String(localized: "me.copy_cookies.failed"),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default))
            presenter.present(alert, animated: true)
            return
        }

        let confirm = UIAlertController(
            title: String(localized: "me.copy_cookies.confirm.title"),
            message: String(localized: "me.copy_cookies.confirm.message"),
            preferredStyle: .alert
        )
        confirm.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        confirm.addAction(UIAlertAction(
            title: String(localized: "me.copy_cookies"),
            style: .destructive
        ) { [weak presenter] _ in
            AppPasteboard.writePlainText(json)
            DispatchQueue.main.async {
                let done = UIAlertController(
                    title: String(localized: "me.copy_cookies.copied"),
                    message: nil,
                    preferredStyle: .alert
                )
                done.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default))
                presenter?.present(done, animated: true)
            }
        })
        presenter.present(confirm, animated: true)
    }
}

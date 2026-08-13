import UIKit

/// Fullscreen host for the password-login hCaptcha WKWebView.
/// The WebView fills the remaining safe area so the image-grid challenge is tappable.
final class PasswordLoginCaptchaViewController: BaseViewController {
    override var backgroundStyle: BackgroundStyle { .grouped }

    var onClose: (() -> Void)?

    let webContainer: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        view.clipsToBounds = false
        return view
    }()

    private let statusLabel: UILabel = {
        let label = UILabel()
        label.font = FontManager.shared.font(size: 14)
        label.textColor = UIColor.secondaryLabel
        label.numberOfLines = 0
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let spinner: UIActivityIndicatorView = {
        let view = UIActivityIndicatorView(style: .medium)
        view.hidesWhenStopped = true
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    private var didAppear = false
    private var appearContinuation: CheckedContinuation<Void, Never>?

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "password_login.captcha.title")
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .close,
            target: self,
            action: #selector(closeTapped)
        )

        let statusRow = UIStackView(arrangedSubviews: [spinner, statusLabel])
        statusRow.axis = .horizontal
        statusRow.alignment = .center
        statusRow.spacing = 8
        statusRow.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(statusRow)
        view.addSubview(webContainer)

        NSLayoutConstraint.activate([
            statusRow.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            statusRow.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 20),
            statusRow.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -20),

            webContainer.topAnchor.constraint(equalTo: statusRow.bottomAnchor, constant: 8),
            webContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            webContainer.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
        ])

        applyCaptchaTheme()
        setStatus(String(localized: "password_login.status.captcha"), busy: true)
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        didAppear = true
        if let appearContinuation {
            self.appearContinuation = nil
            appearContinuation.resume()
        }
    }

    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        applyCaptchaTheme()
    }

    func waitUntilOnScreen() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            if didAppear {
                cont.resume()
            } else {
                appearContinuation = cont
            }
        }
    }

    func setStatus(_ text: String?, busy: Bool) {
        statusLabel.text = text
        if busy {
            spinner.startAnimating()
        } else {
            spinner.stopAnimating()
        }
    }

    private func applyCaptchaTheme() {
        let theme = ThemeManager.shared
        view.backgroundColor = theme.backgroundColor
        webContainer.backgroundColor = theme.cardBackgroundColor
        statusLabel.textColor = UIColor.secondaryLabel
        spinner.color = theme.accentColor
        navigationController?.navigationBar.tintColor = theme.accentColor
    }

    @objc private func closeTapped() {
        onClose?()
        dismiss(animated: true)
    }
}

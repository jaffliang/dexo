import UIKit
import WebKit

/// Polished password-login flow: credentials → Cloudflare (if needed) → visible hCaptcha → session.
final class PasswordLoginViewController: BaseViewController {
    override var backgroundStyle: BackgroundStyle { .grouped }

    var onFinished: ((Result<Void, Error>) -> Void)?

    private let forum: ForumInstance
    private let config: PasswordLoginConfig
    private let authManager = AuthManager.shared

    private enum Step {
        case form
        case captcha
        case working
    }

    private var step: Step = .form
    private var webSession: PasswordLoginWebSession?
    private var captchaWebHost: UIView?
    private var didRetryCF = false
    private var lastCaptchaToken: String?

    private let scrollView = UIScrollView()
    private let contentStack = UIStackView()

    private let titleLabel: UILabel = {
        let label = UILabel()
        label.text = String(localized: "password_login.title")
        label.font = FontManager.shared.font(size: 28, weight: .bold)
        label.textColor = UIColor.label
        label.numberOfLines = 0
        return label
    }()

    private let subtitleLabel: UILabel = {
        let label = UILabel()
        label.text = String(localized: "password_login.subtitle")
        label.font = FontManager.shared.font(size: 15)
        label.textColor = UIColor.secondaryLabel
        label.numberOfLines = 0
        return label
    }()

    private lazy var identifierField: UITextField = makeField(
        placeholder: String(localized: "password_login.identifier_placeholder"),
        secure: false
    )
    private lazy var passwordField: UITextField = makeField(
        placeholder: String(localized: "password_login.password_placeholder"),
        secure: true
    )

    private let primaryButton: UIButton = {
        var config = UIButton.Configuration.filled()
        config.title = String(localized: "password_login.continue")
        config.cornerStyle = .large
        config.baseBackgroundColor = ThemeManager.shared.accentColor
        config.baseForegroundColor = .white
        config.contentInsets = NSDirectionalEdgeInsets(top: 14, leading: 16, bottom: 14, trailing: 16)
        let button = UIButton(configuration: config)
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()

    private let statusLabel: UILabel = {
        let label = UILabel()
        label.font = FontManager.shared.font(size: 14)
        label.textColor = UIColor.secondaryLabel
        label.numberOfLines = 0
        label.textAlignment = .center
        return label
    }()

    private let errorLabel: UILabel = {
        let label = UILabel()
        label.font = FontManager.shared.font(size: 14)
        label.textColor = .systemRed
        label.numberOfLines = 0
        label.textAlignment = .center
        return label
    }()

    private let spinner = UIActivityIndicatorView(style: .medium)

    private let captchaContainer: UIView = {
        let view = UIView()
        view.backgroundColor = ThemeManager.shared.cardBackgroundColor
        view.layer.cornerRadius = 16
        view.layer.cornerCurve = .continuous
        view.clipsToBounds = true
        view.isHidden = true
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    init(forum: ForumInstance, config: PasswordLoginConfig) {
        self.forum = forum
        self.config = config
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "password_login.nav_title")
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel,
            target: self,
            action: #selector(closeTapped)
        )

        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.keyboardDismissMode = .interactive
        contentStack.axis = .vertical
        contentStack.spacing = 16
        contentStack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(scrollView)
        scrollView.addSubview(contentStack)

        [titleLabel, subtitleLabel, identifierField, passwordField, primaryButton, spinner, statusLabel, errorLabel, captchaContainer].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            contentStack.addArrangedSubview($0)
        }
        contentStack.setCustomSpacing(8, after: titleLabel)
        contentStack.setCustomSpacing(20, after: subtitleLabel)
        contentStack.setCustomSpacing(12, after: identifierField)
        contentStack.setCustomSpacing(20, after: passwordField)

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            contentStack.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 24),
            contentStack.leadingAnchor.constraint(equalTo: scrollView.frameLayoutGuide.leadingAnchor, constant: 20),
            contentStack.trailingAnchor.constraint(equalTo: scrollView.frameLayoutGuide.trailingAnchor, constant: -20),
            contentStack.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -32),

            identifierField.heightAnchor.constraint(equalToConstant: 48),
            passwordField.heightAnchor.constraint(equalToConstant: 48),
            captchaContainer.heightAnchor.constraint(greaterThanOrEqualToConstant: 180),
        ])

        primaryButton.addTarget(self, action: #selector(primaryTapped), for: .touchUpInside)
        passwordField.returnKeyType = .go
        passwordField.delegate = self
        identifierField.delegate = self
        spinner.hidesWhenStopped = true

        applyTheme()
    }

    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        applyTheme()
    }

    private func applyTheme() {
        titleLabel.textColor = UIColor.label
        subtitleLabel.textColor = UIColor.secondaryLabel
        statusLabel.textColor = UIColor.secondaryLabel
        captchaContainer.backgroundColor = ThemeManager.shared.cardBackgroundColor
        var config = primaryButton.configuration ?? .filled()
        config.baseBackgroundColor = ThemeManager.shared.accentColor
        primaryButton.configuration = config
        styleField(identifierField)
        styleField(passwordField)
    }

    private func makeField(placeholder: String, secure: Bool) -> UITextField {
        let tf = UITextField()
        tf.placeholder = placeholder
        tf.isSecureTextEntry = secure
        tf.autocapitalizationType = .none
        tf.autocorrectionType = .no
        tf.textContentType = secure ? .password : .username
        tf.borderStyle = .none
        tf.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 14, height: 1))
        tf.leftViewMode = .always
        tf.rightView = UIView(frame: CGRect(x: 0, y: 0, width: 14, height: 1))
        tf.rightViewMode = .always
        styleField(tf)
        return tf
    }

    private func styleField(_ tf: UITextField) {
        tf.backgroundColor = ThemeManager.shared.cardBackgroundColor
        tf.textColor = UIColor.label
        tf.font = FontManager.shared.font(size: 16)
        tf.layer.cornerRadius = 12
        tf.layer.cornerCurve = .continuous
        tf.layer.borderWidth = 1
        tf.layer.borderColor = UIColor.separator.withAlphaComponent(0.35).cgColor
    }

    @objc private func closeTapped() {
        webSession?.tearDown()
        webSession = nil
        onFinished?(.failure(PasswordLoginError.canceled))
        dismiss(animated: true)
    }

    @objc private func primaryTapped() {
        errorLabel.text = nil
        switch step {
        case .form:
            Task { await startFromForm() }
        case .captcha, .working:
            break
        }
    }

    private func setBusy(_ busy: Bool, status: String?) {
        primaryButton.isEnabled = !busy && step == .form
        identifierField.isEnabled = !busy && step == .form
        passwordField.isEnabled = !busy && step == .form
        statusLabel.text = status
        if busy { spinner.startAnimating() } else { spinner.stopAnimating() }
    }

    private func startFromForm() async {
        let identifier = identifierField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordField.text ?? ""
        guard !identifier.isEmpty, !password.isEmpty else {
            errorLabel.text = String(localized: "password_login.error.empty")
            return
        }
        view.endEditing(true)
        step = .working
        setBusy(true, status: String(localized: "password_login.status.cloudflare"))

        do {
            try await CloudflareClearanceGate.ensureClearance(for: forum, config: config, from: self)
            setBusy(true, status: String(localized: "password_login.status.captcha"))
            try await presentCaptchaAndLogin(identifier: identifier, password: password)
        } catch PasswordLoginError.canceled {
            step = .form
            setBusy(false, status: nil)
        } catch {
            step = .form
            setBusy(false, status: nil)
            errorLabel.text = (error as? LocalizedError)?.errorDescription
                ?? String(localized: "password_login.error.unknown")
            captchaContainer.isHidden = true
            webSession?.tearDown()
            webSession = nil
        }
    }

    private func presentCaptchaAndLogin(identifier: String, password: String) async throws {
        webSession?.tearDown()
        let session = PasswordLoginWebSession(forum: forum, config: config)
        webSession = session

        // Visible captcha surface
        captchaContainer.isHidden = false
        captchaContainer.subviews.forEach { $0.removeFromSuperview() }
        step = .captcha

        // Attach session's webview into captcha container by starting with self as presenter,
        // then reparent. Simpler: specialize session to accept a container.
        try await session.start(attachedTo: self, embedIn: captchaContainer)
        setBusy(true, status: String(localized: "password_login.status.captcha_wait"))

        let token = try await session.waitForCaptchaToken()
        lastCaptchaToken = token
        setBusy(true, status: String(localized: "password_login.status.signing_in"))
        try await completeLogin(
            session: session,
            identifier: identifier,
            password: password,
            captchaToken: token,
            secondFactor: nil
        )
    }

    private func completeLogin(
        session: PasswordLoginWebSession,
        identifier: String,
        password: String,
        captchaToken: String?,
        secondFactor: String?
    ) async throws {
        let result = try await session.runLogin(
            identifier: identifier,
            password: password,
            hCaptchaToken: captchaToken,
            secondFactorToken: secondFactor
        )

        switch result.phase {
        case "csrf" where result.status == 403 && !didRetryCF:
            didRetryCF = true
            setBusy(true, status: String(localized: "password_login.status.cloudflare_retry"))
            try await CloudflareClearanceGate.ensureClearance(
                for: forum,
                config: config,
                from: self,
                force: true
            )
            try await session.reprimeCookies()
            try await completeLogin(
                session: session,
                identifier: identifier,
                password: password,
                captchaToken: lastCaptchaToken,
                secondFactor: secondFactor
            )
            return
        case "csrf":
            throw PasswordLoginError.csrfBlocked
        case "hcaptcha":
            throw PasswordLoginError.captchaFailed
        case "session":
            if looksLikeSecondFactor(result.body), secondFactor == nil {
                let code = try await promptSecondFactor()
                try await completeLogin(
                    session: session,
                    identifier: identifier,
                    password: password,
                    captchaToken: nil,
                    secondFactor: code
                )
                return
            }
            if result.status == 200 {
                let exported = try await session.exportSessionCookies()
                try await authManager.loginViaWeb(
                    forum: forum,
                    cookies: exported.cookies,
                    userAgent: exported.userAgent
                )
                session.tearDown()
                webSession = nil
                onFinished?(.success(()))
                dismiss(animated: true)
                return
            }
            if result.status == 401 || result.status == 422 {
                throw PasswordLoginError.invalidCredentials
            }
            throw PasswordLoginError.unexpected(status: result.status, phase: result.phase, body: result.body)
        default:
            throw PasswordLoginError.unexpected(status: result.status, phase: result.phase, body: result.body)
        }
    }

    private func looksLikeSecondFactor(_ body: String) -> Bool {
        let lower = body.lowercased()
        return lower.contains("second_factor")
            || lower.contains("two_factor")
            || lower.contains("totp")
            || lower.contains("second factor")
    }

    private func promptSecondFactor() async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            let alert = UIAlertController(
                title: String(localized: "password_login.second_factor.title"),
                message: String(localized: "password_login.second_factor.message"),
                preferredStyle: .alert
            )
            alert.addTextField { tf in
                tf.keyboardType = .numberPad
                tf.placeholder = String(localized: "password_login.second_factor.placeholder")
                tf.textContentType = .oneTimeCode
            }
            alert.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel) { _ in
                cont.resume(throwing: PasswordLoginError.canceled)
            })
            alert.addAction(UIAlertAction(title: String(localized: "password_login.second_factor.continue"), style: .default) { _ in
                let code = alert.textFields?.first?.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                if code.isEmpty {
                    cont.resume(throwing: PasswordLoginError.secondFactorFailed)
                } else {
                    cont.resume(returning: code)
                }
            })
            present(alert, animated: true)
        }
    }
}

extension PasswordLoginViewController: UITextFieldDelegate {
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        if textField === identifierField {
            passwordField.becomeFirstResponder()
        } else {
            primaryTapped()
        }
        return true
    }
}

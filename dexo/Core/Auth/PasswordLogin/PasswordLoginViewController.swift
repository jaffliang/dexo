import UIKit

/// Polished password-login flow: credentials → Cloudflare (if needed) → fullscreen hCaptcha → session.
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
    private var captchaViewController: PasswordLoginCaptchaViewController?
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
        label.font = FontManager.shared.font(size: 15)
        label.textColor = UIColor.secondaryLabel
        label.numberOfLines = 0
        return label
    }()

    private lazy var identifierField: UITextField = makeField(
        placeholder: String(localized: "password_login.identifier_placeholder"),
        showsVisibilityToggle: false
    )
    private lazy var passwordField: UITextField = makeField(
        placeholder: String(localized: "password_login.password_placeholder"),
        showsVisibilityToggle: true
    )

    /// User chose to hide the password. Secure entry is applied only while the
    /// password field is first responder — a secure field anywhere in the
    /// window disables third-party IMEs on iOS 15, including the username field.
    private var passwordHiddenByUser = false

    private let passwordToggleButton: UIButton = {
        let button = UIButton(type: .system)
        let symbol = UIImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        button.setPreferredSymbolConfiguration(symbol, forImageIn: .normal)
        button.frame = CGRect(x: 0, y: 2, width: 40, height: 44)
        button.accessibilityTraits = .button
        return button
    }()

    private let rememberRow: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()

    private let rememberLabel: UILabel = {
        let label = UILabel()
        label.text = String(localized: "password_login.remember")
        label.font = FontManager.shared.font(size: 16)
        label.textColor = UIColor.label
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let rememberSwitch: UISwitch = {
        let toggle = UISwitch()
        toggle.isOn = true
        toggle.translatesAutoresizingMaskIntoConstraints = false
        return toggle
    }()

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

    private let debugBreadcrumbLabel: UILabel = {
        let label = UILabel()
        label.font = FontManager.shared.font(size: 12)
        label.textColor = UIColor.tertiaryLabel
        label.numberOfLines = 2
        label.textAlignment = .center
        label.isHidden = true
        label.isUserInteractionEnabled = true
        return label
    }()

    private let spinner = UIActivityIndicatorView(style: .medium)
    private var lastUnfinishedBreadcrumb: String?
    private var didOfferBreadcrumb = false

    init(forum: ForumInstance, config: PasswordLoginConfig) {
        self.forum = forum
        self.config = config
        super.init(nibName: nil, bundle: nil)
        subtitleLabel.text = String(localized: "password_login.subtitle \(config.subtitleHost(for: forum.baseURL))")
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

        configureRememberRow()

        [titleLabel, subtitleLabel, identifierField, passwordField, rememberRow, primaryButton, spinner, statusLabel, errorLabel, debugBreadcrumbLabel].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            contentStack.addArrangedSubview($0)
        }
        contentStack.setCustomSpacing(8, after: titleLabel)
        contentStack.setCustomSpacing(20, after: subtitleLabel)
        contentStack.setCustomSpacing(12, after: identifierField)
        contentStack.setCustomSpacing(12, after: passwordField)
        contentStack.setCustomSpacing(20, after: rememberRow)

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
            rememberRow.heightAnchor.constraint(greaterThanOrEqualToConstant: 48),
        ])

        primaryButton.addTarget(self, action: #selector(primaryTapped), for: .touchUpInside)
        passwordToggleButton.addTarget(self, action: #selector(togglePasswordVisibility), for: .touchUpInside)
        passwordField.returnKeyType = .go
        passwordField.delegate = self
        identifierField.delegate = self
        spinner.hidesWhenStopped = true
        updatePasswordToggleAppearance()

        debugBreadcrumbLabel.addGestureRecognizer(
            UITapGestureRecognizer(target: self, action: #selector(debugBreadcrumbTapped))
        )

        applyTheme()
        restoreRememberedCredentials()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        offerUnfinishedBreadcrumbIfNeeded()
    }

    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        applyTheme()
    }

    private func configureRememberRow() {
        rememberRow.addSubview(rememberLabel)
        rememberRow.addSubview(rememberSwitch)
        rememberSwitch.setContentCompressionResistancePriority(.required, for: .horizontal)
        NSLayoutConstraint.activate([
            rememberLabel.leadingAnchor.constraint(equalTo: rememberRow.leadingAnchor, constant: 14),
            rememberLabel.topAnchor.constraint(equalTo: rememberRow.topAnchor, constant: 12),
            rememberLabel.bottomAnchor.constraint(equalTo: rememberRow.bottomAnchor, constant: -12),
            rememberSwitch.leadingAnchor.constraint(greaterThanOrEqualTo: rememberLabel.trailingAnchor, constant: 12),
            rememberSwitch.trailingAnchor.constraint(equalTo: rememberRow.trailingAnchor, constant: -14),
            rememberSwitch.centerYAnchor.constraint(equalTo: rememberRow.centerYAnchor),
        ])
    }

    private func applyTheme() {
        let theme = ThemeManager.shared
        titleLabel.textColor = UIColor.label
        subtitleLabel.textColor = UIColor.secondaryLabel
        statusLabel.textColor = UIColor.secondaryLabel
        debugBreadcrumbLabel.textColor = UIColor.tertiaryLabel
        rememberLabel.textColor = UIColor.label
        rememberRow.backgroundColor = theme.cardBackgroundColor
        rememberRow.layer.cornerRadius = 12
        rememberRow.layer.cornerCurve = .continuous
        rememberRow.layer.borderWidth = 1
        rememberRow.layer.borderColor = UIColor.separator.withAlphaComponent(0.35).cgColor
        rememberSwitch.onTintColor = theme.accentColor
        passwordToggleButton.tintColor = UIColor.secondaryLabel
        var config = primaryButton.configuration ?? .filled()
        config.baseBackgroundColor = theme.accentColor
        primaryButton.configuration = config
        styleField(identifierField)
        styleField(passwordField)
    }

    private func makeField(placeholder: String, showsVisibilityToggle: Bool) -> UITextField {
        let tf = UITextField()
        tf.placeholder = placeholder
        // Visible by default. iOS 15 disables third-party keyboards for the
        // whole form if any field in the window is secure.
        tf.isSecureTextEntry = false
        tf.borderStyle = .none
        tf.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 14, height: 1))
        tf.leftViewMode = .always
        configureLoginFieldKeyboard(tf)
        if showsVisibilityToggle {
            let container = UIView(frame: CGRect(x: 0, y: 0, width: 44, height: 48))
            container.addSubview(passwordToggleButton)
            tf.rightView = container
        } else {
            tf.rightView = UIView(frame: CGRect(x: 0, y: 0, width: 14, height: 1))
        }
        tf.rightViewMode = .always
        styleField(tf)
        return tf
    }

    private func configureLoginFieldKeyboard(_ tf: UITextField) {
        tf.autocapitalizationType = .none
        tf.autocorrectionType = .no
        tf.spellCheckingType = .no
        // `.username` / `.password` / `.oneTimeCode` (and asciiCapable) pull
        // the system autofill keyboard and block third-party IMEs such as Sogou.
        tf.keyboardType = .default
        tf.textContentType = nil
        tf.passwordRules = nil
    }

    @objc private func togglePasswordVisibility() {
        passwordHiddenByUser.toggle()
        let wasFirstResponder = passwordField.isFirstResponder
        if wasFirstResponder {
            passwordField.resignFirstResponder()
        }
        passwordField.isSecureTextEntry = wasFirstResponder && passwordHiddenByUser
        configureLoginFieldKeyboard(passwordField)
        styleField(passwordField)
        updatePasswordToggleAppearance()
        if wasFirstResponder {
            passwordField.becomeFirstResponder()
        }
    }

    private func updatePasswordToggleAppearance() {
        let hidden = passwordHiddenByUser
        let name = hidden ? "eye" : "eye.slash"
        passwordToggleButton.setImage(UIImage(systemName: name), for: .normal)
        passwordToggleButton.accessibilityLabel = String(
            localized: hidden ? "password_login.show_password" : "password_login.hide_password"
        )
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

    private var forumBaseURL: String {
        forum.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private func restoreRememberedCredentials() {
        let remember = PasswordLoginCredentialStore.rememberEnabled(for: forumBaseURL)
        rememberSwitch.isOn = remember
        guard remember, let stored = PasswordLoginCredentialStore.load(for: forumBaseURL) else { return }
        identifierField.text = stored.identifier
        passwordField.text = stored.password
    }

    /// Saves or clears credentials as soon as Continue is tapped, even if login later fails.
    private func persistRememberPreference(identifier: String, password: String) {
        if rememberSwitch.isOn {
            PasswordLoginCredentialStore.setRememberEnabled(true, for: forumBaseURL)
            try? PasswordLoginCredentialStore.save(identifier: identifier, password: password, for: forumBaseURL)
        } else {
            PasswordLoginCredentialStore.setRememberEnabled(false, for: forumBaseURL)
            PasswordLoginCredentialStore.delete(for: forumBaseURL)
        }
    }

    @objc private func closeTapped() {
        PasswordLoginCrashBreadcrumb.finishCanceled()
        webSession?.tearDown()
        webSession = nil
        onFinished?(.failure(PasswordLoginError.canceled))
        dismissLoginFlow()
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
        passwordToggleButton.isEnabled = !busy && step == .form
        rememberSwitch.isEnabled = !busy && step == .form
        statusLabel.text = status
        if busy { spinner.startAnimating() } else { spinner.stopAnimating() }
        captchaViewController?.setStatus(status, busy: busy)
    }

    private func startFromForm() async {
        let identifier = identifierField.text?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let password = passwordField.text ?? ""
        guard !identifier.isEmpty, !password.isEmpty else {
            errorLabel.text = String(localized: "password_login.error.empty")
            return
        }
        persistRememberPreference(identifier: identifier, password: password)
        view.endEditing(true)
        PasswordLoginCrashBreadcrumb.beginFlow()
        step = .working
        setBusy(true, status: String(localized: "password_login.status.cloudflare"))

        do {
            try await presentCaptchaAndLogin(identifier: identifier, password: password)
        } catch PasswordLoginError.canceled {
            PasswordLoginCrashBreadcrumb.finishCanceled()
            await dismissCaptchaIfNeeded()
            step = .form
            setBusy(false, status: nil)
            webSession?.tearDown()
            webSession = nil
        } catch {
            PasswordLoginCrashBreadcrumb.recordError(error)
            LastFatalExceptionStore.recordLoginFailure(error)
            await dismissCaptchaIfNeeded()
            step = .form
            setBusy(false, status: nil)
            errorLabel.text = PasswordLoginError.displayMessage(for: error)
            showCopyHint(isFatalException: LastFatalExceptionStore.peekReport().map(LastFatalExceptionStore.isFatalExceptionReport) ?? false)
            LastFatalExceptionPresenter.presentIfNeeded(from: self)
            webSession?.tearDown()
            webSession = nil
        }
    }

    private func presentCaptchaAndLogin(identifier: String, password: String) async throws {
        webSession?.tearDown()
        let session = PasswordLoginWebSession(forum: forum, config: config)
        webSession = session

        let captchaVC = PasswordLoginCaptchaViewController()
        captchaVC.onClose = { [weak self] in
            PasswordLoginCrashBreadcrumb.finishCanceled()
            self?.webSession?.tearDown()
        }
        captchaViewController = captchaVC
        step = .captcha

        let nav = UINavigationController(rootViewController: captchaVC)
        nav.modalPresentationStyle = .overFullScreen
        nav.modalPresentationCapturesStatusBarAppearance = true
        nav.isModalInPresentation = true
        nav.view.backgroundColor = ThemeManager.shared.backgroundColor
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            present(nav, animated: true) { cont.resume() }
        }
        PasswordLoginCrashBreadcrumb.record(.captchaPresented)
        await captchaVC.waitUntilOnScreen()
        captchaVC.view.layoutIfNeeded()

        do {
            try await session.start(attachedTo: captchaVC, embedIn: captchaVC.webContainer)
            if let challengeURL = config.challengeURL {
                let hasClearance = await session.hasClearanceCookie()
                if !hasClearance {
                    setBusy(true, status: String(localized: "password_login.status.cloudflare"))
                    try await session.runInPlaceCloudflareChallenge(url: challengeURL)
                }
            }
            setBusy(true, status: String(localized: "password_login.status.captcha"))
            try await session.loadCaptchaPage()
            setBusy(true, status: String(localized: "password_login.status.captcha_wait"))

            let token = try await session.waitForCaptchaToken()
            lastCaptchaToken = token
            setBusy(true, status: String(localized: "password_login.status.signing_in"))
            // Let WebKit finish unwinding onPass / popup close before login JS.
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                DispatchQueue.main.async { cont.resume() }
            }
            try await completeLogin(
                session: session,
                identifier: identifier,
                password: password,
                captchaToken: token,
                secondFactor: nil
            )
        } catch {
            await dismissCaptchaIfNeeded()
            throw error
        }
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
        case "csrf" where PasswordLoginSessionResponse.shouldRetryCloudflareChallenge(
            phase: result.phase,
            status: result.status
        ) && !didRetryCF:
            didRetryCF = true
            setBusy(true, status: String(localized: "password_login.status.cloudflare_retry"))
            guard let challengeURL = config.challengeURL else {
                throw PasswordLoginError.unexpected(
                    status: result.status,
                    phase: result.phase,
                    body: result.body
                )
            }
            try await session.runInPlaceCloudflareChallenge(url: challengeURL)
            try await completeLogin(
                session: session,
                identifier: identifier,
                password: password,
                captchaToken: lastCaptchaToken,
                secondFactor: secondFactor
            )
            return
        case "csrf", "hcaptcha", "exception":
            throw PasswordLoginError.unexpected(
                status: result.status,
                phase: result.phase,
                body: result.body
            )
        case "session":
            switch PasswordLoginSessionResponse.interpret(status: result.status, body: result.body) {
            case .needsSecondFactor where secondFactor == nil:
                let code = try await promptSecondFactor()
                try await completeLogin(
                    session: session,
                    identifier: identifier,
                    password: password,
                    captchaToken: nil,
                    secondFactor: code
                )
                return
            case .needsSecondFactor:
                throw PasswordLoginError.secondFactorFailed
            case .invalidCredentials:
                throw PasswordLoginError.invalidCredentials
            case .signedIn:
                let exported = try await session.exportSessionCookies()
                PasswordLoginCrashBreadcrumb.record(.loginViaWeb)
                try await authManager.loginViaWeb(
                    forum: forum,
                    cookies: exported.cookies,
                    userAgent: exported.userAgent
                )
                PasswordLoginCrashBreadcrumb.finishSuccess()
                session.tearDown()
                webSession = nil
                onFinished?(.success(()))
                dismissLoginFlow()
                return
            case .failed(let status, let body):
                throw PasswordLoginError.unexpected(status: status, phase: result.phase, body: body)
            }
        default:
            throw PasswordLoginError.unexpected(status: result.status, phase: result.phase, body: result.body)
        }
    }

    private func promptSecondFactor() async throws -> String {
        let presenter = presentedViewController ?? self
        return try await withCheckedThrowingContinuation { cont in
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
            presenter.present(alert, animated: true)
        }
    }

    private func offerUnfinishedBreadcrumbIfNeeded() {
        if LastFatalExceptionStore.peekReport() != nil {
            // Do not consume/wipe the trail or crash file before the copy UI.
            let fatal = LastFatalExceptionStore.peekReport().map(LastFatalExceptionStore.isFatalExceptionReport) ?? false
            showCopyHint(isFatalException: fatal)
            DispatchQueue.main.async { [weak self] in
                LastFatalExceptionPresenter.presentIfNeeded(from: self)
            }
            return
        }
        if !didOfferBreadcrumb, let trail = PasswordLoginCrashBreadcrumb.consumeUnfinishedTrail() {
            didOfferBreadcrumb = true
            lastUnfinishedBreadcrumb = trail
            debugBreadcrumbLabel.text = String(localized: "password_login.debug.breadcrumb_hint")
            debugBreadcrumbLabel.isHidden = false
            return
        }
        if lastUnfinishedBreadcrumb != nil {
            debugBreadcrumbLabel.text = String(localized: "password_login.debug.breadcrumb_hint")
            debugBreadcrumbLabel.isHidden = false
        }
    }

    private func showCopyHint(isFatalException: Bool) {
        didOfferBreadcrumb = true
        debugBreadcrumbLabel.text = String(
            localized: isFatalException
                ? "password_login.debug.exception_hint"
                : "password_login.debug.copy_hint"
        )
        debugBreadcrumbLabel.isHidden = false
    }

    @objc private func debugBreadcrumbTapped() {
        LastFatalExceptionPresenter.copyToPasteboardAndConfirm(from: self)
        debugBreadcrumbLabel.text = String(localized: "post.raw.copied")
        debugBreadcrumbLabel.isHidden = false
    }

    private func dismissCaptchaIfNeeded() async {
        defer { captchaViewController = nil }
        guard let captcha = captchaViewController else { return }
        let presented = captcha.navigationController ?? captcha
        guard presented.presentingViewController != nil, !presented.isBeingDismissed else { return }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            do {
                try DexoExceptionCatcher.runCatching {
                    presented.dismiss(animated: true) {
                        cont.resume()
                    }
                }
            } catch {
                PasswordLoginCrashBreadcrumb.record(
                    .objcException,
                    detail: "dismissCaptcha \(PasswordLoginCrashBreadcrumb.shortError(error))"
                )
                cont.resume()
            }
        }
    }

    /// Dismisses captcha + the password-login sheet from the original presenter.
    private func dismissLoginFlow() {
        captchaViewController = nil
        let presenter = navigationController?.presentingViewController ?? presentingViewController
        do {
            try DexoExceptionCatcher.runCatching {
                if let presenter {
                    presenter.dismiss(animated: true)
                } else {
                    self.dismiss(animated: true)
                }
            }
        } catch {
            PasswordLoginCrashBreadcrumb.record(
                .objcException,
                detail: "dismissLogin \(PasswordLoginCrashBreadcrumb.shortError(error))"
            )
        }
    }
}

extension PasswordLoginViewController: UITextFieldDelegate {
    func textFieldShouldBeginEditing(_ textField: UITextField) -> Bool {
        if textField === passwordField {
            passwordField.isSecureTextEntry = passwordHiddenByUser
            configureLoginFieldKeyboard(passwordField)
        } else {
            passwordField.isSecureTextEntry = false
            configureLoginFieldKeyboard(passwordField)
        }
        updatePasswordToggleAppearance()
        return true
    }

    func textFieldDidEndEditing(_ textField: UITextField) {
        if textField === passwordField {
            passwordField.isSecureTextEntry = false
            configureLoginFieldKeyboard(passwordField)
        }
        updatePasswordToggleAppearance()
    }

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        if textField === identifierField {
            passwordField.becomeFirstResponder()
        } else {
            primaryTapped()
        }
        return true
    }
}

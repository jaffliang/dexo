import UIKit
import WebKit

extension UIViewController {
    /// Presents the shared Cloudflare challenge prompt and opens this forum's
    /// interstitial page when the user chooses to continue.
    func presentChallengePrompt(
        title: String = String(localized: "challenge.prompt.title"),
        message: String = String(localized: "challenge.prompt.message"),
        actionTitle: String = String(localized: "me.challenge"),
        challengeURL: URL
    ) {
        let alert = UIAlertController(
            title: title,
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: actionTitle, style: .default) { [weak self] _ in
            guard let self else { return }
            ChallengeViewController.present(from: self, challengeURL: challengeURL)
        })
        present(alert, animated: true)
    }

    /// If `error` indicates the request was intercepted by Cloudflare's
    /// challenge, prompts the user to pass it. Returns true if the prompt was
    /// shown, so callers can suppress generic error alerts on that path.
    ///
    /// Each linux.do-family host has its own interstitial URL. Never send an
    /// idcflare user to `linux.do/challenge` — that wouldn't refresh their
    /// cookies, and idcflare's `/challenge` is 404.
    @discardableResult
    func presentChallengePromptIfNeeded(error: Error, on api: DiscourseAPI) -> Bool {
        guard api.isLinuxDoFamily,
              let challengeURL = ForumPolicy.cloudflareInterstitialURL(for: api.baseURL)
        else { return false }
        guard (error as? DiscourseAPIError)?.isChallengeRequired == true else {
            return false
        }
        presentChallengePrompt(challengeURL: challengeURL)
        return true
    }
}

/// Presents this forum's Cloudflare interstitial in a WKWebView seeded with
/// the user's existing web-login cookies. Cookie changes are synced immediately,
/// with a final sync on every dismissal path, so subsequent API requests use
/// the refreshed session even when the challenge completes without a navigation.
final class ChallengeViewController: BaseViewController {
    private let targetURL: URL
    private let userAgent: String?

    private var webView: WKWebView?
    private var proxyLease: AnyObject?
    private var setupTask: Task<Void, Never>?
    private var isFinalCookieSyncInProgress = false
    private var isObservingCookieChanges = false
    private var waitContinuation: CheckedContinuation<Void, Never>?
    private var didResumeWait = false
    private var presentationDelegate: ChallengePresentationDelegate?

    private func makeWebViewConfiguration() async throws -> (WKWebViewConfiguration, AnyObject?) {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WebCookieStore.shared.websiteDataStore
        config.preferences.javaScriptCanOpenWindowsAutomatically = true

        let darkModeCSS = WKUserScript(
            source: "document.documentElement.style.colorScheme = 'light dark';",
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        config.userContentController.addUserScript(darkModeCSS)
        // Keep the shared store; replacing it with `.default()` would split
        // TLS/JA3 from password-login fetches that reuse this jar.
        let lease = try await WebViewDoHConfigurator.configurePreservingDataStore(config)
        return (config, lease)
    }

    private lazy var coordinator = Coordinator(
        onNavigationFinished: { [weak self] in
            self?.hideLoadError()
            self?.syncCookies()
        },
        onNavigationFailed: { [weak self] error in
            self?.showLoadError(error)
        }
    )

    private lazy var progressView: UIProgressView = {
        let pv = UIProgressView(progressViewStyle: .bar)
        pv.translatesAutoresizingMaskIntoConstraints = false
        return pv
    }()

    private lazy var loadErrorView: UIView = {
        let container = UIView()
        container.translatesAutoresizingMaskIntoConstraints = false
        container.isHidden = true

        let stack = UIStackView(arrangedSubviews: [loadErrorLabel, retryButton])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -24),
            stack.centerYAnchor.constraint(equalTo: container.centerYAnchor),
        ])
        return container
    }()

    private lazy var loadErrorLabel: UILabel = {
        let label = UILabel()
        label.font = FontManager.shared.font(size: 15)
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private lazy var retryButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle(String(localized: "action.retry"), for: .normal)
        button.addTarget(self, action: #selector(retryTapped), for: .touchUpInside)
        return button
    }()

    private var progressObservation: NSKeyValueObservation?
    private var persistLoadErrorUntilRetry = false

    init(targetURL: URL, userAgent: String?) {
        self.targetURL = targetURL
        self.userAgent = userAgent
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "challenge.title")

        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped)
        )
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            title: String(localized: "challenge.done"), style: .done, target: self, action: #selector(doneTapped)
        )
        navigationItem.rightBarButtonItem?.isEnabled = false

        view.addSubview(progressView)
        view.addSubview(loadErrorView)
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            loadErrorView.topAnchor.constraint(equalTo: progressView.bottomAnchor),
            loadErrorView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            loadErrorView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            loadErrorView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        applyChallengeTheme()

        setupTask = Task { [weak self] in
            await self?.setUpWebView()
        }
    }

    private func setUpWebView() async {
        do {
            let (configuration, lease) = try await makeWebViewConfiguration()
            guard !Task.isCancelled else { return }

            proxyLease = lease
            let webView = WKWebView(frame: .zero, configuration: configuration)
            webView.navigationDelegate = coordinator
            webView.uiDelegate = coordinator
            webView.isOpaque = false
            webView.backgroundColor = ThemeManager.shared.backgroundColor
            if let userAgent {
                webView.customUserAgent = userAgent
            }
            webView.translatesAutoresizingMaskIntoConstraints = false
            self.webView = webView

            view.insertSubview(webView, belowSubview: progressView)
            NSLayoutConstraint.activate([
                webView.topAnchor.constraint(equalTo: progressView.bottomAnchor),
                webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            ])

            progressObservation = webView.observe(\.estimatedProgress, options: .new) { [weak self] webView, _ in
                self?.progressView.progress = Float(webView.estimatedProgress)
                self?.progressView.isHidden = webView.estimatedProgress >= 1.0
            }
            navigationItem.rightBarButtonItem?.isEnabled = true

            // Stale cf_clearance makes Cloudflare skip the widget and leave
            // the session blocked. Drop it from the native jar and this
            // WebView's store before loading /challenge.
            WebCookieStore.shared.removeClearanceCookies(matching: targetURL)
            await WebCookieStore.shared.removeClearanceCookies(
                from: webView.configuration.websiteDataStore,
                matching: targetURL
            )
            await seedCookies(in: webView)
            guard !Task.isCancelled else { return }
            webView.configuration.websiteDataStore.httpCookieStore.add(coordinator)
            isObservingCookieChanges = true
            hideLoadError()
            if let warning = WebViewDoHConfigurator.attachWarning(from: lease) {
                persistLoadErrorUntilRetry = true
                showLoadError(warning)
            }
            webView.load(URLRequest(url: targetURL))
        } catch {
            guard !Task.isCancelled else { return }
            showProxyUnavailableAlert(error)
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        applyChallengeTheme()
    }

    private func applyChallengeTheme() {
        let theme = ThemeManager.shared
        view.backgroundColor = theme.backgroundColor
        loadErrorView.backgroundColor = theme.backgroundColor
        loadErrorLabel.textColor = UIColor.secondaryLabel
        retryButton.tintColor = theme.accentColor
        webView?.backgroundColor = theme.backgroundColor
        navigationController?.navigationBar.tintColor = theme.accentColor
    }

    private func showProxyUnavailableAlert(_ error: Error) {
        let alert = UIAlertController(
            title: String(localized: "doh.proxy.error.title"),
            message: WebViewDoHProxyDiagnostics.alertMessage(for: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default) { [weak self] _ in
            self?.dismiss(animated: true)
        })
        present(alert, animated: true)
    }

    @MainActor
    private func seedCookies(in webView: WKWebView) async {
        // The native MITM proxy keeps the original HTTPS URL, so WebKit still
        // owns the real-origin cookie jar. Seed the existing login and
        // Cloudflare state in both direct and proxied modes.
        let cookies = WebCookieStore.shared.cookies(for: targetURL)
        let store = webView.configuration.websiteDataStore.httpCookieStore
        for cookie in cookies {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                store.setCookie(cookie) { cont.resume() }
            }
        }
    }

    private func syncCookies() {
        Task { @MainActor in
            await syncWebSession()
        }
    }

    @MainActor
    private func syncWebSession() async {
        guard let webView else { return }
        await WebCookieStore.shared.syncFromWebView(
            webView.configuration.websiteDataStore,
            for: targetURL
        )

        // Cloudflare clearance can be tied to the browser User-Agent. Keep
        // the API request consistent with the WKWebView that passed the
        // challenge, including the first add-forum probe before login state
        // has been persisted.
        if let evaluatedUserAgent = try? await webView.evaluateJavaScript("navigator.userAgent") as? String,
           !evaluatedUserAgent.isEmpty
        {
            WebCookieStore.shared.userAgent = evaluatedUserAgent
        }
    }

    @objc private func retryTapped() {
        persistLoadErrorUntilRetry = false
        hideLoadError()
        webView?.load(URLRequest(url: targetURL))
    }

    fileprivate func showLoadError(_ error: Error) {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorCancelled {
            return
        }
        loadErrorLabel.text = String(
            format: String(localized: "challenge.load_failed.message %@"),
            WebViewDoHProxyDiagnostics.detail(for: error)
        )
        loadErrorView.isHidden = false
        view.bringSubviewToFront(loadErrorView)
        applyChallengeTheme()
    }

    private func hideLoadError() {
        if persistLoadErrorUntilRetry { return }
        loadErrorView.isHidden = true
    }

    @objc private func cancelTapped() {
        setupTask?.cancel()
        syncAndDismiss()
    }

    @objc private func doneTapped() {
        syncAndDismiss()
    }

    private func syncAndDismiss() {
        guard !isFinalCookieSyncInProgress else { return }
        isFinalCookieSyncInProgress = true
        Task { @MainActor in
            await syncWebSession()
            dismiss(animated: true) { [weak self] in
                self?.resumeWaitIfNeeded()
            }
        }
    }

    private func resumeWaitIfNeeded() {
        guard let waitContinuation, !didResumeWait else { return }
        didResumeWait = true
        self.waitContinuation = nil
        presentationDelegate = nil
        waitContinuation.resume()
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        // Also cover an interactive sheet dismissal. Keep a strong Task
        // capture until WebKit has returned its latest cookie snapshot.
        if !isFinalCookieSyncInProgress,
           isBeingDismissed || navigationController?.isBeingDismissed == true
        {
            syncCookies()
        }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if view.window == nil, isObservingCookieChanges {
            webView?.configuration.websiteDataStore.httpCookieStore.remove(coordinator)
            isObservingCookieChanges = false
        }
        // Swipe-to-dismiss / interactive sheet paths may not go through
        // syncAndDismiss's completion handler; still unblock awaiters.
        if view.window == nil,
           isBeingDismissed || navigationController?.isBeingDismissed == true || presentingViewController == nil
        {
            resumeWaitIfNeeded()
        }
    }

    /// Convenience for presenting the challenge flow from any view controller.
    static func present(from presenter: UIViewController, challengeURL: URL) {
        let vc = ChallengeViewController(targetURL: challengeURL, userAgent: WebCookieStore.shared.userAgent)
        let nav = UINavigationController(rootViewController: vc)
        nav.modalPresentationStyle = .pageSheet
        if let sheet = nav.sheetPresentationController {
            sheet.detents = [.large()]
            sheet.prefersGrabberVisible = true
        }
        presenter.present(nav, animated: true)
    }

    /// Presents the challenge sheet and suspends until it is dismissed
    /// (Done, Cancel, or interactive swipe). Cookies are synced on the
    /// existing dismissal paths before this returns in the common case.
    ///
    /// Pass `prefersFullScreen` when the presenter is already a sheet (e.g.
    /// password login) so the WebView is not cramped inside a nested card.
    @MainActor
    static func presentAndWait(
        from presenter: UIViewController,
        challengeURL: URL,
        prefersFullScreen: Bool = false
    ) async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let vc = ChallengeViewController(
                targetURL: challengeURL,
                userAgent: WebCookieStore.shared.userAgent
            )
            vc.waitContinuation = cont
            let nav = UINavigationController(rootViewController: vc)
            if prefersFullScreen {
                nav.modalPresentationStyle = .overFullScreen
                nav.modalPresentationCapturesStatusBarAppearance = true
                nav.view.backgroundColor = ThemeManager.shared.backgroundColor
            } else {
                nav.modalPresentationStyle = .pageSheet
                if let sheet = nav.sheetPresentationController {
                    sheet.detents = [.large()]
                    sheet.prefersGrabberVisible = true
                }
            }
            let delegate = ChallengePresentationDelegate { [weak vc] in
                vc?.resumeWaitIfNeeded()
            }
            vc.presentationDelegate = delegate
            nav.presentationController?.delegate = delegate
            presenter.present(nav, animated: true)
        }
    }

    /// Bridges interactive page-sheet dismissal into `presentAndWait`.
    private final class ChallengePresentationDelegate: NSObject, UIAdaptivePresentationControllerDelegate {
        private let onDismiss: () -> Void

        init(onDismiss: @escaping () -> Void) {
            self.onDismiss = onDismiss
        }

        func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
            onDismiss()
        }
    }

    private final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKHTTPCookieStoreObserver {
        private let onNavigationFinished: () -> Void
        private let onNavigationFailed: (Error) -> Void
        private var trustEvaluator: WebViewProxyTrustEvaluator?

        init(
            onNavigationFinished: @escaping () -> Void,
            onNavigationFailed: @escaping (Error) -> Void
        ) {
            self.onNavigationFinished = onNavigationFinished
            self.onNavigationFailed = onNavigationFailed
        }

        func webView(
            _ webView: WKWebView,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            if trustEvaluator == nil {
                trustEvaluator = WebViewDoHConfigurator.makeTrustEvaluator()
            }
            if let credential = trustEvaluator?.credential(for: challenge) {
                #if DEBUG
                print("[WebViewDoHProxy] Challenge accepted proxy CA for \(challenge.protectionSpace.host)")
                #endif
                completionHandler(.useCredential, credential)
                return
            }
            completionHandler(.performDefaultHandling, nil)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            onNavigationFinished()
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            onNavigationFailed(error)
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            onNavigationFailed(error)
        }

        func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
            onNavigationFinished()
        }

        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView?
        {
            if navigationAction.targetFrame == nil {
                webView.load(navigationAction.request)
            }
            return nil
        }
    }
}

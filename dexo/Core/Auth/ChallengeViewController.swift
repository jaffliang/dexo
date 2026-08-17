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
        // iOS 17+: isolated CONNECT store. iOS 15/16: shared jar, Safari TLS.
        // Never put a proxy on the shared cookie jar or `.default()`.
        let lease = await WebViewDoHConfigurator.attachIsolatedConnectStore(config)
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

    private lazy var attachErrorBanner: UILabel = {
        let label = UILabel()
        label.font = FontManager.shared.font(size: 13)
        label.textAlignment = .left
        label.numberOfLines = 0
        label.isHidden = true
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private var progressObservation: NSKeyValueObservation?

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
        view.addSubview(attachErrorBanner)
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            attachErrorBanner.topAnchor.constraint(equalTo: progressView.bottomAnchor, constant: 8),
            attachErrorBanner.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            attachErrorBanner.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
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
            coordinator.loadProbe = WebViewDoHLoadProbe(lease: lease)
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
            view.bringSubviewToFront(attachErrorBanner)

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
            if let warning = WebViewDoHConfigurator.legacyAttachWarning(from: lease) {
                showAttachWarning(warning)
                return
            }
            webView.load(URLRequest(url: targetURL))
        } catch {
            guard !Task.isCancelled else { return }
            showProxyUnavailableAlert()
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        applyChallengeTheme()
    }

    private func applyChallengeTheme() {
        let theme = ThemeManager.shared
        view.backgroundColor = theme.backgroundColor
        attachErrorBanner.textColor = UIColor.secondaryLabel
        attachErrorBanner.backgroundColor = theme.backgroundColor
        webView?.backgroundColor = theme.backgroundColor
        navigationController?.navigationBar.tintColor = theme.accentColor
    }

    private func showProxyUnavailableAlert() {
        let alert = UIAlertController(
            title: String(localized: "doh.proxy.error.title"),
            message: String(localized: "doh.proxy.error.message"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default) { [weak self] _ in
            self?.dismiss(animated: true)
        })
        present(alert, animated: true)
    }

    @MainActor
    private func seedCookies(in webView: WKWebView) async {
        // iOS 15 uses the shared jar (no WebView proxy). iOS 17 uses the
        // isolated CONNECT store after cookies are copied over.
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

    private func showAttachWarning(_ error: Error) {
        attachErrorBanner.text = String(
            format: String(localized: "challenge.doh_attach_failed.message %@"),
            WebViewChallengeDoHDiagnostics.detail(for: error)
        )
        attachErrorBanner.isHidden = false
        view.bringSubviewToFront(attachErrorBanner)
        applyChallengeTheme()
    }

    fileprivate func showLoadError(_ error: Error) {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorCancelled {
            return
        }
        attachErrorBanner.text = String(
            format: String(localized: "challenge.load_failed.message %@"),
            WebViewChallengeDoHDiagnostics.detail(for: error, probe: coordinator.loadProbe)
        )
        attachErrorBanner.isHidden = false
        view.bringSubviewToFront(attachErrorBanner)
        applyChallengeTheme()
    }

    private func hideLoadError() {
        if WebViewDoHConfigurator.legacyAttachWarning(from: proxyLease) != nil {
            return
        }
        attachErrorBanner.isHidden = true
    }

    private func releaseChallengeDoHSession() {
        (proxyLease as? WebViewLegacyChallengeSession)?.release()
        proxyLease = nil
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
            releaseChallengeDoHSession()
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
        if view.window == nil,
           isBeingDismissed || navigationController?.isBeingDismissed == true || presentingViewController == nil
        {
            releaseChallengeDoHSession()
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

    private nonisolated final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKHTTPCookieStoreObserver, @unchecked Sendable {
        private let onNavigationFinished: () -> Void
        private let onNavigationFailed: (Error) -> Void
        private var trustEvaluator: WebViewProxyTrustEvaluator?
        var loadProbe: WebViewDoHLoadProbe?

        init(
            onNavigationFinished: @escaping () -> Void,
            onNavigationFailed: @escaping (Error) -> Void
        ) {
            self.onNavigationFinished = onNavigationFinished
            self.onNavigationFailed = onNavigationFailed
            self.trustEvaluator = WebViewDoHConfigurator.makeTrustEvaluator()
        }

        func webView(
            _ webView: WKWebView,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
                loadProbe?.markDidReceiveServerTrust()
            }
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
            DispatchQueue.main.async { [onNavigationFinished] in
                onNavigationFinished()
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            DispatchQueue.main.async { [onNavigationFailed] in
                onNavigationFailed(error)
            }
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            DispatchQueue.main.async { [onNavigationFailed] in
                onNavigationFailed(error)
            }
        }

        func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
            DispatchQueue.main.async { [onNavigationFinished] in
                onNavigationFinished()
            }
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

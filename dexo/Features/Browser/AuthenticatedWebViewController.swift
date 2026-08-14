import UIKit
import WebKit

/// In-app browser that reuses the login/Cloudflare `WKWebsiteDataStore` and
/// primes Discourse session cookies before load.
final class AuthenticatedWebViewController: BaseViewController {
    private let initialURL: URL
    private var webView: WKWebView?
    private var popupWebViews: [WKWebView] = []
    private var dismissedPopupIDs: Set<ObjectIdentifier> = []
    private var proxyLease: AnyObject?
    private var setupTask: Task<Void, Never>?
    private var progressObservation: NSKeyValueObservation?
    private var coordinator: Coordinator?
    /// Canonical URLs already loaded by a `/login` bypass, to stop OAuth loops.
    fileprivate var bypassedLoginLoads: Set<String> = []

    private lazy var progressView: UIProgressView = {
        let progressView = UIProgressView(progressViewStyle: .bar)
        progressView.translatesAutoresizingMaskIntoConstraints = false
        return progressView
    }()

    private lazy var backItem = UIBarButtonItem(
        image: UIImage(systemName: "chevron.backward"),
        style: .plain,
        target: self,
        action: #selector(backTapped)
    )

    private lazy var shareItem = UIBarButtonItem(
        barButtonSystemItem: .action,
        target: self,
        action: #selector(shareTapped)
    )

    private lazy var copyCookiesItem = UIBarButtonItem(
        title: String(localized: "browser.copy_cookies"),
        style: .plain,
        target: self,
        action: #selector(copyCookiesTapped)
    )

    init(url: URL) {
        initialURL = url
        super.init(nibName: nil, bundle: nil)
        hidesBottomBarWhenPushed = true
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    static func present(_ url: URL, from presenter: UIViewController) {
        let viewController = AuthenticatedWebViewController(url: url)
        let navigation = UINavigationController(rootViewController: viewController)
        navigation.modalPresentationStyle = .pageSheet
        if let sheet = navigation.sheetPresentationController {
            sheet.detents = [.large()]
            sheet.prefersGrabberVisible = true
        }
        presenter.present(navigation, animated: true)
    }

    static func promptAndPresent(from presenter: UIViewController, defaultURL: URL?) {
        let fallback = WebCookieStore.shared.cookieEditorExportURLFromJar()
            .flatMap { ForumPolicy.defaultInAppBrowserURL(for: $0.absoluteString) }
            ?? URL(string: "https://cdk.linux.do/")
        let alert = UIAlertController(
            title: String(localized: "me.open_web"),
            message: String(localized: "me.open_web.prompt"),
            preferredStyle: .alert
        )
        alert.addTextField { textField in
            textField.keyboardType = .URL
            textField.autocapitalizationType = .none
            textField.autocorrectionType = .no
            textField.text = defaultURL?.absoluteString ?? fallback?.absoluteString
        }
        alert.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: String(localized: "action.open"), style: .default) { _ in
            let raw = alert.textFields?.first?.text ?? ""
            DispatchQueue.main.async {
                guard let url = normalizedWebURL(from: raw) else {
                    let invalid = UIAlertController(
                        title: String(localized: "add_forum.error.invalid_url"),
                        message: nil,
                        preferredStyle: .alert
                    )
                    invalid.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default))
                    presenter.present(invalid, animated: true)
                    return
                }
                ExternalLinkOpener.openTypedURL(url, from: presenter)
            }
        })
        presenter.present(alert, animated: true)
    }

    static func normalizedWebURL(from input: String) -> URL? {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return nil }
        let lowercaseValue = value.lowercased()
        if !lowercaseValue.hasPrefix("http://") && !lowercaseValue.hasPrefix("https://") {
            guard !value.contains("://") else { return nil }
            value = "https://" + value
        }
        guard let components = URLComponents(string: value),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = components.host,
              !host.isEmpty,
              let url = components.url
        else { return nil }
        return url
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "browser.title")
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .close,
            target: self,
            action: #selector(closeTapped)
        )
        navigationController?.isToolbarHidden = false
        backItem.isEnabled = false
        backItem.accessibilityLabel = String(localized: "browser.back")
        shareItem.accessibilityLabel = String(localized: "browser.share")
        copyCookiesItem.accessibilityLabel = String(localized: "browser.copy_cookies")
        toolbarItems = [
            backItem,
            UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil),
            copyCookiesItem,
            UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil),
            shareItem,
        ]

        view.addSubview(progressView)
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])

        setupTask = Task { [weak self] in
            await self?.setUpWebView()
        }
    }

    override func applyThemeBackground() {
        super.applyThemeBackground()
        let theme = ThemeManager.shared
        progressView.progressTintColor = theme.accentColor
        navigationController?.toolbar.tintColor = theme.accentColor
        navigationController?.navigationBar.tintColor = theme.accentColor
        webView?.backgroundColor = theme.cardBackgroundColor
        webView?.underPageBackgroundColor = theme.cardBackgroundColor
        for popup in popupWebViews {
            popup.backgroundColor = theme.cardBackgroundColor
            popup.underPageBackgroundColor = theme.cardBackgroundColor
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if isBeingDismissed || navigationController?.isBeingDismissed == true {
            syncCookies()
        }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if isMovingFromParent || presentingViewController == nil {
            setupTask?.cancel()
            webView?.stopLoading()
        }
    }

    private func setUpWebView() async {
        do {
            let configuration = WKWebViewConfiguration()
            configuration.websiteDataStore = WebCookieStore.shared.websiteDataStore
            configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
            let lease = try await WebViewDoHConfigurator.configurePreservingDataStore(configuration)
            guard !Task.isCancelled else { return }

            proxyLease = lease
            let coordinator = Coordinator(owner: self)
            self.coordinator = coordinator

            let webView = WKWebView(frame: .zero, configuration: configuration)
            webView.navigationDelegate = coordinator
            webView.uiDelegate = coordinator
            webView.isOpaque = false
            webView.backgroundColor = ThemeManager.shared.cardBackgroundColor
            if let userAgent = WebCookieStore.safariCompatibleUserAgent(WebCookieStore.shared.userAgent) {
                webView.customUserAgent = userAgent
            }
            webView.translatesAutoresizingMaskIntoConstraints = false
            self.webView = webView

            view.insertSubview(webView, belowSubview: progressView)
            NSLayoutConstraint.activate([
                webView.topAnchor.constraint(equalTo: progressView.bottomAnchor),
                webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
                webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
                webView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            ])

            progressObservation = webView.observe(\.estimatedProgress, options: .new) { [weak self] webView, _ in
                let progress = Float(webView.estimatedProgress)
                self?.progressView.progress = progress
                self?.progressView.isHidden = progress >= 1
            }

            await WebCookieStore.shared.primeToWebView(
                webView.configuration.websiteDataStore,
                for: initialURL
            )
            guard !Task.isCancelled else { return }
            applyThemeBackground()
            webView.load(URLRequest(url: initialURL))
            updateBackItem()
        } catch {
            guard !Task.isCancelled else { return }
            showProxyUnavailableAlert(error)
        }
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

    fileprivate func attachPopup(_ popup: WKWebView, over parent: WKWebView) {
        let id = ObjectIdentifier(popup)
        guard !dismissedPopupIDs.contains(id) else { return }
        popup.customUserAgent = parent.customUserAgent
        popup.isOpaque = false
        popup.backgroundColor = ThemeManager.shared.cardBackgroundColor
        let host: UIView = parent.superview ?? view
        host.addSubview(popup)
        popup.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            popup.topAnchor.constraint(equalTo: host.topAnchor),
            popup.leadingAnchor.constraint(equalTo: host.leadingAnchor),
            popup.trailingAnchor.constraint(equalTo: host.trailingAnchor),
            popup.bottomAnchor.constraint(equalTo: host.bottomAnchor),
        ])
        popupWebViews.append(popup)
        updateBackItem()
    }

    fileprivate func dismissPopup(_ webView: WKWebView) {
        dismissedPopupIDs.insert(ObjectIdentifier(webView))
        guard let index = popupWebViews.firstIndex(of: webView) else { return }
        popupWebViews.remove(at: index)
        webView.uiDelegate = nil
        webView.navigationDelegate = nil
        webView.removeFromSuperview()
        updateBackItem()
    }

    fileprivate func handleNavigationFinished(in webView: WKWebView) {
        if webView.url != nil {
            title = webView.title?.nilIfEmpty ?? String(localized: "browser.title")
        }
        updateBackItem()
        syncCookies(for: webView.url ?? initialURL)
    }

    fileprivate func handleLoginIntercept(
        _ url: URL,
        in webView: WKWebView,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard WebCookieStore.shared.hasAuthTokenCookie(for: url),
              let replacement = LinuxDoLoginIntercept.replacementURL(
                for: url,
                previouslyLoaded: bypassedLoginLoads
              ),
              LinuxDoLoginIntercept.canonicalKey(replacement) != LinuxDoLoginIntercept.canonicalKey(url)
        else {
            decisionHandler(.allow)
            return
        }
        bypassedLoginLoads.insert(LinuxDoLoginIntercept.canonicalKey(replacement))
        decisionHandler(.cancel)
        webView.load(URLRequest(url: replacement))
    }

    private func syncCookies(for url: URL? = nil) {
        let target = url ?? webView?.url ?? initialURL
        Task { @MainActor in
            await WebCookieStore.shared.syncFromWebView(
                webView?.configuration.websiteDataStore ?? WebCookieStore.shared.websiteDataStore,
                for: target
            )
        }
    }

    private func updateBackItem() {
        backItem.isEnabled = !popupWebViews.isEmpty || (webView?.canGoBack ?? false)
    }

    @objc private func closeTapped() {
        setupTask?.cancel()
        syncCookies()
        dismiss(animated: true)
    }

    @objc private func backTapped() {
        if let popup = popupWebViews.last {
            dismissPopup(popup)
            return
        }
        webView?.goBack()
    }

    @objc private func shareTapped() {
        let url = webView?.url ?? initialURL
        let openSafari = UIAlertAction(
            title: String(localized: "browser.open_in_safari"),
            style: .default
        ) { _ in
            UIApplication.shared.open(url)
        }
        let share = UIAlertAction(
            title: String(localized: "browser.share"),
            style: .default
        ) { [weak self] _ in
            guard let self else { return }
            let activity = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            activity.popoverPresentationController?.barButtonItem = self.shareItem
            self.present(activity, animated: true)
        }
        let sheet = UIAlertController(title: nil, message: nil, preferredStyle: .actionSheet)
        sheet.addAction(share)
        sheet.addAction(openSafari)
        sheet.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        sheet.popoverPresentationController?.barButtonItem = shareItem
        present(sheet, animated: true)
    }

    @objc private func copyCookiesTapped() {
        CookieExportPresenter.confirmAndCopy(from: self, url: webView?.url ?? initialURL)
    }
}

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

/// WebKit delivers UI/navigation callbacks off the main actor on iOS 15.
/// `createWebViewWith` must return a WKWebView synchronously.
private nonisolated final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, @unchecked Sendable {
    weak var owner: AuthenticatedWebViewController?
    private var trustEvaluator: WebViewProxyTrustEvaluator?

    init(owner: AuthenticatedWebViewController) {
        self.owner = owner
        super.init()
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
            completionHandler(.useCredential, credential)
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        DispatchQueue.main.async { [weak self] in
            self?.owner?.handleNavigationFinished(in: webView)
        }
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url,
              LinuxDoLoginIntercept.looksLikeLoginPath(url)
        else {
            decisionHandler(.allow)
            return
        }
        DispatchQueue.main.async { [weak self] in
            guard let owner = self?.owner else {
                decisionHandler(.allow)
                return
            }
            owner.handleLoginIntercept(url, in: webView, decisionHandler: decisionHandler)
        }
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        guard navigationAction.targetFrame == nil else { return nil }
        let popup = WKWebView(frame: .zero, configuration: configuration)
        popup.uiDelegate = self
        popup.navigationDelegate = self
        DispatchQueue.main.async { [weak self] in
            self?.owner?.attachPopup(popup, over: webView)
        }
        return popup
    }

    func webViewDidClose(_ webView: WKWebView) {
        DispatchQueue.main.async { [weak self] in
            self?.owner?.dismissPopup(webView)
        }
    }
}

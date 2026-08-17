@preconcurrency import WebKit
import UIKit

nonisolated struct PasswordLoginBridgeResult: Sendable {
    let phase: String
    let status: Int
    let body: String
}

/// Parsed `webkit.messageHandlers` payload. Built off the main actor so
/// `WKScriptMessage.body` (`Any`) never crosses isolation.
nonisolated enum PasswordLoginScriptMessage: Sendable {
    case ready
    case captchaToken(String)
    case captchaError
    case login(PasswordLoginBridgeResult)
    case loginParseError(String)
    case ignored

    static func parse(name: String, body: Any) -> PasswordLoginScriptMessage {
        switch name {
        case "dexoPasswordLoginReady":
            return .ready
        case "dexoPasswordLoginCaptcha":
            return parseCaptcha(body)
        case "dexoPasswordLogin":
            return parseLogin(body)
        default:
            return .ignored
        }
    }

    private static func dictionary(from body: Any) -> [String: Any]? {
        if let dict = body as? [String: Any] {
            return dict
        }
        if let string = body as? String,
           let data = string.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return obj
        }
        return nil
    }

    private static func parseCaptcha(_ body: Any) -> PasswordLoginScriptMessage {
        if let dict = dictionary(from: body) {
            if let error = dict["error"] as? String, !error.isEmpty {
                return .captchaError
            }
            if let token = dict["token"] as? String, !token.isEmpty {
                return .captchaToken(token)
            }
            return .captchaError
        }
        if let string = body as? String, !string.isEmpty {
            return .captchaToken(string)
        }
        return .captchaError
    }

    private static func parseLogin(_ body: Any) -> PasswordLoginScriptMessage {
        guard let dict = dictionary(from: body) else {
            return .loginParseError("\(body)")
        }
        let phase = dict["phase"] as? String ?? "unknown"
        let status: Int
        if let intStatus = dict["status"] as? Int {
            status = intStatus
        } else if let number = dict["status"] as? NSNumber {
            status = number.intValue
        } else {
            status = 0
        }
        let resultBody = dict["body"] as? String ?? ""
        return .login(PasswordLoginBridgeResult(phase: phase, status: status, body: resultBody))
    }
}

/// WebKit delivers `WKScriptMessageHandler` callbacks off the main actor.
/// This type stays `nonisolated` and hops onto MainActor before touching session state.
private nonisolated final class PasswordLoginScriptBridge: NSObject, WKScriptMessageHandler, @unchecked Sendable {
    weak var session: PasswordLoginWebSession?

    init(session: PasswordLoginWebSession) {
        self.session = session
        super.init()
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        let parsed = PasswordLoginScriptMessage.parse(name: message.name, body: message.body)
        // Hop with GCD, not Task: Jeff's iOS 15.6.1 abort was during
        // `completeTaskWithClosure` → Foundation `__iop_setName_block_invoke`.
        DispatchQueue.main.async { [weak session] in
            session?.handleScriptMessageSafely(parsed)
        }
    }
}

/// WebKit delivers `WKUIDelegate` / `WKNavigationDelegate` callbacks off the main
/// actor on iOS 15. `createWebViewWith` must return a `WKWebView` synchronously;
/// a MainActor-isolated session cannot hop without deadlock/crash.
private nonisolated final class PasswordLoginWebViewDelegateBridge: NSObject, WKUIDelegate, WKNavigationDelegate, @unchecked Sendable {
    weak var session: PasswordLoginWebSession?
    /// During in-place CF interstitial, `window.open` must stay in this WebView
    /// (same kernel as `cf_clearance`), not spawn an hCaptcha-style popup.
    var isChallengeMode = false
    private var trustEvaluator: WebViewProxyTrustEvaluator?

    init(session: PasswordLoginWebSession) {
        self.session = session
        super.init()
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        guard navigationAction.targetFrame == nil else { return nil }
        if isChallengeMode {
            webView.load(navigationAction.request)
            return nil
        }
        // Must construct with WebKit's configuration on this thread and return
        // immediately. Do not hop to MainActor before the return.
        let popup = WKWebView(frame: .zero, configuration: configuration)
        // uiDelegate only: navigationDelegate on a WebKit-provided popup config
        // can recurse (and crash) on iOS 15 hCaptcha window.open.
        popup.uiDelegate = self
        PasswordLoginCrashBreadcrumb.record(.popupCreate)
        DispatchQueue.main.async { [weak session] in
            session?.attachPopupSafely(popup, over: webView)
        }
        return popup
    }

    func webViewDidClose(_ webView: WKWebView) {
        PasswordLoginCrashBreadcrumb.record(.popupClose)
        // Never tear down synchronously; Check often closes the popup in the
        // same turn as onPass.
        DispatchQueue.main.async { [weak session] in
            session?.dismissPopupSafely(webView)
        }
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
        DispatchQueue.main.async { [weak session] in
            session?.handleNavigationFinished()
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        DispatchQueue.main.async { [weak session] in
            session?.handleNavigationFailure(error)
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        DispatchQueue.main.async { [weak session] in
            session?.handleNavigationFailure(error)
        }
    }
}

/// WKWebView session for Cloudflare interstitial + hCaptcha only.
/// csrf / hCaptcha create / session.json run on URLSession (`PasswordLoginAPIClient`).
@MainActor
final class PasswordLoginWebSession {
    private let forum: ForumInstance
    private let config: PasswordLoginConfig
    private let baseURL: URL

    private var webView: WKWebView?
    private var popupWebViews: [WKWebView] = []
    private var dismissedPopupIDs: Set<ObjectIdentifier> = []
    private var hostController: UIViewController?
    private var scriptBridge: PasswordLoginScriptBridge?
    private var webDelegate: PasswordLoginWebViewDelegateBridge?
    private var resultContinuation: CheckedContinuation<PasswordLoginBridgeResult, Error>?
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var captchaContinuation: CheckedContinuation<String, Error>?
    private var pendingCaptchaToken: String?
    private var readyTimeoutTask: Task<Void, Never>?
    private var challengeContinuation: CheckedContinuation<Void, Error>?
    private var clearancePollTask: Task<Void, Never>?
    private var navigationContinuation: CheckedContinuation<Void, Error>?
    private var originTimeoutTask: Task<Void, Never>?
    private var challengeDoHSession: AnyObject?

    init(forum: ForumInstance, config: PasswordLoginConfig) {
        self.forum = forum
        self.config = config
        let trimmed = forum.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        self.baseURL = URL(string: trimmed) ?? URL(string: "https://\(config.host)")!
    }

    func start(attachedTo presenter: UIViewController, embedIn container: UIView) async throws {
        let wkConfig = WKWebViewConfiguration()
        wkConfig.websiteDataStore = WebCookieStore.shared.websiteDataStore
        wkConfig.preferences.javaScriptCanOpenWindowsAutomatically = true
        // Isolated CONNECT store: forum hosts MITM+ECH, Turnstile/hCaptcha
        // stay a raw Safari TLS tunnel. Never skip DoH on iOS 17.
        challengeDoHSession = await WebViewDoHConfigurator.attachIsolatedConnectStore(wkConfig)
        let controller = wkConfig.userContentController
        let bridge = PasswordLoginScriptBridge(session: self)
        scriptBridge = bridge
        controller.add(bridge, name: "dexoPasswordLogin")
        controller.add(bridge, name: "dexoPasswordLoginReady")
        controller.add(bridge, name: "dexoPasswordLoginCaptcha")
        controller.addUserScript(WKUserScript(
            source: "document.documentElement.style.colorScheme = 'light dark';",
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        ))
        // Keep `__dexoPasswordLogin` injected for protocol tests. Login itself
        // uses URLSession; this script is not invoked from completeLogin.
        controller.addUserScript(WKUserScript(
            source: Self.loginJavaScript(config: config),
            injectionTime: .atDocumentEnd,
            forMainFrameOnly: true
        ))

        let webDelegate = PasswordLoginWebViewDelegateBridge(session: self)
        self.webDelegate = webDelegate

        let webView = WKWebView(frame: .zero, configuration: wkConfig)
        webView.navigationDelegate = webDelegate
        webView.uiDelegate = webDelegate
        webView.isOpaque = false
        webView.backgroundColor = ThemeManager.shared.cardBackgroundColor
        webView.scrollView.isScrollEnabled = true
        webView.scrollView.bounces = true
        webView.scrollView.keyboardDismissMode = .interactive
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webView.isUserInteractionEnabled = true
        if let ua = WebCookieStore.shared.userAgent {
            webView.customUserAgent = ua
        }

        container.subviews.forEach { $0.removeFromSuperview() }
        container.addSubview(webView)
        webView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: container.topAnchor),
            webView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])

        self.webView = webView
        self.hostController = presenter
        await WebCookieStore.shared.primeToWebView(
            webView.configuration.websiteDataStore,
            for: baseURL
        )
    }

    func loadCaptchaPage() async throws {
        guard let webView else {
            throw PasswordLoginError.unexpected(status: 0, phase: "captcha", body: "no webview")
        }
        webDelegate?.isChallengeMode = false
        // loadHTMLString with only a baseURL is an opaque origin on WebKit;
        // hCaptcha then rejects the sitekey. Prime with a real same-origin
        // navigation first (this forum's robots.txt), then inject captcha HTML.
        try await navigateToSameOrigin()
        let hint = String(localized: "password_login.captcha_hint")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            self.readyContinuation = cont
            webView.loadHTMLString(
                Self.makeHTML(siteKey: config.hCaptchaSiteKey, captchaHint: hint),
                baseURL: baseURL
            )
            readyTimeoutTask?.cancel()
            readyTimeoutTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 25_000_000_000)
                guard !Task.isCancelled else { return }
                self?.takeReadyContinuation()?.resume(throwing: PasswordLoginError.captchaFailed)
            }
        }
    }

    /// Real `https://{forum-host}/robots.txt` navigation so the document origin
    /// matches this forum (linux.do or idcflare.com — never a hardcoded host)
    /// before captcha HTML is injected. Wait for `didFinish`, not just `load()`.
    func navigateToSameOrigin() async throws {
        guard let webView else {
            throw PasswordLoginError.unexpected(status: 0, phase: "origin", body: "no webview")
        }
        let url = Self.originPrimeURL(for: baseURL)
        PasswordLoginCrashBreadcrumb.record(.originPrime, detail: url.host.map { "\($0)\(url.path)" } ?? url.path)
        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                self.navigationContinuation = cont
                webView.load(URLRequest(url: url))
                originTimeoutTask?.cancel()
                originTimeoutTask = Task { [weak self] in
                    try? await Task.sleep(nanoseconds: 25_000_000_000)
                    guard !Task.isCancelled else { return }
                    self?.takeNavigationContinuation()?.resume(
                        throwing: PasswordLoginError.unexpected(
                            status: 0,
                            phase: "origin",
                            body: "same-origin navigation timed out"
                        )
                    )
                }
            }
        } catch {
            originTimeoutTask?.cancel()
            originTimeoutTask = nil
            throw error
        }
        originTimeoutTask?.cancel()
        originTimeoutTask = nil
    }

    /// Same-origin prime URL for this forum host. Never points idcflare at linux.do.
    nonisolated static func originPrimeURL(for baseURL: URL) -> URL {
        var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) ?? URLComponents()
        components.path = "/robots.txt"
        components.query = nil
        components.fragment = nil
        return components.url ?? baseURL.appendingPathComponent("robots.txt")
    }

    func hasClearanceCookie() async -> Bool {
        guard let webView, let host = baseURL.host else { return false }
        let cookies = await WebCookieStore.shared.exportCookies(
            from: webView.configuration.websiteDataStore,
            matchingHost: host
        )
        return cookies.contains { $0.name == "cf_clearance" }
    }

    /// Loads this forum's Cloudflare interstitial in this session's WKWebView.
    /// On iOS 15 with DoH, traffic uses the URLProtocol gateway. `cf_clearance`
    /// is copied to the native jar before URLSession csrf / session.json.
    /// Does not present a second `ChallengeViewController`. linux.do uses
    /// `/challenge`; idcflare uses `/login` because `/challenge` is 404.
    func runInPlaceCloudflareChallenge(url: URL) async throws {
        guard let webView else {
            throw PasswordLoginError.unexpected(status: 0, phase: "cloudflare", body: "no webview")
        }
        PasswordLoginCrashBreadcrumb.record(.cloudflareInPlace)
        readyTimeoutTask?.cancel()
        readyTimeoutTask = nil
        takeReadyContinuation()?.resume()

        webDelegate?.isChallengeMode = true
        WebCookieStore.shared.removeClearanceCookies(matching: url)
        await WebCookieStore.shared.removeClearanceCookies(
            from: webView.configuration.websiteDataStore,
            matching: url
        )

        if let captchaHost = hostController as? PasswordLoginCaptchaViewController {
            captchaHost.setChallengeMode(true)
            captchaHost.onChallengeDone = { [weak self] in
                self?.completeInPlaceChallengeFromUser()
            }
        }

        defer {
            webDelegate?.isChallengeMode = false
            clearancePollTask?.cancel()
            clearancePollTask = nil
            if let captchaHost = hostController as? PasswordLoginCaptchaViewController {
                captchaHost.onChallengeDone = nil
                captchaHost.setChallengeMode(false)
            }
        }

        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                self.challengeContinuation = cont
                webView.load(URLRequest(url: url))
                clearancePollTask?.cancel()
                clearancePollTask = Task { [weak self] in
                    while !Task.isCancelled {
                        try? await Task.sleep(nanoseconds: 500_000_000)
                        guard !Task.isCancelled else { return }
                        await self?.finishInPlaceChallengeIfCleared()
                    }
                }
            }
        } catch {
            if case PasswordLoginError.canceled = error {
                throw error
            }
            throw error
        }

        dismissAllPopups()
        await syncWebSessionToNativeJar()
        guard await hasClearanceCookie() else {
            throw PasswordLoginError.cloudflareFailed
        }
    }

    func completeInPlaceChallengeFromUser() {
        Task { await self.finishInPlaceChallengeIfCleared(force: true) }
    }

    func runLogin(
        identifier: String,
        password: String,
        hCaptchaToken: String?,
        secondFactorToken: String?
    ) async throws -> PasswordLoginBridgeResult {
        guard let webView else { throw PasswordLoginError.unexpected(status: 0, phase: "session", body: "no webview") }
        let idJS = Self.jsString(identifier)
        let pwJS = Self.jsString(password)
        let captchaJS = hCaptchaToken.map(Self.jsString) ?? "null"
        let totpJS = secondFactorToken.map(Self.jsString) ?? "null"
        // Fire-and-forget only. Do not evaluate the async function source here:
        // iOS 15 cannot bridge a Promise (`执行JavaScript返回结果的类型不受支持`).
        // That WKError is not CSRF — `__dexoPasswordLogin` is a WKUserScript and
        // reports via dexoPasswordLogin. A separate evaluate fix voids the Promise.
        let script = PasswordLoginJavaScriptEvaluate.invocationScript(
            identifierJS: idJS,
            passwordJS: pwJS,
            captchaJS: captchaJS,
            totpJS: totpJS
        )
        PasswordLoginCrashBreadcrumb.record(.loginJsStart)
        if resultContinuation != nil {
            throw PasswordLoginError.unexpected(status: 0, phase: "evaluate", body: "login already in flight")
        }
        do {
            return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<PasswordLoginBridgeResult, Error>) in
                self.resultContinuation = cont
                DexoExceptionCatcher.evaluateJavaScript(script, in: webView) { [weak self] _, error in
                    guard let error else { return }
                    // Promise-bridge false failure on iOS 15. Not Cloudflare/CSRF;
                    // keep waiting for dexoPasswordLogin.
                    if PasswordLoginJavaScriptEvaluate.isUnsupportedResultType(error) {
                        return
                    }
                    DispatchQueue.main.async { [weak self] in
                        let wrapped = PasswordLoginError.unexpected(
                            status: 0,
                            phase: "evaluate",
                            body: PasswordLoginCrashBreadcrumb.exceptionDiagnostic(error)
                        )
                        PasswordLoginCrashBreadcrumb.record(
                            .loginJsResult,
                            detail: PasswordLoginCrashBreadcrumb.shortError(wrapped)
                        )
                        self?.takeResultContinuation()?.resume(throwing: wrapped)
                    }
                }
            }
        } catch {
            if case PasswordLoginError.canceled = error {
                throw error
            }
            PasswordLoginCrashBreadcrumb.recordError(error)
            throw error
        }
    }

    /// Waits for the first hCaptcha token from the embedded widget.
    func waitForCaptchaToken() async throws -> String {
        if let pendingCaptchaToken {
            self.pendingCaptchaToken = nil
            return pendingCaptchaToken
        }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            self.captchaContinuation = cont
        }
    }

    func exportSessionCookies() async throws -> (cookies: [HTTPCookie], userAgent: String?) {
        guard let webView, let host = baseURL.host else {
            throw PasswordLoginError.missingSessionCookie
        }
        let cookies = await WebCookieStore.shared.exportCookies(
            from: webView.configuration.websiteDataStore,
            matchingHost: host
        )
        PasswordLoginCrashBreadcrumb.record(.exportCookies, detail: "count=\(cookies.count)")
        guard cookies.contains(where: { $0.name == "_t" }) else {
            throw PasswordLoginError.missingSessionCookie
        }
        let ua = webView.customUserAgent ?? WebCookieStore.shared.userAgent
        return (cookies, ua)
    }

    func tearDown() {
        PasswordLoginCrashBreadcrumb.record(.teardown)
        (challengeDoHSession as? WebViewLegacyChallengeSession)?.release()
        challengeDoHSession = nil
        readyTimeoutTask?.cancel()
        readyTimeoutTask = nil
        clearancePollTask?.cancel()
        clearancePollTask = nil
        originTimeoutTask?.cancel()
        originTimeoutTask = nil
        // Drop native callbacks first so an in-flight script message becomes a no-op.
        scriptBridge?.session = nil
        webDelegate?.session = nil
        let webView = self.webView
        let popups = popupWebViews
        popupWebViews.removeAll()
        dismissedPopupIDs.formUnion(popups.map(ObjectIdentifier.init))
        self.webView = nil
        hostController = nil
        pendingCaptchaToken = nil
        let scriptBridge = self.scriptBridge
        let webDelegate = self.webDelegate
        self.scriptBridge = nil
        self.webDelegate = nil
        takeReadyContinuation()?.resume(throwing: PasswordLoginError.canceled)
        takeResultContinuation()?.resume(throwing: PasswordLoginError.canceled)
        takeCaptchaContinuation()?.resume(throwing: PasswordLoginError.canceled)
        takeChallengeContinuation()?.resume(throwing: PasswordLoginError.canceled)
        takeNavigationContinuation()?.resume(throwing: PasswordLoginError.canceled)
        // Keep bridges alive until handlers are removed on the next turn.
        DispatchQueue.main.async {
            do {
                try DexoExceptionCatcher.runCatching {
                    for popup in popups {
                        popup.uiDelegate = nil
                        popup.removeFromSuperview()
                    }
                    if let webView {
                        webView.navigationDelegate = nil
                        webView.uiDelegate = nil
                        webView.removeFromSuperview()
                        let controller = webView.configuration.userContentController
                        controller.removeScriptMessageHandler(forName: "dexoPasswordLogin")
                        controller.removeScriptMessageHandler(forName: "dexoPasswordLoginReady")
                        controller.removeScriptMessageHandler(forName: "dexoPasswordLoginCaptcha")
                    }
                }
            } catch {
                PasswordLoginCrashBreadcrumb.record(
                    .objcException,
                    detail: "deferredTeardown \(PasswordLoginCrashBreadcrumb.shortError(error))"
                )
            }
            _ = scriptBridge
            _ = webDelegate
        }
    }

    fileprivate func handleScriptMessageSafely(_ message: PasswordLoginScriptMessage) {
        catching("handleScriptMessage") {
            self.handleScriptMessage(message)
        }
    }

    fileprivate func handleScriptMessage(_ message: PasswordLoginScriptMessage) {
        switch message {
        case .ready:
            readyTimeoutTask?.cancel()
            readyTimeoutTask = nil
            takeReadyContinuation()?.resume()
        case .captchaToken(let token):
            PasswordLoginCrashBreadcrumb.record(
                .captchaToken,
                detail: PasswordLoginCrashBreadcrumb.redactToken(token)
            )
            // Queue popup teardown for the next turn BEFORE resuming login, and
            // never touch the parent captcha WKWebView here.
            DispatchQueue.main.async { [weak self] in
                self?.dismissAllPopups()
            }
            if let continuation = takeCaptchaContinuation() {
                continuation.resume(returning: token)
            } else {
                pendingCaptchaToken = token
            }
        case .captchaError:
            PasswordLoginCrashBreadcrumb.record(.captchaError)
            takeCaptchaContinuation()?.resume(throwing: PasswordLoginError.captchaFailed)
        case .login(let result):
            PasswordLoginCrashBreadcrumb.record(
                .loginJsResult,
                detail: "phase=\(result.phase) status=\(result.status)"
            )
            takeResultContinuation()?.resume(returning: result)
        case .loginParseError(let raw):
            let wrapped = PasswordLoginError.unexpected(status: 0, phase: "parse", body: raw)
            PasswordLoginCrashBreadcrumb.record(
                .loginJsResult,
                detail: PasswordLoginCrashBreadcrumb.shortError(wrapped)
            )
            takeResultContinuation()?.resume(throwing: wrapped)
        case .ignored:
            break
        }
    }

    private func takeReadyContinuation() -> CheckedContinuation<Void, Error>? {
        let pending = readyContinuation
        readyContinuation = nil
        return pending
    }

    private func takeResultContinuation() -> CheckedContinuation<PasswordLoginBridgeResult, Error>? {
        let pending = resultContinuation
        resultContinuation = nil
        return pending
    }

    private func takeCaptchaContinuation() -> CheckedContinuation<String, Error>? {
        let pending = captchaContinuation
        captchaContinuation = nil
        return pending
    }

    private func takeChallengeContinuation() -> CheckedContinuation<Void, Error>? {
        let pending = challengeContinuation
        challengeContinuation = nil
        return pending
    }

    private func takeNavigationContinuation() -> CheckedContinuation<Void, Error>? {
        let pending = navigationContinuation
        navigationContinuation = nil
        return pending
    }

    fileprivate func handleNavigationFinished() {
        originTimeoutTask?.cancel()
        originTimeoutTask = nil
        takeNavigationContinuation()?.resume()
    }

    fileprivate func handleNavigationFailure(_ error: Error) {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorCancelled {
            return
        }
        originTimeoutTask?.cancel()
        originTimeoutTask = nil
        if navigationContinuation != nil {
            takeNavigationContinuation()?.resume(
                throwing: PasswordLoginError.unexpected(
                    status: 0,
                    phase: "origin",
                    body: error.localizedDescription
                )
            )
            return
        }
        guard challengeContinuation != nil else { return }
        takeChallengeContinuation()?.resume(
            throwing: PasswordLoginError.unexpected(
                status: 0,
                phase: "cloudflare",
                body: error.localizedDescription
            )
        )
    }

    fileprivate func finishInPlaceChallengeIfCleared(force: Bool = false) async {
        guard challengeContinuation != nil else { return }
        if force {
            takeChallengeContinuation()?.resume()
            return
        }
        guard await hasClearanceCookie() else { return }
        takeChallengeContinuation()?.resume()
    }

    func syncWebSessionToNativeJar() async {
        guard let webView else { return }
        await WebCookieStore.shared.syncFromWebView(
            webView.configuration.websiteDataStore,
            for: baseURL
        )
        if let evaluatedUserAgent = try? await webView.evaluateJavaScript("navigator.userAgent") as? String,
           !evaluatedUserAgent.isEmpty
        {
            WebCookieStore.shared.userAgent = evaluatedUserAgent
            webView.customUserAgent = evaluatedUserAgent
        }
    }

    fileprivate func attachPopupSafely(_ popup: WKWebView, over parent: WKWebView) {
        catching("attachPopup") {
            self.attachPopup(popup, over: parent)
        }
    }

    fileprivate func dismissPopupSafely(_ webView: WKWebView) {
        catching("dismissPopup") {
            self.dismissPopup(webView)
        }
    }

    fileprivate func attachPopup(_ popup: WKWebView, over parent: WKWebView) {
        let id = ObjectIdentifier(popup)
        guard !dismissedPopupIDs.contains(id) else { return }
        popup.customUserAgent = parent.customUserAgent
        popup.isOpaque = false
        popup.backgroundColor = ThemeManager.shared.cardBackgroundColor
        popup.scrollView.keyboardDismissMode = .interactive
        popup.scrollView.contentInsetAdjustmentBehavior = .never

        let host = parent.superview ?? hostController?.view ?? parent
        host.addSubview(popup)
        popup.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            popup.topAnchor.constraint(equalTo: host.topAnchor),
            popup.leadingAnchor.constraint(equalTo: host.leadingAnchor),
            popup.trailingAnchor.constraint(equalTo: host.trailingAnchor),
            popup.bottomAnchor.constraint(equalTo: host.bottomAnchor),
        ])
        popupWebViews.append(popup)
    }

    fileprivate func dismissPopup(_ webView: WKWebView) {
        dismissedPopupIDs.insert(ObjectIdentifier(webView))
        guard let index = popupWebViews.firstIndex(of: webView) else { return }
        popupWebViews.remove(at: index)
        catching("dismissPopup.webkit") {
            webView.uiDelegate = nil
            webView.removeFromSuperview()
        }
    }

    fileprivate func dismissAllPopups() {
        catching("dismissAllPopups") {
            self.dismissAllPopupsUnguarded()
        }
    }

    private func dismissAllPopupsUnguarded() {
        for popup in popupWebViews {
            dismissedPopupIDs.insert(ObjectIdentifier(popup))
            popup.uiDelegate = nil
            popup.removeFromSuperview()
        }
        popupWebViews.removeAll()
    }

    private func catching(_ phase: String, _ work: () -> Void) {
        do {
            try DexoExceptionCatcher.runCatching(work)
        } catch {
            PasswordLoginCrashBreadcrumb.record(
                .objcException,
                detail: "\(phase) \(PasswordLoginCrashBreadcrumb.shortError(error))"
            )
        }
    }

    nonisolated static func jsString(_ value: String) -> String {
        JavaScriptJSONString.encode(value)
    }

    /// Discourse csrf → hCaptcha create → session.json. Kept as a user script
    /// for protocol tests; production login uses `PasswordLoginAPIClient`.
    /// Fetches use `credentials: 'include'` and never set Cookie / User-Agent / Origin.
    nonisolated static func loginJavaScript(config: PasswordLoginConfig) -> String {
        let endpointsJSON = (try? String(data: JSONEncoder().encode(config.hCaptchaCreateEndpoints), encoding: .utf8)) ?? "[]"
        return """
        window.__dexoPasswordLogin = async function(identifier, password, hcaptchaToken, secondFactorToken) {
          function post(name, payload) {
            try { window.webkit.messageHandlers[name].postMessage(payload); } catch (e) {}
          }
          function done(p) { post('dexoPasswordLogin', p); }
          try {
            var c = await fetch('/session/csrf', {
              method: 'GET',
              headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' },
              credentials: 'include',
              cache: 'no-store'
            });
            if (c.status !== 200) { return done({ phase: 'csrf', status: c.status, body: await c.text() }); }
            var csrf = (await c.json()).csrf;
            if (hcaptchaToken) {
              var endpoints = \(endpointsJSON);
              var last = null;
              var ok = false;
              for (var i = 0; i < endpoints.length; i++) {
                try {
                  var h = await fetch(endpoints[i], {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                      'Content-Type': 'application/x-www-form-urlencoded',
                      'X-CSRF-Token': csrf,
                      'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: 'token=' + encodeURIComponent(hcaptchaToken)
                  });
                  last = { endpoint: endpoints[i], status: h.status, body: await h.text() };
                  if (h.status === 200) { ok = true; break; }
                  if (h.status !== 404) break;
                } catch (e) {
                  last = { endpoint: endpoints[i], status: 0, body: String(e) };
                }
              }
              if (!ok) {
                return done({ phase: 'hcaptcha', status: last ? last.status : 0, body: JSON.stringify(last) });
              }
            }
            var form = 'login=' + encodeURIComponent(identifier) + '&password=' + encodeURIComponent(password);
            if (secondFactorToken) {
              form += '&second_factor_token=' + encodeURIComponent(secondFactorToken) + '&second_factor_method=1';
            }
            var s = await fetch('/session.json', {
              method: 'POST',
              credentials: 'include',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': csrf,
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json'
              },
              body: form
            });
            return done({ phase: 'session', status: s.status, body: await s.text() });
          } catch (e) {
            return done({ phase: 'exception', status: 0, body: String(e) });
          }
        };
        """
    }

    private static func makeHTML(siteKey: String, captchaHint: String) -> String {
        let hintHTML = captchaHint
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        return """
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
          <style>
            html, body {
              margin: 0;
              padding: 0;
              min-height: 100%;
              height: 100%;
              font-family: -apple-system, sans-serif;
              background: transparent;
              color-scheme: light dark;
            }
            .wrap {
              box-sizing: border-box;
              min-height: 100%;
              width: 100%;
              padding: 16px 12px 24px;
              display: flex;
              flex-direction: column;
              align-items: center;
              gap: 16px;
            }
            .hint { color: #888; font-size: 15px; text-align: center; line-height: 1.4; }
            .h-captcha { width: 100%; display: flex; justify-content: center; }
            @media (prefers-color-scheme: dark) {
              .hint { color: #aaa; }
            }
          </style>
        </head>
        <body>
          <div class="wrap">
            <div class="hint">\(hintHTML)</div>
            <div class="h-captcha" data-sitekey="\(siteKey)" data-size="normal" data-callback="onPass" data-error-callback="onErr" data-expired-callback="onExp"></div>
          </div>
          <script>
            function post(name, payload) {
              try { window.webkit.messageHandlers[name].postMessage(payload); } catch (e) {}
            }
            function onPass(token) { post('dexoPasswordLoginCaptcha', { token: String(token || '') }); }
            function onErr(err) { post('dexoPasswordLoginCaptcha', { error: String(err || 'unknown') }); }
            function onExp() { post('dexoPasswordLoginCaptcha', { error: 'expired' }); }
            document.addEventListener('DOMContentLoaded', function() {
              post('dexoPasswordLoginReady', 'ready');
            });
          </script>
          <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
        </body>
        </html>
        """
    }
}



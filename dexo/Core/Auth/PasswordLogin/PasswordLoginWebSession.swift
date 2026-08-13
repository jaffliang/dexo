import UIKit
import WebKit

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
        Task { @MainActor [weak session] in
            session?.handleScriptMessage(parsed)
        }
    }
}

/// WKWebView session that runs csrf → hCaptcha create → session.json with browser TLS.
@MainActor
final class PasswordLoginWebSession: NSObject {
    private let forum: ForumInstance
    private let config: PasswordLoginConfig
    private let baseURL: URL

    private var webView: WKWebView?
    private var popupWebViews: [WKWebView] = []
    private var hostController: UIViewController?
    private var proxyLease: AnyObject?
    private var trustEvaluator: WebViewProxyTrustEvaluator?
    private var scriptBridge: PasswordLoginScriptBridge?
    private var resultContinuation: CheckedContinuation<PasswordLoginBridgeResult, Error>?
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var captchaContinuation: CheckedContinuation<String, Error>?
    private var pendingCaptchaToken: String?
    private var readyTimeoutTask: Task<Void, Never>?

    init(forum: ForumInstance, config: PasswordLoginConfig) {
        self.forum = forum
        self.config = config
        let trimmed = forum.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        self.baseURL = URL(string: trimmed) ?? URL(string: "https://\(config.host)")!
        super.init()
    }

    func start(attachedTo presenter: UIViewController, embedIn container: UIView) async throws {
        let wkConfig = WKWebViewConfiguration()
        wkConfig.websiteDataStore = .nonPersistent()
        wkConfig.preferences.javaScriptCanOpenWindowsAutomatically = true
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

        // Keep the non-persistent jar; still route through DoH when enabled.
        proxyLease = try? await WebViewDoHConfigurator.configurePreservingDataStore(wkConfig)
        trustEvaluator = WebViewDoHConfigurator.makeTrustEvaluator()

        let webView = WKWebView(frame: .zero, configuration: wkConfig)
        webView.navigationDelegate = self
        webView.uiDelegate = self
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
            wkConfig.websiteDataStore,
            for: baseURL,
            excludingNames: WebCookieStore.discourseSessionCookieNames
        )

        let hint = String(localized: "password_login.captcha_hint")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            self.readyContinuation = cont
            webView.loadHTMLString(Self.makeHTML(config: config, captchaHint: hint), baseURL: baseURL)
            readyTimeoutTask?.cancel()
            readyTimeoutTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 25_000_000_000)
                guard !Task.isCancelled else { return }
                self?.takeReadyContinuation()?.resume(throwing: PasswordLoginError.captchaFailed)
            }
        }
    }

    func reprimeCookies() async {
        guard let webView else { return }
        await WebCookieStore.shared.primeToWebView(
            webView.configuration.websiteDataStore,
            for: baseURL,
            excludingNames: WebCookieStore.discourseSessionCookieNames
        )
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
        let script = "window.__dexoPasswordLogin(\(idJS), \(pwJS), \(captchaJS), \(totpJS));"
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<PasswordLoginBridgeResult, Error>) in
            self.resultContinuation = cont
            webView.evaluateJavaScript(script) { [weak self] _, error in
                guard let error else { return }
                Task { @MainActor [weak self] in
                    self?.takeResultContinuation()?.resume(
                        throwing: PasswordLoginError.unexpected(
                            status: 0,
                            phase: "evaluate",
                            body: error.localizedDescription
                        )
                    )
                }
            }
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
        guard cookies.contains(where: { $0.name == "_t" }) else {
            throw PasswordLoginError.missingSessionCookie
        }
        let ua = webView.customUserAgent ?? WebCookieStore.shared.userAgent
        return (cookies, ua)
    }

    func tearDown() {
        readyTimeoutTask?.cancel()
        readyTimeoutTask = nil
        scriptBridge?.session = nil
        scriptBridge = nil
        dismissAllPopups()
        if let webView {
            webView.configuration.userContentController.removeScriptMessageHandler(forName: "dexoPasswordLogin")
            webView.configuration.userContentController.removeScriptMessageHandler(forName: "dexoPasswordLoginReady")
            webView.configuration.userContentController.removeScriptMessageHandler(forName: "dexoPasswordLoginCaptcha")
            webView.navigationDelegate = nil
            webView.uiDelegate = nil
            webView.removeFromSuperview()
        }
        hostController = nil
        webView = nil
        proxyLease = nil
        trustEvaluator = nil
        pendingCaptchaToken = nil
        takeReadyContinuation()?.resume(throwing: PasswordLoginError.canceled)
        takeResultContinuation()?.resume(throwing: PasswordLoginError.canceled)
        takeCaptchaContinuation()?.resume(throwing: PasswordLoginError.canceled)
    }

    fileprivate func handleScriptMessage(_ message: PasswordLoginScriptMessage) {
        switch message {
        case .ready:
            readyTimeoutTask?.cancel()
            readyTimeoutTask = nil
            takeReadyContinuation()?.resume()
        case .captchaToken(let token):
            dismissAllPopups()
            if let continuation = takeCaptchaContinuation() {
                continuation.resume(returning: token)
            } else {
                pendingCaptchaToken = token
            }
        case .captchaError:
            takeCaptchaContinuation()?.resume(throwing: PasswordLoginError.captchaFailed)
        case .login(let result):
            takeResultContinuation()?.resume(returning: result)
        case .loginParseError(let raw):
            takeResultContinuation()?.resume(
                throwing: PasswordLoginError.unexpected(status: 0, phase: "parse", body: raw)
            )
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

    private func attachPopup(_ popup: WKWebView, over parent: WKWebView) {
        popup.navigationDelegate = self
        popup.uiDelegate = self
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

    private func dismissPopup(_ webView: WKWebView) {
        guard let index = popupWebViews.firstIndex(of: webView) else { return }
        popupWebViews.remove(at: index)
        webView.navigationDelegate = nil
        webView.uiDelegate = nil
        webView.removeFromSuperview()
    }

    private func dismissAllPopups() {
        for popup in popupWebViews {
            popup.navigationDelegate = nil
            popup.uiDelegate = nil
            popup.removeFromSuperview()
        }
        popupWebViews.removeAll()
    }

    private static func jsString(_ value: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: value, options: [])
        return data.flatMap { String(data: $0, encoding: .utf8) } ?? "\"\""
    }

    private static func makeHTML(config: PasswordLoginConfig, captchaHint: String) -> String {
        let endpointsJSON = (try? String(data: JSONSerialization.data(withJSONObject: config.hCaptchaCreateEndpoints), encoding: .utf8)) ?? "[]"
        let siteKey = config.hCaptchaSiteKey
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
            window.__dexoPasswordLogin = async function(identifier, password, hcaptchaToken, secondFactorToken) {
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
          </script>
          <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
        </body>
        </html>
        """
    }
}

extension PasswordLoginWebSession: WKNavigationDelegate, WKUIDelegate {
    func webView(
        _ webView: WKWebView,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if let credential = trustEvaluator?.credential(for: challenge) {
            completionHandler(.useCredential, credential)
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        guard navigationAction.targetFrame == nil else { return nil }
        // Must use WebKit's configuration (shared process pool / data store).
        // Loading the popup request into the captcha WKWebView would destroy the widget.
        let popup = WKWebView(frame: .zero, configuration: configuration)
        attachPopup(popup, over: webView)
        return popup
    }

    func webViewDidClose(_ webView: WKWebView) {
        dismissPopup(webView)
    }
}

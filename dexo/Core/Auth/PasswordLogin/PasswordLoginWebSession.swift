import UIKit
import WebKit

struct PasswordLoginBridgeResult {
    let phase: String
    let status: Int
    let body: String
}

/// WKWebView session that runs csrf → hCaptcha create → session.json with browser TLS.
@MainActor
final class PasswordLoginWebSession: NSObject {
    private let forum: ForumInstance
    private let config: PasswordLoginConfig
    private let baseURL: URL

    private var webView: WKWebView?
    private var hostController: UIViewController?
    private var proxyLease: AnyObject?
    private var trustEvaluator: WebViewProxyTrustEvaluator?
    private var resultContinuation: CheckedContinuation<PasswordLoginBridgeResult, Error>?
    private var readyContinuation: CheckedContinuation<Void, Error>?
    private var captchaContinuation: CheckedContinuation<String, Error>?

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
        let controller = wkConfig.userContentController
        controller.add(self, name: "dexoPasswordLogin")
        controller.add(self, name: "dexoPasswordLoginReady")
        controller.add(self, name: "dexoPasswordLoginCaptcha")

        // Keep the non-persistent jar; still route through DoH when enabled.
        proxyLease = try? await WebViewDoHConfigurator.configurePreservingDataStore(wkConfig)
        trustEvaluator = WebViewDoHConfigurator.makeTrustEvaluator()

        let webView = WKWebView(frame: .zero, configuration: wkConfig)
        webView.navigationDelegate = self
        webView.isOpaque = false
        webView.backgroundColor = .clear
        webView.scrollView.isScrollEnabled = true
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
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 25_000_000_000)
                guard let self, let pending = self.readyContinuation else { return }
                self.readyContinuation = nil
                pending.resume(throwing: PasswordLoginError.captchaFailed)
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
            webView.evaluateJavaScript(script) { _, error in
                if let error {
                    #if DEBUG
                    print("[PasswordLogin] evaluate error: \(error)")
                    #endif
                }
            }
        }
    }

    /// Waits for the first hCaptcha token from the embedded widget.
    func waitForCaptchaToken() async throws -> String {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
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
        if let webView {
            webView.configuration.userContentController.removeScriptMessageHandler(forName: "dexoPasswordLogin")
            webView.configuration.userContentController.removeScriptMessageHandler(forName: "dexoPasswordLoginReady")
            webView.configuration.userContentController.removeScriptMessageHandler(forName: "dexoPasswordLoginCaptcha")
            webView.removeFromSuperview()
        }
        hostController = nil
        webView = nil
        proxyLease = nil
        trustEvaluator = nil
        if let readyContinuation {
            self.readyContinuation = nil
            readyContinuation.resume(throwing: PasswordLoginError.canceled)
        }
        if let resultContinuation {
            self.resultContinuation = nil
            resultContinuation.resume(throwing: PasswordLoginError.canceled)
        }
        if let captchaContinuation {
            self.captchaContinuation = nil
            captchaContinuation.resume(throwing: PasswordLoginError.canceled)
        }
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
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <style>
            html, body { margin: 0; padding: 16px; font-family: -apple-system, sans-serif; background: transparent; }
            .wrap { display: flex; flex-direction: column; align-items: center; gap: 12px; }
            .hint { color: #888; font-size: 14px; text-align: center; }
          </style>
        </head>
        <body>
          <div class="wrap">
            <div class="hint">\(hintHTML)</div>
            <div class="h-captcha" data-sitekey="\(siteKey)" data-callback="onPass" data-error-callback="onErr" data-expired-callback="onExp"></div>
          </div>
          <script>
            function post(name, payload) {
              try { window.webkit.messageHandlers[name].postMessage(payload); } catch (e) {}
            }
            function onPass(token) { post('dexoPasswordLoginCaptcha', String(token || '')); }
            function onErr(err) { post('dexoPasswordLoginCaptcha', JSON.stringify({ error: String(err || 'unknown') })); }
            function onExp() { post('dexoPasswordLoginCaptcha', JSON.stringify({ error: 'expired' })); }
            document.addEventListener('DOMContentLoaded', function() {
              post('dexoPasswordLoginReady', 'ready');
            });
            window.__dexoPasswordLogin = async function(identifier, password, hcaptchaToken, secondFactorToken) {
              function done(p) { post('dexoPasswordLogin', JSON.stringify(p)); }
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

extension PasswordLoginWebSession: WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        switch message.name {
        case "dexoPasswordLoginReady":
            if let readyContinuation {
                self.readyContinuation = nil
                readyContinuation.resume()
            }
        case "dexoPasswordLoginCaptcha":
            let raw = "\(message.body)"
            if raw.contains("\"error\""), let captchaContinuation {
                self.captchaContinuation = nil
                captchaContinuation.resume(throwing: PasswordLoginError.captchaFailed)
                return
            }
            if let captchaContinuation {
                self.captchaContinuation = nil
                captchaContinuation.resume(returning: raw)
            }
        case "dexoPasswordLogin":
            guard let resultContinuation else { return }
            self.resultContinuation = nil
            let raw = "\(message.body)"
            guard let data = raw.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                resultContinuation.resume(throwing: PasswordLoginError.unexpected(status: 0, phase: "parse", body: raw))
                return
            }
            let phase = obj["phase"] as? String ?? "unknown"
            let status = obj["status"] as? Int ?? 0
            let body = obj["body"] as? String ?? ""
            resultContinuation.resume(returning: PasswordLoginBridgeResult(phase: phase, status: status, body: body))
        default:
            break
        }
    }
}

extension PasswordLoginWebSession: WKNavigationDelegate {
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
}

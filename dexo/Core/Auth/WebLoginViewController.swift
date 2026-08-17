import UIKit
import WebKit

/// Presents a WKWebView so users can log in to a Discourse forum via their browser.
/// Fires onSuccess once the Discourse session cookie `_t` is detected.
final class WebLoginViewController: BaseViewController {
    private let targetURL: URL
    private let onSuccess: ([HTTPCookie], String?) -> Void

    private var webView: WKWebView?
    private var proxyLease: AnyObject?
    private var setupTask: Task<Void, Never>?
    private var diagnosticEntries: [String] = []
    private var diagnosticsRequested = false

    private lazy var diagnostics = WebLoginDiagnostics { [weak self] event in
        self?.appendDiagnostic(event)
    }

    private func makeWebViewConfiguration() async throws -> (WKWebViewConfiguration, AnyObject?) {
        let config = WKWebViewConfiguration()
        config.preferences.javaScriptCanOpenWindowsAutomatically = true
        diagnostics.register(with: config)

        // Polyfills for iOS < 16.4: CSS.supports override for browser detection,
        // API polyfills, and static{} block transpilation for Webpack chunks.
        if #unavailable(iOS 16.4) {
            let polyfillSource = Self.polyfillJS
            let script = WKUserScript(source: polyfillSource, injectionTime: .atDocumentStart, forMainFrameOnly: false)
            config.userContentController.addUserScript(script)
        }

        // Inject color-scheme hint so the page respects dark mode
        let darkModeCSS = WKUserScript(
            source: "document.documentElement.style.colorScheme = 'light dark';",
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        config.userContentController.addUserScript(darkModeCSS)
        let lease = try await WebViewDoHConfigurator.configure(config)
        return (config, lease)
    }

    private lazy var coordinator = Coordinator(targetURL: targetURL, onCookiesReady: { [weak self] cookies in
        self?.handleCookiesReady(cookies)
    })

    private lazy var progressView: UIProgressView = {
        let pv = UIProgressView(progressViewStyle: .bar)
        pv.translatesAutoresizingMaskIntoConstraints = false
        return pv
    }()

    private var progressObservation: NSKeyValueObservation?

    private lazy var doneButton = UIBarButtonItem(
        title: String(localized: "weblogin.done"),
        style: .done,
        target: self,
        action: #selector(doneTapped)
    )

    private lazy var debugButton = UIBarButtonItem(
        title: String(localized: "weblogin.debug"),
        style: .plain,
        target: self,
        action: #selector(debugTapped)
    )

    private lazy var diagnosticTextView: UITextView = {
        let textView = UITextView()
        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.isEditable = false
        textView.isSelectable = true
        textView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.textContainerInset = UIEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        textView.layer.cornerRadius = 12
        textView.layer.maskedCorners = [.layerMinXMinYCorner, .layerMaxXMinYCorner]
        textView.accessibilityLabel = String(localized: "weblogin.debug.title")
        textView.isHidden = true
        return textView
    }()

    init(targetURL: URL, onSuccess: @escaping ([HTTPCookie], String?) -> Void) {
        self.targetURL = targetURL
        self.onSuccess = onSuccess
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "weblogin.title")

        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped)
        )
        doneButton.isEnabled = false
        navigationItem.rightBarButtonItems = [doneButton, debugButton]

        view.addSubview(progressView)
        view.addSubview(diagnosticTextView)
        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            diagnosticTextView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            diagnosticTextView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            diagnosticTextView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            diagnosticTextView.heightAnchor.constraint(equalToConstant: 240),
        ])
        refreshDiagnosticPanel()

        setupTask = Task { [weak self] in
            await self?.setUpWebView()
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        diagnosticTextView.backgroundColor = ThemeManager.shared.codeBackgroundColor
        diagnosticTextView.textColor = .label
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
            webView.backgroundColor = .systemBackground
            webView.customUserAgent = Self.mobileSafariUserAgent
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
            doneButton.isEnabled = true
            if diagnosticsRequested {
                diagnostics.enable(in: webView)
            }
            webView.load(URLRequest(url: targetURL))
        } catch {
            guard !Task.isCancelled else { return }
            showProxyUnavailableAlert()
        }
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

    // MARK: - Actions

    @objc private func cancelTapped() {
        setupTask?.cancel()
        dismiss(animated: true)
    }

    @objc private func doneTapped() {
        guard let webView else { return }
        coordinator.collectAndFire(from: webView)
    }

    @objc private func debugTapped() {
        if diagnosticsRequested {
            diagnosticsRequested = false
            diagnostics.disable(in: webView)
            diagnosticTextView.isHidden = true
            debugButton.title = String(localized: "weblogin.debug")
            return
        }

        diagnosticsRequested = true
        diagnosticTextView.isHidden = false
        debugButton.title = String(localized: "weblogin.debug.close")
        appendDiagnostic(String(localized: "weblogin.debug.enabled"))

        guard let webView else { return }
        diagnostics.enable(in: webView)
        // The page must load after instrumentation is installed so login API
        // calls made during boot are visible in the diagnostic panel.
        webView.reload()
    }

    private func appendDiagnostic(_ event: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        diagnosticEntries.append("[\(formatter.string(from: Date()))] \(event)")
        if diagnosticEntries.count > 100 {
            diagnosticEntries.removeFirst(diagnosticEntries.count - 100)
        }
        refreshDiagnosticPanel()
    }

    private func refreshDiagnosticPanel() {
        diagnosticTextView.text = diagnosticEntries.isEmpty
            ? String(localized: "weblogin.debug.empty")
            : diagnosticEntries.joined(separator: "\n\n")
        guard !diagnosticEntries.isEmpty else { return }
        diagnosticTextView.scrollRangeToVisible(
            NSRange(location: diagnosticTextView.text.utf16.count, length: 0)
        )
    }

    private func handleCookiesReady(_ cookies: [HTTPCookie]) {
        Task { @MainActor in
            guard let webView else { return }
            // Do not mutate the app-wide cookie store here. AuthManager first
            // persists the new auth marker, then installs these cookies. This
            // preserves the previous login if Keychain persistence fails.
            let evaluatedUserAgent = try? await webView.evaluateJavaScript("navigator.userAgent") as? String
            let userAgent = evaluatedUserAgent ?? webView.customUserAgent
            dismiss(animated: true) {
                self.onSuccess(cookies, userAgent)
            }
        }
    }

    // MARK: - User Agent

    /// Mobile Safari UA that tracks the device's actual iOS version + idiom
    /// so server-side feature detection (Discourse's browser gate, dark-mode
    /// hints, etc.) matches what real Safari would report. WebKit/Safari
    /// build numbers stay pinned — they aren't tied to the iOS version and
    /// real Safari rarely changes them within a major release.
    private static var mobileSafariUserAgent: String {
        let version = UIDevice.current.systemVersion          // e.g. "18.2.1"
        let parts = version.split(separator: ".")
        let major = parts.first.map(String.init) ?? "18"
        let minor = parts.count > 1 ? String(parts[1]) : "0"
        let osToken = "\(major)_\(minor)"                     // "18_2"
        let versionToken = "\(major).\(minor)"                // "18.2"
        let device = UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
        return "Mozilla/5.0 (\(device); CPU \(device) OS \(osToken) like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(versionToken) Mobile/15E148 Safari/604.1"
    }

    // MARK: - Polyfills (iOS < 16.4)

    private static let polyfillJS = """
    (function() {
        // CSS.supports override — Discourse browser detection
        var orig = CSS.supports.bind(CSS);
        CSS.supports = function() {
            var s = arguments.length === 1 ? arguments[0] : arguments[0] + ':' + arguments[1];
            if (s.indexOf('subgrid') !== -1 || s.indexOf('hsl(from') !== -1) return true;
            return orig.apply(CSS, arguments);
        };

        // structuredClone (iOS 15.4+)
        if (typeof globalThis.structuredClone === 'undefined') {
            globalThis.structuredClone = function(obj) { return JSON.parse(JSON.stringify(obj)); };
        }
        // Object.hasOwn (iOS 15.4+)
        if (!Object.hasOwn) {
            Object.hasOwn = function(obj, prop) { return Object.prototype.hasOwnProperty.call(obj, prop); };
        }
        // Array.prototype.at (iOS 15.4+)
        if (!Array.prototype.at) {
            Array.prototype.at = function(i) { var n = Math.trunc(i) || 0; if (n < 0) n += this.length; if (n < 0 || n >= this.length) return undefined; return this[n]; };
        }
        // String.prototype.at (iOS 15.4+)
        if (!String.prototype.at) {
            String.prototype.at = function(i) { var n = Math.trunc(i) || 0; if (n < 0) n += this.length; if (n < 0 || n >= this.length) return undefined; return this[n]; };
        }
        // crypto.randomUUID (iOS 15.4+)
        if (typeof crypto !== 'undefined' && !crypto.randomUUID) {
            crypto.randomUUID = function() {
                var a = new Uint8Array(16); crypto.getRandomValues(a);
                a[6] = (a[6] & 0x0f) | 0x40; a[8] = (a[8] & 0x3f) | 0x80;
                var h = Array.from(a, function(b) { return b.toString(16).padStart(2,'0'); }).join('');
                return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
            };
        }
    })();
    """

    // MARK: - Coordinator

    private nonisolated final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, @unchecked Sendable {
        private let targetHost: String
        private let onCookiesReady: ([HTTPCookie]) -> Void
        private let trustEvaluator: WebViewProxyTrustEvaluator?
        private(set) var didCallback = false

        init(targetURL: URL, onCookiesReady: @escaping ([HTTPCookie]) -> Void) {
            self.targetHost = targetURL.host?.lowercased() ?? ""
            self.onCookiesReady = onCookiesReady
            trustEvaluator = WebViewDoHConfigurator.makeTrustEvaluator()
        }

        func webView(
            _ webView: WKWebView,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            if let credential = trustEvaluator?.credential(for: challenge) {
                #if DEBUG
                print("[WebViewDoHProxy] WebLogin accepted proxy CA for \(challenge.protectionSpace.host)")
                #endif
                completionHandler(.useCredential, credential)
                return
            }
            completionHandler(.performDefaultHandling, nil)
        }

        /// Collect cookies and fire the callback. Only invoked from the "Done" button tap —
        /// auto-dismiss on navigation finish / cookie change was intentionally removed so
        /// the user decides when to hand off to the app.
        func collectAndFire(from webView: WKWebView) {
            guard !didCallback else { return }
            webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
                guard let self, !self.didCallback else { return }
                let relevant = cookies.filter {
                    WebCookieStore.cookieDomain($0.domain, matchesHost: self.targetHost)
                }
                self.didCallback = true
                DispatchQueue.main.async { self.onCookiesReady(relevant) }
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

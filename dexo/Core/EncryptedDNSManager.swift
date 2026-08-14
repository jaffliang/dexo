import DoHGatewayPolicy
import Foundation
import Network
import SDWebImage

final class EncryptedDNSManager {
    static let shared = EncryptedDNSManager()

    // PrivacyContext is encrypted DNS only (visible SNI). The loopback gateway
    // is the FluxDO-style path for URLSession/Alamofire on iOS 15.
    private let privacyContext = NWParameters.PrivacyContext.default

    private init() {}

    /// Seeds preferences and kicks off the gateway off the main thread.
    /// Returns immediately so first paint cannot block on `block_on(probe)`.
    func applyCurrentSettings() {
        AppSettings.shared.seedDefaultDoHServersIfNeeded()
        installOnSharedImageDownloader()
        let settings = AppSettings.shared
        guard settings.dohEnabled else {
            applyAsync(enabled: false, serverURLString: "") { _ in }
            return
        }
        guard let server = settings.defaultDoHServer,
              DoHGatewayPolicy.isProxyEnablementAllowed(
                isEnabled: true,
                serverURLString: server.urlString
              )
        else {
            settings.dohEnabled = false
            applyAsync(enabled: false, serverURLString: "") { _ in }
            return
        }
        applyAsync(enabled: true, serverURLString: server.urlString) { ok in
            if DoHGatewayPolicy.shouldDisableDoHAfterLaunchStart(ok) {
                AppSettings.shared.dohEnabled = false
            }
        }
    }

    /// PrivacyContext / WKWebView teardown stay on the caller (main).
    /// The Rust listener starts and stops on `DoHGatewayRuntime`'s serial queue.
    func applyAsync(
        enabled: Bool,
        serverURLString: String,
        completion: @escaping (Bool) -> Void
    ) {
        prepareSystemResolversForGatewayChange(enabled: enabled)
        DoHGatewayRuntime.shared.applyAsync(
            enabled: enabled,
            serverURLString: serverURLString
        ) { [self] ok in
            if enabled && ok {
                installOnSharedImageDownloader()
                applyPrivacyContextIfAllowed(serverURLString: serverURLString)
                completion(true)
            } else {
                disablePrivacyContext()
                completion(!enabled || ok)
            }
        }
    }

    /// Synchronous path for tests that never reach FFI I/O. Production callers
    /// must use `applyAsync` so start/stop never run on the main thread.
    @discardableResult
    func setEnabled(_ enabled: Bool, serverURLString: String) -> Bool {
        prepareSystemResolversForGatewayChange(enabled: enabled)
        guard enabled else {
            DoHGatewayRuntime.shared.stop()
            return true
        }

        guard DoHGatewayRuntime.shared.setEnabled(true, serverURLString: serverURLString) else {
            disablePrivacyContext()
            return false
        }
        installOnSharedImageDownloader()
        applyPrivacyContextIfAllowed(serverURLString: serverURLString)
        return true
    }

    private func prepareSystemResolversForGatewayChange(enabled: Bool) {
        if !enabled {
            disablePrivacyContext()
        }
        // Existing proxy sessions may keep resolved addresses and open
        // connections, so changing the resolver must rebuild them.
        WebViewDoHProxy.shared.stop()
    }

    private func disablePrivacyContext() {
        privacyContext.requireEncryptedNameResolution(false, fallbackResolver: nil)
        privacyContext.flushCache()
    }

    private func applyPrivacyContextIfAllowed(serverURLString: String) {
        // iOS 15: the loopback gateway is the only ECH path. PrivacyContext
        // encrypted DNS resolves via DoH then handshakes TLS with visible SNI.
        // Any URLSession that misses the protocol (SDWebImage's already-built
        // session, URLSession.shared, a race before canInit sees isProxyActive)
        // would then fail with URLError.secureConnectionFailed. Keep it off so
        // leaked requests fail closed instead of doing visible-SNI TLS.
        if DoHGatewayPolicy.enablePrivacyContextWhileGatewayActive,
           let serverURL = Self.normalizedServerURL(serverURLString)
        {
            let resolver = NWParameters.PrivacyContext.ResolverConfiguration.https(
                serverURL,
                serverAddresses: []
            )
            privacyContext.requireEncryptedNameResolution(true, fallbackResolver: resolver)
        } else {
            disablePrivacyContext()
        }
        privacyContext.flushCache()
    }

    /// Installs the gateway protocol on SDWebImage and drops any session that
    /// was created before the protocol was in `protocolClasses`.
    private func installOnSharedImageDownloader() {
        let downloader = SDWebImageDownloader.shared
        let existing = downloader.config.sessionConfiguration ?? URLSessionConfiguration.default
        guard let sessionConfiguration = existing.copy() as? URLSessionConfiguration else {
            return
        }
        DoHGatewayRuntime.prepare(sessionConfiguration)
        downloader.config.sessionConfiguration = sessionConfiguration
        downloader.invalidateSessionAndCancel(false)
    }

    static func normalizedServerURL(_ input: String) -> URL? {
        DoHGatewayPolicy.normalizedDoHURL(input)
    }
}

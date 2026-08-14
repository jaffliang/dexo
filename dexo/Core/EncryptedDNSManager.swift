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

    /// Applies the persisted preference before any URLSession-backed clients
    /// are created. Returns false only when an enabled endpoint is invalid.
    @discardableResult
    func applyCurrentSettings() -> Bool {
        AppSettings.shared.seedDefaultDoHServersIfNeeded()
        installOnSharedImageDownloader()
        let settings = AppSettings.shared
        guard !settings.dohEnabled || settings.defaultDoHServer != nil else {
            settings.dohEnabled = false
            return setEnabled(false, serverURLString: "")
        }
        return setEnabled(
            settings.dohEnabled,
            serverURLString: settings.defaultDoHServer?.urlString ?? ""
        )
    }

    /// Updates encrypted name resolution for subsequent connections across
    /// all forums and starts or stops the iOS 15 URLSession loopback gateway.
    @discardableResult
    func setEnabled(_ enabled: Bool, serverURLString: String) -> Bool {
        guard enabled else {
            privacyContext.requireEncryptedNameResolution(false, fallbackResolver: nil)
            privacyContext.flushCache()
            DoHGatewayRuntime.shared.stop()
            if #available(iOS 17.0, *) {
                WebViewDoHProxy.shared.stop()
            }
            return true
        }

        if #available(iOS 17.0, *) {
            // Existing proxy sessions may keep resolved addresses and open
            // connections, so changing the resolver must rebuild them.
            WebViewDoHProxy.shared.stop()
        }

        guard DoHGatewayRuntime.shared.setEnabled(true, serverURLString: serverURLString) else {
            privacyContext.requireEncryptedNameResolution(false, fallbackResolver: nil)
            privacyContext.flushCache()
            return false
        }
        installOnSharedImageDownloader()

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
            privacyContext.requireEncryptedNameResolution(false, fallbackResolver: nil)
        }
        privacyContext.flushCache()
        return true
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

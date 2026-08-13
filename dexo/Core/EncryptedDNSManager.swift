import DoHGatewayPolicy
import Foundation
import Network
import SDWebImage

final class EncryptedDNSManager {
    static let shared = EncryptedDNSManager()

    // PrivacyContext is encrypted DNS only (visible SNI). The loopback gateway
    // is the FluxDO-style path for URLSession/Alamofire on iOS 15.
    private let privacyContext = NWParameters.PrivacyContext.default

    private var didInstallImageDownloader = false

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

        guard let serverURL = Self.normalizedServerURL(serverURLString) else {
            return false
        }

        if #available(iOS 17.0, *) {
            // Existing proxy sessions may keep resolved addresses and open
            // connections, so changing the resolver must rebuild them.
            WebViewDoHProxy.shared.stop()
        }

        guard DoHGatewayRuntime.shared.setEnabled(true, serverURLString: serverURL.absoluteString) else {
            privacyContext.requireEncryptedNameResolution(false, fallbackResolver: nil)
            privacyContext.flushCache()
            return false
        }
        installOnSharedImageDownloader()

        let resolver = NWParameters.PrivacyContext.ResolverConfiguration.https(
            serverURL,
            serverAddresses: []
        )
        privacyContext.requireEncryptedNameResolution(true, fallbackResolver: resolver)
        privacyContext.flushCache()
        return true
    }

    private func installOnSharedImageDownloader() {
        guard !didInstallImageDownloader else { return }
        didInstallImageDownloader = true
        let downloader = SDWebImageDownloader.shared
        let sessionConfiguration = downloader.config.sessionConfiguration
        DoHGatewayRuntime.prepare(sessionConfiguration)
        downloader.config.sessionConfiguration = sessionConfiguration
    }

    static func normalizedServerURL(_ input: String) -> URL? {
        DoHGatewayPolicy.normalizedDoHURL(input)
    }
}

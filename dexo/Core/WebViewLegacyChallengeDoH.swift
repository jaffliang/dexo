import DoHGatewayPolicy
import Foundation
import Network
import WebKit

/// Isolated-store CONNECT attach failures. Never applied to `.default()` or
/// `WebCookieStore.shared`.
nonisolated enum WebViewLegacyChallengeError: Error, LocalizedError, Equatable {
    case gatewayInactive
    case schemeRegistrationUnavailable(String)
    case isolatedStoreFailed(String)

    var errorDescription: String? {
        switch self {
        case .gatewayInactive:
            return "DoH gateway is not listening"
        case .schemeRegistrationUnavailable(let reason):
            return reason
        case .isolatedStoreFailed(let reason):
            return reason
        }
    }
}

nonisolated enum WebViewChallengeDoHDiagnostics {
    static func detail(for error: Error) -> String {
        if let challenge = error as? WebViewLegacyChallengeError {
            return challenge.localizedDescription
        }
        let nsError = error as NSError
        return "\(nsError.domain) (\(nsError.code)): \(error.localizedDescription)"
    }
}

/// Custom-scheme registration is disabled. After http/https are registered,
/// `URLProtocol.canInit == false` does not fall through to system TLS, so
/// Turnstile cannot get Safari JA3. Kept as a no-op so leftover builds can
/// still unregister on launch.
nonisolated enum WebViewCustomProtocolSchemes {
    private static let lock = NSLock()
    private static var retainCount = 0

    static var isAvailable: Bool { false }

    static var registrationCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return retainCount
    }

    static var isRetained: Bool { false }

    static func acquire() -> Lease? {
        nil
    }

    static func unregisterIfNeeded() {
        performOnMain {
            WebViewDoHChallengeSPI.unregisterHTTPAndHTTPSCustomProtocolSchemes()
        }
    }

    @discardableResult
    private static func performOnMain<T>(_ work: () -> T) -> T {
        if Thread.isMainThread {
            return work()
        }
        var result: T?
        DispatchQueue.main.sync {
            result = work()
        }
        return result!
    }

    nonisolated final class Lease: Sendable {
        fileprivate init() {}
    }
}

/// Held while a challenge / in-app / password-login WebView uses the isolated
/// CONNECT store. Does not retain process-wide scheme registration.
final class WebViewLegacyChallengeSession: @unchecked Sendable {
    fileprivate(set) var warning: Error?

    func release() {}
}

/// Clears leftover `_setProxyConfiguration:` on the process-shared jars and
/// unregisters any leftover custom schemes. Does not start a CONNECT listener.
enum WebViewLegacyProxyRecovery {
    static func clearLeakedProxies() {
        EncryptedDNSManager.shared.clearLeftoverWebKitHTTPProxies()
        WebViewCustomProtocolSchemes.unregisterIfNeeded()
    }
}

extension WebViewDoHConfigurator {
    /// Isolated WKWebsiteDataStore pointed at the Rust CONNECT port.
    /// Never mutates `.default()` or `WebCookieStore.shared` in place.
    static func attachIsolatedConnectStore(
        _ configuration: WKWebViewConfiguration
    ) async -> AnyObject? {
        guard AppSettings.shared.dohEnabled else { return nil }

        let session = WebViewLegacyChallengeSession()
        let gateway = DoHGatewayRuntime.shared.currentConfiguration
        guard gateway.isConnectProxyActive else {
            session.warning = WebViewLegacyChallengeError.gatewayInactive
            return session
        }

        let originalStore = configuration.websiteDataStore
        do {
            let store = try makeIsolatedConnectDataStore(port: gateway.connectPort)
            if originalStore === WKWebsiteDataStore.default()
                || originalStore === WebCookieStore.shared.websiteDataStore
            {
                await transferCookies(from: originalStore, to: store)
            }
            configuration.websiteDataStore = store
            session.warning = nil
            return session
        } catch {
            session.warning = error
            configuration.websiteDataStore = originalStore
            return session
        }
    }

    /// iOS 15/16 production WebViews use the isolated CONNECT store, not
    /// `registerSchemeForCustomProtocol`.
    static func attachLegacyChallengeRouting(
        _ configuration: WKWebViewConfiguration
    ) async -> AnyObject? {
        await attachIsolatedConnectStore(configuration)
    }

    static func legacyAttachWarning(from lease: AnyObject?) -> Error? {
        (lease as? WebViewLegacyChallengeSession)?.warning
    }

    static func makeIsolatedConnectDataStore(port: Int) throws -> WKWebsiteDataStore {
        guard port > 0, port <= Int(UInt16.max) else {
            throw WebViewLegacyChallengeError.isolatedStoreFailed("isolated store port is \(port)")
        }
        if #available(iOS 17.0, *) {
            return try makePublicConnectDataStore(port: UInt16(port))
        }
        return try makeIsolatedProxiedDataStore(port: port)
    }

    @available(iOS 17.0, *)
    private static func makePublicConnectDataStore(port: UInt16) throws -> WKWebsiteDataStore {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw WebViewLegacyChallengeError.isolatedStoreFailed("isolated store port is \(port)")
        }
        let store = WKWebsiteDataStore.nonPersistent()
        let endpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: nwPort)
        store.proxyConfigurations = [ProxyConfiguration(httpCONNECTProxy: endpoint)]
        return store
    }

    static func makeIsolatedProxiedDataStore(port: Int) throws -> WKWebsiteDataStore {
        guard port > 0, port <= Int(UInt16.max) else {
            throw WebViewLegacyChallengeError.isolatedStoreFailed("isolated store port is \(port)")
        }
        do {
            return try WebViewDoHChallengeSPI.makeNonPersistentDataStore(
                httpProxyPort: UInt16(port)
            )
        } catch {
            throw WebViewLegacyChallengeError.isolatedStoreFailed(
                WebViewDoHChallengeSPI.lastFailureReason()
                    ?? error.localizedDescription
            )
        }
    }

    static func transferCookies(
        from source: WKWebsiteDataStore,
        to destination: WKWebsiteDataStore
    ) async {
        guard source !== destination else { return }
        let cookies = await withCheckedContinuation { cont in
            source.httpCookieStore.getAllCookies { cont.resume(returning: $0) }
        }
        for cookie in cookies {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                destination.httpCookieStore.setCookie(cookie) { cont.resume() }
            }
        }
    }
}

import DoHGatewayPolicy
import Foundation
import WebKit

/// iOS 15/16 path that reuses the working URLSession DoH gateway for the
/// Cloudflare challenge WKWebView. Does not install an HTTP/CONNECT proxy
/// on `WKWebsiteDataStore.default()` or `WebCookieStore.shared`.
nonisolated enum WebViewLegacyChallengeError: Error, LocalizedError, Equatable {
    case gatewayInactive
    case schemeRegistrationUnavailable(String)
    case isolatedStoreFailed(String)

    var errorDescription: String? {
        switch self {
        case .gatewayInactive:
            return "DoH gateway is not listening"
        case .schemeRegistrationUnavailable(let reason):
            return "WKBrowsingContextController registerSchemeForCustomProtocol: unavailable (\(reason))"
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

/// Ref-counted `http`/`https` custom-scheme registration. Unregister as soon
/// as the last challenge / password-login session is gone — never leave this
/// installed app-wide.
nonisolated enum WebViewCustomProtocolSchemes {
    private static let lock = NSLock()
    private static var retainCount = 0
    private static var isRegistered = false

    static var isAvailable: Bool {
        WebViewDoHChallengeSPI.canRegisterCustomProtocolSchemes()
    }

    static var registrationCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return retainCount
    }

    /// True while a challenge / password-login WebView holds a scheme lease.
    static var isRetained: Bool {
        registrationCount > 0
    }

    static func acquire() -> Lease? {
        lock.lock()
        if !isRegistered {
            lock.unlock()
            guard performOnMain({
                WebViewDoHChallengeSPI.registerHTTPAndHTTPSCustomProtocolSchemes()
            }) else {
                return nil
            }
            lock.lock()
            if !isRegistered {
                isRegistered = true
            }
        }
        retainCount += 1
        lock.unlock()
        return Lease()
    }

    fileprivate static func release() {
        let shouldUnregister: Bool = {
            lock.lock()
            defer { lock.unlock() }
            guard retainCount > 0 else { return false }
            retainCount -= 1
            if retainCount == 0, isRegistered {
                isRegistered = false
                return true
            }
            return false
        }()
        guard shouldUnregister else { return }
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

        deinit {
            WebViewCustomProtocolSchemes.release()
        }
    }
}

/// Held by Challenge / password-login while the WebView is on screen.
final class WebViewLegacyChallengeSession: @unchecked Sendable {
    fileprivate(set) var warning: Error?
    fileprivate var schemeLease: WebViewCustomProtocolSchemes.Lease?

    func release() {
        schemeLease = nil
    }

    deinit {
        schemeLease = nil
    }
}

/// Clears leftover `_setProxyConfiguration:` on the process-shared jars.
/// Does not start a CONNECT listener.
enum WebViewLegacyProxyRecovery {
    static func clearLeakedProxies() {
        EncryptedDNSManager.shared.clearLeftoverWebKitHTTPProxies()
    }
}

extension WebViewDoHConfigurator {
    /// iOS 15/16: route the challenge WKWebView through `DoHGatewayURLProtocol`.
    /// Keeps the caller's data store (shared cookie jar) when the scheme hook
    /// works. Isolated-store fallback is last resort and never mutates
    /// `.default()` or the shared jar in place.
    static func attachLegacyChallengeRouting(
        _ configuration: WKWebViewConfiguration
    ) async -> AnyObject? {
        guard AppSettings.shared.dohEnabled else { return nil }

        let session = WebViewLegacyChallengeSession()
        let gateway = DoHGatewayRuntime.shared.currentConfiguration
        guard gateway.isProxyActive else {
            session.warning = WebViewLegacyChallengeError.gatewayInactive
            return session
        }

        if let lease = WebViewCustomProtocolSchemes.acquire() {
            session.schemeLease = lease
            return session
        }

        let schemeReason = WebViewDoHChallengeSPI.lastFailureReason()
            ?? "WKBrowsingContextController registerSchemeForCustomProtocol: unavailable"
        let originalStore = configuration.websiteDataStore
        do {
            let store = try makeIsolatedProxiedDataStore(port: gateway.gatewayPort)
            if originalStore === WKWebsiteDataStore.default()
                || originalStore === WebCookieStore.shared.websiteDataStore
            {
                await transferCookies(from: originalStore, to: store)
            }
            configuration.websiteDataStore = store
            session.warning = nil
            return session
        } catch {
            session.warning = WebViewLegacyChallengeError.isolatedStoreFailed(
                "\(WebViewLegacyChallengeError.schemeRegistrationUnavailable(schemeReason).localizedDescription); isolated store: \(WebViewChallengeDoHDiagnostics.detail(for: error))"
            )
            configuration.websiteDataStore = originalStore
            return session
        }
    }

    static func legacyAttachWarning(from lease: AnyObject?) -> Error? {
        (lease as? WebViewLegacyChallengeSession)?.warning
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

    private static func transferCookies(
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

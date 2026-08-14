import Foundation
import Network
import Security
import WebKit

/// Applies the app's global DoH preference to Cloudflare-clearance WKWebViews.
/// WebKit keeps the original HTTPS URL and connects through a loopback CONNECT
/// proxy. Forum hosts are MITM'd so upstream TLS can use the DoH/ECH gateway;
/// Cloudflare Turnstile and hCaptcha stay end-to-end.
///
/// iOS 17+ uses public `ProxyConfiguration`. iOS 15/16 attach the same
/// listener through WebKit's per-data-store HTTP proxy hooks (string
/// selectors only) and keep one shared jar so `cf_clearance` still syncs.
enum WebViewDoHConfigurator {
    static func configure(_ configuration: WKWebViewConfiguration) async throws -> AnyObject? {
        let dataStore = WKWebsiteDataStore.default()
        configuration.websiteDataStore = dataStore
        clearProxy(on: dataStore)

        guard AppSettings.shared.dohEnabled else { return nil }
        let lease = try await WebViewDoHProxy.shared.acquire()
        do {
            try apply(lease, to: configuration)
        } catch {
            lease.attachWarning = error
        }
        return lease
    }

    /// Applies the DoH CONNECT proxy to whatever data store the caller already
    /// attached (e.g. the shared Cloudflare / password-login jar), without
    /// replacing it with `.default()`.
    static func configurePreservingDataStore(
        _ configuration: WKWebViewConfiguration
    ) async throws -> AnyObject? {
        clearProxy(on: configuration.websiteDataStore)
        guard AppSettings.shared.dohEnabled else { return nil }
        let lease = try await WebViewDoHProxy.shared.acquire()
        let original = configuration.websiteDataStore
        do {
            try apply(lease, to: configuration)
        } catch {
            // Listener is up. Keep the shared jar and let the caller present
            // the WebView instead of blocking the challenge sheet.
            configuration.websiteDataStore = original
            lease.attachWarning = error
            return lease
        }
        if configuration.websiteDataStore !== original {
            await transferCookies(from: original, to: configuration.websiteDataStore)
            if original === WebCookieStore.shared.websiteDataStore {
                WebCookieStore.shared.adoptWebsiteDataStore(configuration.websiteDataStore)
            }
        }
        return lease
    }

    static func attachWarning(from lease: AnyObject?) -> Error? {
        (lease as? WebViewDoHProxy.Lease)?.attachWarning
    }

    /// Configures the debug browser for a pure local MITM capture. This path
    /// intentionally ignores the DoH switch and uses normal URLSession
    /// networking upstream so certificate interception can be tested alone.
    static func configureDebugMITM(
        _ configuration: WKWebViewConfiguration
    ) async throws -> AnyObject? {
        guard #available(iOS 17.0, *) else { return nil }

        let dataStore = WKWebsiteDataStore.nonPersistent()
        configuration.websiteDataStore = dataStore
        dataStore.proxyConfigurations = []

        let lease = try await WebViewDoHProxy.shared.acquireForDebugCapture()
        dataStore.proxyConfigurations = [lease.proxyConfiguration]
        return lease
    }

    /// Configures an ordinary URLSession to use the same local CONNECT proxy
    /// as the WKWebView debug capture. Keeping this path separate makes it
    /// possible to isolate URLSession TLS behavior from WebKit.
    static func configureDebugMITM(
        _ configuration: URLSessionConfiguration
    ) async throws -> AnyObject? {
        guard #available(iOS 17.0, *) else { return nil }

        let lease = try await WebViewDoHProxy.shared.acquireForDebugCapture()
        configuration.proxyConfigurations = [lease.proxyConfiguration]
        return lease
    }

    static func makeTrustEvaluator() -> WebViewProxyTrustEvaluator? {
        guard let certificateData = WebViewDoHProxy.shared.caCertificateData else { return nil }
        return WebViewProxyTrustEvaluator(certificateData: certificateData)
    }

    static func clearProxy(on dataStore: WKWebsiteDataStore) {
        if #available(iOS 17.0, *) {
            dataStore.proxyConfigurations = []
            return
        }
        WebViewLegacyHTTPProxy.clear(dataStore)
    }

    private static func apply(
        _ lease: WebViewDoHProxy.Lease,
        to configuration: WKWebViewConfiguration
    ) throws {
        if #available(iOS 17.0, *) {
            configuration.websiteDataStore.proxyConfigurations = [lease.proxyConfiguration]
            return
        }

        // iOS 15/16: keep the caller's jar (shared Cloudflare cookies) and
        // attach the CONNECT listener in place. Only mint a replacement
        // store if `_setProxyConfiguration:` is missing on that instance.
        let existing = configuration.websiteDataStore
        if WebViewLegacyHTTPProxy.apply(port: lease.port, to: existing) {
            #if DEBUG
            print("[WebViewDoHProxy] attached CONNECT proxy to existing data store on 127.0.0.1:\(lease.port)")
            #endif
            return
        }

        do {
            let store = try WebViewDoHProxy.shared.legacyProxiedDataStore(port: lease.port)
            configuration.websiteDataStore = store
            #if DEBUG
            print("[WebViewDoHProxy] replaced data store with proxied store on 127.0.0.1:\(lease.port)")
            #endif
        } catch {
            throw WebViewDoHProxy.ProxyError.legacyProxyAttachFailed(
                WebViewLegacyHTTPProxy.attachFailureReason(port: lease.port, dataStore: existing)
            )
        }
    }

    private static func transferCookies(from source: WKWebsiteDataStore, to destination: WKWebsiteDataStore) async {
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

/// Evaluates the server-trust challenge produced by the app's loopback MITM
/// proxy against its private CA. The host policy already attached to SecTrust
/// is preserved, so a certificate for another hostname is still rejected.
nonisolated final class WebViewProxyTrustEvaluator: @unchecked Sendable {
    private let caCertificate: SecCertificate

    init?(certificateData: Data) {
        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            return nil
        }
        caCertificate = certificate
    }

    func credential(for challenge: URLAuthenticationChallenge) -> URLCredential? {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            return nil
        }

        guard SecTrustSetAnchorCertificates(trust, [caCertificate] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, false) == errSecSuccess
        else {
            return nil
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else { return nil }
        return URLCredential(trust: trust)
    }
}

final class WebViewDoHProxy {
    static let shared = WebViewDoHProxy()

    final class Lease {
        fileprivate let id: UUID
        let port: UInt16
        fileprivate(set) var attachWarning: Error?

        @available(iOS 17.0, *)
        var proxyConfiguration: ProxyConfiguration {
            let endpoint = NWEndpoint.hostPort(
                host: .ipv4(.loopback),
                port: NWEndpoint.Port(rawValue: port) ?? 443
            )
            return ProxyConfiguration(httpCONNECTProxy: endpoint)
        }

        fileprivate init(id: UUID, port: UInt16) {
            self.id = id
            self.port = port
        }

        deinit {
            let id = id
            Task { @MainActor in
                WebViewDoHProxy.shared.release(id)
            }
        }
    }

    enum ProxyError: Error, LocalizedError {
        case listenerStopped
        case unavailablePort
        case invalidDoHConfiguration
        case certificateAuthorityFailed(Error)
        case listenerStartFailed(Error)
        case legacyProxyAttachFailed(String)

        var caseName: String {
            switch self {
            case .listenerStopped: return "listenerStopped"
            case .unavailablePort: return "unavailablePort"
            case .invalidDoHConfiguration: return "invalidDoHConfiguration"
            case .certificateAuthorityFailed: return "certificateAuthorityFailed"
            case .listenerStartFailed: return "listenerStartFailed"
            case .legacyProxyAttachFailed: return "legacyProxyAttachFailed"
            }
        }

        var errorDescription: String? {
            switch self {
            case .listenerStopped:
                return "CONNECT listener stopped"
            case .unavailablePort:
                return "CONNECT listener has no port"
            case .invalidDoHConfiguration:
                return "DoH is on but the selected server URL is missing or invalid"
            case .certificateAuthorityFailed(let error):
                return error.localizedDescription
            case .listenerStartFailed(let error):
                return error.localizedDescription
            case .legacyProxyAttachFailed(let reason):
                return reason
            }
        }
    }

    private let queue = DispatchQueue(label: "xyz.47258.dexo.webview-native-mitm")
    private var listener: NWListener?
    private var listenerPort: NWEndpoint.Port?
    private var certificateAuthority: WebViewProxyCertificateAuthority?
    private var leases = Set<UUID>()
    private var debugCaptureLeases = Set<UUID>()
    private var tunnels: [UUID: WebViewDoHMITMTunnel] = [:]
    private var cachedLegacyDataStore: WKWebsiteDataStore?
    private struct PendingAcquire {
        let isDebugCapture: Bool
        let continuation: CheckedContinuation<Lease, Error>
    }
    private var pendingAcquires: [PendingAcquire] = []

    private init() {}

    var caCertificateData: Data? {
        certificateAuthority.map { SecCertificateCopyData($0.certificate) as Data }
    }

    func acquire() async throws -> Lease {
        guard AppSettings.shared.dohEnabled,
              let serverURLString = AppSettings.shared.defaultDoHServer?.urlString,
              EncryptedDNSManager.normalizedServerURL(serverURLString) != nil
        else {
            throw ProxyError.invalidDoHConfiguration
        }

        return try await acquire(isDebugCapture: false)
    }

    func acquireForDebugCapture() async throws -> Lease {
        try await acquire(isDebugCapture: true)
    }

    private func acquire(isDebugCapture: Bool) async throws -> Lease {
        if let listenerPort {
            return makeLease(port: listenerPort, isDebugCapture: isDebugCapture)
        }

        return try await withCheckedThrowingContinuation { continuation in
            pendingAcquires.append(
                PendingAcquire(
                    isDebugCapture: isDebugCapture,
                    continuation: continuation
                )
            )
            guard listener == nil else { return }
            do {
                try startListener()
            } catch {
                failPendingAcquires(error)
            }
        }
    }

    func stop() {
        if #available(iOS 17.0, *) {
            WKWebsiteDataStore.default().proxyConfigurations = []
        } else {
            WebViewLegacyHTTPProxy.clear(WKWebsiteDataStore.default())
            if let cachedLegacyDataStore {
                WebViewLegacyHTTPProxy.clear(cachedLegacyDataStore)
            }
            WebViewLegacyHTTPProxy.clear(WebCookieStore.shared.websiteDataStore)
        }
        cachedLegacyDataStore = nil
        stopListener(error: ProxyError.listenerStopped)
    }

    func legacyProxiedDataStore(port: UInt16) throws -> WKWebsiteDataStore {
        if let cachedLegacyDataStore {
            return cachedLegacyDataStore
        }
        if let store = WebViewLegacyHTTPProxy.makeNonPersistentDataStore(port: port) {
            cachedLegacyDataStore = store
            return store
        }
        let fallback = WKWebsiteDataStore.nonPersistent()
        if WebViewLegacyHTTPProxy.apply(port: port, to: fallback) {
            cachedLegacyDataStore = fallback
            return fallback
        }
        throw ProxyError.legacyProxyAttachFailed(
            WebViewLegacyHTTPProxy.attachFailureReason(port: port, dataStore: fallback)
        )
    }

    private func startListener() throws {
        let certificateAuthority: WebViewProxyCertificateAuthority
        do {
            certificateAuthority = try WebViewProxyCertificateAuthority.loadOrCreate()
        } catch {
            throw ProxyError.certificateAuthorityFailed(error)
        }
        self.certificateAuthority = certificateAuthority

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        let parameters = NWParameters(tls: nil, tcp: tcpOptions)
        parameters.allowLocalEndpointReuse = true
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        WebViewMITMFramerContext.shared.install(certificateAuthority)
        parameters.defaultProtocolStack.applicationProtocols.insert(
            HTTPConnectMITMFramer.options(),
            at: 0
        )

        let listener: NWListener
        do {
            listener = try makeLoopbackListener(parameters: parameters)
        } catch {
            WebViewMITMFramerContext.shared.clear()
            self.certificateAuthority = nil
            throw ProxyError.listenerStartFailed(error)
        }
        if #available(iOS 16.0, *) {
            listener.newConnectionLimit = 128
        }
        self.listener = listener

        listener.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                self?.handleListenerState(state)
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in
                self?.accept(connection)
            }
        }
        listener.start(queue: queue)
    }

    private func makeLoopbackListener(parameters: NWParameters) throws -> NWListener {
        do {
            return try NWListener(using: parameters, on: .any)
        } catch {
            // iOS 15.0–15.6: requiredLocalEndpoint + on:.any can fail together.
            parameters.requiredLocalEndpoint = nil
            return try NWListener(using: parameters, on: .any)
        }
    }

    private func handleListenerState(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener?.port else {
                stopListener(error: ProxyError.unavailablePort)
                return
            }
            listenerPort = port
            #if DEBUG
            print("[WebViewDoHProxy] native MITM ready on 127.0.0.1:\(port.rawValue)")
            #endif
            let continuations = pendingAcquires
            pendingAcquires.removeAll()
            continuations.forEach {
                $0.continuation.resume(
                    returning: makeLease(
                        port: port,
                        isDebugCapture: $0.isDebugCapture
                    )
                )
            }
        case .failed(let error):
            stopListener(error: ProxyError.listenerStartFailed(error))
        case .cancelled:
            if !pendingAcquires.isEmpty {
                stopListener(error: ProxyError.listenerStopped)
            }
        default:
            break
        }
    }

    private func accept(_ connection: NWConnection) {
        guard listener != nil,
              AppSettings.shared.dohEnabled || !debugCaptureLeases.isEmpty
        else {
            connection.cancel()
            return
        }

        let id = UUID()
        let tunnel = WebViewDoHMITMTunnel(
            id: id,
            client: connection,
            queue: queue,
            onStop: {
                Task { @MainActor in
                    WebViewDoHProxy.shared.tunnels.removeValue(forKey: id)
                }
            }
        )
        tunnels[id] = tunnel
        tunnel.start()
    }

    private func makeLease(port: NWEndpoint.Port, isDebugCapture: Bool) -> Lease {
        let id = UUID()
        leases.insert(id)
        if isDebugCapture {
            debugCaptureLeases.insert(id)
        }
        return Lease(id: id, port: port.rawValue)
    }

    private func release(_ id: UUID) {
        leases.remove(id)
        debugCaptureLeases.remove(id)
        if leases.isEmpty, pendingAcquires.isEmpty {
            stopListener(error: nil)
        }
    }

    private func failPendingAcquires(_ error: Error) {
        let continuations = pendingAcquires
        pendingAcquires.removeAll()
        continuations.forEach { $0.continuation.resume(throwing: error) }
        listener?.cancel()
        listener = nil
        listenerPort = nil
        certificateAuthority = nil
        WebViewMITMFramerContext.shared.clear()
    }

    private func stopListener(error: Error?) {
        let activeListener = listener
        listener = nil
        listenerPort = nil
        certificateAuthority = nil
        WebViewMITMFramerContext.shared.clear()
        activeListener?.stateUpdateHandler = nil
        activeListener?.newConnectionHandler = nil
        activeListener?.cancel()

        let activeTunnels = Array(tunnels.values)
        tunnels.removeAll()
        activeTunnels.forEach { $0.cancel() }

        leases.removeAll()
        debugCaptureLeases.removeAll()
        if !pendingAcquires.isEmpty {
            failPendingAcquires(error ?? ProxyError.listenerStopped)
        }
    }
}

enum WebViewDoHProxyDiagnostics {
    static func detail(for error: Error) -> String {
        if let proxy = error as? WebViewDoHProxy.ProxyError {
            return "ProxyError.\(proxy.caseName): \(proxy.localizedDescription)"
        }
        let nsError = error as NSError
        return "\(nsError.domain) (\(nsError.code)): \(error.localizedDescription)"
    }

    static func alertMessage(for error: Error) -> String {
        String(localized: "doh.proxy.error.message") + "\n\n" + detail(for: error)
    }
}

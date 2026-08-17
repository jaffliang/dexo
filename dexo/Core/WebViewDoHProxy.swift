import Foundation
import Network
import Security
import WebKit

/// Applies the app's global DoH preference to every production WKWebView on
/// iOS 17 and later, regardless of the forum host. WebKit keeps the original
/// HTTPS URL and connects through a loopback CONNECT proxy. The proxy
/// terminates local TLS, while URLSession performs upstream TLS with the app's
/// encrypted resolver configuration.
enum WebViewDoHConfigurator {
    /// Production WKWebViews use an isolated store pointed at the Rust
    /// CONNECT port. Never installs a proxy on `.default()` or the shared jar.
    static func configure(_ configuration: WKWebViewConfiguration) async throws -> AnyObject? {
        let lease = await attachIsolatedConnectStore(configuration)
        if let warning = legacyAttachWarning(from: lease) {
            throw warning
        }
        return lease
    }

    /// Same isolated CONNECT store as `configure`. The caller store is replaced
    /// when DoH is on so the shared cookie jar never receives a proxy.
    static func configurePreservingDataStore(
        _ configuration: WKWebViewConfiguration
    ) async throws -> AnyObject? {
        try await configure(configuration)
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
        var certificates: [Data] = []
        if let rustCA = DoHGatewayRuntime.shared.mitmCACertificateData, !rustCA.isEmpty {
            certificates.append(rustCA)
        }
        if #available(iOS 17.0, *), let swiftCA = WebViewDoHProxy.shared.caCertificateData {
            certificates.append(swiftCA)
        }
        return WebViewProxyTrustEvaluator(certificateData: certificates)
    }
}

/// Accepts loopback MITM leaves signed by the exported Rust (or debug Swift)
/// CA. iOS ATS / `SecTrustEvaluateWithError` often rejects homemade CAs even
/// after they are set as anchors; our own CONNECT certs must still be used.
nonisolated final class WebViewProxyTrustEvaluator: @unchecked Sendable {
    private let caCertificates: [SecCertificate]

    convenience init?(certificateData: Data) {
        self.init(certificateData: [certificateData])
    }

    init?(certificateData: [Data]) {
        let certificates = certificateData.compactMap {
            SecCertificateCreateWithData(nil, $0 as CFData)
        }
        guard !certificates.isEmpty else { return nil }
        caCertificates = certificates
    }

    func credential(for challenge: URLAuthenticationChallenge) -> URLCredential? {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let leaf = Self.leafCertificate(from: trust)
        else {
            return nil
        }

        guard caCertificates.contains(where: { Self.certificate(leaf, isIssuedBy: $0) }) else {
            return nil
        }

        let host = challenge.protectionSpace.host
        if !host.isEmpty, !Self.certificate(leaf, matchesHost: host) {
            return nil
        }

        _ = SecTrustSetAnchorCertificates(trust, caCertificates as CFArray)
        _ = SecTrustSetAnchorCertificatesOnly(trust, true)
        var error: CFError?
        _ = SecTrustEvaluateWithError(trust, &error)
        return URLCredential(trust: trust)
    }

    static func leafCertificate(from trust: SecTrust) -> SecCertificate? {
        (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
    }

    static func certificate(_ leaf: SecCertificate, isIssuedBy ca: SecCertificate) -> Bool {
        if CFEqual(leaf, ca) {
            return true
        }
        guard let issuer = SecCertificateCopyNormalizedIssuerSequence(leaf) as Data?,
              let subject = SecCertificateCopyNormalizedSubjectSequence(ca) as Data?,
              !issuer.isEmpty,
              issuer == subject
        else {
            return false
        }
        return true
    }

    static func certificate(_ leaf: SecCertificate, matchesHost host: String) -> Bool {
        let expected = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        guard !expected.isEmpty else { return false }
        if let summary = SecCertificateCopySubjectSummary(leaf) as String?,
           nameMatches(summary, host: expected)
        {
            return true
        }
        // iOS has no SecCertificateCopyValues. The MITM leaf embeds the
        // CONNECT host as CN/SAN ASCII in the DER.
        let der = SecCertificateCopyData(leaf) as Data
        if der.range(of: Data(expected.utf8)) != nil {
            return true
        }
        return false
    }

    private static func nameMatches(_ name: String, host: String) -> Bool {
        let candidate = name.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        if candidate == host {
            return true
        }
        if candidate.hasPrefix("*.") {
            let suffix = candidate.dropFirst(1)
            return host.hasSuffix(suffix) && host != String(suffix.dropFirst())
        }
        return false
    }
}

@available(iOS 17.0, *)
final class WebViewDoHProxy {
    static let shared = WebViewDoHProxy()

    final class Lease {
        fileprivate let id: UUID
        let proxyConfiguration: ProxyConfiguration

        fileprivate init(id: UUID, proxyConfiguration: ProxyConfiguration) {
            self.id = id
            self.proxyConfiguration = proxyConfiguration
        }

        deinit {
            let id = id
            Task { @MainActor in
                WebViewDoHProxy.shared.release(id)
            }
        }
    }

    enum ProxyError: Error {
        case listenerStopped
        case unavailablePort
        case invalidDoHConfiguration
    }

    private let queue = DispatchQueue(label: "xyz.47258.dexo.webview-native-mitm")
    private var listener: NWListener?
    private var listenerPort: NWEndpoint.Port?
    private var certificateAuthority: WebViewProxyCertificateAuthority?
    private var leases = Set<UUID>()
    private var debugCaptureLeases = Set<UUID>()
    private var tunnels: [UUID: WebViewDoHMITMTunnel] = [:]
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
        WKWebsiteDataStore.default().proxyConfigurations = []
        stopListener(error: ProxyError.listenerStopped)
    }

    private func startListener() throws {
        let certificateAuthority = try WebViewProxyCertificateAuthority.loadOrCreate()
        self.certificateAuthority = certificateAuthority

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        let parameters = NWParameters(tls: nil, tcp: tcpOptions)
        parameters.allowLocalEndpointReuse = true
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let context = WebViewMITMFramerContext(certificateAuthority: certificateAuthority)
        parameters.defaultProtocolStack.applicationProtocols.insert(
            HTTPConnectMITMFramer.options(context: context),
            at: 0
        )

        let listener = try NWListener(using: parameters, on: .any)
        listener.newConnectionLimit = 128
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
            stopListener(error: error)
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
        let endpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: port)
        return Lease(
            id: id,
            proxyConfiguration: ProxyConfiguration(httpCONNECTProxy: endpoint)
        )
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
    }

    private func stopListener(error: Error?) {
        let activeListener = listener
        listener = nil
        listenerPort = nil
        certificateAuthority = nil
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

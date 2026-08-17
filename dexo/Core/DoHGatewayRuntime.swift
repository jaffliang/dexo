import DoHGatewayPolicy
import Foundation

/// Owns the Rust loopback listener and the configuration `URLProtocol` reads.
nonisolated final class DoHGatewayRuntime: @unchecked Sendable {
    static let shared = DoHGatewayRuntime()

    private let lock = NSLock()
    private var configuration = DoHGatewayPolicy.Configuration(
        isEnabled: false,
        gatewayPort: 0,
        dohHost: nil,
        connectPort: 0
    )
    private var lastErrorStorage: String?
    private var mitmCAStorage: Data?
    private var didRegisterURLProtocol = false
    private let workQueue = DispatchQueue(label: "com.eilgnaw.dexo.doh-gateway")

    private init() {}

    var currentConfiguration: DoHGatewayPolicy.Configuration {
        lock.lock()
        defer { lock.unlock() }
        return configuration
    }

    var lastError: String? {
        lock.lock()
        defer { lock.unlock() }
        return lastErrorStorage
    }

    /// CONNECT MITM CA (DER). Isolated WebViews trust this; it is not in the system store.
    var mitmCACertificateData: Data? {
        lock.lock()
        defer { lock.unlock() }
        return mitmCAStorage
    }

    /// True when `libdexo_doh_gateway.a` was built with Encrypted Client Hello.
    static var echCompiled: Bool {
        dexo_doh_gateway_ech_compiled() != 0
    }

    static var echCompiledLabel: String {
        echCompiled
            ? String(localized: "settings.doh.ech_compiled.yes")
            : String(localized: "settings.doh.ech_compiled.no")
    }

    /// Inserts the gateway `URLProtocol` into every URLSession the app creates
    /// for forum API / image traffic. Safe to call more than once.
    static func prepare(_ configuration: URLSessionConfiguration) {
        DoHGatewayURLProtocol.register(on: configuration)
    }

    /// Starts or stops the Rust listener on a dedicated queue so `block_on(probe)`
    /// never runs on the main thread (settings freeze / next-launch black screen).
    func applyAsync(
        enabled: Bool,
        serverURLString: String,
        completion: @escaping (Bool) -> Void
    ) {
        workQueue.async { [self] in
            let ok = self.setEnabled(enabled, serverURLString: serverURLString)
            DispatchQueue.main.async {
                completion(ok)
            }
        }
    }

    /// Synchronous start/stop. Call from `workQueue` or tests that return
    /// before FFI I/O (invalid URL). A real start `block_on`s the probe.
    @discardableResult
    func setEnabled(_ enabled: Bool, serverURLString: String) -> Bool {
        stopListener()
        lock.lock()
        lastErrorStorage = nil
        lock.unlock()
        guard enabled else { return true }
        guard let serverURL = DoHGatewayPolicy.normalizedDoHURL(serverURLString) else {
            recordError("DoH URL must be HTTPS")
            return false
        }

        let port = serverURL.absoluteString.withCString { cString in
            dexo_doh_gateway_start(cString, 0)
        }
        guard port > 0 else {
            let reason = Self.gatewayLastErrorText()
            recordError(reason)
            print("[DoHGateway] failed to start listener (code \(port)): \(reason)")
            return false
        }

        let connectPort = dexo_doh_gateway_connect_port()
        let caData = Self.copyMitmCACertificate()
        lock.lock()
        configuration = DoHGatewayPolicy.Configuration(
            isEnabled: true,
            gatewayPort: Int(port),
            dohHost: serverURL.host,
            connectPort: Int(connectPort)
        )
        mitmCAStorage = caData
        lock.unlock()
        registerGlobalURLProtocol()
        print(
            "[DoHGateway] URLSession HTTP 127.0.0.1:\(port) WebView CONNECT 127.0.0.1:\(connectPort) doh=\(serverURL.absoluteString)"
        )
        return true
    }

    func stop() {
        stopListener()
    }

    private static func copyMitmCACertificate() -> Data? {
        var length: size_t = 0
        guard let pointer = dexo_doh_gateway_mitm_ca_der(&length), length > 0 else {
            return nil
        }
        return Data(bytes: pointer, count: Int(length))
    }

    private func recordError(_ message: String) {
        lock.lock()
        lastErrorStorage = message
        lock.unlock()
    }

    private static func gatewayLastErrorText() -> String {
        guard let pointer = dexo_doh_gateway_last_error() else {
            return "DoH gateway failed to start"
        }
        let text = String(cString: pointer)
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "DoH gateway failed to start" : trimmed
    }

    private func stopListener() {
        dexo_doh_gateway_stop()
        unregisterGlobalURLProtocol()
        lock.lock()
        configuration = DoHGatewayPolicy.Configuration(
            isEnabled: false,
            gatewayPort: 0,
            dohHost: nil,
            connectPort: 0
        )
        mitmCAStorage = nil
        lock.unlock()
    }

    /// So `URLSession.shared` and configs that missed `prepare` still rewrite.
    /// The inner Relay session sets `protocolClasses = []` and will not recurse.
    private func registerGlobalURLProtocol() {
        lock.lock()
        let already = didRegisterURLProtocol
        if !already { didRegisterURLProtocol = true }
        lock.unlock()
        guard !already else { return }
        URLProtocol.registerClass(DoHGatewayURLProtocol.self)
    }

    private func unregisterGlobalURLProtocol() {
        lock.lock()
        let shouldUnregister = didRegisterURLProtocol
        didRegisterURLProtocol = false
        lock.unlock()
        guard shouldUnregister else { return }
        URLProtocol.unregisterClass(DoHGatewayURLProtocol.self)
    }
}

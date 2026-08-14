import DoHGatewayPolicy
import Foundation

/// Owns the Rust loopback listener and the configuration `URLProtocol` reads.
nonisolated final class DoHGatewayRuntime: @unchecked Sendable {
    static let shared = DoHGatewayRuntime()

    private let lock = NSLock()
    private var configuration = DoHGatewayPolicy.Configuration(
        isEnabled: false,
        gatewayPort: 0,
        dohHost: nil
    )
    private var lastErrorStorage: String?

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

        lock.lock()
        configuration = DoHGatewayPolicy.Configuration(
            isEnabled: true,
            gatewayPort: Int(port),
            dohHost: serverURL.host
        )
        lock.unlock()
        print("[DoHGateway] URLSession/Alamofire traffic via 127.0.0.1:\(port) doh=\(serverURL.absoluteString)")
        return true
    }

    func stop() {
        stopListener()
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
        lock.lock()
        configuration = DoHGatewayPolicy.Configuration(
            isEnabled: false,
            gatewayPort: 0,
            dohHost: nil
        )
        lock.unlock()
    }
}

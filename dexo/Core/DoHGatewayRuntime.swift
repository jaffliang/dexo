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

    private init() {}

    var currentConfiguration: DoHGatewayPolicy.Configuration {
        lock.lock()
        defer { lock.unlock() }
        return configuration
    }

    /// Inserts the gateway `URLProtocol` into every URLSession the app creates
    /// for forum API / image traffic. Safe to call more than once.
    static func prepare(_ configuration: URLSessionConfiguration) {
        DoHGatewayURLProtocol.register(on: configuration)
    }

    @discardableResult
    func setEnabled(_ enabled: Bool, serverURLString: String) -> Bool {
        stopListener()
        guard enabled else { return true }
        guard let serverURL = DoHGatewayPolicy.normalizedDoHURL(serverURLString) else {
            return false
        }

        let port = serverURL.absoluteString.withCString { cString in
            dexo_doh_gateway_start(cString, 0)
        }
        guard port > 0 else {
            print("[DoHGateway] failed to start listener (code \(port))")
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

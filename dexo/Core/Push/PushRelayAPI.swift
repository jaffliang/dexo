import Foundation

struct PushRelayEndpointRequest: Encodable, Sendable {
    let version: Int
    let apnsToken: String
    let apnsEnvironment: String
    let subscriptionID: String
    let forumBaseURL: String
    let forumVAPIDPublicKey: String

    enum CodingKeys: String, CodingKey {
        case version
        case apnsToken = "apns_token"
        case apnsEnvironment = "apns_environment"
        case subscriptionID = "subscription_id"
        case forumBaseURL = "forum_base_url"
        case forumVAPIDPublicKey = "forum_vapid_public_key"
    }
}

struct PushRelayEndpointResponse: Decodable, Sendable {
    let version: Int
    let endpoint: String
    let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case version, endpoint
        case expiresAt = "expires_at"
    }
}

private struct PushRelayEndpointRevocationRequest: Encodable, Sendable {
    let version = 1
    let endpoint: String
}

final class PushRelayAPI: Sendable {
    private let session: URLSession
    private let baseURL: URL

    init(baseURL: URL) {
        self.baseURL = baseURL
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        DoHGatewayRuntime.prepare(configuration)
        session = URLSession(configuration: configuration)
    }

    func createEndpoint(_ input: PushRelayEndpointRequest) async throws -> PushRelayEndpointResponse {
        let url = baseURL.appendingPathComponent("v1/endpoints")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.httpBody = try JSONEncoder().encode(input)
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else {
#if DEBUG
            print("[PushRelayAPI] POST /v1/endpoints returned a non-HTTP response")
#endif
            throw PushSubscriptionError.relayRejected
        }
#if DEBUG
        Self.logResponse(data: data, statusCode: response.statusCode)
#endif
        guard (200 ..< 300).contains(response.statusCode) else {
            throw PushSubscriptionError.relayRejected
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let output = try decoder.decode(PushRelayEndpointResponse.self, from: data)
#if DEBUG
        print(
            "[PushRelayAPI] endpoint response version=\(output.version) " +
                "host=" +
                "expiresAt=\(output.expiresAt)"
        )
#endif
        guard output.version == 1,
              output.endpoint.hasPrefix(baseURL.absoluteString + "/v1/webpush/")
        else {
            throw PushSubscriptionError.relayRejected
        }
        return output
    }

    /// Revocation is capability-based: the relay opens its own sealed endpoint,
    /// extracts the opaque subscription ID, and persists only an HMAC index.
    func revokeEndpoint(_ endpoint: String) async throws {
        let url = baseURL.appendingPathComponent("v1/revocations")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.httpBody = try JSONEncoder().encode(
            PushRelayEndpointRevocationRequest(endpoint: endpoint)
        )
        let (_, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse,
              (200 ..< 300).contains(response.statusCode) else {
            throw PushSubscriptionError.relayRejected
        }
    }

#if DEBUG
    private static func logResponse(data: Data, statusCode: Int) {
        if (200 ..< 300).contains(statusCode) {
            // A successful body contains the sealed APNs routing endpoint. Never log it.
            print("[PushRelayAPI] POST /v1/endpoints status=\(statusCode) body=<redacted>")
            return
        }
        let body = String(data: data.prefix(1_024), encoding: .utf8) ?? "<non-UTF8 body>"
        print("[PushRelayAPI] POST /v1/endpoints status=\(statusCode) body=\(body)")
    }
#endif
}

import Foundation

/// Outcome of Discourse `POST /session.json` (often HTTP 200 even on failure).
enum PasswordLoginSessionOutcome: Equatable {
    case signedIn
    case invalidCredentials
    case needsSecondFactor
    case failed(status: Int, body: String)
}

enum PasswordLoginSessionResponse {
    struct ParsedBody: Equatable {
        var reason: String?
        var error: String?
        var hasUser: Bool
    }

    static func interpret(status: Int, body: String) -> PasswordLoginSessionOutcome {
        let parsed = parseBody(body)
        let reason = parsed.reason?.lowercased() ?? ""

        if isSecondFactorReason(reason) || looksLikeSecondFactor(body) {
            return .needsSecondFactor
        }
        if isInvalidCredentialsReason(reason) {
            return .invalidCredentials
        }
        if status == 200, parsed.hasUser, parsed.error == nil {
            return .signedIn
        }
        if status == 200, parsed.error == nil, parsed.reason == nil, looksLikeJSONObject(body) {
            return .signedIn
        }
        return .failed(status: status, body: displayBody(status: status, parsed: parsed, raw: body))
    }

    static func parseBody(_ body: String) -> ParsedBody {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return ParsedBody(reason: nil, error: nil, hasUser: false)
        }
        let reason = trimmedNonEmpty(json["reason"] as? String)
        let error = trimmedNonEmpty(json["error"] as? String)
        let hasUser: Bool
        if let user = json["user"] as? [String: Any] {
            hasUser = user["id"] != nil || user["username"] != nil
        } else {
            hasUser = false
        }
        return ParsedBody(reason: reason, error: error, hasUser: hasUser)
    }

    static func looksLikeSecondFactor(_ body: String) -> Bool {
        let lower = body.lowercased()
        return lower.contains("second_factor")
            || lower.contains("second-factor")
            || lower.contains("two_factor")
            || lower.contains("totp")
            || lower.contains("second factor")
            || lower.contains("backup_code")
    }

    static func isSecondFactorReason(_ reason: String) -> Bool {
        let r = reason.lowercased()
        return r.contains("second_factor")
            || r.contains("second-factor")
            || r.contains("totp")
            || r.contains("backup_code")
    }

    static func isInvalidCredentialsReason(_ reason: String) -> Bool {
        let r = reason.lowercased()
        return r == "invalid_credentials"
            || r == "incorrect_username"
            || r == "incorrect_password"
    }

    private static func displayBody(status: Int, parsed: ParsedBody, raw: String) -> String {
        if status == 200, let error = parsed.error, !error.isEmpty {
            if let reason = parsed.reason, !reason.isEmpty {
                return "\(error) (\(reason))"
            }
            return error
        }
        return raw
    }

    private static func trimmedNonEmpty(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func looksLikeJSONObject(_ body: String) -> Bool {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix("{") && trimmed.hasSuffix("}")
    }
}

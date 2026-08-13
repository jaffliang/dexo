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
        var secondFactorRequired: Bool
    }

    /// In-place Cloudflare interstitial retry is only for Discourse CSRF 403.
    /// `phase=evaluate` / `执行JavaScript返回结果的类型不受支持` is an iOS 15
    /// Promise-bridge false failure, not Cloudflare.
    static func shouldRetryCloudflareChallenge(phase: String, status: Int) -> Bool {
        phase == "csrf" && status == 403
    }

    static func interpret(status: Int, body: String) -> PasswordLoginSessionOutcome {
        let parsed = parseBody(body)
        let reason = parsed.reason?.lowercased() ?? ""

        if requiresSecondFactor(parsed) {
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
            return ParsedBody(reason: nil, error: nil, hasUser: false, secondFactorRequired: false)
        }
        let reason = trimmedNonEmpty(json["reason"] as? String)
        let error = trimmedNonEmpty(json["error"] as? String)
        let hasUser: Bool
        if let user = json["user"] as? [String: Any] {
            hasUser = user["id"] != nil || user["username"] != nil
        } else {
            hasUser = false
        }
        // Capability flags like `totp_enabled: false` must not count as a challenge.
        let secondFactorRequired = isTruthyFlag(json["second_factor_required"])
        return ParsedBody(
            reason: reason,
            error: error,
            hasUser: hasUser,
            secondFactorRequired: secondFactorRequired
        )
    }

    /// 2FA only from parsed JSON fields — never a raw-body substring.
    /// Successful `/session.json` often includes `"totp_enabled": false` on `user`.
    static func requiresSecondFactor(_ parsed: ParsedBody) -> Bool {
        if isSecondFactorReason(parsed.reason ?? "") {
            return true
        }
        if parsed.secondFactorRequired {
            return true
        }
        return errorRequiresSecondFactor(parsed.error)
    }

    static func isSecondFactorReason(_ reason: String) -> Bool {
        switch reason.lowercased() {
        case "second_factor", "invalid_second_factor", "second_factor_required":
            return true
        default:
            return false
        }
    }

    static func isInvalidCredentialsReason(_ reason: String) -> Bool {
        let r = reason.lowercased()
        return r == "invalid_credentials"
            || r == "incorrect_username"
            || r == "incorrect_password"
    }

    private static func errorRequiresSecondFactor(_ error: String?) -> Bool {
        guard let error else { return false }
        let e = error.lowercased()
        return e.contains("second_factor_required")
            || e.contains("second_factor")
            || e.contains("second-factor")
            || e.contains("second factor")
            || e.contains("two_factor")
            || e.contains("two-factor")
            || e.contains("two factor")
            || e.contains("invalid totp")
            || e.contains("totp challenge")
    }

    private static func isTruthyFlag(_ value: Any?) -> Bool {
        if let flag = value as? Bool {
            return flag
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        if let string = value as? String {
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return trimmed == "true" || trimmed == "1" || trimmed == "yes"
        }
        return false
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

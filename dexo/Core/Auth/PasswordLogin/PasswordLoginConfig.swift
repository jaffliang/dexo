import Foundation

/// Host-specific knobs for Cloudflare-aware password login.
/// Site keys are public values embedded in the forum's login page.
struct PasswordLoginConfig: Sendable {
    let host: String
    let hCaptchaSiteKey: String
    let hCaptchaCreateEndpoints: [String]
    let challengeURL: URL?

    static let linuxDo = PasswordLoginConfig(
        host: "linux.do",
        hCaptchaSiteKey: "a776b4ac-8c4c-441e-986a-c6ee9ed8cf08",
        hCaptchaCreateEndpoints: [
            "/captcha/hcaptcha/create.json",
            "/hcaptcha/create.json",
        ],
        challengeURL: URL(string: "https://linux.do/challenge")
    )

    private static let all: [PasswordLoginConfig] = [.linuxDo]

    static func config(for baseURL: String) -> PasswordLoginConfig? {
        guard let host = URL(string: baseURL)?.host?.lowercased() else { return nil }
        return all.first { $0.host == host }
    }

    static func supportsPasswordLogin(for baseURL: String) -> Bool {
        config(for: baseURL) != nil
    }
}

enum PasswordLoginError: Error, LocalizedError {
    case canceled
    case unsupportedForum
    case cloudflareFailed
    case captchaFailed
    case invalidCredentials
    case secondFactorFailed
    case csrfBlocked
    case missingSessionCookie
    case unexpected(status: Int, phase: String, body: String)

    var errorDescription: String? {
        switch self {
        case .canceled:
            return String(localized: "password_login.error.canceled")
        case .unsupportedForum:
            return String(localized: "password_login.error.unsupported")
        case .cloudflareFailed:
            return String(localized: "password_login.error.cloudflare")
        case .captchaFailed:
            return String(localized: "password_login.error.captcha")
        case .invalidCredentials:
            return String(localized: "password_login.error.credentials")
        case .secondFactorFailed:
            return String(localized: "password_login.error.second_factor")
        case .csrfBlocked:
            return String(localized: "password_login.error.csrf")
        case .missingSessionCookie:
            return String(localized: "password_login.error.session")
        case .unexpected:
            return String(localized: "password_login.error.unknown")
        }
    }
}

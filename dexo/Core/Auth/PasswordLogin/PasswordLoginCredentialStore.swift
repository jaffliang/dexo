import Foundation

/// Keychain-backed username/password for password login, scoped per forum.
/// The remember-me preference is a non-secret UserDefaults flag; the password
/// itself is never written to UserDefaults.
enum PasswordLoginCredentialStore {
    private static let rememberDefaultsPrefix = "passwordLogin.remember."

    struct Credentials: Codable {
        var identifier: String
        var password: String
    }

    static func normalizedBaseURL(_ baseURL: String) -> String {
        baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    static func rememberEnabled(for baseURL: String) -> Bool {
        let key = rememberKey(for: baseURL)
        if UserDefaults.standard.object(forKey: key) == nil {
            return true
        }
        return UserDefaults.standard.bool(forKey: key)
    }

    static func setRememberEnabled(_ enabled: Bool, for baseURL: String) {
        UserDefaults.standard.set(enabled, forKey: rememberKey(for: baseURL))
    }

    static func save(identifier: String, password: String, for baseURL: String) throws {
        let payload = Credentials(identifier: identifier, password: password)
        let data = try JSONEncoder().encode(payload)
        try KeychainHelper.savePasswordLoginCredentials(data, for: normalizedBaseURL(baseURL))
    }

    static func load(for baseURL: String) -> Credentials? {
        guard let data = KeychainHelper.getPasswordLoginCredentials(for: normalizedBaseURL(baseURL)) else {
            return nil
        }
        return try? JSONDecoder().decode(Credentials.self, from: data)
    }

    static func delete(for baseURL: String) {
        KeychainHelper.deletePasswordLoginCredentials(for: normalizedBaseURL(baseURL))
    }

    private static func rememberKey(for baseURL: String) -> String {
        rememberDefaultsPrefix + normalizedBaseURL(baseURL)
    }
}

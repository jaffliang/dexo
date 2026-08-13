import Foundation
import Security

enum KeychainHelper {

    // MARK: - User API Key (GenericPassword)

    static func saveUserApiKey(_ key: String, for baseURL: String) throws {
        let data = Data(key.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.eilgnaw.dexo.userApiKey",
            kSecAttrAccount as String: baseURL,
        ]

        // Updating an existing item is atomic: if the update fails, Keychain
        // keeps the previous credential intact. Never delete-first here,
        // because a transient Keychain failure must not log the user out.
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: updateStatus)
        }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return
        }

        // Another writer may have inserted the item between the update and
        // add. Retrying the atomic update resolves that race without deleting
        // either value.
        if status == errSecDuplicateItem {
            let retryStatus = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard retryStatus == errSecSuccess else {
                throw KeychainError.unhandledError(status: retryStatus)
            }
            return
        }

        throw KeychainError.unhandledError(status: status)
    }

    static func getUserApiKey(for baseURL: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.eilgnaw.dexo.userApiKey",
            kSecAttrAccount as String: baseURL,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    static func deleteUserApiKey(for baseURL: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.eilgnaw.dexo.userApiKey",
            kSecAttrAccount as String: baseURL,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Password Login Credentials (GenericPassword)

    private static let passwordLoginService = "com.eilgnaw.dexo.passwordLogin"

    /// Persists identifier + password for a forum. Never log the payload.
    static func savePasswordLoginCredentials(_ payload: Data, for baseURL: String) throws {
        try saveGenericPassword(payload, service: passwordLoginService, account: baseURL)
    }

    static func getPasswordLoginCredentials(for baseURL: String) -> Data? {
        getGenericPassword(service: passwordLoginService, account: baseURL)
    }

    static func deletePasswordLoginCredentials(for baseURL: String) {
        deleteGenericPassword(service: passwordLoginService, account: baseURL)
    }

    private static func saveGenericPassword(_ data: Data, service: String, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: updateStatus)
        }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return
        }

        if status == errSecDuplicateItem {
            let retryStatus = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard retryStatus == errSecSuccess else {
                throw KeychainError.unhandledError(status: retryStatus)
            }
            return
        }

        throw KeychainError.unhandledError(status: status)
    }

    private static func getGenericPassword(service: String, account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    private static func deleteGenericPassword(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - RSA Key Pair

    private static func rsaTag(for baseURL: String) -> String {
        "com.eilgnaw.dexo.rsaKey.\(baseURL)"
    }

    @discardableResult
    static func generateAndStoreRSAKeyPair(for baseURL: String) throws -> SecKey {
        // Delete any existing key pair first
        deleteRSAKeyPair(for: baseURL)

        let tag = rsaTag(for: baseURL)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 4096,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }

    static func getRSAPrivateKey(for baseURL: String) -> SecKey? {
        let tag = rsaTag(for: baseURL)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as! SecKey?
    }

    static func deleteRSAKeyPair(for baseURL: String) {
        let tag = rsaTag(for: baseURL)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Export Public Key PEM

    static func exportPublicKeyPEM(from privateKey: SecKey) throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeychainError.publicKeyExportFailed
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        // SecKeyCopyExternalRepresentation returns PKCS#1 (RSAPublicKey) format.
        // Discourse expects PKCS#8 SubjectPublicKeyInfo PEM.
        // Build proper PKCS#8 wrapper with correct lengths.
        let bitStringContent = Data([0x00]) + publicKeyData // 0x00 = unused bits prefix
        let bitString = asn1LengthPrefixed(tag: 0x03, content: bitStringContent)

        let algorithmIdentifier = Data([
            0x30, 0x0D,
            0x06, 0x09,
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00,
        ])

        let sequenceContent = algorithmIdentifier + bitString
        let pkcs8Data = asn1LengthPrefixed(tag: 0x30, content: sequenceContent)

        let base64 = pkcs8Data.base64EncodedString(options: .lineLength64Characters)
        return "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----"
    }

    private static func asn1LengthPrefixed(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        let length = content.count
        if length < 0x80 {
            result.append(UInt8(length))
        } else if length <= 0xFF {
            result.append(contentsOf: [0x81, UInt8(length)])
        } else {
            result.append(contentsOf: [0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
        }
        result.append(content)
        return result
    }
}

// MARK: - Errors

enum KeychainError: Error, LocalizedError {
    case unhandledError(status: OSStatus)
    case publicKeyExportFailed

    var errorDescription: String? {
        switch self {
        case .unhandledError(let status):
            return "Keychain error: \(status)"
        case .publicKeyExportFailed:
            return "Failed to export public key"
        }
    }
}

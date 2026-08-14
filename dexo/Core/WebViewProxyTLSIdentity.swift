import Foundation
import Security

nonisolated final class WebViewProxyTLSIdentity: @unchecked Sendable {
    let host: String
    let networkIdentity: sec_identity_t
    let leafCertificateData: Data

    init(host: String, networkIdentity: sec_identity_t, leafCertificateData: Data) {
        self.host = host
        self.networkIdentity = networkIdentity
        self.leafCertificateData = leafCertificateData
    }
}

/// App-local certificate authority for the WKWebView DoH proxy. A leaf
/// certificate with an exact SAN is generated and signed for every CONNECT
/// hostname. Nothing is installed into the system trust store.
nonisolated final class WebViewProxyCertificateAuthority: @unchecked Sendable {
    enum AuthorityError: Error {
        case caPrivateKeyLookupFailed(OSStatus)
        case caCertificateLookupFailed(OSStatus)
        case caPrivateKeyGenerationFailed(CFError?)
        case missingCAPublicKey
        case caPublicKeyExportFailed(CFError?)
        case caCertificateGenerationFailed(CFError?)
        case invalidCACertificate
        case caCertificateAddFailed(OSStatus)
        case leafPrivateKeyGenerationFailed(CFError?)
        case missingLeafPublicKey
        case publicKeyExportFailed(CFError?)
        case certificateGenerationFailed(CFError?)
        case invalidCertificate
        case certificateAddFailed(OSStatus)
        case identityLookupFailed(OSStatus)
        case identityCertificateMismatch
        case identityBridgeFailed
    }

    let certificate: SecCertificate

    private struct KeychainMaterial {
        let keyTag: Data
        let certificateLabel: String
    }

    private let caPrivateKey: SecKey
    private let sessionID = UUID().uuidString
    private let lock = NSLock()
    private var identities: [String: WebViewProxyTLSIdentity] = [:]
    private var keychainMaterials: [KeychainMaterial] = []

    private static let storageLock = NSLock()
    private static let caKeyTag = Data(
        "com.eilgnaw.dexo.webview-mitm.ca-key.v1".utf8
    )
    private static let caCertificateLabel = "Dexo Local DoH CA v1"

    private init(
        caPrivateKey: SecKey,
        certificate: SecCertificate
    ) {
        self.caPrivateKey = caPrivateKey
        self.certificate = certificate
    }

    static func loadOrCreate() throws -> WebViewProxyCertificateAuthority {
        storageLock.lock()
        defer { storageLock.unlock() }

        let storedPrivateKey = try loadCAPrivateKey()
        let storedCertificate = try loadCACertificate()
        if let storedPrivateKey,
           let storedCertificate,
           caCertificate(storedCertificate, matches: storedPrivateKey)
        {
            return WebViewProxyCertificateAuthority(
                caPrivateKey: storedPrivateKey,
                certificate: storedCertificate
            )
        }

        // A partial or mismatched pair can be left behind if generation was
        // interrupted. Replace it atomically from the app's point of view.
        deleteStoredCA()
        return try createAndStoreCA()
    }

    private static func loadCAPrivateKey() throws -> SecKey? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrApplicationTag as String: caKeyTag,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ] as CFDictionary,
            &result
        )
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let result else {
            throw AuthorityError.caPrivateKeyLookupFailed(status)
        }
        return (result as! SecKey)
    }

    private static func loadCACertificate() throws -> SecCertificate? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: caCertificateLabel,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ] as CFDictionary,
            &result
        )
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let result else {
            throw AuthorityError.caCertificateLookupFailed(status)
        }
        return (result as! SecCertificate)
    }

    private static func caCertificate(
        _ certificate: SecCertificate,
        matches privateKey: SecKey
    ) -> Bool {
        guard let expectedPublicKey = SecKeyCopyPublicKey(privateKey),
              let certificatePublicKey = SecCertificateCopyKey(certificate)
        else {
            return false
        }

        var expectedError: Unmanaged<CFError>?
        var certificateError: Unmanaged<CFError>?
        guard let expectedBytes = SecKeyCopyExternalRepresentation(
            expectedPublicKey,
            &expectedError
        ),
            let certificateBytes = SecKeyCopyExternalRepresentation(
                certificatePublicKey,
                &certificateError
            )
        else {
            return false
        }
        return expectedBytes as Data == certificateBytes as Data
    }

    private static func createAndStoreCA() throws -> WebViewProxyCertificateAuthority {
        var shouldCleanUp = true
        defer {
            if shouldCleanUp {
                deleteStoredCA()
            }
        }

        var keyError: Unmanaged<CFError>?
        var keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: caKeyTag,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            ],
        ]
        #if !targetEnvironment(simulator)
        // Device builds keep the signing key non-exportable in Secure Enclave.
        // Simulators use the ordinary Keychain because no Secure Enclave exists.
        keyAttributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        guard let privateKey = SecKeyCreateRandomKey(
            keyAttributes as CFDictionary,
            &keyError
        ) else {
            throw AuthorityError.caPrivateKeyGenerationFailed(
                keyError?.takeRetainedValue()
            )
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw AuthorityError.missingCAPublicKey
        }
        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(
            publicKey,
            &exportError
        ) else {
            throw AuthorityError.caPublicKeyExportFailed(
                exportError?.takeRetainedValue()
            )
        }

        let tbsCertificate = try WebViewProxyX509Builder.makeCATBSCertificate(
            publicKeyBytes: publicKeyData as Data
        )
        var signatureError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            tbsCertificate as CFData,
            &signatureError
        ) else {
            throw AuthorityError.caCertificateGenerationFailed(
                signatureError?.takeRetainedValue()
            )
        }
        let certificateData = WebViewProxyX509Builder.makeCertificate(
            tbsCertificate: tbsCertificate,
            signature: signature as Data
        )
        guard let certificate = SecCertificateCreateWithData(
            nil,
            certificateData as CFData
        ) else {
            throw AuthorityError.invalidCACertificate
        }

        let addStatus = SecItemAdd(
            [
                kSecValueRef as String: certificate,
                kSecAttrLabel as String: caCertificateLabel,
            ] as CFDictionary,
            nil
        )
        guard addStatus == errSecSuccess else {
            throw AuthorityError.caCertificateAddFailed(addStatus)
        }

        shouldCleanUp = false
        return WebViewProxyCertificateAuthority(
            caPrivateKey: privateKey,
            certificate: certificate
        )
    }

    private static func deleteStoredCA() {
        SecItemDelete(
            [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: caCertificateLabel,
            ] as CFDictionary
        )
        SecItemDelete(
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: caKeyTag,
            ] as CFDictionary
        )
    }

    func identity(for rawHost: String) throws -> WebViewProxyTLSIdentity {
        let host = rawHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        lock.lock()
        defer { lock.unlock() }
        if let cached = identities[host] {
            return cached
        }

        let keyTag = Data("com.eilgnaw.dexo.webview-mitm.\(sessionID).\(UUID().uuidString)".utf8)
        let certificateLabel = "Dexo WebView MITM \(sessionID) \(host)"
        var shouldCleanUp = true
        defer {
            if shouldCleanUp {
                Self.deleteKeychainMaterial(
                    KeychainMaterial(
                        keyTag: keyTag,
                        certificateLabel: certificateLabel
                    )
                )
            }
        }

        var keyError: Unmanaged<CFError>?
        let leafKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            ],
        ]
        guard let leafPrivateKey = SecKeyCreateRandomKey(
            leafKeyAttributes as CFDictionary,
            &keyError
        ) else {
            throw AuthorityError.leafPrivateKeyGenerationFailed(
                keyError?.takeRetainedValue()
            )
        }
        guard let leafPublicKey = SecKeyCopyPublicKey(leafPrivateKey) else {
            throw AuthorityError.missingLeafPublicKey
        }
        var exportError: Unmanaged<CFError>?
        guard let leafPublicKeyData = SecKeyCopyExternalRepresentation(
            leafPublicKey,
            &exportError
        ) else {
            throw AuthorityError.publicKeyExportFailed(exportError?.takeRetainedValue())
        }

        let tbsCertificate = try WebViewProxyX509Builder.makeTBSCertificate(
            host: host,
            publicKeyBytes: leafPublicKeyData as Data
        )
        var signatureError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            caPrivateKey,
            .ecdsaSignatureMessageX962SHA256,
            tbsCertificate as CFData,
            &signatureError
        ) else {
            throw AuthorityError.certificateGenerationFailed(
                signatureError?.takeRetainedValue()
            )
        }
        let certificateData = WebViewProxyX509Builder.makeCertificate(
            tbsCertificate: tbsCertificate,
            signature: signature as Data
        )
        guard let leafCertificate = SecCertificateCreateWithData(
            nil,
            certificateData as CFData
        ) else {
            throw AuthorityError.invalidCertificate
        }

        let addCertificateStatus = SecItemAdd(
            [
                kSecValueRef as String: leafCertificate,
                kSecAttrLabel as String: certificateLabel,
            ] as CFDictionary,
            nil
        )
        guard addCertificateStatus == errSecSuccess else {
            throw AuthorityError.certificateAddFailed(addCertificateStatus)
        }

        var identityResult: CFTypeRef?
        let identityStatus = SecItemCopyMatching(
            [
                kSecClass as String: kSecClassIdentity,
                kSecAttrLabel as String: certificateLabel,
                kSecReturnRef as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ] as CFDictionary,
            &identityResult
        )
        guard identityStatus == errSecSuccess, let identityResult else {
            throw AuthorityError.identityLookupFailed(identityStatus)
        }
        let leafSecurityIdentity = identityResult as! SecIdentity

        var identityCertificate: SecCertificate?
        guard SecIdentityCopyCertificate(
            leafSecurityIdentity,
            &identityCertificate
        ) == errSecSuccess,
            let identityCertificate,
            SecCertificateCopyData(identityCertificate) as Data == certificateData
        else {
            throw AuthorityError.identityCertificateMismatch
        }

        // The SecIdentity already contributes the dynamic leaf. The explicit
        // certificate array contains only the additional issuer certificate;
        // including the leaf here duplicates it in the TLS Certificate list.
        guard let networkIdentity = sec_identity_create_with_certificates(
            leafSecurityIdentity,
            [certificate] as CFArray
        ) else {
            throw AuthorityError.identityBridgeFailed
        }

        let generated = WebViewProxyTLSIdentity(
            host: host,
            networkIdentity: networkIdentity,
            leafCertificateData: certificateData
        )
        identities[host] = generated
        keychainMaterials.append(
            KeychainMaterial(
                keyTag: keyTag,
                certificateLabel: certificateLabel
            )
        )
        shouldCleanUp = false
        return generated
    }

    func removeGeneratedIdentities() {
        lock.lock()
        let materials = keychainMaterials
        keychainMaterials.removeAll()
        identities.removeAll()
        lock.unlock()

        materials.forEach(Self.deleteKeychainMaterial)
    }

    deinit {
        removeGeneratedIdentities()
    }

    private static func deleteKeychainMaterial(_ material: KeychainMaterial) {
        SecItemDelete(
            [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: material.certificateLabel,
            ] as CFDictionary
        )
        SecItemDelete(
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: material.keyTag,
            ] as CFDictionary
        )
    }

}

import Foundation
import WebKit

/// Swift entry points for the iOS 15/16 WKWebView HTTP proxy hooks.
enum WebViewLegacyHTTPProxy {
    static func apply(port: UInt16, to dataStore: WKWebsiteDataStore) -> Bool {
        WKWebsiteDataStore.dexo_applyProxyPort(port, to: dataStore)
    }

    static func clear(_ dataStore: WKWebsiteDataStore) {
        WKWebsiteDataStore.dexo_clearProxy(on: dataStore)
    }

    static func makeNonPersistentDataStore(port: UInt16) -> WKWebsiteDataStore? {
        WKWebsiteDataStore.dexo_makeNonPersistentStore(proxyPort: port)
    }

    static func supportsProxyConfiguration(_ dataStore: WKWebsiteDataStore) -> Bool {
        WKWebsiteDataStore.dexo_supportsProxyConfiguration(dataStore)
    }

    static func lastFailureReason() -> String? {
        WKWebsiteDataStore.dexo_lastFailureReason()
    }

    static func attachFailureReason(port: UInt16, dataStore: WKWebsiteDataStore) -> String {
        var parts: [String] = []
        if port == 0 {
            parts.append("port=0")
        }
        if supportsProxyConfiguration(dataStore) {
            parts.append("_setProxyConfiguration: available but apply failed")
        } else {
            parts.append("_setProxyConfiguration: not available")
        }
        parts.append("_WKWebsiteDataStoreConfiguration/_initWithConfiguration: returned nil")
        if let lastFailure = lastFailureReason(), !lastFailure.isEmpty {
            parts.append(lastFailure)
        }
        return parts.joined(separator: "; ")
    }
}

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
}

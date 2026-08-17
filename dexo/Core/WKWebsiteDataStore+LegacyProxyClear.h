#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Clears leftover HTTP proxies on `WKWebsiteDataStore` via string selectors
/// only. Covers `_setProxyConfiguration:` and the iOS 15 CONNECT-era
/// `_setHTTPProxy:` / `httpProxy` fields. Does not apply a proxy, create a
/// store, or start a listener.
@interface WKWebsiteDataStore (DexoLegacyProxyClear)

+ (void)dexo_clearProxyConfigurationOnDataStore:(WKWebsiteDataStore *)dataStore
    NS_SWIFT_NAME(dexo_clearProxyConfiguration(_:));

@end

NS_ASSUME_NONNULL_END

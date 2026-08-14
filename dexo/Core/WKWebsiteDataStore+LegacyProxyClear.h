#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Clears a leftover HTTP proxy on `WKWebsiteDataStore` via string selectors
/// only (`_setProxyConfiguration:` / `setProxyConfiguration:`). Does not
/// apply a proxy, create a store, or start a listener.
@interface WKWebsiteDataStore (DexoLegacyProxyClear)

+ (void)dexo_clearProxyConfigurationOnDataStore:(WKWebsiteDataStore *)dataStore
    NS_SWIFT_NAME(dexo_clearProxyConfiguration(_:));

@end

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

/// iOS 15/16 have no public per-WKWebView proxy API (`ProxyConfiguration` is
/// iOS 17+). These helpers talk to WebKit only through string selectors so the
/// app does not link private symbols. Used solely for Cloudflare-clearance
/// WebViews while DoH is on.
@interface WKWebsiteDataStore (DexoLegacyDoHProxy)

+ (nullable WKWebsiteDataStore *)dexo_nonPersistentDataStoreWithLoopbackHTTPProxyPort:(uint16_t)port
    NS_SWIFT_NAME(dexo_makeNonPersistentStore(proxyPort:));

+ (BOOL)dexo_applyLoopbackHTTPProxyPort:(uint16_t)port toDataStore:(WKWebsiteDataStore *)dataStore
    NS_SWIFT_NAME(dexo_applyProxyPort(_:to:));

+ (void)dexo_clearLoopbackHTTPProxyOnDataStore:(WKWebsiteDataStore *)dataStore
    NS_SWIFT_NAME(dexo_clearProxy(on:));

@end

NS_ASSUME_NONNULL_END

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

/// iOS 15/16 Cloudflare-challenge helpers. Talks to WebKit only through
/// string selectors so the app does not link private symbols.
@interface WebViewDoHChallengeSPI : NSObject

/// Leftover-scheme cleanup only. Production WebViews no longer register
/// `http`/`https` for `URLProtocol` (that MITMs Turnstile).
+ (BOOL)registerHTTPAndHTTPSCustomProtocolSchemes
    NS_SWIFT_NAME(registerHTTPAndHTTPSCustomProtocolSchemes());
+ (void)unregisterHTTPAndHTTPSCustomProtocolSchemes
    NS_SWIFT_NAME(unregisterHTTPAndHTTPSCustomProtocolSchemes());
+ (BOOL)canRegisterCustomProtocolSchemes
    NS_SWIFT_NAME(canRegisterCustomProtocolSchemes());

/// Brand-new **non-persistent** store (`initNonPersistentConfiguration`)
/// whose http(s) proxy is set on `_WKWebsiteDataStoreConfiguration` only.
/// Never call this for `WKWebsiteDataStore.default()` or the shared jar.
/// Refuses to proxy a persistent configuration.
+ (nullable WKWebsiteDataStore *)makeNonPersistentDataStoreWithHTTPProxyPort:(uint16_t)port
                                                                      error:(NSError * _Nullable * _Nullable)error
    NS_SWIFT_NAME(makeNonPersistentDataStore(httpProxyPort:));

/// Clear-only: `_setProxyConfiguration:` plus `httpProxy`/`httpsProxy`.
/// Used to recover leftover process-wide proxies from older builds.
+ (void)clearLegacyProxyConfigurationOnDataStore:(WKWebsiteDataStore *)dataStore
    NS_SWIFT_NAME(clearLegacyProxyConfiguration(on:));

+ (nullable NSString *)lastFailureReason
    NS_SWIFT_NAME(lastFailureReason());

@end

NS_ASSUME_NONNULL_END

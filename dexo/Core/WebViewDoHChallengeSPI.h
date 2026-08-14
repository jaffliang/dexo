#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

/// iOS 15/16 Cloudflare-challenge helpers. Talks to WebKit only through
/// string selectors so the app does not link private symbols.
@interface WebViewDoHChallengeSPI : NSObject

/// `WKBrowsingContextController` `registerSchemeForCustomProtocol:` for
/// `http` and `https`. When this succeeds, those WKWebView requests go
/// through the process `URLProtocol` stack (`DoHGatewayURLProtocol`).
+ (BOOL)registerHTTPAndHTTPSCustomProtocolSchemes
    NS_SWIFT_NAME(registerHTTPAndHTTPSCustomProtocolSchemes());
+ (void)unregisterHTTPAndHTTPSCustomProtocolSchemes
    NS_SWIFT_NAME(unregisterHTTPAndHTTPSCustomProtocolSchemes());
+ (BOOL)canRegisterCustomProtocolSchemes
    NS_SWIFT_NAME(canRegisterCustomProtocolSchemes());

/// Brand-new non-persistent store whose http(s) proxy is set on
/// `_WKWebsiteDataStoreConfiguration` only. Never call this for
/// `WKWebsiteDataStore.default()` or the shared cookie jar.
+ (nullable WKWebsiteDataStore *)makeNonPersistentDataStoreWithHTTPProxyPort:(uint16_t)port
                                                                      error:(NSError * _Nullable * _Nullable)error
    NS_SWIFT_NAME(makeNonPersistentDataStore(httpProxyPort:));

/// Clear-only: `_setProxyConfiguration:` with an empty dictionary.
/// Used to recover leftover process-wide proxies from older builds.
+ (void)clearLegacyProxyConfigurationOnDataStore:(WKWebsiteDataStore *)dataStore
    NS_SWIFT_NAME(clearLegacyProxyConfiguration(on:));

+ (nullable NSString *)lastFailureReason
    NS_SWIFT_NAME(lastFailureReason());

@end

NS_ASSUME_NONNULL_END

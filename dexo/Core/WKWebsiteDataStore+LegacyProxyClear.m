#import "WKWebsiteDataStore+LegacyProxyClear.h"

@implementation WKWebsiteDataStore (DexoLegacyProxyClear)

+ (void)dexo_clearHTTPProxiesOnObject:(id)object {
    if (object == nil) {
        return;
    }

    NSArray<NSString *> *selectorNames = @[
        @"_setHTTPSProxy:",
        @"_setHTTPProxy:",
        @"setHttpsProxy:",
        @"setHttpProxy:",
        @"setHTTPSProxy:",
        @"setHTTPProxy:",
    ];
    for (NSString *name in selectorNames) {
        SEL selector = NSSelectorFromString(name);
        if (![object respondsToSelector:selector]) {
            continue;
        }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        @try {
            [object performSelector:selector withObject:nil];
        } @catch (NSException *exception) {
            NSLog(@"[DexoLegacyProxyClear] %@ %@", name, exception);
        }
#pragma clang diagnostic pop
    }

    NSArray<NSString *> *keys = @[
        @"httpsProxy",
        @"httpProxy",
        @"_httpsProxy",
        @"_httpProxy",
    ];
    for (NSString *key in keys) {
        @try {
            [object setValue:nil forKey:key];
        } @catch (NSException *exception) {
            NSLog(@"[DexoLegacyProxyClear] KVC %@ %@", key, exception);
        }
    }
}

+ (void)dexo_clearProxyConfigurationOnDataStore:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil) {
        return;
    }

    NSArray<NSString *> *selectorNames = @[
        @"_setProxyConfiguration:",
        @"setProxyConfiguration:",
    ];
    for (NSString *name in selectorNames) {
        SEL selector = NSSelectorFromString(name);
        if (![dataStore respondsToSelector:selector]) {
            continue;
        }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        @try {
            [dataStore performSelector:selector withObject:@{}];
            [dataStore performSelector:selector withObject:nil];
        } @catch (NSException *exception) {
            NSLog(@"[DexoLegacyProxyClear] %@", exception);
        }
#pragma clang diagnostic pop
        break;
    }

    // v2.2-pr26-connect set these on `_WKWebsiteDataStoreConfiguration`.
    // `[[config alloc] init]` is persistent; a leaked default/shared store
    // then sends CFNetwork / URLSession through a dead CONNECT port (-1001).
    [self dexo_clearHTTPProxiesOnObject:dataStore];
    NSArray<NSString *> *configurationKeys = @[ @"_configuration", @"configuration" ];
    for (NSString *key in configurationKeys) {
        @try {
            id configuration = [dataStore valueForKey:key];
            [self dexo_clearHTTPProxiesOnObject:configuration];
        } @catch (NSException *exception) {
            NSLog(@"[DexoLegacyProxyClear] %@", exception);
        }
    }
}

@end

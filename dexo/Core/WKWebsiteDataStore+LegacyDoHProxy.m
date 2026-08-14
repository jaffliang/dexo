#import "WKWebsiteDataStore+LegacyDoHProxy.h"

static NSString *DexoLegacyProxyLastFailure = nil;

@implementation WKWebsiteDataStore (DexoLegacyDoHProxy)

+ (void)dexo_recordFailure:(NSString *)reason {
    DexoLegacyProxyLastFailure = [reason copy];
}

+ (nullable NSString *)dexo_lastFailureReason {
    return DexoLegacyProxyLastFailure;
}

+ (NSURL *)dexo_loopbackProxyURLWithPort:(uint16_t)port {
    return [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%u", port]];
}

+ (NSDictionary *)dexo_loopbackProxyDictionaryWithPort:(uint16_t)port {
    return @{
        @"HTTPEnable": @YES,
        @"HTTPProxy": @"127.0.0.1",
        @"HTTPPort": @(port),
        @"HTTPSEnable": @YES,
        @"HTTPSProxy": @"127.0.0.1",
        @"HTTPSPort": @(port),
    };
}

+ (BOOL)dexo_setProxyURL:(NSURL *)url onConfiguration:(id)config {
    NSArray<NSString *> *selectorNames = @[
        @"_setHTTPSProxy:",
        @"_setHTTPProxy:",
        @"setHttpsProxy:",
        @"setHttpProxy:",
        @"setHTTPSProxy:",
        @"setHTTPProxy:",
    ];
    BOOL didSet = NO;
    for (NSString *name in selectorNames) {
        SEL selector = NSSelectorFromString(name);
        if (![config respondsToSelector:selector]) {
            continue;
        }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [config performSelector:selector withObject:url];
#pragma clang diagnostic pop
        didSet = YES;
    }

    NSArray<NSString *> *keys = @[ @"httpsProxy", @"httpProxy", @"_httpsProxy", @"_httpProxy" ];
    for (NSString *key in keys) {
        @try {
            [config setValue:url forKey:key];
            didSet = YES;
        } @catch (NSException *exception) {
            continue;
        }
    }
    return didSet;
}

+ (NSArray<NSString *> *)dexo_proxyConfigurationSelectorNames {
    return @[ @"_setProxyConfiguration:", @"setProxyConfiguration:" ];
}

+ (BOOL)dexo_dataStoreSupportsProxyConfiguration:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil) {
        return NO;
    }
    for (NSString *name in [self dexo_proxyConfigurationSelectorNames]) {
        if ([dataStore respondsToSelector:NSSelectorFromString(name)]) {
            return YES;
        }
    }
    return NO;
}

+ (BOOL)dexo_applyProxyObject:(id)object toDataStore:(WKWebsiteDataStore *)dataStore {
    for (NSString *name in [self dexo_proxyConfigurationSelectorNames]) {
        SEL selector = NSSelectorFromString(name);
        if (![dataStore respondsToSelector:selector]) {
            continue;
        }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [dataStore performSelector:selector withObject:object];
#pragma clang diagnostic pop
        return YES;
    }
    return NO;
}

+ (nullable WKWebsiteDataStore *)dexo_nonPersistentDataStoreWithLoopbackHTTPProxyPort:(uint16_t)port {
    if (port == 0) {
        [self dexo_recordFailure:@"legacy store port is 0"];
        return nil;
    }

    NSArray<NSString *> *classNames = @[
        @"_WKWebsiteDataStoreConfiguration",
        @"WKWebsiteDataStoreConfiguration",
    ];
    Class configClass = Nil;
    for (NSString *name in classNames) {
        configClass = NSClassFromString(name);
        if (configClass != Nil) {
            break;
        }
    }
    if (configClass == Nil) {
        [self dexo_recordFailure:@"_WKWebsiteDataStoreConfiguration class missing"];
        return nil;
    }

    id config = [[configClass alloc] init];
    if (config == nil) {
        [self dexo_recordFailure:@"_WKWebsiteDataStoreConfiguration init returned nil"];
        return nil;
    }

    NSURL *url = [self dexo_loopbackProxyURLWithPort:port];
    if (![self dexo_setProxyURL:url onConfiguration:config]) {
        [self dexo_recordFailure:@"httpProxy/httpsProxy setters missing on data-store configuration"];
        return nil;
    }

    WKWebsiteDataStore *store = [WKWebsiteDataStore alloc];
    NSArray<NSString *> *initNames = @[ @"_initWithConfiguration:", @"initWithConfiguration:" ];
    for (NSString *name in initNames) {
        SEL initSelector = NSSelectorFromString(name);
        if (![store respondsToSelector:initSelector]) {
            continue;
        }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        store = [store performSelector:initSelector withObject:config];
#pragma clang diagnostic pop
        if (store != nil) {
            DexoLegacyProxyLastFailure = nil;
            return store;
        }
    }

    [self dexo_recordFailure:@"WKWebsiteDataStore _initWithConfiguration: returned nil"];
    return nil;
}

+ (BOOL)dexo_applyLoopbackHTTPProxyPort:(uint16_t)port toDataStore:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil) {
        [self dexo_recordFailure:@"data store is nil"];
        return NO;
    }
    if (port == 0) {
        [self dexo_recordFailure:@"proxy port is 0"];
        return NO;
    }
    if (![self dexo_applyProxyObject:[self dexo_loopbackProxyDictionaryWithPort:port] toDataStore:dataStore]) {
        [self dexo_recordFailure:@"_setProxyConfiguration: is not available on this WKWebsiteDataStore"];
        return NO;
    }
    DexoLegacyProxyLastFailure = nil;
    return YES;
}

+ (void)dexo_clearLoopbackHTTPProxyOnDataStore:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil) {
        return;
    }
    [self dexo_applyProxyObject:@{} toDataStore:dataStore];
}

@end

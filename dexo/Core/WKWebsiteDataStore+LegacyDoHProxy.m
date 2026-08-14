#import "WKWebsiteDataStore+LegacyDoHProxy.h"

@implementation WKWebsiteDataStore (DexoLegacyDoHProxy)

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
    NSArray<NSString *> *keys = @[ @"httpsProxy", @"httpProxy", @"_httpsProxy", @"_httpProxy" ];
    BOOL didSet = NO;
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

+ (nullable WKWebsiteDataStore *)dexo_nonPersistentDataStoreWithLoopbackHTTPProxyPort:(uint16_t)port {
    if (port == 0) {
        return nil;
    }
    Class configClass = NSClassFromString(@"_WKWebsiteDataStoreConfiguration");
    if (configClass == Nil) {
        return nil;
    }
    id config = [[configClass alloc] init];
    if (config == nil) {
        return nil;
    }
    NSURL *url = [self dexo_loopbackProxyURLWithPort:port];
    if (![self dexo_setProxyURL:url onConfiguration:config]) {
        return nil;
    }

    WKWebsiteDataStore *store = [WKWebsiteDataStore alloc];
    SEL initSelector = NSSelectorFromString(@"_initWithConfiguration:");
    if (![store respondsToSelector:initSelector]) {
        return nil;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    store = [store performSelector:initSelector withObject:config];
#pragma clang diagnostic pop
    return store;
}

+ (BOOL)dexo_applyLoopbackHTTPProxyPort:(uint16_t)port toDataStore:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil || port == 0) {
        return NO;
    }
    SEL selector = NSSelectorFromString(@"_setProxyConfiguration:");
    if (![dataStore respondsToSelector:selector]) {
        return NO;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    [dataStore performSelector:selector withObject:[self dexo_loopbackProxyDictionaryWithPort:port]];
#pragma clang diagnostic pop
    return YES;
}

+ (void)dexo_clearLoopbackHTTPProxyOnDataStore:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil) {
        return;
    }
    SEL selector = NSSelectorFromString(@"_setProxyConfiguration:");
    if (![dataStore respondsToSelector:selector]) {
        return;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    [dataStore performSelector:selector withObject:@{}];
#pragma clang diagnostic pop
}

@end

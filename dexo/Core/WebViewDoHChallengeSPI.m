#import "WebViewDoHChallengeSPI.h"

static NSString *DexoChallengeSPILastFailure = nil;

@implementation WebViewDoHChallengeSPI

+ (void)recordFailure:(NSString *)reason {
    DexoChallengeSPILastFailure = [reason copy];
}

+ (nullable NSString *)lastFailureReason {
    return DexoChallengeSPILastFailure;
}

+ (Class)browsingContextControllerClass {
    return NSClassFromString(@"WKBrowsingContextController");
}

+ (BOOL)canRegisterCustomProtocolSchemes {
    Class cls = [self browsingContextControllerClass];
    if (cls == Nil) {
        return NO;
    }
    SEL selector = NSSelectorFromString(@"registerSchemeForCustomProtocol:");
    return [cls respondsToSelector:selector];
}

+ (BOOL)performSchemeSelector:(NSString *)selectorName scheme:(NSString *)scheme {
    Class cls = [self browsingContextControllerClass];
    if (cls == Nil) {
        [self recordFailure:@"WKBrowsingContextController class missing"];
        return NO;
    }
    SEL selector = NSSelectorFromString(selectorName);
    if (![cls respondsToSelector:selector]) {
        [self recordFailure:[NSString stringWithFormat:@"%@ is not available", selectorName]];
        return NO;
    }
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [cls performSelector:selector withObject:scheme];
#pragma clang diagnostic pop
        return YES;
    } @catch (NSException *exception) {
        [self recordFailure:[NSString stringWithFormat:@"%@ threw %@", selectorName, exception.reason ?: exception.name]];
        return NO;
    }
}

+ (BOOL)registerHTTPAndHTTPSCustomProtocolSchemes {
    if (![self performSchemeSelector:@"registerSchemeForCustomProtocol:" scheme:@"https"]) {
        return NO;
    }
    if (![self performSchemeSelector:@"registerSchemeForCustomProtocol:" scheme:@"http"]) {
        [self performSchemeSelector:@"unregisterSchemeForCustomProtocol:" scheme:@"https"];
        return NO;
    }
    DexoChallengeSPILastFailure = nil;
    return YES;
}

+ (void)unregisterHTTPAndHTTPSCustomProtocolSchemes {
    [self performSchemeSelector:@"unregisterSchemeForCustomProtocol:" scheme:@"http"];
    [self performSchemeSelector:@"unregisterSchemeForCustomProtocol:" scheme:@"https"];
}

+ (NSURL *)loopbackProxyURLWithPort:(uint16_t)port {
    return [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%u", (unsigned)port]];
}

+ (BOOL)setProxyURL:(NSURL *)url onConfiguration:(id)config {
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
        @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            [config performSelector:selector withObject:url];
#pragma clang diagnostic pop
            didSet = YES;
        } @catch (NSException *exception) {
            continue;
        }
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

+ (nullable WKWebsiteDataStore *)makeNonPersistentDataStoreWithHTTPProxyPort:(uint16_t)port
                                                                      error:(NSError * _Nullable * _Nullable)error
{
    if (port == 0) {
        NSString *reason = @"isolated store port is 0";
        [self recordFailure:reason];
        if (error) {
            *error = [NSError errorWithDomain:@"xyz.47258.dexo.webview-doh-challenge"
                                         code:1
                                     userInfo:@{ NSLocalizedDescriptionKey: reason }];
        }
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
        NSString *reason = @"_WKWebsiteDataStoreConfiguration class missing";
        [self recordFailure:reason];
        if (error) {
            *error = [NSError errorWithDomain:@"xyz.47258.dexo.webview-doh-challenge"
                                         code:2
                                     userInfo:@{ NSLocalizedDescriptionKey: reason }];
        }
        return nil;
    }

    id config = [[configClass alloc] init];
    if (config == nil) {
        NSString *reason = @"_WKWebsiteDataStoreConfiguration init returned nil";
        [self recordFailure:reason];
        if (error) {
            *error = [NSError errorWithDomain:@"xyz.47258.dexo.webview-doh-challenge"
                                         code:3
                                     userInfo:@{ NSLocalizedDescriptionKey: reason }];
        }
        return nil;
    }

    @try {
        [config setValue:@NO forKey:@"persistent"];
    } @catch (NSException *exception) {
        // Optional; identifier-less configuration is already non-persistent.
    }

    NSURL *url = [self loopbackProxyURLWithPort:port];
    if (![self setProxyURL:url onConfiguration:config]) {
        NSString *reason = @"httpProxy/httpsProxy setters missing on data-store configuration";
        [self recordFailure:reason];
        if (error) {
            *error = [NSError errorWithDomain:@"xyz.47258.dexo.webview-doh-challenge"
                                         code:4
                                     userInfo:@{ NSLocalizedDescriptionKey: reason }];
        }
        return nil;
    }

    WKWebsiteDataStore *store = [WKWebsiteDataStore alloc];
    NSArray<NSString *> *initNames = @[ @"_initWithConfiguration:", @"initWithConfiguration:" ];
    for (NSString *name in initNames) {
        SEL initSelector = NSSelectorFromString(name);
        if (![store respondsToSelector:initSelector]) {
            continue;
        }
        WKWebsiteDataStore *initialized = nil;
        @try {
            IMP imp = [store methodForSelector:initSelector];
            if (imp == NULL) {
                continue;
            }
            WKWebsiteDataStore *(*initFn)(id, SEL, id) = (WKWebsiteDataStore *(*)(id, SEL, id))imp;
            initialized = initFn(store, initSelector, config);
        } @catch (NSException *exception) {
            [self recordFailure:[NSString stringWithFormat:@"%@ threw %@", name, exception.reason ?: exception.name]];
            continue;
        }
        if (initialized != nil) {
            DexoChallengeSPILastFailure = nil;
            return initialized;
        }
    }

    NSString *reason = @"WKWebsiteDataStore _initWithConfiguration: returned nil";
    [self recordFailure:reason];
    if (error) {
        *error = [NSError errorWithDomain:@"xyz.47258.dexo.webview-doh-challenge"
                                     code:5
                                 userInfo:@{ NSLocalizedDescriptionKey: reason }];
    }
    return nil;
}

+ (void)clearLegacyProxyConfigurationOnDataStore:(WKWebsiteDataStore *)dataStore {
    if (dataStore == nil) {
        return;
    }
    NSArray<NSString *> *names = @[ @"_setProxyConfiguration:", @"setProxyConfiguration:" ];
    for (NSString *name in names) {
        SEL selector = NSSelectorFromString(name);
        if (![dataStore respondsToSelector:selector]) {
            continue;
        }
        @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            [dataStore performSelector:selector withObject:@{}];
#pragma clang diagnostic pop
        } @catch (NSException *exception) {
            continue;
        }
    }
}

@end

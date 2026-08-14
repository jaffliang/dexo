#import "WKWebsiteDataStore+LegacyProxyClear.h"

@implementation WKWebsiteDataStore (DexoLegacyProxyClear)

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
        return;
    }
}

@end

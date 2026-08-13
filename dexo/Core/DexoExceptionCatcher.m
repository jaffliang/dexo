#import "DexoExceptionCatcher.h"

static NSString * const DexoLastFatalExceptionKey = @"dexo.lastFatalException";
static NSString * const DexoExceptionErrorDomain = @"xyz.47258.dexo.objc-exception";

static NSUncaughtExceptionHandler *DexoPreviousUncaughtExceptionHandler = NULL;
static BOOL DexoExceptionHandlerInstalled = NO;

static NSError *DexoErrorFromException(NSException *exception) {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    if (exception.name) {
        info[@"exception.name"] = exception.name;
    }
    NSString *reason = exception.reason ?: @"NSException";
    info[NSLocalizedDescriptionKey] = reason;
    NSArray<NSString *> *symbols = exception.callStackSymbols;
    if (symbols.count > 0) {
        info[@"exception.stack"] = [symbols componentsJoinedByString:@"\n"];
    }
    return [NSError errorWithDomain:DexoExceptionErrorDomain code:1 userInfo:info];
}

static void DexoUncaughtExceptionHandler(NSException *exception) {
    @try {
        NSMutableDictionary *payload = [NSMutableDictionary dictionary];
        payload[@"name"] = exception.name ?: @"";
        payload[@"reason"] = exception.reason ?: @"";
        payload[@"stack"] = [exception.callStackSymbols componentsJoinedByString:@"\n"] ?: @"";
        payload[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
        payload[@"build"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
        payload[@"version"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
        NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
        if (data != nil) {
            [[NSUserDefaults standardUserDefaults] setObject:data forKey:DexoLastFatalExceptionKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        NSLog(@"[DexoException] %@ %@", exception.name, exception.reason);
    } @catch (NSException *ignored) {
        // Never throw from the uncaught handler.
    }
    if (DexoPreviousUncaughtExceptionHandler) {
        DexoPreviousUncaughtExceptionHandler(exception);
    }
}

@implementation DexoExceptionCatcher

+ (void)installUncaughtExceptionHandler {
    if (DexoExceptionHandlerInstalled) {
        return;
    }
    DexoExceptionHandlerInstalled = YES;
    DexoPreviousUncaughtExceptionHandler = NSGetUncaughtExceptionHandler();
    NSSetUncaughtExceptionHandler(&DexoUncaughtExceptionHandler);
}

+ (BOOL)runCatching:(void (NS_NOESCAPE ^)(void))work error:(NSError * _Nullable * _Nullable)error {
    if (work == nil) {
        return YES;
    }
    @try {
        work();
        return YES;
    } @catch (NSException *exception) {
        if (error != NULL) {
            *error = DexoErrorFromException(exception);
        }
        NSLog(@"[DexoException] caught %@ %@", exception.name, exception.reason);
        return NO;
    }
}

+ (void)evaluateJavaScript:(NSString *)script
                 inWebView:(WKWebView *)webView
                completion:(void (^)(id _Nullable result, NSError * _Nullable error))completion {
    if (webView == nil || script.length == 0) {
        if (completion) {
            completion(nil, [NSError errorWithDomain:DexoExceptionErrorDomain
                                                code:2
                                            userInfo:@{NSLocalizedDescriptionKey: @"missing webview or script"}]);
        }
        return;
    }
    @try {
        [webView evaluateJavaScript:script completionHandler:^(id result, NSError *evalError) {
            @try {
                if (completion) {
                    completion(result, evalError);
                }
            } @catch (NSException *exception) {
                if (completion) {
                    completion(nil, DexoErrorFromException(exception));
                }
            }
        }];
    } @catch (NSException *exception) {
        if (completion) {
            completion(nil, DexoErrorFromException(exception));
        }
    }
}

@end

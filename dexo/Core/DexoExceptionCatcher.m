#import "DexoExceptionCatcher.h"

static NSString * const DexoLastFatalExceptionKey = @"dexo.lastFatalException";
static NSString * const DexoLastFatalExceptionSummaryKey = @"dexo.lastFatalException.summary";
static NSString * const DexoExceptionErrorDomain = @"xyz.47258.dexo.objc-exception";
static const NSUInteger DexoLastFatalExceptionStackMaxBytes = 12 * 1024;

static NSUncaughtExceptionHandler *DexoPreviousUncaughtExceptionHandler = NULL;
static BOOL DexoExceptionHandlerInstalled = NO;

static NSString *DexoCappedStack(NSArray<NSString *> *symbols) {
    NSString *joined = [symbols componentsJoinedByString:@"\n"] ?: @"";
    NSData *utf8 = [joined dataUsingEncoding:NSUTF8StringEncoding];
    if (utf8.length <= DexoLastFatalExceptionStackMaxBytes) {
        return joined;
    }
    NSData *prefix = [utf8 subdataWithRange:NSMakeRange(0, DexoLastFatalExceptionStackMaxBytes)];
    NSString *trimmed = [[NSString alloc] initWithData:prefix encoding:NSUTF8StringEncoding];
    if (trimmed.length == 0) {
        NSUInteger chars = MIN(joined.length, DexoLastFatalExceptionStackMaxBytes);
        trimmed = [joined substringToIndex:chars];
    }
    return [trimmed stringByAppendingString:@"\n…(truncated)"];
}

static NSString *DexoExceptionReason(NSException *exception) {
    if (exception.reason.length > 0) {
        return exception.reason;
    }
    id userInfo = exception.userInfo;
    if (userInfo != nil) {
        NSString *info = [userInfo description];
        if (info.length > 0) {
            if (info.length > 2048) {
                return [[info substringToIndex:2048] stringByAppendingString:@"…"];
            }
            return info;
        }
    }
    return @"";
}

static NSError *DexoErrorFromException(NSException *exception) {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    if (exception.name) {
        info[@"exception.name"] = exception.name;
    }
    NSString *reason = DexoExceptionReason(exception);
    info[NSLocalizedDescriptionKey] = reason.length > 0 ? reason : @"NSException";
    NSArray<NSString *> *symbols = exception.callStackSymbols;
    if (symbols.count > 0) {
        info[@"exception.stack"] = DexoCappedStack(symbols);
    }
    return [NSError errorWithDomain:DexoExceptionErrorDomain code:1 userInfo:info];
}

static void DexoUncaughtExceptionHandler(NSException *exception) {
    @try {
        NSString *name = exception.name ?: @"";
        NSString *reason = DexoExceptionReason(exception);
        NSString *summary = [NSString stringWithFormat:@"%@: %@", name, reason.length > 0 ? reason : @"(empty reason)"];
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        // Tiny write first so name/reason survive if we abort while serializing the stack.
        [defaults setObject:summary forKey:DexoLastFatalExceptionSummaryKey];
        [defaults synchronize];

        NSMutableDictionary *payload = [NSMutableDictionary dictionary];
        payload[@"name"] = name;
        payload[@"reason"] = reason;
        payload[@"stack"] = DexoCappedStack(exception.callStackSymbols);
        payload[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
        payload[@"build"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
        payload[@"version"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
        [defaults setObject:payload forKey:DexoLastFatalExceptionKey];
        [defaults synchronize];
        NSLog(@"[DexoException] %@", summary);
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

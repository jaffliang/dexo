#import "DexoExceptionCatcher.h"

#import <fcntl.h>
#import <limits.h>
#import <string.h>
#import <unistd.h>

static NSString * const DexoLastFatalExceptionKey = @"dexo.lastFatalException";
static NSString * const DexoLastFatalExceptionSummaryKey = @"dexo.lastFatalException.summary";
static NSString * const DexoLastCrashFileName = @"dexo-last-crash.txt";
static NSString * const DexoBreadcrumbFileName = @"dexo-password-login-breadcrumbs.txt";
static NSString * const DexoExceptionErrorDomain = @"xyz.47258.dexo.objc-exception";
static const NSUInteger DexoLastFatalExceptionStackMaxBytes = 12 * 1024;
static const NSUInteger DexoLastCrashStackMaxLines = 80;

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

static NSString *DexoCappedStackLines(NSString *stack) {
    if (stack.length == 0) {
        return stack;
    }
    NSArray<NSString *> *lines = [stack componentsSeparatedByString:@"\n"];
    if (lines.count <= DexoLastCrashStackMaxLines) {
        return stack;
    }
    NSArray<NSString *> *head = [lines subarrayWithRange:NSMakeRange(0, DexoLastCrashStackMaxLines)];
    return [[head componentsJoinedByString:@"\n"] stringByAppendingString:@"\n…(truncated)"];
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

static NSString *DexoSanitize(NSString *value) {
    if (value.length == 0) {
        return value;
    }
    NSString *text = [value stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    NSArray<NSString *> *keys = @[@"password", @"passwd", @"second_factor_token"];
    for (NSString *key in keys) {
        NSString *pattern = [NSString stringWithFormat:@"%@=[^&\\s\"]+", key];
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                               options:NSRegularExpressionCaseInsensitive
                                                                                 error:nil];
        if (regex != nil) {
            text = [regex stringByReplacingMatchesInString:text
                                                   options:0
                                                     range:NSMakeRange(0, text.length)
                                              withTemplate:[key stringByAppendingString:@"=***"]];
        }
    }
    if (text.length > 240) {
        return [[text substringToIndex:240] stringByAppendingString:@"…"];
    }
    return text;
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

static NSURL *DexoSupportDirectory(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *dir = [[fm URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
    if (dir == nil) {
        return nil;
    }
    [fm createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSURL *DexoURLForFile(NSString *name) {
    return [DexoSupportDirectory() URLByAppendingPathComponent:name];
}

static BOOL DexoFsyncDirectoryOfURL(NSURL *url) {
    NSString *dir = url.URLByDeletingLastPathComponent.path;
    if (dir.length == 0) {
        return NO;
    }
    int fd = open(dir.fileSystemRepresentation, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        fd = open(dir.fileSystemRepresentation, O_RDONLY);
    }
    if (fd < 0) {
        return NO;
    }
    int rc = fsync(fd);
    close(fd);
    return rc == 0;
}

static BOOL DexoWriteBytesAndFsync(const char *path, const void *bytes, size_t length) {
    if (path == NULL) {
        return NO;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return NO;
    }
    const char *cursor = bytes;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written <= 0) {
            close(fd);
            return NO;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    if (fsync(fd) != 0) {
        close(fd);
        return NO;
    }
    close(fd);

    char dir[PATH_MAX];
    if (strlen(path) >= sizeof(dir)) {
        return YES;
    }
    memcpy(dir, path, strlen(path) + 1);
    char *slash = strrchr(dir, '/');
    if (slash != NULL) {
        if (slash == dir) {
            dir[1] = '\0';
        } else {
            *slash = '\0';
        }
        int dfd = open(dir, O_RDONLY | O_DIRECTORY);
        if (dfd < 0) {
            dfd = open(dir, O_RDONLY);
        }
        if (dfd >= 0) {
            fsync(dfd);
            close(dfd);
        }
    }
    return YES;
}

/// `atomic` uses a temp file + rename so readers never see a torn breadcrumb file.
/// Crash-handler summaries skip atomic so a tiny name/reason lands even if we abort mid-rename.
static BOOL DexoWriteUTF8Fsync(NSURL *url, NSString *text, BOOL atomic) {
    if (url == nil || text == nil) {
        return NO;
    }
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil) {
        data = [NSData data];
    }
    const char *path = url.fileSystemRepresentation;
    if (atomic) {
        NSError *error = nil;
        if (![data writeToURL:url options:NSDataWritingAtomic error:&error]) {
            return DexoWriteBytesAndFsync(path, data.bytes, (size_t)data.length);
        }
        NSError *handleError = nil;
        NSFileHandle *handle = [NSFileHandle fileHandleForUpdatingURL:url error:&handleError];
        if (handle != nil) {
            [handle synchronizeAndReturnError:nil];
            [handle closeFile];
        }
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            fsync(fd);
            close(fd);
        }
        DexoFsyncDirectoryOfURL(url);
        return YES;
    }
    return DexoWriteBytesAndFsync(path, data.bytes, (size_t)data.length);
}

static NSString *DexoReadUTF8(NSURL *url) {
    if (url == nil) {
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (data.length == 0) {
        return nil;
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static void DexoDeleteFile(NSURL *url) {
    if (url == nil) {
        return;
    }
    [[NSFileManager defaultManager] removeItemAtURL:url error:nil];
}

static NSString *DexoISO8601Now(void) {
    NSISO8601DateFormatter *fmt = [[NSISO8601DateFormatter alloc] init];
    fmt.formatOptions = NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
    return [fmt stringFromDate:[NSDate date]] ?: @"";
}

static NSString *DexoFormatCrashReport(NSString *name, NSString *reason, NSString *stack, NSString *breadcrumbs) {
    NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *build = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"dexo %@ (%@)\n", version, build];
    [out appendFormat:@"%@\n", DexoISO8601Now()];
    [out appendFormat:@"name: %@\n", name.length > 0 ? name : @"(empty)"];
    if (reason.length > 0) {
        [out appendFormat:@"reason: %@\n", DexoSanitize(reason)];
    } else {
        [out appendString:@"reason: (empty — NSException.reason was nil)\n"];
    }
    if (breadcrumbs.length > 0) {
        [out appendString:@"\n-- breadcrumbs --\n"];
        [out appendString:breadcrumbs];
        if (![breadcrumbs hasSuffix:@"\n"]) {
            [out appendString:@"\n"];
        }
    }
    NSString *cappedStack = DexoCappedStackLines(stack);
    if (cappedStack.length > 0) {
        [out appendString:@"\n-- stack --\n"];
        [out appendString:cappedStack];
        if (![cappedStack hasSuffix:@"\n"]) {
            [out appendString:@"\n"];
        }
    }
    return out;
}

static void DexoUncaughtExceptionHandler(NSException *exception) {
    @try {
        NSString *name = exception.name ?: @"";
        NSString *reason = DexoExceptionReason(exception);
        NSURL *crashURL = DexoURLForFile(DexoLastCrashFileName);
        // Tiny write first so name/reason survive if we abort while serializing the stack.
        NSString *summary = DexoFormatCrashReport(name, reason, @"", @"");
        DexoWriteUTF8Fsync(crashURL, summary, NO);

        NSString *breadcrumbs = DexoReadUTF8(DexoURLForFile(DexoBreadcrumbFileName)) ?: @"";
        NSString *stack = DexoCappedStack(exception.callStackSymbols);
        NSString *full = DexoFormatCrashReport(name, reason, stack, breadcrumbs);
        // Atomic so an abort while writing the stack leaves the summary file in place.
        DexoWriteUTF8Fsync(crashURL, full, YES);

        NSString *logLine = [NSString stringWithFormat:@"%@: %@", name, reason.length > 0 ? reason : @"(empty reason)"];
        NSLog(@"[DexoException] %@", logLine);

        // Best-effort extra copy. UserDefaults.synchronize often does not flush before abort.
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:logLine forKey:DexoLastFatalExceptionSummaryKey];
        NSMutableDictionary *payload = [NSMutableDictionary dictionary];
        payload[@"name"] = name;
        payload[@"reason"] = reason;
        payload[@"stack"] = stack;
        payload[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
        payload[@"build"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
        payload[@"version"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
        [defaults setObject:payload forKey:DexoLastFatalExceptionKey];
        [defaults synchronize];
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

+ (NSURL *)lastCrashReportURL {
    return DexoURLForFile(DexoLastCrashFileName);
}

+ (void)writeLastCrashReport:(NSString *)text {
    DexoWriteUTF8Fsync(DexoURLForFile(DexoLastCrashFileName), text, YES);
}

+ (NSString *)readLastCrashReport {
    return DexoReadUTF8(DexoURLForFile(DexoLastCrashFileName));
}

+ (void)clearLastCrashReport {
    DexoDeleteFile(DexoURLForFile(DexoLastCrashFileName));
}

+ (void)writeBreadcrumbTrail:(NSString *)text {
    DexoWriteUTF8Fsync(DexoURLForFile(DexoBreadcrumbFileName), text, YES);
}

+ (NSString *)readBreadcrumbTrail {
    return DexoReadUTF8(DexoURLForFile(DexoBreadcrumbFileName));
}

+ (void)clearBreadcrumbTrail {
    DexoDeleteFile(DexoURLForFile(DexoBreadcrumbFileName));
}

@end

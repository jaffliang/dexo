#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Catches Objective-C `NSException`s that Swift `do/catch` cannot see, and
/// records the last uncaught exception before abort.
@interface DexoExceptionCatcher : NSObject

+ (void)installUncaughtExceptionHandler;

/// Runs `work` inside `@try/@catch`. Returns `NO` and populates `error` if an NSException is thrown.
+ (BOOL)runCatching:(void (NS_NOESCAPE ^)(void))work error:(NSError * _Nullable * _Nullable)error;

+ (void)evaluateJavaScript:(NSString *)script
                 inWebView:(WKWebView *)webView
                completion:(void (^)(id _Nullable result, NSError * _Nullable error))completion;

/// `Library/Application Support/dexo-last-crash.txt`
+ (NSURL *)lastCrashReportURL;

/// Writes UTF-8 text with `fsync` so the report survives kill + relaunch.
+ (void)writeLastCrashReport:(NSString *)text;

+ (nullable NSString *)readLastCrashReport;

+ (void)clearLastCrashReport;

/// Durable password-login breadcrumb trail, snapshotted into the crash file on abort.
+ (void)writeBreadcrumbTrail:(NSString *)text;

+ (nullable NSString *)readBreadcrumbTrail;

+ (void)clearBreadcrumbTrail;

@end

NS_ASSUME_NONNULL_END

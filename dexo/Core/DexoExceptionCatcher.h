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

@end

NS_ASSUME_NONNULL_END

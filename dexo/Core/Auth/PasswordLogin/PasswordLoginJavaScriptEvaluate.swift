import Foundation
import WebKit

/// iOS 15 `WKWebView.evaluateJavaScript` cannot bridge a Promise to ObjC.
/// Login still reports via `webkit.messageHandlers.dexoPasswordLogin`; evaluate
/// is only a fire-and-forget kickoff.
nonisolated enum PasswordLoginJavaScriptEvaluate: Sendable {
    static func invocationScript(
        identifierJS: String,
        passwordJS: String,
        captchaJS: String,
        totpJS: String
    ) -> String {
        "void window.__dexoPasswordLogin(\(identifierJS), \(passwordJS), \(captchaJS), \(totpJS)); true;"
    }

    /// `WKError.javaScriptResultTypeIsUnsupported` (code 5), including the
    /// Chinese localization Jeff hit: 执行JavaScript返回结果的类型不受支持
    static func isUnsupportedResultType(_ error: Error) -> Bool {
        let nsError = error as NSError
        if nsError.domain == WKErrorDomain,
           nsError.code == WKError.javaScriptResultTypeIsUnsupported.rawValue {
            return true
        }
        let text = nsError.localizedDescription
        return text.contains("类型不受支持")
            || text.localizedCaseInsensitiveContains("unsupported type")
    }
}

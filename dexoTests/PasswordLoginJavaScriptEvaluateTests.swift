import XCTest
import WebKit
@testable import dexo

final class PasswordLoginJavaScriptEvaluateTests: XCTestCase {
    func testInvocationScriptDoesNotReturnThePromise() {
        let encoded = JavaScriptJSONString.encode("user")
        let script = PasswordLoginJavaScriptEvaluate.invocationScript(
            identifierJS: encoded,
            passwordJS: JavaScriptJSONString.encode("pass"),
            captchaJS: "null",
            totpJS: "null"
        )
        XCTAssertTrue(script.hasPrefix("void window.__dexoPasswordLogin("))
        XCTAssertTrue(script.hasSuffix("true;"))
        XCTAssertEqual(PasswordLoginWebSession.jsString("user"), encoded)
    }

    func testUnsupportedResultTypeMatchesJeffChineseEvaluateError() {
        let chinese = NSError(
            domain: WKErrorDomain,
            code: WKError.javaScriptResultTypeIsUnsupported.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "执行JavaScript返回结果的类型不受支持"]
        )
        XCTAssertTrue(PasswordLoginJavaScriptEvaluate.isUnsupportedResultType(chinese))

        let english = NSError(
            domain: "SomethingElse",
            code: 0,
            userInfo: [NSLocalizedDescriptionKey: "JavaScript execution returned a result of an unsupported type"]
        )
        XCTAssertTrue(PasswordLoginJavaScriptEvaluate.isUnsupportedResultType(english))

        let syntax = NSError(
            domain: WKErrorDomain,
            code: WKError.javaScriptExceptionOccurred.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "Can't find variable: __dexoPasswordLogin"]
        )
        XCTAssertFalse(PasswordLoginJavaScriptEvaluate.isUnsupportedResultType(syntax))
    }
}

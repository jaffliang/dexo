import XCTest
@testable import dexo

final class JavaScriptJSONStringTests: XCTestCase {
    func testEncodesLongTokenLikeStringWithoutThrowing() throws {
        let token = "P1_e" + String(repeating: "A", count: 2350) + "RGXs"
        XCTAssertEqual(token.count, 2358)

        let encoded = JavaScriptJSONString.encode(token)
        let decoded = try JSONDecoder().decode(String.self, from: Data(encoded.utf8))

        XCTAssertEqual(decoded, token)
        XCTAssertTrue(encoded.hasPrefix("\""))
        XCTAssertTrue(encoded.hasSuffix("\""))
        XCTAssertEqual(PasswordLoginWebSession.jsString(token), encoded)
    }

    func testEncodesQuotesNewlinesAndBackslashes() throws {
        let value = "say \"hello\"\nworld\\path"
        let encoded = JavaScriptJSONString.encode(value)
        let decoded = try JSONDecoder().decode(String.self, from: Data(encoded.utf8))

        XCTAssertEqual(decoded, value)
        XCTAssertTrue(encoded.contains("\\\""))
        XCTAssertTrue(encoded.contains("\\n"))
        XCTAssertTrue(encoded.contains("\\\\"))
        XCTAssertEqual(PasswordLoginWebSession.jsString(value), encoded)
    }

    func testEmptyStringIsQuotedJSON() throws {
        let encoded = JavaScriptJSONString.encode("")
        XCTAssertEqual(encoded, "\"\"")
        XCTAssertEqual(try JSONDecoder().decode(String.self, from: Data(encoded.utf8)), "")
    }
}

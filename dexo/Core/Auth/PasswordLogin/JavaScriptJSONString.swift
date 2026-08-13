import Foundation

/// Encodes a Swift `String` as a JSON string literal for JavaScript injection.
///
/// `JSONSerialization.data(withJSONObject:)` requires Array or Dictionary as the
/// top-level object. Passing a `String` raises `NSInvalidArgumentException`
/// ("Invalid top-level type in JSON write"). Swift `try?` does not catch that
/// Objective-C exception, so the process aborts.
nonisolated enum JavaScriptJSONString: Sendable {
    static func encode(_ value: String) -> String {
        guard let data = try? JSONEncoder().encode(value),
              let encoded = String(data: data, encoding: .utf8)
        else { return "\"\"" }
        return encoded
    }
}

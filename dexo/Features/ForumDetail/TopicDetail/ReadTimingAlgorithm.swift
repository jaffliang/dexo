import Foundation

/// Read-time rules aligned with Discourse's `/topics/timings` contract and
/// FluxDO's ScreenTrack behavior (rewritten; not a source copy).
///
/// Discourse's `read_time_word_count` site setting defaults to 500 words per
/// minute. FluxDO ticks once per second and rush-flushes a previously unsent
/// post as soon as that first tick lands, which is the moment its unread
/// indicator can clear.
enum ReadTimingAlgorithm {
    /// Discourse default `read_time_word_count`.
    static let wordsPerMinute = 500

    /// FluxDO ScreenTrack tick / first rush-flush threshold.
    static let tickIntervalMs = 1_000

    /// Per-post ceiling copied from Discourse / FluxDO (`MAX_TRACKING_TIME`).
    static let maxTrackingMs = 6 * 60 * 1_000

    /// Pause accumulation after this much idle time without a scroll.
    static let pauseUnlessScrolledMs = 3 * 60 * 1_000

    /// Periodic flush when no new unread post is rushing out.
    static let flushIntervalMs = 60 * 1_000

    /// Transient statuses that should be retried with backoff.
    static let retryableStatusCodes: Set<Int> = [403, 405, 429, 500, 501, 502, 503, 504]

    /// FluxDO ajax-failure delays: 5s, 10s, 20s, 40s.
    static let retryDelays: [TimeInterval] = [5, 10, 20, 40]

    /// Visible time required before a post is considered read.
    ///
    /// Seconds at Discourse's 500 wpm, never below FluxDO's 1s first tick.
    static func requiredReadTimeMs(wordCount: Int) -> Int {
        let words = max(wordCount, 0)
        let seconds = Int((Double(words) / Double(wordsPerMinute) * 60.0).rounded(.up))
        return max(tickIntervalMs, seconds * 1_000)
    }

    static func remainingReadTimeMs(wordCount: Int, accumulatedMs: Int) -> Int {
        max(0, requiredReadTimeMs(wordCount: wordCount) - max(0, accumulatedMs))
    }

    static func isRead(wordCount: Int, accumulatedMs: Int) -> Bool {
        remainingReadTimeMs(wordCount: wordCount, accumulatedMs: accumulatedMs) == 0
    }

    static func retryDelay(afterFailureCount failureCount: Int) -> TimeInterval {
        let index = min(max(failureCount, 0), retryDelays.count - 1)
        return retryDelays[index]
    }

    static func isRetryable(statusCode: Int?, outcome: TopicTimingOutcome) -> Bool {
        if outcome == .cloudflareChallenge { return true }
        if let statusCode, retryableStatusCodes.contains(statusCode) { return true }
        return statusCode == nil
    }
}

/// Builds the `application/x-www-form-urlencoded` body Discourse expects:
/// `topic_id`, `topic_time`, and `timings[N]=ms` per post number.
enum TopicTimingsFormEncoder {
    static func parameters(topicId: Int, topicTime: Int, timings: [Int: Int]) -> [String: Any] {
        var parameters: [String: Any] = [
            "topic_id": topicId,
            "topic_time": topicTime,
        ]
        for postNumber in timings.keys.sorted() {
            parameters["timings[\(postNumber)]"] = timings[postNumber] ?? 0
        }
        return parameters
    }

    static func queryString(topicId: Int, topicTime: Int, timings: [Int: Int]) -> String {
        var parts = [
            "topic_id=\(topicId)",
            "topic_time=\(topicTime)",
        ]
        for postNumber in timings.keys.sorted() {
            parts.append("timings[\(postNumber)]=\(timings[postNumber] ?? 0)")
        }
        return parts.joined(separator: "&")
    }
}

/// Rough word count when the topic payload omitted `word_count`.
/// Latin tokens count as one word; CJK scalars each count as one word.
enum CookedWordCounter {
    static func count(_ cooked: String) -> Int {
        let stripped = cooked.replacingOccurrences(
            of: "<[^>]+>",
            with: " ",
            options: .regularExpression
        )
        var total = 0
        var latinLength = 0
        for scalar in stripped.unicodeScalars {
            if Self.isCJK(scalar) {
                if latinLength > 0 {
                    total += 1
                    latinLength = 0
                }
                total += 1
            } else if CharacterSet.alphanumerics.contains(scalar) {
                latinLength += 1
            } else if latinLength > 0 {
                total += 1
                latinLength = 0
            }
        }
        if latinLength > 0 { total += 1 }
        return total
    }

    private static func isCJK(_ scalar: Unicode.Scalar) -> Bool {
        (0x4E00 ... 0x9FFF).contains(scalar.value)
            || (0x3400 ... 0x4DBF).contains(scalar.value)
            || (0x3040 ... 0x30FF).contains(scalar.value)
            || (0xAC00 ... 0xD7AF).contains(scalar.value)
    }
}

enum ReadTimingCountdownState: Equatable, Sendable {
    case hidden
    case remaining(ms: Int)
    case complete
}

enum ReadTimingUserStatus: Equatable, Sendable {
    case idle
    case retrying(delay: TimeInterval, summary: String)
    case failed(summary: String)
    case succeeded
}

extension ForumPolicy {
    /// Countdown chrome is linux.do-only and follows the existing opt-in switch.
    static func showsReadTimingCountdown(baseURL: String) -> Bool {
        usesLinuxDoReadTimingsGuard(baseURL: baseURL) && tracksReadTimings(baseURL: baseURL)
    }
}

import Foundation

/// Read-time rules aligned with Discourse's `/topics/timings` contract and
/// FluxDO's ScreenTrack behavior (rewritten; not a source copy).
enum ReadTimingAlgorithm {
    /// FluxDO ScreenTrack tick interval.
    static let tickIntervalMs = 1_000

    /// Per-post ceiling (`MAX_TRACKING_TIME`).
    static let maxTrackingMs = 6 * 60 * 1_000

    /// Pause accumulation after this much idle time without a scroll.
    static let pauseUnlessScrolledMs = 3 * 60 * 1_000

    /// Periodic flush when no new unread post is rushing out.
    static let flushIntervalMs = 60 * 1_000

    /// Statuses FluxDO re-queues. 403 is not among them.
    static let retryableStatusCodes: Set<Int> = [405, 429, 500, 501, 502, 503, 504]

    /// FluxDO ajax-failure delays: 5s, 10s, 20s, 40s.
    static let retryDelays: [TimeInterval] = [5, 10, 20, 40]

    static func retryDelay(afterFailureCount failureCount: Int) -> TimeInterval {
        let index = min(max(failureCount, 0), retryDelays.count - 1)
        return retryDelays[index]
    }

    static func isRetryable(statusCode: Int?, outcome: TopicTimingOutcome) -> Bool {
        guard outcome != .cloudflareChallenge, let statusCode else { return false }
        return retryableStatusCodes.contains(statusCode)
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

enum ReadTimingUserStatus: Equatable, Sendable {
    case idle
    case retrying(delay: TimeInterval, summary: String)
    case failed(summary: String)
    case succeeded
}

extension ForumPolicy {
    /// Unread-dot chrome is linux.do-only and follows the existing opt-in switch.
    static func showsReadTimingUnreadDot(baseURL: String) -> Bool {
        usesLinuxDoReadTimingsGuard(baseURL: baseURL) && tracksReadTimings(baseURL: baseURL)
    }
}

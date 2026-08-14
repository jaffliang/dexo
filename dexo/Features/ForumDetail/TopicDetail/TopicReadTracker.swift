import QuartzCore
import Foundation

/// Tracks how long each post was visible so we can POST `/topics/timings`.
///
/// Behavior is rewritten from FluxDO's ScreenTrack rules:
/// per-post visible time, `topic_time`, 60s flush, rush-flush of newly seen
/// posts, 3-minute idle pause, 6-minute per-post cap, and freeze while a
/// Cloudflare challenge is in progress. Failed retryable payloads stay queued.
/// A post's unread dot clears only after a successful send (or the server
/// already marked it read).
///
/// `nonisolated` to dodge the iOS 26 back-deploy
/// `swift_task_deinitOnExecutorMainActorBackDeploy` crash for MainActor
/// helper deinits.
nonisolated final class TopicReadTracker {
    private let now: @Sendable () -> CFTimeInterval

    private var visibleStarts: [Int: CFTimeInterval] = [:]
    private var elapsedByPost: [Int: Int] = [:]
    private var totalSentByPost: [Int: Int] = [:]
    private var serverReadPosts: Set<Int> = []
    private var sessionReadPosts: Set<Int> = []
    private var sessionStart: CFTimeInterval?
    private var sessionAccumulated: Int = 0
    private var lastScrolled: CFTimeInterval
    private var lastFlush: CFTimeInterval
    private var hasFocus = true
    private var isFrozen = false
    private var inFlightTopicTime = 0
    private var inFlightTimings: [Int: Int] = [:]

    init(now: @escaping @Sendable () -> CFTimeInterval = { CACurrentMediaTime() }) {
        self.now = now
        let timestamp = now()
        lastScrolled = timestamp
        lastFlush = timestamp
    }

    /// Begin / resume the topic-level timer. Idempotent.
    func startSession() {
        guard sessionStart == nil else { return }
        let timestamp = now()
        sessionStart = timestamp
        lastScrolled = timestamp
        hasFocus = true
        isFrozen = false
    }

    func recordVisible(postNumber: Int) {
        guard visibleStarts[postNumber] == nil else { return }
        visibleStarts[postNumber] = now()
    }

    func recordHidden(postNumber: Int) {
        guard let start = visibleStarts.removeValue(forKey: postNumber) else { return }
        addElapsed(postNumber: postNumber, elapsed: msSince(start))
    }

    func markServerRead(_ postNumber: Int) {
        serverReadPosts.insert(postNumber)
    }

    func markScrolled() {
        let timestamp = now()
        if timestamp - lastScrolled > Double(ReadTimingAlgorithm.pauseUnlessScrolledMs) / 1000 {
            for postNumber in visibleStarts.keys {
                visibleStarts[postNumber] = timestamp
            }
            if sessionStart != nil {
                sessionStart = timestamp
            }
        }
        lastScrolled = timestamp
    }

    func setHasFocus(_ focused: Bool) {
        guard hasFocus != focused else { return }
        if !focused {
            pause()
        } else {
            startSession()
        }
        hasFocus = focused
    }

    /// Drop unsent deltas and stop counting, matching FluxDO's CF-freeze.
    func freezeForChallenge() {
        pause()
        elapsedByPost = [:]
        sessionAccumulated = 0
        inFlightTopicTime = 0
        inFlightTimings = [:]
        isFrozen = true
    }

    func unfreeze() {
        isFrozen = false
        lastScrolled = now()
        startSession()
    }

    /// Roll up in-flight timers and stop counting until the next `startSession`.
    func pause() {
        let timestamp = now()
        for (postNumber, start) in visibleStarts {
            addElapsed(postNumber: postNumber, elapsed: Int((timestamp - start) * 1000))
        }
        visibleStarts = [:]
        if let start = sessionStart {
            sessionAccumulated += Int((timestamp - start) * 1000)
            sessionStart = nil
        }
        hasFocus = false
    }

    /// Snapshot the unsent delta. Visible cells keep ticking. Data stays
    /// queued until `commitSend()` so a failed retryable POST can be retried.
    func snapshotDelta() -> (topicTime: Int, timings: [Int: Int]) {
        harvestVisible()
        let topicTime = sessionAccumulated + inFlightTopicTime
        var timings = elapsedByPost
        for (postNumber, milliseconds) in inFlightTimings {
            timings[postNumber, default: 0] += milliseconds
        }
        timings = timings.filter { $0.value > 0 }
        inFlightTopicTime = topicTime
        inFlightTimings = timings
        sessionAccumulated = 0
        elapsedByPost = [:]
        lastFlush = now()
        return (topicTime, timings)
    }

    func commitSend() {
        for (postNumber, milliseconds) in inFlightTimings {
            totalSentByPost[postNumber, default: 0] += milliseconds
            sessionReadPosts.insert(postNumber)
        }
        inFlightTopicTime = 0
        inFlightTimings = [:]
    }

    func revertSend() {
        // Keep `inFlight*` so the next snapshot consolidates the same payload.
    }

    func dropInFlight() {
        inFlightTopicTime = 0
        inFlightTimings = [:]
    }

    /// `!post.read && !readInThisSession`
    func showsUnreadDot(postNumber: Int, serverRead: Bool) -> Bool {
        if serverRead || serverReadPosts.contains(postNumber) { return false }
        return !sessionReadPosts.contains(postNumber)
    }

    /// True when a post has accumulated time and has never been sent.
    func shouldRushFlush() -> Bool {
        guard !isFrozen else { return false }
        for (postNumber, milliseconds) in elapsedByPost where milliseconds > 0 {
            if totalSentByPost[postNumber] == nil { return true }
        }
        for postNumber in visibleStarts.keys {
            let live = liveElapsed(for: postNumber)
            if live > 0, totalSentByPost[postNumber] == nil, inFlightTimings[postNumber] == nil {
                return true
            }
        }
        return false
    }

    func shouldPeriodicFlush() -> Bool {
        guard !isFrozen else { return false }
        let elapsed = (now() - lastFlush) * 1000
        return elapsed >= Double(ReadTimingAlgorithm.flushIntervalMs) && hasUnsentDelta()
    }

    func hasUnsentDelta() -> Bool {
        pendingTimings.contains { $0.value > 0 }
    }

    private func harvestVisible() {
        guard !isFrozen, hasFocus else { return }
        let timestamp = now()
        if timestamp - lastScrolled > Double(ReadTimingAlgorithm.pauseUnlessScrolledMs) / 1000 {
            return
        }
        for (postNumber, start) in visibleStarts {
            addElapsed(postNumber: postNumber, elapsed: Int((timestamp - start) * 1000))
            visibleStarts[postNumber] = timestamp
        }
        if let start = sessionStart {
            sessionAccumulated += Int((timestamp - start) * 1000)
            sessionStart = timestamp
        }
    }

    private var pendingTimings: [Int: Int] {
        var timings = elapsedByPost
        for (postNumber, milliseconds) in inFlightTimings {
            timings[postNumber, default: 0] += milliseconds
        }
        for (postNumber, _) in visibleStarts {
            let live = liveElapsed(for: postNumber)
            if live > 0 {
                timings[postNumber, default: 0] += live
            }
        }
        return timings.filter { $0.value > 0 }
    }

    private func liveElapsed(for postNumber: Int) -> Int {
        guard let start = visibleStarts[postNumber], hasFocus, !isFrozen else { return 0 }
        if now() - lastScrolled > Double(ReadTimingAlgorithm.pauseUnlessScrolledMs) / 1000 {
            return 0
        }
        return max(0, Int((now() - start) * 1000))
    }

    /// Caps cumulative *sent + pending* at MAX_TRACKING_TIME (6 min).
    private func addElapsed(postNumber: Int, elapsed: Int) {
        guard elapsed > 0 else { return }
        let pending = elapsedByPost[postNumber, default: 0]
        let alreadySent = totalSentByPost[postNumber, default: 0] + inFlightTimings[postNumber, default: 0]
        let remaining = max(0, ReadTimingAlgorithm.maxTrackingMs - pending - alreadySent)
        let toAdd = min(elapsed, remaining)
        if toAdd > 0 {
            elapsedByPost[postNumber] = pending + toAdd
        }
    }

    private func msSince(_ start: CFTimeInterval) -> Int {
        Int((now() - start) * 1000)
    }
}

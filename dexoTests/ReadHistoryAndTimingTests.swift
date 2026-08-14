import Foundation
import XCTest
@testable import dexo

final class ReadHistoryDatabaseTests: XCTestCase {
    func testMigrationUpsertAccountIsolationAndForumCascade() throws {
        try withDatabase { database in
            var forum = ForumInstance.new(title: "Forum", baseURL: "https://forum.example.com")
            try database.saveForum(&forum)
            let forumID = try XCTUnwrap(forum.id)
            let alice = ReadHistoryScope(forumId: forumID, accountKey: "user:alice", accountName: "Alice")
            let bob = ReadHistoryScope(forumId: forumID, accountKey: "user:bob", accountName: "Bob")

            let firstViewedAt = Date(timeIntervalSince1970: 1_700_000_000)
            let latestViewedAt = Date(timeIntervalSince1970: 1_700_000_100)
            let first = try makeTopic(
                id: 42,
                title: "First title",
                fancyTitle: "Fancy title",
                avatarTemplate: "/avatar/{size}.png",
                tags: [["id": 7, "name": "Swift", "slug": "swift"]]
            )
            try database.recordLocalRead(topic: first, scope: alice, viewedAt: firstViewedAt)

            let updated = try makeTopic(id: 42, title: "Updated title")
            try database.recordLocalRead(topic: updated, scope: alice, viewedAt: latestViewedAt)

            let aliceRows = try database.fetchLocalReads(scope: alice)
            XCTAssertEqual(aliceRows.count, 1)
            XCTAssertEqual(aliceRows[0].title, "Updated title")
            XCTAssertEqual(aliceRows[0].fancyTitle, "Fancy title")
            XCTAssertEqual(aliceRows[0].avatarTemplate, "/avatar/{size}.png")
            XCTAssertEqual(aliceRows[0].tags, [TopicListTag(id: 7, name: "Swift", slug: "swift")])
            XCTAssertEqual(aliceRows[0].lastViewedAt.timeIntervalSince1970, latestViewedAt.timeIntervalSince1970, accuracy: 0.001)
            XCTAssertEqual(try database.fetchLocalReadTopicIDs(scope: alice), [42])
            XCTAssertTrue(try database.fetchLocalReads(scope: bob).isEmpty)

            var secondForum = ForumInstance.new(title: "Second", baseURL: "https://second.example.com")
            try database.saveForum(&secondForum)
            let secondScope = ReadHistoryScope(
                forumId: try XCTUnwrap(secondForum.id),
                accountKey: alice.accountKey,
                accountName: alice.accountName
            )
            try database.recordLocalRead(
                topic: try makeTopic(id: 42, title: "Same ID on another forum"),
                scope: secondScope
            )
            XCTAssertEqual(try database.fetchLocalReads(scope: secondScope).count, 1)

            try database.deleteForum(forum)
            XCTAssertTrue(try database.fetchLocalReads(scope: alice).isEmpty)
            XCTAssertEqual(try database.fetchLocalReads(scope: secondScope).count, 1)
        }
    }

    func testTimingReportsAreGloballyTrimmedToLatestTwoHundredAndCanBeCleared() throws {
        try withDatabase { database in
            var forum = ForumInstance.new(title: "Forum", baseURL: "https://forum.example.com")
            try database.saveForum(&forum)
            let forumID = try XCTUnwrap(forum.id)

            for index in 0 ..< 205 {
                var report = TopicTimingReport(
                    id: nil,
                    forumId: forumID,
                    baseURL: forum.baseURL,
                    accountName: "alice",
                    topicId: index,
                    attemptedAt: Date(timeIntervalSince1970: TimeInterval(index)),
                    topicTime: 1_000,
                    postCount: 1,
                    visibleTime: 900,
                    requestDuration: 20,
                    statusCode: index.isMultiple(of: 2) ? 200 : 503,
                    outcome: index.isMultiple(of: 2) ? .success : .failure,
                    consecutiveFailureCount: 0,
                    trippedBreaker: false,
                    errorSummary: nil
                )
                try database.saveTopicTimingReport(&report)
            }

            let reports = try database.fetchTopicTimingReports()
            XCTAssertEqual(reports.count, 200)
            XCTAssertEqual(reports.first?.topicId, 204)
            XCTAssertEqual(reports.last?.topicId, 5)
            XCTAssertEqual(
                try database.fetchTopicTimingReports(filter: .success).count,
                100
            )
            XCTAssertEqual(
                try database.fetchTopicTimingReports(filter: .failure).count,
                100
            )

            try database.clearTopicTimingReports()
            XCTAssertTrue(try database.fetchTopicTimingReports().isEmpty)
        }
    }

    private func withDatabase(_ body: (DatabaseManager) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dexo-read-history-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        do {
            let database = try DatabaseManager(testingPath: directory.appendingPathComponent("test.sqlite").path)
            try body(database)
        }
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeTopic(
        id: Int,
        title: String,
        fancyTitle: String? = nil,
        avatarTemplate: String? = nil,
        tags: [[String: Any]] = []
    ) throws -> DiscourseTopicDetail {
        var post: [String: Any] = [
            "id": id * 10,
            "username": "alice",
            "post_number": 1,
        ]
        if let avatarTemplate { post["avatar_template"] = avatarTemplate }
        var object: [String: Any] = [
            "id": id,
            "title": title,
            "posts_count": 2,
            "reply_count": 1,
            "created_at": "2026-07-01T00:00:00.000Z",
            "archetype": "regular",
            "tags": tags,
            "post_stream": ["posts": [post], "stream": [id * 10]],
        ]
        if let fancyTitle { object["fancy_title"] = fancyTitle }
        return try JSONDecoder().decode(
            DiscourseTopicDetail.self,
            from: JSONSerialization.data(withJSONObject: object)
        )
    }
}

final class ReadTopicMergerTests: XCTestCase {
    func testMergeDeduplicatesUsesCloudMetadataAndTracksBothOrigins() throws {
        let localDate = try XCTUnwrap(ReadTopicRow.parseISODate("2026-07-10T00:00:00.000Z"))
        let local = LocalReadTopic(
            topic: try makeTopic(id: 1, title: "Local snapshot"),
            scope: ReadHistoryScope(forumId: 1, accountKey: "user:alice", accountName: "Alice"),
            viewedAt: localDate
        )
        let cloud = makeCloudTopic(
            id: 1,
            title: "Cloud metadata",
            bumpedAt: "2026-07-09T00:00:00.000Z",
            lastVisitedAt: "2026-07-12T00:00:00.000Z"
        )

        let rows = ReadTopicMerger.merge(localTopics: [local], cloudTopics: [cloud])

        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].topic.title, "Cloud metadata")
        XCTAssertEqual(rows[0].origins, [.local, .cloud])
        XCTAssertEqual(
            rows[0].mergedSortDate,
            try XCTUnwrap(ReadTopicRow.parseISODate("2026-07-12T00:00:00.000Z"))
        )
    }

    func testMergeSortUsesLocalReadTimeThenCloudActivityFallback() throws {
        let scope = ReadHistoryScope(forumId: 1, accountKey: "anonymous", accountName: nil)
        let newestLocal = LocalReadTopic(
            topic: try makeTopic(id: 3, title: "Local"),
            scope: scope,
            viewedAt: try XCTUnwrap(ReadTopicRow.parseISODate("2026-07-13T00:00:00.000Z"))
        )
        let cloudWithLastPost = makeCloudTopic(
            id: 2,
            title: "Cloud",
            bumpedAt: nil,
            lastPostedAt: "2026-07-11T00:00:00.000Z"
        )
        let cloudWithCreationOnly = makeCloudTopic(
            id: 4,
            title: "Older cloud",
            bumpedAt: nil,
            lastPostedAt: nil,
            createdAt: "2026-07-09T00:00:00.000Z"
        )

        let rows = ReadTopicMerger.merge(
            localTopics: [newestLocal],
            cloudTopics: [cloudWithCreationOnly, cloudWithLastPost]
        )

        XCTAssertEqual(rows.map(\.id), [3, 2, 4])
    }

    private func makeTopic(id: Int, title: String) throws -> DiscourseTopicDetail {
        try JSONDecoder().decode(
            DiscourseTopicDetail.self,
            from: Data("""
            {
              "id": \(id), "title": "\(title)", "posts_count": 1,
              "reply_count": 0, "created_at": "2026-07-01T00:00:00.000Z",
              "archetype": "regular", "post_stream": { "posts": [], "stream": [] }
            }
            """.utf8)
        )
    }

    private func makeCloudTopic(
        id: Int,
        title: String,
        bumpedAt: String?,
        lastPostedAt: String? = nil,
        lastVisitedAt: String? = nil,
        createdAt: String = "2026-07-01T00:00:00.000Z"
    ) -> DiscourseTopicList.Topic {
        DiscourseTopicList.Topic(
            id: id,
            fancyTitle: title,
            title: title,
            postsCount: 1,
            replyCount: 0,
            views: 0,
            categoryId: nil,
            createdAt: createdAt,
            lastPostedAt: lastPostedAt,
            bumpedAt: bumpedAt,
            lastVisitedAt: lastVisitedAt,
            pinned: nil,
            unseen: nil,
            excerpt: nil,
            posters: nil,
            tags: []
        )
    }
}

final class TopicTimingPolicyTests: XCTestCase {
    func testLinuxDoDefaultsOffAndManualReenableAdvancesGeneration() throws {
        let suiteName = "dexo-topic-timing-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let settings = AppSettings(testingDefaults: defaults)

        XCTAssertFalse(settings.linuxDoReadTimingsEnabled)
        XCTAssertEqual(settings.linuxDoReadTimingsActivationGeneration, 0)
        settings.linuxDoReadTimingsEnabled = true
        XCTAssertEqual(settings.linuxDoReadTimingsActivationGeneration, 1)
        settings.linuxDoReadTimingsEnabled = true
        XCTAssertEqual(settings.linuxDoReadTimingsActivationGeneration, 1)
        settings.linuxDoReadTimingsEnabled = false
        settings.linuxDoReadTimingsEnabled = true
        XCTAssertEqual(settings.linuxDoReadTimingsActivationGeneration, 2)
    }

    func testLinuxDoPolicyCoversSubdomainsWithoutChangingOtherForums() {
        let settings = AppSettings.shared
        let original = settings.linuxDoReadTimingsEnabled
        defer { settings.linuxDoReadTimingsEnabled = original }

        settings.linuxDoReadTimingsEnabled = false
        XCTAssertFalse(ForumPolicy.tracksReadTimings(baseURL: "https://linux.do"))
        XCTAssertFalse(ForumPolicy.tracksReadTimings(baseURL: "https://meta.linux.do"))
        XCTAssertTrue(ForumPolicy.tracksReadTimings(baseURL: "https://example.com"))
        XCTAssertTrue(ForumPolicy.tracksReadTimings(baseURL: "https://idcflare.com"))
        settings.linuxDoReadTimingsEnabled = true
        XCTAssertTrue(ForumPolicy.tracksReadTimings(baseURL: "https://linux.do"))
        XCTAssertTrue(ForumPolicy.tracksReadTimings(baseURL: "https://idcflare.com"))
        XCTAssertTrue(ForumPolicy.showsReadTimingUnreadDot(baseURL: "https://linux.do"))
        XCTAssertTrue(ForumPolicy.showsReadTimingUnreadDot(baseURL: "https://idcflare.com"))
        XCTAssertTrue(ForumPolicy.showsReadTimingUnreadDot(baseURL: "https://www.idcflare.com"))
        settings.linuxDoReadTimingsEnabled = false
        XCTAssertFalse(ForumPolicy.showsReadTimingUnreadDot(baseURL: "https://linux.do"))
        XCTAssertTrue(ForumPolicy.tracksReadTimings(baseURL: "https://idcflare.com"))
        XCTAssertTrue(ForumPolicy.showsReadTimingUnreadDot(baseURL: "https://idcflare.com"))
        XCTAssertFalse(ForumPolicy.showsReadTimingUnreadDot(baseURL: "https://example.com"))
    }

    func testLinuxDoFamilyIncludesIdcflareWithoutSharingChallengeURL() {
        XCTAssertTrue(ForumPolicy.isLinuxDoFamily(baseURL: "https://linux.do"))
        XCTAssertTrue(ForumPolicy.isLinuxDoFamily(baseURL: "https://idcflare.com"))
        XCTAssertTrue(ForumPolicy.isLinuxDoFamily(baseURL: "https://www.idcflare.com"))
        XCTAssertTrue(ForumPolicy.isLinuxDoFamily(baseURL: "https://cdk.linux.do"))
        XCTAssertTrue(ForumPolicy.isLinuxDoFamily(url: URL(string: "https://cdk.linux.do/redeem")!))
        XCTAssertFalse(ForumPolicy.isLinuxDoFamily(baseURL: "https://example.com"))
        XCTAssertEqual(ForumPolicy.linuxDoFamilyRegistrableHost(forHost: "cdk.linux.do"), "linux.do")
        XCTAssertEqual(
            ForumPolicy.defaultInAppBrowserURL(for: "https://linux.do"),
            URL(string: "https://cdk.linux.do/")
        )

        XCTAssertEqual(
            ForumPolicy.cloudflareInterstitialURL(for: "https://linux.do"),
            URL(string: "https://linux.do/challenge")
        )
        XCTAssertEqual(
            ForumPolicy.cloudflareInterstitialURL(for: "https://idcflare.com"),
            URL(string: "https://idcflare.com/login")
        )
        XCTAssertNil(ForumPolicy.cloudflareInterstitialURL(for: "https://example.com"))

        XCTAssertTrue(ForumPolicy.usesLinuxDoReadTimingsGuard(baseURL: "https://linux.do"))
        XCTAssertFalse(ForumPolicy.usesLinuxDoReadTimingsGuard(baseURL: "https://idcflare.com"))
    }

    func testCloudflareChallengeWinsOverSuccessStatus() {
        for statusCode in [200, 403, 503] {
            let assessment = assessTopicTimingResponse(
                statusCode: statusCode,
                data: Data("<html><title>Just a moment...</title><script>__cf_chl_</script></html>".utf8),
                errorDescription: nil
            )
            XCTAssertEqual(assessment.outcome, .cloudflareChallenge)
            XCTAssertEqual(assessment.statusCode, statusCode)
        }
    }

    func testSuccessAndOrdinaryFailureClassification() {
        XCTAssertEqual(
            assessTopicTimingResponse(statusCode: 204, data: Data(), errorDescription: nil).outcome,
            .success
        )
        let failure = assessTopicTimingResponse(statusCode: 500, data: Data(), errorDescription: nil)
        XCTAssertEqual(failure.outcome, .failure)
        XCTAssertEqual(failure.errorSummary, "HTTP 500")
    }

    func testRepeatedFailuresNeverTripOrDisableTheToggle() {
        let suiteName = "dexo-topic-timing-no-disable-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let settings = AppSettings(testingDefaults: defaults)
        settings.linuxDoReadTimingsEnabled = true

        var breaker = TopicTimingCircuitBreaker()
        XCTAssertFalse(breaker.record(.failure, statusCode: 403))
        XCTAssertFalse(breaker.isBlocked)
        XCTAssertFalse(breaker.record(.cloudflareChallenge, statusCode: 403))
        XCTAssertFalse(breaker.isBlocked)
        XCTAssertFalse(breaker.record(.failure, statusCode: 429))
        XCTAssertFalse(breaker.record(.failure, statusCode: 503))
        XCTAssertFalse(breaker.record(.failure))
        XCTAssertFalse(breaker.isTripped)
        XCTAssertTrue(breaker.isBlocked)
        XCTAssertGreaterThan(breaker.remainingBackoff, 0)
        XCTAssertTrue(settings.linuxDoReadTimingsEnabled)

        XCTAssertFalse(breaker.record(.success, statusCode: 200))
        XCTAssertEqual(breaker.failureCount, 0)
        XCTAssertFalse(breaker.isBlocked)
        XCTAssertTrue(settings.linuxDoReadTimingsEnabled)
    }
}

final class ManualReadTimingClock: @unchecked Sendable {
    var time: CFTimeInterval
    init(time: CFTimeInterval) { self.time = time }
}

final class ReadTimingAlgorithmTests: XCTestCase {
    func testRetryBackoffMatchesFluxDODelays() {
        XCTAssertEqual(ReadTimingAlgorithm.retryDelays, [5, 10, 20, 40])
        XCTAssertEqual(ReadTimingAlgorithm.retryDelay(afterFailureCount: 0), 5)
        XCTAssertEqual(ReadTimingAlgorithm.retryDelay(afterFailureCount: 1), 10)
        XCTAssertEqual(ReadTimingAlgorithm.retryDelay(afterFailureCount: 2), 20)
        XCTAssertEqual(ReadTimingAlgorithm.retryDelay(afterFailureCount: 3), 40)
        XCTAssertEqual(ReadTimingAlgorithm.flushIntervalMs, 60_000)
        XCTAssertEqual(
            ReadTimingAlgorithm.retryableStatusCodes,
            [405, 429, 500, 501, 502, 503, 504]
        )
        XCTAssertFalse(ReadTimingAlgorithm.isRetryable(statusCode: 403, outcome: .failure))
        XCTAssertTrue(ReadTimingAlgorithm.isRetryable(statusCode: 405, outcome: .failure))
        XCTAssertTrue(ReadTimingAlgorithm.isRetryable(statusCode: 429, outcome: .failure))
        XCTAssertTrue(ReadTimingAlgorithm.isRetryable(statusCode: 500, outcome: .failure))
        XCTAssertFalse(ReadTimingAlgorithm.isRetryable(statusCode: nil, outcome: .failure))
        XCTAssertFalse(ReadTimingAlgorithm.isRetryable(statusCode: 200, outcome: .cloudflareChallenge))
        XCTAssertFalse(ReadTimingAlgorithm.isRetryable(statusCode: 503, outcome: .cloudflareChallenge))
    }

    func testFormEncodingUsesTimingsPostNumberKeys() {
        let query = TopicTimingsFormEncoder.queryString(
            topicId: 42,
            topicTime: 1500,
            timings: [3: 800, 1: 1200]
        )
        XCTAssertEqual(query, "topic_id=42&topic_time=1500&timings[1]=1200&timings[3]=800")

        let parameters = TopicTimingsFormEncoder.parameters(
            topicId: 42,
            topicTime: 1500,
            timings: [3: 800, 1: 1200]
        )
        XCTAssertEqual(parameters["topic_id"] as? Int, 42)
        XCTAssertEqual(parameters["topic_time"] as? Int, 1500)
        XCTAssertEqual(parameters["timings[1]"] as? Int, 1200)
        XCTAssertEqual(parameters["timings[3]"] as? Int, 800)
        XCTAssertNil(parameters["timings"])
    }

    func testUnreadDotClearsOnlyAfterSuccessfulSendOrServerRead() {
        let clock = ManualReadTimingClock(time: 100)
        let tracker = TopicReadTracker(now: { clock.time })
        tracker.startSession()

        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 1, serverRead: false))
        XCTAssertFalse(tracker.showsUnreadDot(postNumber: 2, serverRead: true))
        tracker.markServerRead(3)
        XCTAssertFalse(tracker.showsUnreadDot(postNumber: 3, serverRead: false))

        tracker.recordVisible(postNumber: 1)
        clock.time += 1
        XCTAssertTrue(tracker.shouldRushFlush())
        XCTAssertFalse(tracker.shouldPeriodicFlush())
        let snapshot = tracker.snapshotDelta()
        XCTAssertEqual(snapshot.timings[1], 1_000)
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 1, serverRead: false))

        tracker.commitSend()
        XCTAssertFalse(tracker.showsUnreadDot(postNumber: 1, serverRead: false))
        XCTAssertFalse(tracker.shouldRushFlush())
    }

    func testStareWithoutScrollStillRushesAfterLateVisibleSync() {
        let clock = ManualReadTimingClock(time: 0)
        let tracker = TopicReadTracker(now: { clock.time })
        tracker.startSession()

        clock.time += 60
        XCTAssertFalse(tracker.shouldRushFlush())
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 1, serverRead: false))

        tracker.recordVisible(postNumber: 1)
        XCTAssertFalse(tracker.shouldRushFlush())
        clock.time += 1
        XCTAssertTrue(tracker.shouldRushFlush())

        _ = tracker.snapshotDelta()
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 1, serverRead: false))
        tracker.commitSend()
        XCTAssertFalse(tracker.showsUnreadDot(postNumber: 1, serverRead: false))

        tracker.recordVisible(postNumber: 1)
        XCTAssertFalse(tracker.showsUnreadDot(postNumber: 1, serverRead: false))
    }

    func testSpuriousHideThenOnScreenReconcileStillRushes() {
        let clock = ManualReadTimingClock(time: 10)
        let tracker = TopicReadTracker(now: { clock.time })
        tracker.startSession()
        tracker.recordVisible(postNumber: 1)
        tracker.recordHidden(postNumber: 1)
        XCTAssertFalse(tracker.shouldRushFlush())
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 1, serverRead: false))

        tracker.recordVisible(postNumber: 1)
        clock.time += 1
        XCTAssertTrue(tracker.shouldRushFlush())
        _ = tracker.snapshotDelta()
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 1, serverRead: false))
        tracker.commitSend()
        XCTAssertFalse(tracker.showsUnreadDot(postNumber: 1, serverRead: false))
    }

    func testPeriodicFlushWaitsSixtySecondsAfterASend() {
        let clock = ManualReadTimingClock(time: 0)
        let tracker = TopicReadTracker(now: { clock.time })
        tracker.startSession()
        tracker.recordVisible(postNumber: 1)
        clock.time += 1
        XCTAssertTrue(tracker.shouldRushFlush())
        _ = tracker.snapshotDelta()
        tracker.commitSend()

        clock.time += 1
        XCTAssertFalse(tracker.shouldRushFlush())
        XCTAssertFalse(tracker.shouldPeriodicFlush())
        clock.time += 59
        XCTAssertTrue(tracker.shouldPeriodicFlush())
    }

    func testInFlightSnapshotConsolidatesAndNonRetryableDropDoesNotMarkRead() {
        let clock = ManualReadTimingClock(time: 0)
        let tracker = TopicReadTracker(now: { clock.time })
        tracker.startSession()
        tracker.recordVisible(postNumber: 4)
        clock.time += 1
        let first = tracker.snapshotDelta()
        XCTAssertEqual(first.timings[4], 1_000)

        clock.time += 1
        let second = tracker.snapshotDelta()
        XCTAssertEqual(second.timings[4], 2_000)
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 4, serverRead: false))

        tracker.dropInFlight()
        XCTAssertTrue(tracker.showsUnreadDot(postNumber: 4, serverRead: false))
        XCTAssertFalse(tracker.hasUnsentDelta())
    }

    func testPostReadFlagDecodesWithoutWordCount() throws {
        let unread = try JSONDecoder().decode(
            DiscourseTopicDetail.Post.self,
            from: Data("""
            {
              "id": 1, "username": "alice", "cooked": "<p>hello world</p>",
              "post_number": 1, "created_at": "2026-07-01T00:00:00.000Z"
            }
            """.utf8)
        )
        XCTAssertFalse(unread.read)

        let alreadyRead = try JSONDecoder().decode(
            DiscourseTopicDetail.Post.self,
            from: Data("""
            {
              "id": 2, "username": "bob", "cooked": "<p>ignored</p>",
              "post_number": 2, "created_at": "2026-07-01T00:00:00.000Z",
              "word_count": 42, "read": true
            }
            """.utf8)
        )
        XCTAssertTrue(alreadyRead.read)
    }
}

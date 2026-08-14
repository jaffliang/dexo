import Foundation
import GRDB

enum TopicTimingOutcome: String, Codable, CaseIterable, DatabaseValueConvertible, Sendable {
    case success
    case failure
    case cloudflareChallenge

    var isFailure: Bool { self != .success }
}

struct TopicTimingReport: Codable, Identifiable, FetchableRecord, MutablePersistableRecord, Sendable {
    static let databaseTableName = "topicTimingReport"

    var id: Int64?
    var forumId: Int64
    var baseURL: String
    var accountName: String?
    var topicId: Int
    var attemptedAt: Date
    var topicTime: Int
    var postCount: Int
    var visibleTime: Int
    var requestDuration: Int
    var statusCode: Int?
    var outcome: TopicTimingOutcome
    var consecutiveFailureCount: Int
    var trippedBreaker: Bool
    var errorSummary: String?

    mutating func didInsert(_ inserted: InsertionSuccess) {
        id = inserted.rowID
    }
}

enum TopicTimingReportPersistence {
    /// Used when the API has no `forumID` and no saved forum matches `baseURL`.
    /// Reports stay keyed by `baseURL` so Settings can still show the attempt.
    static let unresolvedForumId: Int64 = 0

    static func resolvedForumId(
        preferred: Int64?,
        baseURL: String,
        forums: [ForumInstance]
    ) -> Int64 {
        if let preferred { return preferred }
        let trimmed = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if let match = forums.first(where: {
            $0.baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                .caseInsensitiveCompare(trimmed) == .orderedSame
        }), let id = match.id {
            return id
        }
        return unresolvedForumId
    }
}

enum TopicTimingReportFilter: Int, CaseIterable, Sendable {
    case all
    case success
    case failure
}

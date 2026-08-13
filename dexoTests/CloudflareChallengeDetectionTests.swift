import Foundation
import XCTest

@testable import dexo

final class CloudflareChallengeDetectionTests: XCTestCase {
    func testHtmlBodyMarkersAreDetected() {
        let html = Data("Just a moment... __cf_chl_opt".utf8)
        XCTAssertTrue(isCloudflareChallengeResponse(html))
    }

    func testCfMitigatedChallengeHeaderIsDetectedWithoutHtml() throws {
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: URL(string: "https://linux.do/latest.json")!,
                statusCode: 403,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "cf-mitigated": "challenge",
                    "Server": "cloudflare",
                ]
            )
        )
        XCTAssertTrue(isCloudflareChallengeResponse(Data("{}".utf8), headers: response))
        XCTAssertTrue(isCloudflareMitigatedChallenge(response))
    }

    func testCfMitigatedWithoutCloudflareServerIsIgnored() throws {
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: URL(string: "https://linux.do/latest.json")!,
                statusCode: 403,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "cf-mitigated": "challenge",
                    "Server": "nginx",
                ]
            )
        )
        XCTAssertFalse(isCloudflareMitigatedChallenge(response))
        XCTAssertFalse(isCloudflareChallengeResponse(Data("{}".utf8), headers: response))
    }

    func testEmptyBodyWithoutHeadersIsNotAChallenge() {
        XCTAssertFalse(isCloudflareChallengeResponse(nil))
        XCTAssertFalse(isCloudflareChallengeResponse(Data()))
    }
}

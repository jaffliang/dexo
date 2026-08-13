import XCTest
@testable import dexo

final class LinuxDoLoginInterceptTests: XCTestCase {
    func testExtractsConnectOAuthURLFromLoginRedirectQuery() throws {
        let login = try XCTUnwrap(URL(string:
            "https://linux.do/login?redirect=https%3A%2F%2Fconnect.linux.do%2Foauth2%2Fauthorize%3Fclient_id%3Dabc%26response_type%3Dcode"
        ))
        let replacement = try XCTUnwrap(
            LinuxDoLoginIntercept.replacementURL(for: login, previouslyLoaded: [])
        )
        XCTAssertEqual(replacement.scheme, "https")
        XCTAssertEqual(replacement.host, "connect.linux.do")
        XCTAssertEqual(replacement.path, "/oauth2/authorize")
        XCTAssertTrue(replacement.absoluteString.contains("client_id=abc"))
    }

    func testTrailingSlashLoginPathIsIntercepted() throws {
        let login = try XCTUnwrap(URL(string: "https://linux.do/login/"))
        XCTAssertTrue(LinuxDoLoginIntercept.isLoginPage(login))
        XCTAssertEqual(
            LinuxDoLoginIntercept.replacementURL(for: login),
            URL(string: "https://linux.do/")
        )
    }

    func testLoginWithoutRedirectLoadsForumOrigin() throws {
        let login = try XCTUnwrap(URL(string: "https://linux.do/login"))
        XCTAssertEqual(
            LinuxDoLoginIntercept.replacementURL(for: login),
            URL(string: "https://linux.do/")
        )
    }

    func testIdcflareLoginLoadsIdcflareOrigin() throws {
        let login = try XCTUnwrap(URL(string: "https://idcflare.com/login"))
        XCTAssertEqual(
            LinuxDoLoginIntercept.replacementURL(for: login),
            URL(string: "https://idcflare.com/")
        )
    }

    func testIgnoresNonFamilyLoginPages() throws {
        let login = try XCTUnwrap(URL(string: "https://api.coee.ccwu.cc/login?redirect=https://connect.linux.do/oauth2/"))
        XCTAssertFalse(LinuxDoLoginIntercept.isLoginPage(login))
        XCTAssertNil(LinuxDoLoginIntercept.replacementURL(for: login))
    }

    func testRejectsOffSiteRedirect() throws {
        let login = try XCTUnwrap(URL(string:
            "https://linux.do/login?redirect=https%3A%2F%2Fevil.example%2Fphish"
        ))
        XCTAssertEqual(
            LinuxDoLoginIntercept.replacementURL(for: login),
            URL(string: "https://linux.do/")
        )
    }

    func testSkipsLoginToLoginRedirect() throws {
        let login = try XCTUnwrap(URL(string:
            "https://linux.do/login?redirect=https%3A%2F%2Flinux.do%2Flogin"
        ))
        XCTAssertEqual(
            LinuxDoLoginIntercept.replacementURL(for: login),
            URL(string: "https://linux.do/")
        )
    }

    func testPreventsOAuthRedirectLoop() throws {
        let login = try XCTUnwrap(URL(string:
            "https://linux.do/login?redirect=https%3A%2F%2Fconnect.linux.do%2Foauth2%2Fauthorize"
        ))
        let connect = try XCTUnwrap(URL(string: "https://connect.linux.do/oauth2/authorize"))
        let first = try XCTUnwrap(LinuxDoLoginIntercept.replacementURL(for: login, previouslyLoaded: []))
        XCTAssertEqual(first.host, "connect.linux.do")

        let second = LinuxDoLoginIntercept.replacementURL(
            for: login,
            previouslyLoaded: [LinuxDoLoginIntercept.canonicalKey(connect)]
        )
        XCTAssertEqual(second, URL(string: "https://linux.do/"))
    }

    func testReturnPathRelativeRedirectResolvesOnForumOrigin() throws {
        let login = try XCTUnwrap(URL(string: "https://linux.do/login?return_path=%2Flatest"))
        XCTAssertEqual(
            LinuxDoLoginIntercept.replacementURL(for: login),
            URL(string: "https://linux.do/latest")
        )
    }
}

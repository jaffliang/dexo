import XCTest
@testable import dexo

final class LastFatalExceptionStoreTests: XCTestCase {
    override func setUp() {
        super.setUp()
        LastFatalExceptionStore.clear()
        PasswordLoginCrashBreadcrumb.resetForTesting()
    }

    override func tearDown() {
        LastFatalExceptionStore.clear()
        PasswordLoginCrashBreadcrumb.resetForTesting()
        super.tearDown()
    }

    func testCrashFileRoundTrip() {
        let payload = """
        dexo 1.0 (2)
        2026-08-13T03:38:00.000Z
        name: NSInvalidArgumentException
        reason: Invalid top-level type in JSON write
        """
        DexoExceptionCatcher.writeLastCrashReport(payload)

        let report = LastFatalExceptionStore.peekReport()
        XCTAssertEqual(report, payload)
        XCTAssertNotNil(DexoExceptionCatcher.readLastCrashReport())

        LastFatalExceptionStore.clear()
        XCTAssertNil(LastFatalExceptionStore.peekReport())
        XCTAssertNil(DexoExceptionCatcher.readLastCrashReport())
    }

    func testPeekDoesNotDeleteCrashFile() {
        DexoExceptionCatcher.writeLastCrashReport("name: Stay\nreason: until dismiss")
        XCTAssertTrue(LastFatalExceptionStore.peekReport()?.contains("Stay") == true)
        XCTAssertTrue(LastFatalExceptionStore.peekReport()?.contains("until dismiss") == true)
    }

    func testBreadcrumbAppendWritesDurableFile() {
        PasswordLoginCrashBreadcrumb.beginFlow()
        PasswordLoginCrashBreadcrumb.record(.captchaPresented, detail: "hcaptcha")

        let trail = DexoExceptionCatcher.readBreadcrumbTrail()
        XCTAssertNotNil(trail)
        XCTAssertTrue(trail?.contains("session_start") == true)
        XCTAssertTrue(trail?.contains("captcha_presented") == true)
        XCTAssertTrue(trail?.contains("hcaptcha") == true)
    }

    func testBreadcrumbRedactsPasswordInDurableFile() {
        PasswordLoginCrashBreadcrumb.beginFlow()
        PasswordLoginCrashBreadcrumb.record(.error, detail: "password=secret123 extra")

        let trail = DexoExceptionCatcher.readBreadcrumbTrail()
        XCTAssertNotNil(trail)
        XCTAssertFalse(trail?.contains("secret123") == true)
        XCTAssertTrue(trail?.contains("password=***") == true)
    }

    func testPeekReportAppendsBreadcrumbsWhenMissingFromCrashFile() {
        PasswordLoginCrashBreadcrumb.beginFlow()
        PasswordLoginCrashBreadcrumb.record(.captchaPresented)
        DexoExceptionCatcher.writeLastCrashReport("dexo 1.0 (2)\nname: Test\nreason: boom\n")

        let report = LastFatalExceptionStore.peekReport()
        XCTAssertTrue(report?.contains("name: Test") == true)
        XCTAssertTrue(report?.contains("-- breadcrumbs --") == true)
        XCTAssertTrue(report?.contains("captcha_presented") == true)
    }

    func testBeginFlowDoesNotWipeTrailWhileCrashFileExists() {
        PasswordLoginCrashBreadcrumb.beginFlow()
        PasswordLoginCrashBreadcrumb.record(.captchaPresented)
        DexoExceptionCatcher.writeLastCrashReport("name: TestCrash\nreason: boom")

        PasswordLoginCrashBreadcrumb.beginFlow()

        let trail = DexoExceptionCatcher.readBreadcrumbTrail()
        XCTAssertTrue(trail?.contains("captcha_presented") == true)
        XCTAssertTrue(trail?.contains("pending_crash_report") == true)
    }

    func testUserDefaultsFallbackWhenFileMissing() {
        UserDefaults.standard.set(
            [
                "name": "NSInvalidArgumentException",
                "reason": "boom",
                "stack": "frame0",
                "timestamp": Date().timeIntervalSince1970,
                "version": "1.0",
                "build": "2",
            ],
            forKey: LastFatalExceptionStore.defaultsKey
        )

        let report = LastFatalExceptionStore.peekReport()
        XCTAssertTrue(report?.contains("NSInvalidArgumentException") == true)
        XCTAssertTrue(report?.contains("boom") == true)
        XCTAssertTrue(report?.contains("frame0") == true)
    }
}

import Foundation
import os.log

/// Lightweight trail of password-login steps so a mid-flow crash can be pasted back.
/// Persisted to a fsynced Application Support file (and UserDefaults); never records
/// passwords or full captcha tokens.
nonisolated enum PasswordLoginCrashBreadcrumb: Sendable {
    private static let defaultsKey = "password_login.crash_breadcrumb.v1"
    private static let log = OSLog(subsystem: Bundle.main.bundleIdentifier ?? "com.eilgnaw.dexo", category: "PasswordLogin")
    private static let queue = DispatchQueue(label: "xyz.47258.dexo.password-login-breadcrumb")

    enum Step: String, Sendable {
        case sessionStart = "session_start"
        case captchaPresented = "captcha_presented"
        case popupCreate = "popup_create"
        case popupClose = "popup_close"
        case captchaToken = "captcha_token"
        case captchaError = "captcha_error"
        case loginJsStart = "login_js_start"
        case loginJsResult = "login_js_result"
        case exportCookies = "export_cookies"
        case loginViaWeb = "loginViaWeb"
        case teardown = "teardown"
        case objcException = "objc_exception"
        case loginSuccess = "login_success"
        case canceled = "canceled"
        case error = "error"
    }

    private enum Outcome: String, Codable, Sendable {
        case inProgress = "in_progress"
        case success
        case canceled
        case failed
    }

    private struct Event: Codable, Sendable {
        var at: TimeInterval
        var step: String
        var detail: String?
    }

    private struct State: Codable, Sendable {
        var startedAt: TimeInterval
        var events: [Event]
        var outcome: Outcome
        var reported: Bool
    }

    static func beginFlow() {
        // Keep the surviving trail until the last-crash copy UI is dismissed.
        if DexoExceptionCatcher.readLastCrashReport()?.isEmpty == false {
            record(.sessionStart, detail: "pending_crash_report")
            return
        }
        mutate { state in
            state = State(
                startedAt: Date().timeIntervalSince1970,
                events: [],
                outcome: .inProgress,
                reported: false
            )
        }
        record(.sessionStart)
    }

    static func record(_ step: Step, detail: String? = nil) {
        let safeDetail = detail.map(sanitize)
        let now = Date().timeIntervalSince1970
        mutate { state in
            if state.outcome != .inProgress, step != .teardown, step != .objcException {
                return
            }
            state.events.append(Event(at: now, step: step.rawValue, detail: safeDetail))
            switch step {
            case .loginSuccess:
                state.outcome = .success
            case .canceled:
                state.outcome = .canceled
            case .error:
                state.outcome = .failed
            default:
                break
            }
        }
        emit("\(step.rawValue)\(safeDetail.map { " \($0)" } ?? "")")
    }

    static func finishCanceled() {
        record(.canceled)
    }

    static func finishSuccess() {
        record(.loginSuccess)
    }

    static func recordError(_ error: Error) {
        record(.error, detail: shortError(error))
    }

    /// First unfinished trail from a previous process death, if any. Marks it reported.
    static func consumeUnfinishedTrail() -> String? {
        queue.sync {
            var state = loadUnlocked()
            guard state.outcome == .inProgress, !state.events.isEmpty, !state.reported else {
                return nil
            }
            state.reported = true
            saveUnlocked(state)
            return format(state)
        }
    }

    /// Snapshot of the current trail for attaching to an NSException report.
    static func currentTrailForDiagnostics() -> String? {
        if let file = DexoExceptionCatcher.readBreadcrumbTrail(), !file.isEmpty {
            return file
        }
        return queue.sync {
            let state = loadUnlocked()
            guard !state.events.isEmpty else { return nil }
            return format(state)
        }
    }

    /// After the last-crash alert is copied or dismissed, don't re-offer this trail.
    static func markCurrentTrailReported() {
        queue.sync {
            var state = loadUnlocked()
            guard !state.events.isEmpty, !state.reported else { return }
            state.reported = true
            saveUnlocked(state)
        }
    }

    static func resetForTesting() {
        queue.sync {
            UserDefaults.standard.removeObject(forKey: defaultsKey)
            DexoExceptionCatcher.clearBreadcrumbTrail()
        }
    }

    static func redactToken(_ token: String) -> String {
        let count = token.count
        guard count > 8 else { return "len=\(count)" }
        return "\(token.prefix(4))…\(token.suffix(4)) len=\(count)"
    }

    static func shortError(_ error: Error) -> String {
        if let login = error as? PasswordLoginError {
            switch login {
            case .unexpected(let status, let phase, let body):
                return "unexpected status=\(status) phase=\(phase) body=\(clip(sanitize(body), limit: 180))"
            default:
                return String(describing: login)
            }
        }
        let ns = error as NSError
        if ns.userInfo["exception.name"] != nil {
            return clip(exceptionDiagnostic(error), limit: 180)
        }
        return clip(sanitize(error.localizedDescription), limit: 180)
    }

    /// Name + reason (+ a few stack frames) from `DexoExceptionCatcher` NSError userInfo.
    static func exceptionDiagnostic(_ error: Error) -> String {
        let ns = error as NSError
        var parts: [String] = []
        if let name = ns.userInfo["exception.name"] as? String, !name.isEmpty {
            parts.append("name=\(name)")
        }
        let reason = ns.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        if !reason.isEmpty {
            parts.append(sanitize(reason, limit: 400))
        }
        if let stack = ns.userInfo["exception.stack"] as? String, !stack.isEmpty {
            let frames = stack.split(separator: "\n", omittingEmptySubsequences: false).prefix(12).joined(separator: " | ")
            parts.append("stack=\(frames)")
        }
        if parts.isEmpty {
            return clip(sanitize(String(describing: error)), limit: 400)
        }
        return parts.joined(separator: " ")
    }

    static func sanitizeForReport(_ value: String, limit: Int = 240) -> String {
        sanitize(value, limit: limit)
    }

    private static func mutate(_ body: (inout State) -> Void) {
        queue.sync {
            var state = loadUnlocked()
            body(&state)
            saveUnlocked(state)
        }
    }

    private static func loadUnlocked() -> State {
        guard let data = UserDefaults.standard.data(forKey: defaultsKey),
              let state = try? JSONDecoder().decode(State.self, from: data)
        else {
            return State(startedAt: Date().timeIntervalSince1970, events: [], outcome: .inProgress, reported: true)
        }
        return state
    }

    private static func saveUnlocked(_ state: State) {
        if let data = try? JSONEncoder().encode(state) {
            UserDefaults.standard.set(data, forKey: defaultsKey)
            UserDefaults.standard.synchronize()
        }
        DexoExceptionCatcher.writeBreadcrumbTrail(format(state))
    }

    private static func format(_ state: State) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var lines: [String] = [
            "started \(formatter.string(from: Date(timeIntervalSince1970: state.startedAt)))",
            "outcome=\(state.outcome.rawValue)",
        ]
        for event in state.events {
            let time = formatter.string(from: Date(timeIntervalSince1970: event.at))
            if let detail = event.detail, !detail.isEmpty {
                lines.append("\(time) \(event.step) \(detail)")
            } else {
                lines.append("\(time) \(event.step)")
            }
        }
        return lines.joined(separator: "\n")
    }

    private static func emit(_ line: String) {
        os_log("%{public}@", log: log, type: .info, line)
        #if DEBUG
        print("[PasswordLogin] \(line)")
        #endif
    }

    private static func sanitize(_ value: String, limit: Int = 240) -> String {
        var text = value
        let passwordKeys = ["password", "passwd", "second_factor_token"]
        for key in passwordKeys {
            // Drop query-ish assignments that might appear in JS/eval error text.
            if let regex = try? NSRegularExpression(pattern: "\(key)=[^&\\s\"]+", options: .caseInsensitive) {
                text = regex.stringByReplacingMatches(
                    in: text,
                    range: NSRange(text.startIndex..., in: text),
                    withTemplate: "\(key)=***"
                )
            }
        }
        return clip(text.replacingOccurrences(of: "\n", with: " "), limit: limit)
    }

    private static func clip(_ value: String, limit: Int) -> String {
        guard value.count > limit else { return value }
        return String(value.prefix(limit)) + "…"
    }
}

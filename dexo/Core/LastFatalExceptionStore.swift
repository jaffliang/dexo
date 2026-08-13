import Foundation
import UIKit

/// Reads the durable last-crash / last-error file written by `DexoExceptionCatcher`.
/// Falls back to `dexo.lastFatalException` UserDefaults from older builds.
nonisolated enum LastFatalExceptionStore: Sendable {
    static let defaultsKey = "dexo.lastFatalException"
    private static let summaryKey = "dexo.lastFatalException.summary"
    private static let loginFailureMarker = "kind: login_failure"

    static func peekReport() -> String? {
        if var file = DexoExceptionCatcher.readLastCrashReport(), !file.isEmpty {
            if !file.contains("-- breadcrumbs --"),
               let trail = DexoExceptionCatcher.readBreadcrumbTrail(), !trail.isEmpty {
                file += "\n-- breadcrumbs --\n\(trail)"
            }
            return file
        }
        guard let payload = loadPayload() else { return nil }
        return format(payload)
    }

    /// Always returns something copyable so a hint tap is never a no-op.
    static func copyableReport() -> String {
        if let report = peekReport()?.trimmingCharacters(in: .whitespacesAndNewlines), !report.isEmpty {
            return report
        }
        var lines: [String] = [Self.appHeader(), Self.timestampLine()]
        if let trail = DexoExceptionCatcher.readBreadcrumbTrail() ?? PasswordLoginCrashBreadcrumb.currentTrailForDiagnostics(),
           !trail.isEmpty {
            lines.append("")
            lines.append("-- breadcrumbs --")
            lines.append(trail)
        } else {
            lines.append("(no crash report, breadcrumbs, or login error)")
        }
        return lines.joined(separator: "\n")
    }

    static func recordLoginFailure(_ error: Error) {
        let blob = formatLoginFailure(error)
        if let existing = DexoExceptionCatcher.readLastCrashReport(), !existing.isEmpty, isFatalExceptionReport(existing) {
            DexoExceptionCatcher.writeLastCrashReport(existing + "\n\n-- later login failure --\n" + blob)
            return
        }
        DexoExceptionCatcher.writeLastCrashReport(blob)
    }

    static func isFatalExceptionReport(_ text: String) -> Bool {
        !text.contains(loginFailureMarker) && (text.contains("name:") || text.contains("name: "))
    }

    static func clear() {
        DexoExceptionCatcher.clearLastCrashReport()
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: defaultsKey)
        defaults.removeObject(forKey: summaryKey)
        PasswordLoginCrashBreadcrumb.markCurrentTrailReported()
    }

    private struct Payload {
        var name: String
        var reason: String
        var stack: String
        var timestamp: TimeInterval
        var version: String
        var build: String
    }

    private static func appHeader() -> String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        return "dexo \(version) (\(build))"
    }

    private static func timestampLine() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }

    private static func formatLoginFailure(_ error: Error) -> String {
        var lines = [appHeader(), timestampLine(), loginFailureMarker]
        if let login = error as? PasswordLoginError {
            switch login {
            case .unexpected(let status, let phase, let body):
                lines.append("phase: \(phase)")
                lines.append("status: \(status)")
                lines.append("body: \(PasswordLoginCrashBreadcrumb.sanitizeForReport(body, limit: 1500))")
            default:
                lines.append("error: \(login.errorDescription ?? String(describing: login))")
            }
        } else {
            let ns = error as NSError
            lines.append("domain: \(ns.domain) code: \(ns.code)")
            if let name = ns.userInfo["exception.name"] as? String, !name.isEmpty {
                lines.append("name: \(name)")
            }
            lines.append("reason: \(PasswordLoginCrashBreadcrumb.sanitizeForReport(ns.localizedDescription, limit: 1500))")
            if let stack = ns.userInfo["exception.stack"] as? String, !stack.isEmpty {
                let capped = stack.split(separator: "\n", omittingEmptySubsequences: false).prefix(80).joined(separator: "\n")
                lines.append("")
                lines.append("-- stack --")
                lines.append(capped)
            }
        }
        if let trail = DexoExceptionCatcher.readBreadcrumbTrail() ?? PasswordLoginCrashBreadcrumb.currentTrailForDiagnostics(),
           !trail.isEmpty {
            lines.append("")
            lines.append("-- breadcrumbs --")
            lines.append(trail)
        }
        return lines.joined(separator: "\n")
    }

    private static func loadPayload() -> Payload? {
        let defaults = UserDefaults.standard
        let object = defaults.object(forKey: defaultsKey)
        let json: [String: Any]
        if let data = object as? Data,
           let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            json = parsed
        } else if let dict = object as? [String: Any] {
            json = dict
        } else if let text = object as? String, !text.isEmpty {
            return Payload(name: "unknown", reason: text, stack: "", timestamp: Date().timeIntervalSince1970, version: "", build: "")
        } else if let summary = defaults.string(forKey: summaryKey), !summary.isEmpty {
            return Payload(name: "unknown", reason: summary, stack: "", timestamp: Date().timeIntervalSince1970, version: "", build: "")
        } else {
            return nil
        }
        let timestamp: TimeInterval
        if let number = json["timestamp"] as? NSNumber {
            timestamp = number.doubleValue
        } else if let value = json["timestamp"] as? Double {
            timestamp = value
        } else {
            timestamp = 0
        }
        return Payload(
            name: json["name"] as? String ?? "",
            reason: json["reason"] as? String ?? "",
            stack: json["stack"] as? String ?? "",
            timestamp: timestamp,
            version: json["version"] as? String ?? "",
            build: json["build"] as? String ?? ""
        )
    }

    private static func format(_ payload: Payload) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let when = payload.timestamp > 0
            ? formatter.string(from: Date(timeIntervalSince1970: payload.timestamp))
            : "unknown-time"
        var lines = [
            "dexo \(payload.version) (\(payload.build))",
            when,
            "name: \(payload.name.isEmpty ? "(empty)" : payload.name)",
            "reason: \(payload.reason.isEmpty ? "(empty — NSException.reason was nil)" : PasswordLoginCrashBreadcrumb.sanitizeForReport(payload.reason))",
        ]
        if let trail = DexoExceptionCatcher.readBreadcrumbTrail(), !trail.isEmpty {
            lines.append("")
            lines.append("-- breadcrumbs --")
            lines.append(trail)
        } else if let trail = PasswordLoginCrashBreadcrumb.currentTrailForDiagnostics() {
            lines.append("")
            lines.append("-- breadcrumbs --")
            lines.append(trail)
        }
        let stack = payload.stack
            .split(separator: "\n", omittingEmptySubsequences: false)
            .prefix(80)
            .joined(separator: "\n")
        if !stack.isEmpty {
            lines.append("")
            lines.append("-- stack --")
            lines.append(stack)
        }
        return lines.joined(separator: "\n")
    }
}

@MainActor
enum LastFatalExceptionPresenter {
    private nonisolated(unsafe) static var isPresenting = false

    /// iOS 15 drops `UIPasteboard.general.string` set inside a dismissing `UIAlertAction`.
    /// Write on the main thread while the app is still the active first responder.
    static func writePasteboard(_ text: String) {
        let board = UIPasteboard.general
        board.string = text
        board.setItems([["public.utf8-plain-text": text]], options: [:])
    }

    /// Hint tap / Copy: put text on the pasteboard *before* presenting or dismissing, then confirm.
    static func copyToPasteboardAndConfirm(from presenter: UIViewController?, clearOnOK: Bool = true) {
        let report = LastFatalExceptionStore.copyableReport()
        writePasteboard(report)
        presentCopiedConfirmation(from: presenter, report: report, clearOnOK: clearOnOK)
    }

    static func presentIfNeeded(from presenter: UIViewController?) {
        guard let presenter, !isPresenting else { return }
        guard let report = LastFatalExceptionStore.peekReport() else { return }
        let host = presentableHost(from: presenter)
        guard host.view.window != nil else { return }

        let title = LastFatalExceptionStore.isFatalExceptionReport(report)
            ? String(localized: "password_login.debug.exception_title")
            : String(localized: "password_login.debug.error_title")
        let alert = UIAlertController(
            title: title,
            message: truncatedForAlert(report),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "post.raw.copy"), style: .default) { _ in
            isPresenting = false
            writePasteboard(report)
            DispatchQueue.main.async {
                presentCopiedConfirmation(from: host, report: report, clearOnOK: true)
            }
        })
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .cancel) { _ in
            LastFatalExceptionStore.clear()
            isPresenting = false
        })
        isPresenting = true
        presentStacked(alert, on: host) {
            writePasteboard(report)
            if host.presentedViewController !== alert && host.presentedViewController?.presentedViewController !== alert {
                isPresenting = false
            }
        }
    }

    private static func presentCopiedConfirmation(from presenter: UIViewController?, report: String, clearOnOK: Bool) {
        writePasteboard(report)
        guard let presenter else { return }
        let host = presentableHost(from: presenter)
        let alert = UIAlertController(
            title: String(localized: "post.raw.copied"),
            message: nil,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .cancel) { _ in
            if clearOnOK {
                LastFatalExceptionStore.clear()
            }
            isPresenting = false
        })
        presentStacked(alert, on: host) {
            writePasteboard(report)
        }
    }

    private static func presentStacked(_ alert: UIAlertController, on host: UIViewController, completion: (() -> Void)? = nil) {
        var target = host
        if target.isBeingDismissed, let presenting = target.presentingViewController {
            target = topViewController(from: presenting)
        }
        if let existing = target.presentedViewController, !existing.isBeingDismissed, existing !== alert {
            existing.present(alert, animated: true, completion: completion)
            return
        }
        target.present(alert, animated: true, completion: completion)
    }

    private static func presentableHost(from presenter: UIViewController) -> UIViewController {
        var host = topViewController(from: presenter)
        if host.isBeingDismissed, let presenting = host.presentingViewController {
            host = topViewController(from: presenting)
        }
        return host
    }

    private static func truncatedForAlert(_ text: String) -> String {
        if text.count <= 1800 { return text }
        return String(text.prefix(1800)) + "\n" + String(localized: "password_login.debug.truncated")
    }

    private static func topViewController(from root: UIViewController) -> UIViewController {
        if let presented = root.presentedViewController, !presented.isBeingDismissed {
            return topViewController(from: presented)
        }
        if let nav = root as? UINavigationController, let visible = nav.visibleViewController {
            return topViewController(from: visible)
        }
        if let tab = root as? UITabBarController, let selected = tab.selectedViewController {
            return topViewController(from: selected)
        }
        return root
    }
}

import Foundation
import UIKit

/// Reads `dexo.lastFatalException` written by `DexoExceptionCatcher` before abort.
nonisolated enum LastFatalExceptionStore: Sendable {
    static let defaultsKey = "dexo.lastFatalException"

    static func peekReport() -> String? {
        guard let payload = loadPayload() else { return nil }
        return format(payload)
    }

    static func clear() {
        UserDefaults.standard.removeObject(forKey: defaultsKey)
    }

    private struct Payload {
        var name: String
        var reason: String
        var stack: String
        var timestamp: TimeInterval
        var version: String
        var build: String
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
            "name: \(payload.name)",
            "reason: \(PasswordLoginCrashBreadcrumb.sanitizeForReport(payload.reason))",
        ]
        if let trail = PasswordLoginCrashBreadcrumb.currentTrailForDiagnostics() {
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

    static func presentIfNeeded(from presenter: UIViewController?) {
        guard let presenter, !isPresenting else { return }
        guard LastFatalExceptionStore.peekReport() != nil else { return }
        let host = Self.topViewController(from: presenter)
        guard host.presentedViewController == nil else { return }
        guard let report = LastFatalExceptionStore.peekReport() else { return }
        isPresenting = true

        let alert = UIAlertController(
            title: String(localized: "password_login.debug.exception_title"),
            message: report,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "post.raw.copy"), style: .default) { _ in
            UIPasteboard.general.string = report
            LastFatalExceptionStore.clear()
            isPresenting = false
        })
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .cancel) { _ in
            LastFatalExceptionStore.clear()
            isPresenting = false
        })
        host.present(alert, animated: true)
    }

    private static func topViewController(from root: UIViewController) -> UIViewController {
        if let presented = root.presentedViewController {
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

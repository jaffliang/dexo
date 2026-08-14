import UIKit

/// FluxDO-style unread indicator: a 6×6 pt primary circle with a 1pt
/// surface border, pinned to the top-right of the post timestamp.
final class ReadTimingUnreadDot: UIView {
    static let size: CGFloat = 6
    static let fadeDuration: TimeInterval = 0.5

    override init(frame: CGRect) {
        super.init(frame: frame)
        translatesAutoresizingMaskIntoConstraints = false
        isUserInteractionEnabled = false
        clipsToBounds = true
        alpha = 0
        isHidden = true
        NSLayoutConstraint.activate([
            widthAnchor.constraint(equalToConstant: Self.size),
            heightAnchor.constraint(equalToConstant: Self.size),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        layer.cornerRadius = bounds.height / 2
    }

    func apply(showsDot: Bool, animated: Bool) {
        backgroundColor = ThemeManager.shared.accentColor
        layer.borderColor = ThemeManager.shared.cardBackgroundColor.cgColor
        layer.borderWidth = 1
        isAccessibilityElement = showsDot
        accessibilityLabel = showsDot ? String(localized: "read_timings.unread_dot") : nil
        let changes = {
            self.alpha = showsDot ? 1 : 0
        }
        let finish = {
            self.isHidden = !showsDot
        }
        if showsDot { isHidden = false }
        if animated {
            UIView.animate(withDuration: Self.fadeDuration, animations: changes) { _ in
                finish()
            }
        } else {
            changes()
            finish()
        }
    }
}

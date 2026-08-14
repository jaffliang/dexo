import UIKit

/// Small blue remaining-time indicator at the top-right of a post header.
/// Counts down seconds until FluxDO / Discourse would treat the post as read,
/// then dims into a checkmark.
final class ReadTimingCountdownView: UIView {
    static let size: CGFloat = 18

    private let label = UILabel()
    private let checkmark = UIImageView()
    private var widthConstraint: NSLayoutConstraint!

    override init(frame: CGRect) {
        super.init(frame: frame)
        translatesAutoresizingMaskIntoConstraints = false
        isUserInteractionEnabled = false
        clipsToBounds = true
        widthConstraint = widthAnchor.constraint(equalToConstant: Self.size)

        label.translatesAutoresizingMaskIntoConstraints = false
        label.textAlignment = .center
        label.adjustsFontSizeToFitWidth = true
        label.minimumScaleFactor = 0.6
        addSubview(label)

        checkmark.translatesAutoresizingMaskIntoConstraints = false
        checkmark.contentMode = .scaleAspectFit
        checkmark.isHidden = true
        addSubview(checkmark)

        NSLayoutConstraint.activate([
            widthConstraint,
            heightAnchor.constraint(equalToConstant: Self.size),
            label.centerXAnchor.constraint(equalTo: centerXAnchor),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 1),
            label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -1),
            checkmark.centerXAnchor.constraint(equalTo: centerXAnchor),
            checkmark.centerYAnchor.constraint(equalTo: centerYAnchor),
            checkmark.widthAnchor.constraint(equalToConstant: 10),
            checkmark.heightAnchor.constraint(equalToConstant: 10),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override func layoutSubviews() {
        super.layoutSubviews()
        layer.cornerRadius = bounds.height / 2
    }

    func apply(_ state: ReadTimingCountdownState) {
        switch state {
        case .hidden:
            isHidden = true
            widthConstraint.constant = 0
        case .complete:
            isHidden = false
            widthConstraint.constant = Self.size
            backgroundColor = UIColor.systemBlue.withAlphaComponent(0.35)
            label.isHidden = true
            checkmark.isHidden = false
            let symbol = UIImage.SymbolConfiguration(pointSize: 8, weight: .bold)
            checkmark.image = UIImage(systemName: "checkmark", withConfiguration: symbol)
            checkmark.tintColor = UIColor.white.withAlphaComponent(0.85)
            accessibilityLabel = String(localized: "read_timings.countdown.complete")
        case .remaining(let remainingMs):
            isHidden = false
            widthConstraint.constant = Self.size
            let remainingSeconds = max(1, (remainingMs + 999) / 1000)
            backgroundColor = .systemBlue
            label.isHidden = false
            checkmark.isHidden = true
            label.font = .monospacedDigitSystemFont(ofSize: remainingSeconds > 9 ? 8 : 10, weight: .semibold)
            label.textColor = .white
            label.text = remainingSeconds > 99 ? "99" : "\(remainingSeconds)"
            accessibilityLabel = String(localized: "read_timings.countdown.remaining \(remainingSeconds)")
        }
    }
}

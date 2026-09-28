import AppKit

/// Native placeholder shown while the helper server is not (yet) reachable.
@MainActor
final class LoadingView: NSView {
    var onRetry: (() -> Void)?
    var onShowLog: (() -> Void)?

    private let spinner = NSProgressIndicator()
    private let icon = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let retryButton = NSButton(title: "Retry", target: nil, action: nil)
    private let logButton = NSButton(title: "Show Server Log", target: nil, action: nil)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        setUp()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    private func setUp() {
        spinner.style = .spinning
        spinner.controlSize = .regular
        spinner.isDisplayedWhenStopped = false

        icon.image = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: "Error")
        icon.symbolConfiguration = .init(pointSize: 28, weight: .regular)
        icon.contentTintColor = .systemOrange
        icon.isHidden = true

        titleLabel.font = .systemFont(ofSize: 17, weight: .semibold)
        titleLabel.alignment = .center

        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.alignment = .center
        detailLabel.preferredMaxLayoutWidth = 420

        retryButton.bezelStyle = .push
        retryButton.keyEquivalent = "\r"
        retryButton.target = self
        retryButton.action = #selector(retryPressed)

        logButton.bezelStyle = .push
        logButton.target = self
        logButton.action = #selector(logPressed)

        let buttons = NSStackView(views: [logButton, retryButton])
        buttons.orientation = .horizontal
        buttons.spacing = 12

        let stack = NSStackView(views: [spinner, icon, titleLabel, detailLabel, buttons])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 12
        stack.setCustomSpacing(20, after: detailLabel)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
            stack.widthAnchor.constraint(lessThanOrEqualToConstant: 460),
        ])
        showWaiting()
    }

    func showWaiting(detail: String = "Waiting for http://localhost:3333 to respond.") {
        icon.isHidden = true
        spinner.startAnimation(nil)
        titleLabel.stringValue = "Starting helper server…"
        detailLabel.stringValue = detail
    }

    func showFailure(_ message: String) {
        spinner.stopAnimation(nil)
        icon.isHidden = false
        titleLabel.stringValue = "Helper server is not responding"
        detailLabel.stringValue = message
    }

    @objc private func retryPressed() { onRetry?() }
    @objc private func logPressed() { onShowLog?() }
}

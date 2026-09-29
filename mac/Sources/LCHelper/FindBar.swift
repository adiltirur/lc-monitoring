import AppKit

/// Small find-in-page overlay pinned to the top-right of the window.
/// Enter = next, Shift+Enter = previous, Esc = close.
@MainActor
final class FindBar: NSVisualEffectView, NSTextFieldDelegate {
    var onFind: ((_ text: String, _ backwards: Bool) -> Void)?
    var onClose: (() -> Void)?

    let field = NSTextField()
    private let statusLabel = NSTextField(labelWithString: "")

    var searchText: String { field.stringValue }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        setUp()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    private func setUp() {
        material = .popover
        blendingMode = .withinWindow
        state = .active
        wantsLayer = true
        layer?.cornerRadius = 10
        layer?.masksToBounds = true
        layer?.borderWidth = 0.5
        layer?.borderColor = NSColor.separatorColor.cgColor

        field.placeholderString = "Find in page"
        field.delegate = self
        field.bezelStyle = .roundedBezel
        field.focusRingType = .none
        field.translatesAutoresizingMaskIntoConstraints = false
        field.widthAnchor.constraint(equalToConstant: 200).isActive = true

        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.widthAnchor.constraint(equalToConstant: 64).isActive = true

        let prev = Self.iconButton("chevron.up", "Previous (⇧↩)", #selector(previousPressed), target: self)
        let next = Self.iconButton("chevron.down", "Next (↩)", #selector(nextPressed), target: self)
        let done = Self.iconButton("xmark", "Close (Esc)", #selector(closePressed), target: self)

        let stack = NSStackView(views: [field, statusLabel, prev, next, done])
        stack.orientation = .horizontal
        stack.spacing = 6
        stack.edgeInsets = NSEdgeInsets(top: 6, left: 8, bottom: 6, right: 8)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }

    private static func iconButton(_ symbol: String, _ tip: String, _ action: Selector, target: AnyObject) -> NSButton {
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: tip) ?? NSImage()
        let button = NSButton(image: image, target: target, action: action)
        button.bezelStyle = .accessoryBarAction
        button.isBordered = false
        button.toolTip = tip
        return button
    }

    func focus() {
        window?.makeFirstResponder(field)
        field.currentEditor()?.selectAll(nil)
    }

    func setResult(found: Bool?) {
        switch found {
        case .none: statusLabel.stringValue = ""
        case .some(true): statusLabel.stringValue = ""
        case .some(false): statusLabel.stringValue = "No matches"
        }
    }

    // MARK: Actions

    @objc private func previousPressed() { onFind?(field.stringValue, true) }
    @objc private func nextPressed() { onFind?(field.stringValue, false) }
    @objc private func closePressed() { onClose?() }

    // MARK: NSTextFieldDelegate

    func controlTextDidChange(_ obj: Notification) {
        if field.stringValue.isEmpty {
            setResult(found: nil)
        } else {
            onFind?(field.stringValue, false)
        }
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        switch commandSelector {
        case #selector(NSResponder.insertNewline(_:)), #selector(NSResponder.insertLineBreak(_:)):
            let backwards = NSApp.currentEvent?.modifierFlags.contains(.shift) ?? false
            onFind?(field.stringValue, backwards)
            return true
        case #selector(NSResponder.cancelOperation(_:)):
            onClose?()
            return true
        default:
            return false
        }
    }
}

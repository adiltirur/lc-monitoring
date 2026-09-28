import AppKit
import WebKit

/// WKWebView that remembers the last mouse-down so the page can ask the
/// native side to start a window drag (`lcNative.post('drag')`).
@MainActor
final class LCWebView: WKWebView {
    private(set) var lastMouseDown: NSEvent?

    override func mouseDown(with event: NSEvent) {
        lastMouseDown = event
        super.mouseDown(with: event)
    }
}

/// One browser-like window hosting the helper SPA.
@MainActor
final class MainWindowController: NSWindowController, NSWindowDelegate, NSMenuItemValidation {
    static let prodRed = NSColor(srgbRed: 0xB5 / 255, green: 0x35 / 255, blue: 0x35 / 255, alpha: 1) // matches --band

    let webView: LCWebView
    private let coordinator: WebViewCoordinator
    private let backdrop = NSVisualEffectView()
    private let loadingView = LoadingView()
    private let prodStrip = NSView()
    private let findBar = FindBar()

    private var pollTask: Task<Void, Never>?
    private var pendingURL: URL?

    /// Last environment reported by the page via `setEnv`.
    private(set) var environment: String?
    var isProduction: Bool { environment == "production" || environment == "prod" }

    var onClose: ((MainWindowController) -> Void)?
    var onEnvironmentChange: (() -> Void)?

    /// - Parameters:
    ///   - popupConfiguration: configuration handed to us by WebKit for `window.open`;
    ///     WebKit loads the request itself in that case.
    ///   - autosaveFrame: only one window may own the frame autosave name.
    init(initialHash: String? = nil, popupConfiguration: WKWebViewConfiguration? = nil, autosaveFrame: Bool) {
        let configuration = popupConfiguration ?? WebViewFactory.makeConfiguration()
        webView = LCWebView(frame: .zero, configuration: configuration)
        coordinator = WebViewCoordinator()

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1440, height: 900),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.title = "LC Helper"
        window.contentMinSize = NSSize(width: 1000, height: 640)
        window.isReleasedWhenClosed = false
        window.tabbingMode = .disallowed
        window.collectionBehavior.insert(.fullScreenPrimary)

        super.init(window: window)
        window.delegate = self
        coordinator.controller = self

        buildContent(in: window)

        window.center()
        if autosaveFrame {
            window.setFrameAutosaveName("LCHelperMainWindow")
        }

        if popupConfiguration == nil {
            var url = AppConstants.webBaseURL
            if let initialHash, var comps = URLComponents(url: url, resolvingAgainstBaseURL: false) {
                comps.fragment = initialHash
                url = comps.url ?? url
            }
            waitForServer(thenLoad: url)
        } else {
            loadingView.isHidden = true
        }
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    // MARK: - Layout

    private func buildContent(in window: NSWindow) {
        backdrop.material = .sidebar
        backdrop.blendingMode = .behindWindow
        backdrop.state = .followsWindowActiveState
        window.contentView = backdrop

        webView.navigationDelegate = coordinator
        webView.uiDelegate = coordinator
        webView.isInspectable = true
        webView.allowsBackForwardNavigationGestures = true
        webView.allowsMagnification = false
        webView.setValue(false, forKey: "drawsBackground")
        webView.underPageBackgroundColor = .clear
        webView.pageZoom = ZoomSettings.current

        loadingView.onRetry = { [weak self] in self?.retryLoading() }
        loadingView.onShowLog = { AppDelegate.shared?.showServerLog() }

        prodStrip.wantsLayer = true
        prodStrip.layer?.backgroundColor = Self.prodRed.cgColor
        prodStrip.isHidden = true

        findBar.isHidden = true
        findBar.onFind = { [weak self] text, backwards in self?.find(text, backwards: backwards) }
        findBar.onClose = { [weak self] in self?.hideFindBar() }

        for view in [webView, loadingView, prodStrip, findBar] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            backdrop.addSubview(view)
        }

        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
            webView.topAnchor.constraint(equalTo: backdrop.topAnchor),
            webView.bottomAnchor.constraint(equalTo: backdrop.bottomAnchor),

            loadingView.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
            loadingView.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
            loadingView.topAnchor.constraint(equalTo: backdrop.topAnchor),
            loadingView.bottomAnchor.constraint(equalTo: backdrop.bottomAnchor),

            prodStrip.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
            prodStrip.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
            prodStrip.topAnchor.constraint(equalTo: backdrop.topAnchor),
            prodStrip.heightAnchor.constraint(equalToConstant: 3),

            findBar.topAnchor.constraint(equalTo: backdrop.topAnchor, constant: 40),
            findBar.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor, constant: -16),
        ])
    }

    // MARK: - Server availability

    /// Shows the native loading view and polls the helper every second (up to 30 s),
    /// then loads `url` once it responds.
    func waitForServer(thenLoad url: URL) {
        pendingURL = url
        pollTask?.cancel()
        loadingView.isHidden = false
        loadingView.showWaiting()

        pollTask = Task { [weak self] in
            let deadline = Date().addingTimeInterval(30)
            while !Task.isCancelled {
                if await LocalStackClient.shared.isServerUp() {
                    self?.serverBecameReachable()
                    return
                }
                if Date() >= deadline {
                    self?.loadingView.showFailure(
                        "Nothing answered on http://localhost:3333 within 30 seconds. "
                        + "Check the server log, or run mac/install.sh if the LaunchAgent is not installed.")
                    return
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func serverBecameReachable() {
        pollTask = nil
        loadingView.isHidden = true
        webView.load(URLRequest(url: pendingURL ?? AppConstants.webBaseURL))
        pendingURL = nil
    }

    private func retryLoading() {
        waitForServer(thenLoad: pendingURL ?? webView.url ?? AppConstants.webBaseURL)
    }

    /// Called by the navigation delegate when a main-frame load failed with a connection error.
    func serverUnreachable(failingURL: URL?) {
        let url = failingURL.flatMap { AppConstants.isLocalHost($0.host) ? $0 : nil } ?? AppConstants.webBaseURL
        waitForServer(thenLoad: url)
    }

    // MARK: - Native bridge

    func handleNativeMessage(type: String, payload: [String: Any]?) {
        guard let window else { return }
        switch type {
        case "drag":
            // Only start a drag while the primary button is still held.
            guard let event = webView.lastMouseDown, NSEvent.pressedMouseButtons & 1 != 0 else { return }
            window.performDrag(with: event)
        case "zoom":
            window.performZoom(nil)
        case "notify":
            let title = payload?["title"] as? String ?? "LC Helper"
            let body = payload?["body"] as? String ?? ""
            Notifier.post(title: title, body: body)
        case "setEnv":
            setEnvironment(payload?["env"] as? String)
        default:
            break
        }
    }

    private func setEnvironment(_ env: String?) {
        environment = env?.lowercased()
        let prod = isProduction
        prodStrip.isHidden = !prod
        window?.backgroundColor = prod ? Self.prodRed.withAlphaComponent(0.12) : .windowBackgroundColor
        onEnvironmentChange?()
    }

    // MARK: - JS helpers

    func setHash(_ hash: String) {
        if !loadingView.isHidden, var comps = URLComponents(url: pendingURL ?? AppConstants.webBaseURL,
                                                            resolvingAgainstBaseURL: false) {
            // Page not loaded yet — just change the URL we are going to load.
            comps.fragment = hash
            pendingURL = comps.url
            return
        }
        webView.callAsyncJavaScript("location.hash = h", arguments: ["h": "#" + hash],
                                    in: nil, in: .page, completionHandler: nil)
    }

    func showToast(_ message: String) {
        webView.callAsyncJavaScript("window.showToast && window.showToast(msg)", arguments: ["msg": message],
                                    in: nil, in: .page, completionHandler: nil)
    }

    func applyZoom() {
        webView.pageZoom = ZoomSettings.current
    }

    // MARK: - Find

    private func find(_ text: String, backwards: Bool) {
        guard !text.isEmpty else { findBar.setResult(found: nil); return }
        let configuration = WKFindConfiguration()
        configuration.backwards = backwards
        configuration.caseSensitive = false
        configuration.wraps = true
        webView.find(text, configuration: configuration) { [weak self] result in
            self?.findBar.setResult(found: result.matchFound)
        }
    }

    private func hideFindBar() {
        findBar.isHidden = true
        window?.makeFirstResponder(webView)
    }

    // MARK: - Menu actions (reached through the responder chain)

    @objc func showFindBar(_ sender: Any?) {
        findBar.isHidden = false
        findBar.focus()
    }

    @objc func findNextMatch(_ sender: Any?) {
        if findBar.isHidden || findBar.searchText.isEmpty { showFindBar(sender); return }
        find(findBar.searchText, backwards: false)
    }

    @objc func findPreviousMatch(_ sender: Any?) {
        if findBar.isHidden || findBar.searchText.isEmpty { showFindBar(sender); return }
        find(findBar.searchText, backwards: true)
    }

    @objc func reloadPage(_ sender: Any?) {
        if !loadingView.isHidden { retryLoading(); return }
        webView.reload()
    }

    @objc func forceReloadPage(_ sender: Any?) {
        if !loadingView.isHidden { retryLoading(); return }
        webView.reloadFromOrigin()
    }

    @objc func goBack(_ sender: Any?) { webView.goBack() }
    @objc func goForward(_ sender: Any?) { webView.goForward() }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        switch menuItem.action {
        case #selector(goBack(_:)): return webView.canGoBack
        case #selector(goForward(_:)): return webView.canGoForward
        default: return true
        }
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        pollTask?.cancel()
        pollTask = nil
        webView.stopLoading()
        // Drop SSE / long-poll connections promptly.
        webView.loadHTMLString("", baseURL: nil)
        onClose?(self)
    }
}

// MARK: - Zoom persistence

@MainActor
enum ZoomSettings {
    private static let key = "pageZoom"
    static let steps: [CGFloat] = [0.5, 0.67, 0.75, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0]

    static var current: CGFloat {
        get {
            let value = UserDefaults.standard.double(forKey: key)
            return value > 0 ? CGFloat(value) : 1.0
        }
        set { UserDefaults.standard.set(Double(newValue), forKey: key) }
    }

    static func zoomIn() {
        current = steps.first(where: { $0 > current + 0.001 }) ?? steps.last!
    }

    static func zoomOut() {
        current = steps.last(where: { $0 < current - 0.001 }) ?? steps.first!
    }

    static func reset() { current = 1.0 }
}

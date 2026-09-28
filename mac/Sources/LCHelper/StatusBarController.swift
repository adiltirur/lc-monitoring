import AppKit
import ServiceManagement

/// Small colored dot overlaid on the (template) menu bar glyph.
@MainActor
final class StatusDotView: NSView {
    var fillColor: NSColor = .systemGray { didSet { needsDisplay = true } }
    var ringColor: NSColor? { didSet { needsDisplay = true } }

    override func draw(_ dirtyRect: NSRect) {
        let rect = bounds.insetBy(dx: 1, dy: 1)
        fillColor.setFill()
        NSBezierPath(ovalIn: rect.insetBy(dx: ringColor == nil ? 1 : 1.5, dy: ringColor == nil ? 1 : 1.5)).fill()
        if let ringColor {
            ringColor.setStroke()
            let ring = NSBezierPath(ovalIn: rect.insetBy(dx: 0.5, dy: 0.5))
            ring.lineWidth = 1.5
            ring.stroke()
        }
    }

    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}

/// Menu bar extra: status dot + quick controls for the helper server and Serverpod.
@MainActor
final class StatusBarController: NSObject, NSMenuDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let dot = StatusDotView()
    private let menu = NSMenu()

    private let helperLine = NSMenuItem(title: "Helper server: Checking…", action: nil, keyEquivalent: "")
    private let serverpodLine = NSMenuItem(title: "Serverpod: —", action: nil, keyEquivalent: "")
    private let dockerLine = NSMenuItem(title: "Docker: —", action: nil, keyEquivalent: "")
    private var startItem: NSMenuItem!
    private var stopItem: NSMenuItem!
    private var restartItem: NSMenuItem!
    private var launchAtLoginItem: NSMenuItem!

    private var probe: StackProbe = .unknown
    private var isProduction = false
    private var refreshInFlight = false
    private var actionInFlight = false
    private var timer: Timer?

    override init() {
        super.init()
        configureButton()
        buildMenu()
        render()
        startPolling()
    }

    // MARK: Setup

    private func configureButton() {
        guard let button = statusItem.button else { return }
        let glyph = NSImage(systemSymbolName: "stethoscope", accessibilityDescription: "LC Helper")?
            .withSymbolConfiguration(.init(pointSize: 14, weight: .medium))
        glyph?.isTemplate = true
        button.image = glyph
        button.imagePosition = .imageOnly
        button.toolTip = "LC Helper"

        dot.translatesAutoresizingMaskIntoConstraints = false
        button.addSubview(dot)
        NSLayoutConstraint.activate([
            dot.widthAnchor.constraint(equalToConstant: 8),
            dot.heightAnchor.constraint(equalToConstant: 8),
            dot.trailingAnchor.constraint(equalTo: button.trailingAnchor, constant: -1),
            dot.bottomAnchor.constraint(equalTo: button.bottomAnchor, constant: -2),
        ])
    }

    private func buildMenu() {
        menu.delegate = self
        menu.autoenablesItems = false

        let open = item("Open LC Helper", #selector(openApp), key: "o")
        let browser = item("Open in Browser", #selector(openInBrowser))
        for line in [helperLine, serverpodLine, dockerLine] { line.isEnabled = false }

        startItem = item("Start Serverpod", #selector(startServerpod))
        stopItem = item("Stop Serverpod", #selector(stopServerpod))
        restartItem = item("Restart Serverpod", #selector(restartServerpod))
        let restartHelper = item("Restart Helper Server", #selector(restartHelperServer))
        restartHelper.toolTip = "launchctl kickstart -k gui/<uid>/\(AppConstants.launchAgentLabel)"

        let serverLog = item("Show Server Log", #selector(showServerLog))
        let serverpodLog = item("Show Serverpod Log", #selector(showServerpodLog))
        launchAtLoginItem = item("Launch at Login", #selector(toggleLaunchAtLogin))

        let quit = item("Quit LC Helper", #selector(quit), key: "q")
        quit.toolTip = "Quits the app only — the helper server keeps running under launchd."

        menu.items = [
            open, browser, .separator(),
            helperLine, serverpodLine, dockerLine,
            startItem, stopItem, restartItem, restartHelper, .separator(),
            serverLog, serverpodLog, launchAtLoginItem, .separator(),
            quit,
        ]
        statusItem.menu = menu
    }

    private func item(_ title: String, _ action: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.target = self
        return item
    }

    private func startPolling() {
        refresh()
        let timer = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    // MARK: State

    func refresh() {
        guard !refreshInFlight else { return }
        refreshInFlight = true
        Task { [weak self] in
            let result = await LocalStackClient.shared.probe()
            guard let self else { return }
            self.refreshInFlight = false
            self.probe = result
            self.render()
        }
    }

    func setProduction(_ production: Bool) {
        isProduction = production
        render()
    }

    private func render() {
        var serverpodState: String?

        switch probe {
        case .unknown:
            helperLine.title = "Helper server: Checking…"
            serverpodLine.title = "Serverpod: —"
            dockerLine.title = "Docker: —"
            dot.fillColor = .systemGray
        case .helperDown:
            helperLine.title = "Helper server: Down"
            serverpodLine.title = "Serverpod: Unknown (helper down)"
            dockerLine.title = "Docker: Unknown"
            dot.fillColor = .systemRed
        case .apiUnavailable(let reason):
            helperLine.title = "Helper server: Running on :3333"
            serverpodLine.title = "Serverpod: Unknown (\(reason))"
            dockerLine.title = "Docker: Unknown"
            dot.fillColor = .systemGreen
        case .status(let status):
            helperLine.title = "Helper server: Running on :3333"
            serverpodState = status.serverpod?.state
            serverpodLine.title = "Serverpod: " + describe(status.serverpod, includePid: true)
            dockerLine.title = "Docker: " + describe(status.docker, includePid: false)
            dot.fillColor = color(serverpod: status.serverpod?.state, docker: status.docker?.state)
        }

        let busy = actionInFlight || serverpodState == nil
        startItem.isEnabled = !busy && ["stopped", "crashed"].contains(serverpodState ?? "")
        stopItem.isEnabled = !busy && ["running", "starting"].contains(serverpodState ?? "")
        restartItem.isEnabled = !busy && ["running", "crashed"].contains(serverpodState ?? "")

        dot.ringColor = isProduction ? MainWindowController.prodRed : nil
        statusItem.button?.toolTip = [helperLine.title, serverpodLine.title, dockerLine.title]
            .joined(separator: "\n") + (isProduction ? "\nEnvironment: PRODUCTION" : "")

        updateLaunchAtLoginState()
    }

    private func describe(_ component: LocalStackStatus.Component?, includePid: Bool) -> String {
        guard let component else { return "Unknown" }
        var text = component.state.prefix(1).uppercased() + component.state.dropFirst()
        if includePid, let pid = component.pid, component.state == "running" { text += " (pid \(pid))" }
        if let detail = component.detail, !detail.isEmpty { text += " — \(detail.prefix(80))" }
        return text
    }

    private func color(serverpod: String?, docker: String?) -> NSColor {
        if serverpod == "running" && (docker == nil || docker == "running") { return .systemGreen }
        return .systemYellow // starting / stopping / stopped / crashed / docker not running → partial
    }

    private func updateLaunchAtLoginState() {
        switch SMAppService.mainApp.status {
        case .enabled: launchAtLoginItem.state = .on
        case .requiresApproval: launchAtLoginItem.state = .mixed
        default: launchAtLoginItem.state = .off
        }
    }

    // MARK: NSMenuDelegate

    func menuWillOpen(_ menu: NSMenu) {
        updateLaunchAtLoginState()
        refresh()
    }

    // MARK: Actions

    @objc private func openApp() { AppDelegate.shared?.showMainWindow() }

    @objc private func openInBrowser() { NSWorkspace.shared.open(AppConstants.webBaseURL) }

    @objc private func startServerpod() { perform(.start) }
    @objc private func stopServerpod() { perform(.stop) }
    @objc private func restartServerpod() { perform(.restart) }

    private func perform(_ action: LocalStackAction) {
        actionInFlight = true
        render()
        Task { [weak self] in
            do {
                if let status = try await LocalStackClient.shared.perform(action) {
                    self?.probe = .status(status)
                }
            } catch {
                Self.showError("Could not \(action.rawValue) Serverpod", error.localizedDescription)
            }
            self?.actionInFlight = false
            self?.render()
            self?.refresh()
        }
    }

    @objc private func restartHelperServer() {
        Task { [weak self] in
            let result = await Shell.run("/bin/launchctl",
                                         ["kickstart", "-k", "gui/\(getuid())/\(AppConstants.launchAgentLabel)"])
            if result.status != 0 {
                Self.showError("Could not restart the helper server",
                               (result.output.isEmpty ? "launchctl exited with \(result.status)." : result.output)
                               + "\n\nIs the LaunchAgent installed? Run mac/install.sh.")
            }
            self?.probe = .unknown
            self?.render()
            try? await Task.sleep(for: .seconds(1.5))
            self?.refresh()
        }
    }

    @objc private func showServerLog() { AppDelegate.shared?.showServerLog() }

    @objc private func showServerpodLog() { AppDelegate.shared?.showMainWindow(hash: "local-stack") }

    @objc private func toggleLaunchAtLogin() {
        let service = SMAppService.mainApp
        do {
            switch service.status {
            case .enabled:
                try service.unregister()
            case .requiresApproval:
                SMAppService.openSystemSettingsLoginItems()
            default:
                try service.register()
                if service.status == .requiresApproval {
                    SMAppService.openSystemSettingsLoginItems()
                }
            }
        } catch {
            Self.showError("Could not change Launch at Login", error.localizedDescription)
        }
        updateLaunchAtLoginState()
    }

    @objc private func quit() { NSApp.terminate(nil) }

    static func showError(_ title: String, _ message: String) {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

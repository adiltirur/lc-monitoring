import AppKit
import UserNotifications
import WebKit

@main
@MainActor
enum LCHelperApp {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        withExtendedLifetime(delegate) {
            app.run()
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private(set) static weak var shared: AppDelegate?

    private var controllers: [MainWindowController] = []
    private var statusBar: StatusBarController?

    override init() {
        super.init()
        Self.shared = self
    }

    // MARK: - Lifecycle

    func applicationWillFinishLaunching(_ notification: Notification) {
        NSWindow.allowsAutomaticWindowTabbing = false
        NSApp.mainMenu = MainMenuBuilder.build()
        if CommandLine.arguments.contains("--background") {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
        statusBar = StatusBarController()

        if CommandLine.arguments.contains("--background") || Self.launchedAsLoginItem() {
            NSApp.setActivationPolicy(.accessory)
        } else {
            showMainWindow()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !controllers.contains(where: { $0.window?.isVisible == true }) {
            showMainWindow()
        }
        return true
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }

    private static func launchedAsLoginItem() -> Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == AEEventID(kAEOpenApplication)
            && event.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue
                == OSType(keyAELaunchedAsLogInItem)
    }

    // MARK: - Windows

    /// Brings an existing window forward (or creates one) and optionally navigates to `#hash`.
    func showMainWindow(hash: String? = nil) {
        let controller: MainWindowController
        if let existing = frontmostController() {
            controller = existing
            if let hash { controller.setHash(hash) }
        } else {
            controller = makeController(hash: hash, popupConfiguration: nil)
        }
        present(controller)
    }

    @discardableResult
    func openPopupWindow(configuration: WKWebViewConfiguration) -> MainWindowController {
        let controller = makeController(hash: nil, popupConfiguration: configuration)
        present(controller)
        return controller
    }

    private func makeController(hash: String?, popupConfiguration: WKWebViewConfiguration?) -> MainWindowController {
        let ownsAutosave = !controllers.contains { $0.window?.frameAutosaveName == "LCHelperMainWindow" }
        let controller = MainWindowController(initialHash: hash, popupConfiguration: popupConfiguration,
                                              autosaveFrame: ownsAutosave)
        if !ownsAutosave, let anchor = frontmostController()?.window, let window = controller.window {
            window.setFrameTopLeftPoint(window.cascadeTopLeft(from: anchor.frame.origin
                .applying(.init(translationX: 0, y: anchor.frame.height))))
        }
        controller.onClose = { [weak self] closed in self?.controllerDidClose(closed) }
        controller.onEnvironmentChange = { [weak self] in self?.updateProductionIndicators() }
        controllers.append(controller)
        return controller
    }

    private func present(_ controller: MainWindowController) {
        NSApp.setActivationPolicy(.regular)
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate()
    }

    private func frontmostController() -> MainWindowController? {
        if let key = NSApp.keyWindow?.windowController as? MainWindowController { return key }
        if let main = NSApp.mainWindow?.windowController as? MainWindowController { return main }
        // NSApp.orderedWindows is front-to-back.
        for window in NSApp.orderedWindows {
            if let controller = window.windowController as? MainWindowController,
               controllers.contains(where: { $0 === controller }) {
                return controller
            }
        }
        return controllers.last
    }

    private func controllerDidClose(_ controller: MainWindowController) {
        controllers.removeAll { $0 === controller }
        updateProductionIndicators()
        // The closing window is still visible during willClose — decide on the next turn.
        DispatchQueue.main.async { [weak self] in self?.updateActivationPolicy() }
    }

    private func updateActivationPolicy() {
        let hasWindow = controllers.contains { $0.window?.isVisible == true || $0.window?.isMiniaturized == true }
        NSApp.setActivationPolicy(hasWindow ? .regular : .accessory)
    }

    private func updateProductionIndicators() {
        let production = controllers.contains { $0.isProduction }
        NSApp.dockTile.badgeLabel = production ? "PROD" : nil
        statusBar?.setProduction(production)
    }

    // MARK: - Shared actions

    func showServerLog() {
        let path = AppConstants.serverLogURL.path
        guard FileManager.default.fileExists(atPath: path) else {
            StatusBarController.showError("No server log yet",
                                          "\(path) does not exist. Run mac/install.sh to install the helper server LaunchAgent.")
            return
        }
        Task {
            let result = await Shell.run("/usr/bin/open", ["-a", "Console", path])
            if result.status != 0 {
                StatusBarController.showError("Could not open the server log", result.output)
            }
        }
    }

    // MARK: - Menu actions (end of the responder chain)

    @objc func newWindow(_ sender: Any?) {
        let hash = frontmostController()?.webView.url?.fragment
        present(makeController(hash: hash, popupConfiguration: nil))
    }

    @objc func openMainWindow(_ sender: Any?) { showMainWindow() }

    @objc func jumpToHash(_ sender: NSMenuItem) {
        guard let hash = sender.representedObject as? String else { return }
        showMainWindow(hash: hash)
    }

    @objc func zoomInPage(_ sender: Any?) { ZoomSettings.zoomIn(); applyZoom() }
    @objc func zoomOutPage(_ sender: Any?) { ZoomSettings.zoomOut(); applyZoom() }
    @objc func actualSizePage(_ sender: Any?) { ZoomSettings.reset(); applyZoom() }

    private func applyZoom() {
        controllers.forEach { $0.applyZoom() }
    }

    // MARK: - UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification) async
        -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse) async {
        await MainActor.run { AppDelegate.shared?.showMainWindow() }
    }
}

// MARK: - Main menu

@MainActor
enum MainMenuBuilder {
    static func build() -> NSMenu {
        let main = NSMenu()
        main.addItem(submenu(appMenu()))
        main.addItem(submenu(editMenu()))
        main.addItem(submenu(viewMenu()))
        main.addItem(submenu(goMenu()))
        let window = windowMenu()
        main.addItem(submenu(window))
        NSApp.windowsMenu = window
        let help = NSMenu(title: "Help")
        main.addItem(submenu(help))
        NSApp.helpMenu = help
        return main
    }

    private static func submenu(_ menu: NSMenu) -> NSMenuItem {
        let item = NSMenuItem(title: menu.title, action: nil, keyEquivalent: "")
        item.submenu = menu
        return item
    }

    private static func item(_ title: String, _ action: Selector?, _ key: String = "",
                             _ modifiers: NSEvent.ModifierFlags = .command) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.keyEquivalentModifierMask = modifiers
        return item
    }

    private static func appMenu() -> NSMenu {
        let menu = NSMenu(title: "LC Helper")
        menu.addItem(item("About LC Helper", #selector(NSApplication.orderFrontStandardAboutPanel(_:))))
        menu.addItem(.separator())
        let services = NSMenu(title: "Services")
        let servicesItem = NSMenuItem(title: "Services", action: nil, keyEquivalent: "")
        servicesItem.submenu = services
        NSApp.servicesMenu = services
        menu.addItem(servicesItem)
        menu.addItem(.separator())
        menu.addItem(item("Hide LC Helper", #selector(NSApplication.hide(_:)), "h"))
        menu.addItem(item("Hide Others", #selector(NSApplication.hideOtherApplications(_:)), "h", [.command, .option]))
        menu.addItem(item("Show All", #selector(NSApplication.unhideAllApplications(_:))))
        menu.addItem(.separator())
        let quit = item("Quit LC Helper", #selector(NSApplication.terminate(_:)), "q")
        quit.toolTip = "Quits the app only — the helper server keeps running under launchd."
        menu.addItem(quit)
        return menu
    }

    private static func editMenu() -> NSMenu {
        let menu = NSMenu(title: "Edit")
        menu.addItem(item("Undo", Selector(("undo:")), "z"))
        menu.addItem(item("Redo", Selector(("redo:")), "z", [.command, .shift]))
        menu.addItem(.separator())
        menu.addItem(item("Cut", #selector(NSText.cut(_:)), "x"))
        menu.addItem(item("Copy", #selector(NSText.copy(_:)), "c"))
        menu.addItem(item("Paste", #selector(NSText.paste(_:)), "v"))
        menu.addItem(item("Paste and Match Style", #selector(NSTextView.pasteAsPlainText(_:)), "v",
                          [.command, .option, .shift]))
        menu.addItem(item("Delete", #selector(NSText.delete(_:))))
        menu.addItem(item("Select All", #selector(NSText.selectAll(_:)), "a"))
        menu.addItem(.separator())

        let find = NSMenu(title: "Find")
        find.addItem(item("Find…", #selector(MainWindowController.showFindBar(_:)), "f"))
        find.addItem(item("Find Next", #selector(MainWindowController.findNextMatch(_:)), "g"))
        find.addItem(item("Find Previous", #selector(MainWindowController.findPreviousMatch(_:)), "g",
                          [.command, .shift]))
        let findItem = NSMenuItem(title: "Find", action: nil, keyEquivalent: "")
        findItem.submenu = find
        menu.addItem(findItem)
        return menu
    }

    private static func viewMenu() -> NSMenu {
        let menu = NSMenu(title: "View")
        menu.addItem(item("Reload", #selector(MainWindowController.reloadPage(_:)), "r"))
        menu.addItem(item("Force Reload", #selector(MainWindowController.forceReloadPage(_:)), "r", [.command, .shift]))
        menu.addItem(.separator())
        menu.addItem(item("Actual Size", #selector(AppDelegate.actualSizePage(_:)), "0"))
        menu.addItem(item("Zoom In", #selector(AppDelegate.zoomInPage(_:)), "+"))
        let zoomInAlt = item("Zoom In", #selector(AppDelegate.zoomInPage(_:)), "=")
        zoomInAlt.isHidden = true
        zoomInAlt.allowsKeyEquivalentWhenHidden = true
        menu.addItem(zoomInAlt)
        menu.addItem(item("Zoom Out", #selector(AppDelegate.zoomOutPage(_:)), "-"))
        menu.addItem(.separator())
        menu.addItem(item("Enter Full Screen", #selector(NSWindow.toggleFullScreen(_:)), "f", [.command, .control]))
        return menu
    }

    private static func goMenu() -> NSMenu {
        let menu = NSMenu(title: "Go")
        menu.addItem(item("Back", #selector(MainWindowController.goBack(_:)), "["))
        menu.addItem(item("Forward", #selector(MainWindowController.goForward(_:)), "]"))
        menu.addItem(.separator())
        let jumps: [(String, String, String)] = [
            ("Monitor", "monitoring", "1"),
            ("Session Logs", "session-logs", "2"),
            ("Users", "users", "3"),
            ("Query Runner", "query-runner", "4"),
            ("Local Stack", "local-stack", "5"),
        ]
        for (title, hash, key) in jumps {
            let jump = item(title, #selector(AppDelegate.jumpToHash(_:)), key)
            jump.representedObject = hash
            menu.addItem(jump)
        }
        return menu
    }

    private static func windowMenu() -> NSMenu {
        let menu = NSMenu(title: "Window")
        menu.addItem(item("New Window", #selector(AppDelegate.newWindow(_:)), "n"))
        menu.addItem(.separator())
        menu.addItem(item("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"))
        menu.addItem(item("Zoom", #selector(NSWindow.performZoom(_:))))
        menu.addItem(.separator())
        menu.addItem(item("Open LC Helper", #selector(AppDelegate.openMainWindow(_:)), "o"))
        menu.addItem(.separator())
        menu.addItem(item("Bring All to Front", #selector(NSApplication.arrangeInFront(_:))))
        return menu
    }
}

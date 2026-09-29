import AppKit
import UserNotifications
import WebKit

// MARK: - Configuration factory

@MainActor
enum WebViewFactory {
    static let messageHandlerName = "lc"

    static func makeConfiguration() -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.applicationNameForUserAgent = "LCHelperMac/\(AppConstants.appVersion)"
        configuration.preferences.isElementFullscreenEnabled = true
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true

        let content = configuration.userContentController
        content.addUserScript(WKUserScript(source: bridgeScript,
                                           injectionTime: .atDocumentStart,
                                           forMainFrameOnly: true))
        content.addUserScript(WKUserScript(source: dragRegionScript,
                                           injectionTime: .atDocumentStart,
                                           forMainFrameOnly: true))
        content.add(ScriptMessageRouter.shared, name: messageHandlerName)
        return configuration
    }

    private static var bridgeScript: String {
        let version = AppConstants.appVersion
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "'", with: "\\'")
        return """
        (function () {
          var mark = function () { document.documentElement && (document.documentElement.dataset.shell = 'mac'); };
          if (document.documentElement) { mark(); } else { document.addEventListener('DOMContentLoaded', mark); }
          window.__LC_SHELL__ = { platform: 'mac', version: '\(version)' };
          window.lcNative = {
            post: function (type, payload) {
              window.webkit.messageHandlers.lc.postMessage({ type: type, payload: payload === undefined ? null : payload });
            }
          };
        })();
        """
    }

    private static let dragRegionScript = """
    (function () {
      var NO_DRAG = 'button, a, input, select, textarea, [data-no-drag]';
      function inDragRegion(target) {
        var el = target instanceof Element ? target : (target && target.parentElement);
        if (!el || !el.closest('[data-drag-region]')) return false;
        return !el.closest(NO_DRAG);
      }
      document.addEventListener('mousedown', function (e) {
        if (e.button !== 0 || e.detail > 1 || !inDragRegion(e.target)) return;
        window.lcNative && window.lcNative.post('drag');
      });
      document.addEventListener('dblclick', function (e) {
        if (e.button !== 0 || !inDragRegion(e.target)) return;
        window.lcNative && window.lcNative.post('zoom');
      });
    })();
    """
}

// MARK: - Script message routing

/// Single handler shared by every window. Popup windows inherit their opener's
/// user content controller, so we dispatch on `message.webView` rather than on
/// which controller registered the handler.
@MainActor
final class ScriptMessageRouter: NSObject, WKScriptMessageHandler {
    static let shared = ScriptMessageRouter()

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        // Only trust the helper's own main frame.
        guard message.frameInfo.isMainFrame,
              AppConstants.isLocalHost(message.frameInfo.securityOrigin.host),
              let controller = message.webView?.window?.windowController as? MainWindowController,
              let body = message.body as? [String: Any],
              let type = body["type"] as? String
        else { return }
        controller.handleNativeMessage(type: type, payload: body["payload"] as? [String: Any])
    }
}

// MARK: - Notifications

@MainActor
enum Notifier {
    static func post(title: String, body: String) {
        Task {
            let center = UNUserNotificationCenter.current()
            let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
            try? await center.add(request)
        }
    }
}

// MARK: - Coordinator

/// UI, navigation and download delegate for one window's web view.
@MainActor
final class WebViewCoordinator: NSObject, WKUIDelegate, WKNavigationDelegate, WKDownloadDelegate {
    weak var controller: MainWindowController?

    /// Destinations of in-flight downloads, keyed by the WKDownload instance.
    private var downloadDestinations: [ObjectIdentifier: URL] = [:]

    private static let destructiveKeywords = [
        "delete", "wipe", "drop", "destroy", "production", "prod",
        "truncate", "refresh", "restore", "remove",
    ]

    private static let connectionErrorCodes: Set<Int> = [
        NSURLErrorCannotConnectToHost, NSURLErrorNetworkConnectionLost, NSURLErrorTimedOut,
        NSURLErrorNotConnectedToInternet, NSURLErrorCannotFindHost,
    ]

    // MARK: JavaScript panels

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor () -> Void) {
        let alert = makeAlert(message: message)
        alert.addButton(withTitle: "OK")
        present(alert, in: webView) { _ in completionHandler() }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor (Bool) -> Void) {
        let alert = makeAlert(message: message)
        let lowered = message.lowercased()
        let destructive = Self.destructiveKeywords.contains { lowered.contains($0) }

        if destructive {
            // Cancel is the default (Return) button; OK must be clicked deliberately.
            alert.alertStyle = .warning
            let cancel = alert.addButton(withTitle: "Cancel")
            cancel.keyEquivalent = "\r"
            let ok = alert.addButton(withTitle: "OK")
            ok.keyEquivalent = ""
            ok.hasDestructiveAction = true
            present(alert, in: webView) { completionHandler($0 == .alertSecondButtonReturn) }
        } else {
            alert.addButton(withTitle: "OK")
            let cancel = alert.addButton(withTitle: "Cancel")
            cancel.keyEquivalent = "\u{1b}"
            present(alert, in: webView) { completionHandler($0 == .alertFirstButtonReturn) }
        }
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping @MainActor (String?) -> Void) {
        let alert = makeAlert(message: prompt)
        let field = NSTextField(string: defaultText ?? "")
        field.frame = NSRect(x: 0, y: 0, width: 320, height: 24)
        field.usesSingleLineMode = true
        field.cell?.isScrollable = true
        alert.accessoryView = field
        alert.addButton(withTitle: "OK")
        let cancel = alert.addButton(withTitle: "Cancel")
        cancel.keyEquivalent = "\u{1b}"
        alert.window.initialFirstResponder = field
        present(alert, in: webView) { response in
            completionHandler(response == .alertFirstButtonReturn ? field.stringValue : nil)
        }
        alert.window.makeFirstResponder(field)
    }

    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.resolvesAliases = true
        let finish: (NSApplication.ModalResponse) -> Void = { response in
            completionHandler(response == .OK ? panel.urls : nil)
        }
        if let window = webView.window {
            panel.beginSheetModal(for: window, completionHandler: finish)
        } else {
            finish(panel.runModal())
        }
    }

    // MARK: Windows

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        let url = navigationAction.request.url
        if let url, !Self.isLocalOrBlank(url) {
            NSWorkspace.shared.open(url)
            return nil
        }
        return AppDelegate.shared?.openPopupWindow(configuration: configuration).webView
    }

    func webViewDidClose(_ webView: WKWebView) {
        webView.window?.close()
    }

    // MARK: Navigation policy

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
        if navigationAction.shouldPerformDownload {
            decisionHandler(.download)
            return
        }
        guard let url = navigationAction.request.url, let scheme = url.scheme?.lowercased() else {
            decisionHandler(.allow)
            return
        }
        switch scheme {
        case "http", "https":
            let isMainFrame = navigationAction.targetFrame?.isMainFrame ?? true
            if isMainFrame && !AppConstants.isLocalHost(url.host) {
                // External sites (incl. Google OAuth, which refuses embedded web views) go to the browser.
                NSWorkspace.shared.open(url)
                decisionHandler(.cancel)
            } else {
                decisionHandler(.allow)
            }
        case "about", "blob", "data", "javascript", "file":
            decisionHandler(.allow)
        default:
            // mailto:, tel:, x-apple... — hand to the system.
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
        }
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void) {
        if !navigationResponse.canShowMIMEType {
            decisionHandler(.download)
            return
        }
        if let http = navigationResponse.response as? HTTPURLResponse,
           let disposition = http.value(forHTTPHeaderField: "Content-Disposition")?
               .trimmingCharacters(in: .whitespaces).lowercased(),
           disposition.hasPrefix("attachment") {
            decisionHandler(.download)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    // MARK: Navigation failures

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        handleNavigationError(error)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        handleNavigationError(error)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        webView.reload()
    }

    private func handleNavigationError(_ error: Error) {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain, Self.connectionErrorCodes.contains(nsError.code) else { return }
        let failingURL = nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL
        guard failingURL == nil || AppConstants.isLocalHost(failingURL?.host) else { return }
        controller?.serverUnreachable(failingURL: failingURL)
    }

    // MARK: WKDownloadDelegate

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping @MainActor (URL?) -> Void) {
        let destination = uniqueDownloadURL(for: suggestedFilename)
        downloadDestinations[ObjectIdentifier(download)] = destination
        completionHandler(destination)
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let destination = downloadDestinations.removeValue(forKey: ObjectIdentifier(download)) else { return }
        DistributedNotificationCenter.default().post(name: .init("com.apple.DownloadFileFinished"),
                                                     object: destination.path)
        toast("Saved to Downloads: \(destination.lastPathComponent)", via: download)
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        let destination = downloadDestinations.removeValue(forKey: ObjectIdentifier(download))
        let name = destination?.lastPathComponent ?? "file"
        toast("Download failed (\(name)): \(error.localizedDescription)", via: download)
    }

    private func toast(_ message: String, via download: WKDownload) {
        if let webView = download.webView, let controller = webView.window?.windowController as? MainWindowController {
            controller.showToast(message)
        } else {
            controller?.showToast(message)
        }
    }

    /// ~/Downloads/<name>, or "<name> (1).<ext>", "<name> (2).<ext>", … if taken.
    /// Also avoids names reserved by other in-flight downloads (WKDownload requires a non-existent destination).
    private func uniqueDownloadURL(for suggestedFilename: String) -> URL {
        let fm = FileManager.default
        let folder = fm.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? fm.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        var name = suggestedFilename
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty || name == "." || name == ".." { name = "download" }

        let ext = (name as NSString).pathExtension
        let stem = (name as NSString).deletingPathExtension
        let reserved = Set(downloadDestinations.values.map(\.path))

        var candidate = folder.appendingPathComponent(name)
        var counter = 1
        while fm.fileExists(atPath: candidate.path) || reserved.contains(candidate.path) {
            let numbered = ext.isEmpty ? "\(stem) (\(counter))" : "\(stem) (\(counter)).\(ext)"
            candidate = folder.appendingPathComponent(numbered)
            counter += 1
        }
        return candidate
    }

    // MARK: Helpers

    private static func isLocalOrBlank(_ url: URL) -> Bool {
        let scheme = url.scheme?.lowercased() ?? ""
        if scheme.isEmpty || scheme == "about" || scheme == "blob" || scheme == "data" { return true }
        return AppConstants.isLocalHost(url.host)
    }

    /// messageText = first line (if short); everything else goes into informativeText
    /// so long messages are always fully visible.
    private func makeAlert(message: String) -> NSAlert {
        let alert = NSAlert()
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        let lines = trimmed.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        let firstLine = lines.first.map(String.init) ?? ""
        let rest = lines.count > 1 ? String(lines[1]).trimmingCharacters(in: .whitespacesAndNewlines) : ""

        if firstLine.count <= 120 {
            alert.messageText = firstLine.isEmpty ? "localhost:3333" : firstLine
            alert.informativeText = rest
        } else {
            alert.messageText = "localhost:3333 says"
            alert.informativeText = trimmed
        }
        return alert
    }

    private func present(_ alert: NSAlert, in webView: WKWebView,
                         completion: @escaping @MainActor (NSApplication.ModalResponse) -> Void) {
        if let window = webView.window, window.isVisible, window.attachedSheet == nil {
            alert.beginSheetModal(for: window) { response in completion(response) }
        } else {
            completion(alert.runModal())
        }
    }
}

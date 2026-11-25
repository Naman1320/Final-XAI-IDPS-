import AppKit
@preconcurrency import WebKit

@MainActor
final class DashboardApp: NSObject, NSApplicationDelegate, WKUIDelegate, WKNavigationDelegate, WKDownloadDelegate {
    private var window: NSWindow!
    private let web = WKWebView()
    private var connecting = false
    private var server: DashboardServer!
    private var downloads: [ObjectIdentifier: (temporary: URL, destination: URL)] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        let bundle = Bundle.main
        guard let project = bundle.object(forInfoDictionaryKey: "IDPSWebRoot") as? String,
              let node = bundle.object(forInfoDictionaryKey: "IDPSNode") as? String,
              let assets = bundle.resourceURL?.appendingPathComponent("Dashboard") else {
            NSApp.presentError(DashboardError.missingCheckout)
            NSApp.terminate(nil)
            return
        }
        server = DashboardServer(webRoot: URL(fileURLWithPath: project), node: URL(fileURLWithPath: node), assets: assets)
        configureMenu()
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 800),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "IDPS SOC"
        window.minSize = NSSize(width: 580, height: 400)
        window.center()
        window.setFrameAutosaveName("Dashboard")
        web.uiDelegate = self
        web.navigationDelegate = self
        web.allowsBackForwardNavigationGestures = true
        window.contentView = web
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        home()
    }

    private func configureMenu() {
        let bar = NSMenu()
        func submenu(_ title: String) -> NSMenu {
            let item = NSMenuItem()
            bar.addItem(item)
            let menu = NSMenu(title: title)
            item.submenu = menu
            return menu
        }
        let app = submenu("IDPS SOC")
        app.addItem(withTitle: "Quit IDPS SOC", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let edit = submenu("Edit")
        for (name, key) in [("Cut","x"), ("Copy","c"), ("Paste","v"), ("Select All","a")] {
            let action = name == "Select All" ? "selectAll:" : name.lowercased() + ":"
            edit.addItem(withTitle: name, action: Selector(action), keyEquivalent: key)
        }
        let view = submenu("View")
        for (name, action, key) in [("Dashboard Home", #selector(home), "1"), ("Back", #selector(back), "["),
                                    ("Reload", #selector(reload), "r")] {
            view.addItem(withTitle: name, action: action, keyEquivalent: key).target = self
        }
        let windows = submenu("Window")
        windows.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windows.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        NSApp.windowsMenu = windows
        NSApp.mainMenu = bar
    }

    @objc private func home() {
        guard !connecting else { return }
        connecting = true
        window.subtitle = "Connecting…"
        Task {
            defer { connecting = false }
            do {
                try await server.start()
                web.load(URLRequest(url: server.origin))
            } catch {
                showConnectionError(error)
            }
        }
    }

    @objc private func back() { if web.canGoBack { web.goBack() } }
    @objc private func reload() {
        if web.url == nil { home() } else { web.reload() }
    }

    private func showConnectionError(_ error: Error) {
        window.subtitle = "Connection unavailable"
        let alert = NSAlert()
        alert.messageText = "Couldn’t open the dashboard"
        alert.informativeText = error.localizedDescription
        alert.addButton(withTitle: "Retry")
        alert.addButton(withTitle: "Cancel")
        alert.beginSheetModal(for: window) { result in
            if result == .alertFirstButtonReturn { self.home() }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { server?.stop() }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        guard let url = webView.url else { return }
        window.subtitle = url.host == server.origin.host && url.port == server.origin.port
            ? "Local dashboard" : (url.host ?? "")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        let issue = error as NSError
        if issue.domain == NSURLErrorDomain && issue.code != NSURLErrorCancelled { showConnectionError(error) }
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url else { decisionHandler(.cancel); return }
        if action.shouldPerformDownload && (url.scheme == "blob" || url.scheme == "https" || url.scheme == "http") {
            decisionHandler(.download)
        } else if url.scheme == "https" || (url.scheme == "http" && ["127.0.0.1", "localhost", "::1"].contains(url.host ?? "")) {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
        }
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = frame.securityOrigin.host
        alert.informativeText = message
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Confirm")
        alert.beginSheetModal(for: window) { completionHandler($0 == .alertSecondButtonReturn) }
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let save = NSSavePanel()
        save.nameFieldStringValue = (suggestedFilename as NSString).lastPathComponent
        save.beginSheetModal(for: window) { result in
            guard result == .OK, let destination = save.url else { completionHandler(nil); return }
            // WebKit needs a new file. Replace an approved existing file only after a successful download.
            do {
                let temp = try FileManager.default.url(for: .itemReplacementDirectory, in: .userDomainMask,
                                                       appropriateFor: destination, create: true)
                let file = temp.appendingPathComponent("download")
                self.downloads[ObjectIdentifier(download)] = (file, destination)
                completionHandler(file)
            } catch {
                completionHandler(nil)
                NSApp.presentError(error)
            }
        }
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let paths = downloads.removeValue(forKey: ObjectIdentifier(download)) else { return }
        let files = FileManager.default
        defer { try? files.removeItem(at: paths.temporary.deletingLastPathComponent()) }
        do {
            if files.fileExists(atPath: paths.destination.path) {
                _ = try files.replaceItemAt(paths.destination, withItemAt: paths.temporary)
            } else {
                try files.moveItem(at: paths.temporary, to: paths.destination)
            }
        } catch { NSApp.presentError(error) }
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        if let paths = downloads.removeValue(forKey: ObjectIdentifier(download)) {
            try? FileManager.default.removeItem(at: paths.temporary.deletingLastPathComponent())
        }
        if (error as NSError).code != NSURLErrorCancelled { NSApp.presentError(error) }
    }
}

@main
struct DesktopMain {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = DashboardApp()
        app.setActivationPolicy(.regular)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}

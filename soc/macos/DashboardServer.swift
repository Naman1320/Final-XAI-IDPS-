import Foundation

enum DashboardError: LocalizedError {
    case portInUse, missingCheckout, startupFailed

    var errorDescription: String? {
        switch self {
        case .portInUse: return "Another application is using the dashboard port."
        case .missingCheckout: return "To start the frontend, restore the project's Node dependencies or start the unified dashboard from the project."
        case .startupFailed: return "The dashboard frontend could not start. Check the project dependencies and try again."
        }
    }
}

@MainActor
final class DashboardServer {
    let origin: URL
    private let webRoot: URL
    private let node: URL
    private let assets: URL
    private var child: Process?

    init(port: Int = 5173, webRoot: URL, node: URL, assets: URL) {
        self.origin = URL(string: "http://127.0.0.1:\(port)/")!
        self.webRoot = webRoot
        self.node = node
        self.assets = assets
    }

    private func isDashboardRunning() async throws -> Bool {
        var request = URLRequest(url: origin, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 2)
        request.setValue("text/html", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let html = String(decoding: data, as: UTF8.self)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == origin,
                  html.contains("<title>IDPS SOC</title>"), html.contains("id=\"root\"") else {
                throw DashboardError.portInUse
            }
            return true
        } catch let error as URLError where error.code == .cannotConnectToHost {
            return false
        }
    }

    func start() async throws {
        if try await isDashboardRunning() { return }
        if child?.isRunning != true {
            let vite = webRoot.appendingPathComponent("node_modules/vite/bin/vite.js")
            let files = FileManager.default
            guard files.isExecutableFile(atPath: node.path), files.fileExists(atPath: vite.path),
                  files.fileExists(atPath: assets.appendingPathComponent("index.html").path) else {
                throw DashboardError.missingCheckout
            }
            let process = Process()
            process.executableURL = node
            process.currentDirectoryURL = webRoot
            process.arguments = [vite.path, "preview", "--mode", "unified", "--outDir", assets.path,
                                 "--host", "127.0.0.1", "--port", String(origin.port!), "--strictPort"]
            var environment = ProcessInfo.processInfo.environment
            // Finder's PATH does not normally contain Homebrew or Docker Desktop.
            environment["PATH"] = [node.deletingLastPathComponent().path, "/opt/homebrew/bin",
                                   "/usr/local/bin", "/Applications/Docker.app/Contents/Resources/bin",
                                   environment["PATH"] ?? "/usr/bin:/bin"].joined(separator: ":")
            process.environment = environment
            try process.run()
            child = process
        }
        for _ in 0..<50 {
            try await Task.sleep(nanoseconds: 200_000_000)
            if try await isDashboardRunning() { return }
            if child?.isRunning != true { break }
        }
        stop()
        throw DashboardError.startupFailed
    }

    func stop() {
        if let child = child, child.isRunning { child.terminate() }
        child = nil
    }
}

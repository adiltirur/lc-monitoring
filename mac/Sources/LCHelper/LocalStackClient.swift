import Foundation

// MARK: - Constants

enum AppConstants {
    static let bundleID = "care.lillian.helper"
    static let launchAgentLabel = "care.lillian.helper.server"
    /// URL loaded in the web view (the page itself uses relative URLs).
    static let webBaseURL = URL(string: "http://localhost:3333/")!
    /// URL used for native health / API calls (avoids ::1 vs 127.0.0.1 ambiguity).
    static let apiBaseURL = URL(string: "http://127.0.0.1:3333/")!

    static var serverLogURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/LCHelper/server.log")
    }

    static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    }

    static func isLocalHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased() else { return false }
        return ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host)
    }
}

// MARK: - Local stack API models

struct LocalStackStatus: Decodable, Sendable {
    struct Component: Decodable, Sendable {
        let state: String
        let pid: Int?
        let since: String?
        let detail: String?

        private enum CodingKeys: String, CodingKey { case state, pid, since, detail }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            state = (try? c.decode(String.self, forKey: .state)) ?? "unknown"
            pid = try? c.decodeIfPresent(Int.self, forKey: .pid)
            // `since` may be an ISO string or an epoch number — accept both.
            if let s = try? c.decodeIfPresent(String.self, forKey: .since) {
                since = s
            } else if let n = try? c.decodeIfPresent(Double.self, forKey: .since) {
                since = String(format: "%.0f", n)
            } else {
                since = nil
            }
            detail = try? c.decodeIfPresent(String.self, forKey: .detail)
        }
    }

    struct Config: Decodable, Sendable {
        let autostart: Bool?
        let applyMigrations: Bool?
    }

    let docker: Component?
    let serverpod: Component?
    let config: Config?
}

enum StackProbe: Sendable {
    case unknown
    case helperDown
    case apiUnavailable(String)
    case status(LocalStackStatus)
}

enum LocalStackAction: String, Sendable {
    case start, stop, restart
}

// MARK: - Client

final class LocalStackClient: Sendable {
    static let shared = LocalStackClient()

    private let session: URLSession

    init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 4
        config.timeoutIntervalForResource = 10
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.waitsForConnectivity = false
        session = URLSession(configuration: config)
    }

    /// Any HTTP response from the helper counts as "up".
    func isServerUp() async -> Bool {
        var request = URLRequest(url: AppConstants.apiBaseURL)
        request.timeoutInterval = 2
        do {
            let (_, response) = try await session.data(for: request)
            return response is HTTPURLResponse
        } catch {
            return false
        }
    }

    /// Full probe: helper reachability + local-stack status.
    func probe() async -> StackProbe {
        guard await isServerUp() else { return .helperDown }
        let url = AppConstants.apiBaseURL.appendingPathComponent("api/local-stack/status")
        do {
            let (data, response) = try await session.data(from: url)
            guard let http = response as? HTTPURLResponse else { return .apiUnavailable("No response") }
            guard (200..<300).contains(http.statusCode) else {
                return .apiUnavailable(http.statusCode == 404
                                       ? "Local stack API not available"
                                       : "HTTP \(http.statusCode)")
            }
            return .status(try JSONDecoder().decode(LocalStackStatus.self, from: data))
        } catch is DecodingError {
            return .apiUnavailable("Unexpected status payload")
        } catch {
            return .apiUnavailable(error.localizedDescription)
        }
    }

    /// POST /api/local-stack/{start|stop|restart}. Throws a user-presentable error.
    func perform(_ action: LocalStackAction) async throws -> LocalStackStatus? {
        var request = URLRequest(url: AppConstants.apiBaseURL.appendingPathComponent("api/local-stack/\(action.rawValue)"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data("{}".utf8)
        // Starting Serverpod (Docker + migrations) can take a while.
        request.timeoutInterval = 120
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ClientError(message: "No HTTP response from helper server.")
        }
        guard (200..<300).contains(http.statusCode) else {
            let serverMessage = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw ClientError(message: serverMessage ?? (http.statusCode == 404
                ? "The helper server does not expose /api/local-stack yet."
                : "HTTP \(http.statusCode)"))
        }
        return try? JSONDecoder().decode(LocalStackStatus.self, from: data)
    }

    struct ClientError: LocalizedError, Sendable {
        let message: String
        var errorDescription: String? { message }
    }
}

// MARK: - Shell helper

enum Shell {
    struct Result: Sendable {
        let status: Int32
        let output: String
    }

    /// Runs an executable off the main thread and returns its exit status + combined output.
    static func run(_ executable: String, _ arguments: [String]) async -> Result {
        await Task.detached(priority: .userInitiated) { () -> Result in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            do {
                try process.run()
            } catch {
                return Result(status: -1, output: error.localizedDescription)
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return Result(status: process.terminationStatus,
                          output: String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }.value
    }
}

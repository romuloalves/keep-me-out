import AppKit
import Foundation

struct Status: Decodable {
    var domains: [String]
    var blocking: Bool
    var stale: Bool
}

struct EngineError: LocalizedError {
    var message: String
    var errorDescription: String? { message }
}

struct Engine {
    var binary: URL
    var dataDir: URL

    static func make() throws -> Engine {
        let binary = try locateBinary()
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let dataDir = support.appendingPathComponent("KeepMeOut", isDirectory: true)
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
        return Engine(binary: binary, dataDir: dataDir)
    }

    func status() throws -> Status {
        let output = try run(["status"])
        guard let data = output.data(using: .utf8) else {
            throw EngineError(message: "Couldn't read blocker status.")
        }
        do {
            return try JSONDecoder().decode(Status.self, from: data)
        } catch {
            throw EngineError(message: "Couldn't read blocker status.")
        }
    }

    func add(_ input: String) throws {
        _ = try run(["add", input])
    }

    func remove(_ domain: String) throws {
        _ = try run(["remove", domain])
    }

    func startBlocking() throws {
        try runAsAdmin(["helper", "start"])
    }

    func stopBlocking() throws {
        try runAsAdmin(["helper", "stop"])
    }

    private func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = binary
        process.arguments = ["--data-dir", dataDir.path] + arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let output = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let errorOutput = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = errorOutput.trimmingCharacters(in: .whitespacesAndNewlines)
            throw EngineError(message: message.isEmpty ? "The helper failed." : message)
        }
        return output
    }

    private func runAsAdmin(_ arguments: [String]) throws {
        let pieces = ([binary.path, "--data-dir", dataDir.path] + arguments).map { value in
            "quoted form of \(appleScriptString(value))"
        }
        let source = "do shell script \(pieces.joined(separator: " & \" \" & ")) with administrator privileges"
        var errorInfo: NSDictionary?
        guard let script = NSAppleScript(source: source) else {
            throw EngineError(message: "Couldn't ask for an administrator password.")
        }
        _ = script.executeAndReturnError(&errorInfo)
        if let errorInfo {
            let number = (errorInfo[NSAppleScript.errorNumber] as? NSNumber)?.intValue
            if number == -128 {
                throw EngineError(message: "The administrator password was cancelled.")
            }
            let message = (errorInfo[NSAppleScript.errorMessage] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw EngineError(message: message.isEmpty ? "The administrator command failed." : message)
        }
    }
}

private func locateBinary() throws -> URL {
    let files = FileManager.default
    if let override = ProcessInfo.processInfo.environment["KEEP_ME_OUT_BIN"], !override.isEmpty {
        if files.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }
        throw EngineError(message: "KEEP_ME_OUT_BIN is not an executable.")
    }

    var candidates: [URL] = []
    if let executable = Bundle.main.executableURL {
        candidates.append(executable.deletingLastPathComponent().appendingPathComponent("keep-me-out"))
        var directory = executable.deletingLastPathComponent()
        for _ in 0..<8 {
            candidates.append(directory.appendingPathComponent("target/debug/keep-me-out"))
            candidates.append(directory.appendingPathComponent("target/release/keep-me-out"))
            directory.deleteLastPathComponent()
        }
    }
    let current = URL(fileURLWithPath: files.currentDirectoryPath)
    candidates.append(current.appendingPathComponent("target/debug/keep-me-out"))
    candidates.append(current.appendingPathComponent("target/release/keep-me-out"))

    if let match = candidates.first(where: { files.isExecutableFile(atPath: $0.path) }) {
        return match
    }
    throw EngineError(message: "Couldn't find the keep-me-out helper. Run cargo build from the project, or set KEEP_ME_OUT_BIN.")
}

private func appleScriptString(_ value: String) -> String {
    let escaped = value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
}

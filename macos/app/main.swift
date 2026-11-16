// DPIGate menu bar app (M3a): starts and stops `dpigate run` from the menu bar.
// All system changes stay in the dpigate script; this app only supervises it.
import AppKit

enum RunState { case stopped, starting, running, stopping }

final class AppDelegate: NSObject, NSApplicationDelegate {
    let env = ProcessInfo.processInfo.environment
    var statusItem: NSStatusItem!
    var state = RunState.stopped
    var child: Process?
    var generation = 0              // ignores callbacks from superseded children
    var failures: [Date] = []
    var userStop = false            // the current child was stopped on purpose
    var logHandle: FileHandle?
    var signalSources: [DispatchSourceSignal] = []

    let statusLine = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let toggleItem = NSMenuItem(title: "", action: #selector(toggle), keyEquivalent: "")

    // MARK: paths

    var scriptPath: String {
        if let s = env["DPIGATE_APP_SCRIPT"], !s.isEmpty { return s }
        return (Bundle.main.resourcePath ?? ".") + "/dpigate"
    }
    var logPath: String {
        if let s = env["DPIGATE_APP_LOG"], !s.isEmpty { return s }
        return NSHomeDirectory() + "/Library/Logs/DPIGate/dpigate.log"
    }
    var stateFile: String {
        let dir = env["STATE_DIR"] ?? NSHomeDirectory() + "/Library/Application Support/DPIGate"
        return dir + "/state"
    }

    // MARK: launch

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)
        try? FileManager.default.createDirectory(
            atPath: (logPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil)
        }
        logHandle = FileHandle(forWritingAtPath: logPath)
        _ = try? logHandle?.seekToEnd()

        statusItem = NSStatusItem.make()
        buildMenu()
        refreshUI()
        installSignalHandlers()

        // A previous crash may have left proxy settings behind; undo them first.
        if FileManager.default.fileExists(atPath: stateFile) {
            log("app: stale state file found, running restore")
            runBlocking(["restore"])
        }
        if env["DPIGATE_APP_AUTOSTART"] == "1" { start() }
    }

    func installSignalHandlers() {
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [weak self] in
                self?.shutdownBlocking()
                exit(0)
            }
            src.resume()
            signalSources.append(src)
        }
    }

    // MARK: menu

    func buildMenu() {
        let m = NSMenu()
        m.autoenablesItems = false
        statusLine.isEnabled = false
        m.addItem(statusLine)
        toggleItem.target = self
        m.addItem(toggleItem)
        m.addItem(.separator())
        m.addItem(disabled("DNS: 1.1.1.1"))
        m.addItem(disabled("Edit Program Filters (not available on macOS)"))
        m.addItem(disabled("Bypass All Traffic"))
        m.addItem(disabled("Auto Start"))
        m.addItem(disabled("Uninstall"))
        m.addItem(.separator())
        let log = NSMenuItem(title: "Open Log", action: #selector(openLog), keyEquivalent: "")
        log.target = self
        m.addItem(log)
        let quit = NSMenuItem(title: "Exit", action: #selector(quit), keyEquivalent: "")
        quit.target = self
        m.addItem(quit)
        statusItem.menu = m
    }

    func disabled(_ t: String) -> NSMenuItem {
        let i = NSMenuItem(title: t, action: nil, keyEquivalent: "")
        i.isEnabled = false
        return i
    }

    func refreshUI() {
        let (text, toggle): (String, String)
        switch state {
        case .stopped: (text, toggle) = ("Stopped", "Turn On")
        case .starting: (text, toggle) = ("Starting…", "Turn Off")
        case .running: (text, toggle) = ("Running", "Turn Off")
        case .stopping: (text, toggle) = ("Stopping…", "Turn Off")
        }
        statusLine.title = "DPIGate: " + text
        toggleItem.title = toggle
        toggleItem.isEnabled = state != .stopping
        statusItem.setIcon(on: state == .running || state == .starting)
        statusItem.button?.toolTip = "DPIGate: " + text
    }

    @objc func toggle() {
        if state == .stopped { failures = []; start() } else { stop() }
    }

    @objc func openLog() { NSWorkspace.shared.open(URL(fileURLWithPath: logPath)) }

    @objc func quit() {
        shutdownBlocking()
        NSApp.terminate(nil)
    }

    func applicationWillTerminate(_ n: Notification) { shutdownBlocking() }

    // MARK: child process

    func log(_ s: String) {
        logHandle?.write(Data((s + "\n").utf8))
    }

    func start() {
        guard state == .stopped else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [scriptPath, "run"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        generation += 1
        let gen = generation
        var seen = false
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; return }
            self?.logHandle?.write(d)
            if !seen, String(decoding: d, as: UTF8.self).contains("running on") {
                seen = true
                DispatchQueue.main.async {
                    guard let s = self, s.generation == gen, s.state == .starting else { return }
                    s.state = .running
                    s.refreshUI()
                }
            }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async { self?.childExited(gen, status: proc.terminationStatus) }
        }
        log("app: starting \(scriptPath) run")
        do { try p.run() } catch {
            log("app: cannot start: \(error)")
            notify("Could not start dpigate - see log")
            return
        }
        child = p
        userStop = false
        state = .starting
        refreshUI()
    }

    func childExited(_ gen: Int, status: Int32) {
        guard gen == generation else { return }
        child = nil
        let wasUserStop = userStop
        state = .stopped
        refreshUI()
        if wasUserStop { log("app: stopped"); return }
        log("app: dpigate exited unexpectedly (status \(status))")
        let now = Date()
        failures = failures.filter { now.timeIntervalSince($0) < 60 } + [now]
        if failures.count >= 3 {
            notify("Stopped - see log")
            return
        }
        notify("DPIGate stopped unexpectedly, restarting")
        let g = generation
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let s = self, s.generation == g, s.state == .stopped else { return }
            s.start()
        }
    }

    /// Asks the script to stop (SIGINT, it restores the settings itself); SIGTERM after 10 s.
    func stop() {
        guard let p = child, p.isRunning else { return }
        userStop = true
        state = .stopping
        refreshUI()
        p.interrupt()
        let pid = p.processIdentifier
        let g = generation
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            if let s = self, s.generation == g, s.child?.isRunning == true { kill(pid, SIGTERM) }
        }
    }

    /// Synchronous variant for Exit, signals and logout: waits for the script's cleanup.
    func shutdownBlocking() {
        guard let p = child, p.isRunning else { return }
        userStop = true
        generation += 1      // the termination handler no longer touches the UI
        p.interrupt()
        var waited = 0.0
        while p.isRunning && waited < 10 { usleep(100_000); waited += 0.1 }
        if p.isRunning {
            kill(p.processIdentifier, SIGTERM)
            waited = 0
            while p.isRunning && waited < 5 { usleep(100_000); waited += 0.1 }
        }
        log("app: shutdown complete")
    }

    func runBlocking(_ args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [scriptPath] + args
        if let h = logHandle { p.standardOutput = h; p.standardError = h }
        p.standardInput = FileHandle.nullDevice
        do { try p.run(); p.waitUntilExit() } catch { log("app: \(args) failed: \(error)") }
    }

    // MARK: notifications

    func notify(_ msg: String) {
        if let f = env["DPIGATE_APP_NOTIFY_LOG"], !f.isEmpty {
            if let h = FileHandle(forWritingAtPath: f) ?? {
                FileManager.default.createFile(atPath: f, contents: nil)
                return FileHandle(forWritingAtPath: f)
            }() { _ = try? h.seekToEnd(); h.write(Data((msg + "\n").utf8)); try? h.close() }
            return
        }
        let esc = msg.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", "display notification \"\(esc)\" with title \"DPIGate\""]
        p.standardInput = FileHandle.nullDevice
        try? p.run()
    }
}

extension NSStatusItem {
    static func make() -> NSStatusItem {
        NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    }
    func setIcon(on: Bool) {
        let name = on ? "shield.lefthalf.filled" : "shield.slash"
        if let img = NSImage(systemSymbolName: name, accessibilityDescription: "DPIGate") {
            img.isTemplate = true
            button?.image = img
            button?.title = ""
        } else {
            button?.image = nil
            button?.title = "DPI"
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()

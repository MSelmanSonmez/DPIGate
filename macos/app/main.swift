// DPIGate menu bar app: starts and stops `dpigate run` from the menu bar and offers the same
// settings as the Linux tray (DNS, bypass mode, program filters, auto start, uninstall).
// All system changes stay in the dpigate script; this app only supervises it.
import AppKit
import Darwin

enum RunState { case stopped, starting, running, stopping }

struct DNSCandidate { let name: String; let addr: String; let port: Int }
struct DNSResult { let cand: DNSCandidate; var ms = -1; var status = "testing" }

// Same list and order as linux/dns_detect.py (IPv6 columns are not used on macOS).
let defaultCandidates = [
    DNSCandidate(name: "Yandex", addr: "77.88.8.8", port: 1253),
    DNSCandidate(name: "Yandex", addr: "77.88.8.8", port: 53),
    DNSCandidate(name: "Cloudflare", addr: "1.1.1.1", port: 53),
    DNSCandidate(name: "Quad9", addr: "9.9.9.9", port: 53),
    DNSCandidate(name: "AdGuard", addr: "94.140.14.14", port: 53),
]

// Block-page / poisoned answers: Turk Telekom's 195.175.254.x range (as in dns_detect.py), plus the
// 212.175.180.11 answer measured on a poisoned modem resolver, and null/loopback.
func isPoisoned(_ ip: String) -> Bool {
    ip.hasPrefix("195.175.254.") || ip == "212.175.180.11" || ip == "0.0.0.0" || ip.hasPrefix("127.")
}

func parseA(_ d: [UInt8]) -> String? {
    guard d.count >= 12, d[2] & 0x80 != 0 else { return nil }
    var pos = 12
    while pos < d.count && d[pos] != 0 { pos += Int(d[pos]) + 1 }
    pos += 5
    let n = Int(d[6]) << 8 | Int(d[7])
    for _ in 0..<n {
        if pos >= d.count { break }
        if d[pos] & 0xC0 != 0 { pos += 2 } else {
            while pos < d.count && d[pos] != 0 { pos += Int(d[pos]) + 1 }
            pos += 1
        }
        if pos + 10 > d.count { break }
        let t = Int(d[pos]) << 8 | Int(d[pos + 1]); pos += 8
        let rl = Int(d[pos]) << 8 | Int(d[pos + 1]); pos += 2
        if t == 1 && rl == 4 && pos + 4 <= d.count { return "\(d[pos]).\(d[pos + 1]).\(d[pos + 2]).\(d[pos + 3])" }
        pos += rl
    }
    return nil
}

/// Probes every candidate in parallel with one UDP A query for discord.com (blocking, up to timeoutMs).
func measureDNS(_ cands: [DNSCandidate], timeoutMs: Int = 800) -> [DNSResult] {
    var q: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
    for l in "discord.com".split(separator: ".") { q.append(UInt8(l.count)); q += Array(l.utf8) }
    q += [0, 0, 1, 0, 1]
    var res = cands.map { DNSResult(cand: $0) }
    var fds = [Int32](repeating: -1, count: cands.count)
    for (i, c) in cands.enumerated() {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        if fd < 0 { res[i].status = "unreachable"; continue }
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = UInt16(c.port).bigEndian
        inet_pton(AF_INET, c.addr, &sa.sin_addr)
        let sent = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, q, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if sent == q.count { fds[i] = fd; res[i].status = "no-response" } else { close(fd); res[i].status = "unreachable" }
    }
    let start = DispatchTime.now().uptimeNanoseconds
    func elapsedMs() -> Int { Int((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000) }
    while true {
        var idx: [Int] = []
        for i in 0..<fds.count where fds[i] >= 0 && res[i].status == "no-response" { idx.append(i) }
        let left = timeoutMs - elapsedMs()
        if idx.isEmpty || left <= 0 { break }
        var pf = idx.map { pollfd(fd: fds[$0], events: Int16(POLLIN), revents: 0) }
        if poll(&pf, nfds_t(pf.count), Int32(min(left, 50))) <= 0 { continue }
        for (k, i) in idx.enumerated() where pf[k].revents & Int16(POLLIN) != 0 {
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = recv(fds[i], &buf, buf.count, 0)
            if n < 0 { continue }
            res[i].ms = elapsedMs()
            if let ip = parseA(Array(buf[0..<n])) { res[i].status = isPoisoned(ip) ? "poisoned" : "ok" } else { res[i].status = "no-record" }
        }
    }
    for fd in fds where fd >= 0 { close(fd) }
    return res
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let env = ProcessInfo.processInfo.environment
    var statusItem: NSStatusItem!
    var state = RunState.stopped
    var child: Process?
    var generation = 0              // ignores callbacks from superseded children
    var failures: [Date] = []
    var userStop = false            // the current child was stopped on purpose
    var restartPending = false      // a setting changed: start again once the child has stopped
    var logHandle: FileHandle?
    let logLock = NSLock()          // log() runs on the main thread and in the pipe's reader thread
    var signalSources: [DispatchSourceSignal] = []

    // DNS state
    var candidates = defaultCandidates
    var dnsResults: [DNSResult] = []
    var measuring = false
    var measuredOnce = false
    var pendingStart = false        // Turn On waits for the first DNS measurement
    var startedArgs: [String]?      // proxy arguments of the running child (site list)
    var pendingAction: String?      // test hook: run after the child announced itself

    let statusLine = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let toggleItem = NSMenuItem(title: "", action: #selector(toggle), keyEquivalent: "")
    let dnsItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let bypassItem = NSMenuItem(title: "Bypass All Traffic", action: #selector(toggleBypass), keyEquivalent: "")
    let siteItem = NSMenuItem(title: "Only Listed Sites (site list)", action: #selector(toggleSiteMode), keyEquivalent: "")
    let launchItem = NSMenuItem(title: "Launch via DPIGate", action: nil, keyEquivalent: "")
    let autostartItem = NSMenuItem(title: "Auto Start", action: #selector(toggleAutostart), keyEquivalent: "")

    let agentLabel = "org.dpigate.menubar"

    // MARK: paths and settings

    func nonEmpty(_ k: String) -> String? { if let s = env[k], !s.isEmpty { return s }; return nil }
    var scriptPath: String { nonEmpty("DPIGATE_APP_SCRIPT") ?? (Bundle.main.resourcePath ?? ".") + "/dpigate" }
    var defaultLogPath: String { NSHomeDirectory() + "/Library/Logs/DPIGate/dpigate.log" }
    var logPath: String { nonEmpty("DPIGATE_APP_LOG") ?? defaultLogPath }
    var defaultStateDir: String { NSHomeDirectory() + "/Library/Application Support/DPIGate" }
    var stateDir: String { nonEmpty("STATE_DIR") ?? defaultStateDir }
    var stateFile: String { stateDir + "/state" }
    var configDir: String { nonEmpty("DPIGATE_CONFIG_DIR") ?? stateDir + "/config" }
    var configFile: String { configDir + "/config" }
    var appsFile: String { configDir + "/apps.txt" }
    var sitesFile: String { configDir + "/sites.txt" }
    var launchAgentsDir: String { nonEmpty("DPIGATE_LAUNCH_AGENTS_DIR") ?? NSHomeDirectory() + "/Library/LaunchAgents" }
    var agentPath: String { launchAgentsDir + "/" + agentLabel + ".plist" }
    var port: String { nonEmpty("DPIGATE_PORT") ?? "1080" }

    func readConfig() -> [String: String] {
        var out: [String: String] = [:]
        guard let t = try? String(contentsOfFile: configFile, encoding: .utf8) else { return out }
        for line in t.split(separator: "\n") {
            guard let eq = line.firstIndex(of: "=") else { continue }
            out[String(line[..<eq])] = String(line[line.index(after: eq)...])
        }
        return out
    }

    func setConfig(_ key: String, _ value: String) {
        var c = readConfig()
        c[key] = value
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        let text = c.keys.sorted().map { "\($0)=\(c[$0]!)" }.joined(separator: "\n") + "\n"
        try? text.write(toFile: configFile, atomically: true, encoding: .utf8)
    }

    var bypassAll: Bool { (readConfig()["bypass_all"] ?? "1") != "0" }
    /// "Only Listed Sites": the proxy applies its DPI tricks to the hosts in sites.txt only (default off).
    var siteMode: Bool { (readConfig()["site_mode"] ?? "0") == "1" }
    var configuredDNSIndex: Int { Int(readConfig()["dns_index"] ?? "") ?? -1 }

    func ensureAppsFile() {
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: appsFile) {
            try? "/Applications/Discord.app\n".write(toFile: appsFile, atomically: true, encoding: .utf8)
        }
    }

    static let defaultSites = ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"]

    func ensureSitesFile() {
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: sitesFile) {
            let text = "# Domains DPIGate applies its DPI tricks to (Only Listed Sites mode). One per line, # starts a note.\n"
                + "# A domain also covers its subdomains: discord.com covers cdn.discord.com.\n"
                + AppDelegate.defaultSites.joined(separator: "\n") + "\n"
            try? text.write(toFile: sitesFile, atomically: true, encoding: .utf8)
        }
    }

    /// Valid, lower-case domains from sites.txt; anything else is skipped.
    func sites() -> [String] {
        guard let t = try? String(contentsOfFile: sitesFile, encoding: .utf8) else { return [] }
        var out: [String] = []
        for line in t.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let body = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
            for word in body.split(whereSeparator: { $0 == " " || $0 == "\t" }) {
                var d = word.lowercased()
                if d.hasPrefix("*.") { d.removeFirst(2) }
                while d.hasPrefix(".") { d.removeFirst() }
                guard !d.isEmpty, d.allSatisfy({ ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") || $0 == "-" || $0 == "." }) else { continue }
                if !out.contains(d) { out.append(d) }
            }
        }
        return out
    }

    /// Proxy arguments for the current mode. ByeDPI's -H limits the tricks of the first group to the listed
    /// hosts (subdomains included); -An starts an empty second group, so every other connection passes untouched.
    /// An empty list would make ByeDPI drop everything, so it falls back to a host that never occurs.
    func proxyArgs() -> [String] {
        guard siteMode else { return [] }
        let list = sites()
        return ["--", "-H", ":" + (list.isEmpty ? "dpigate.invalid" : list.joined(separator: " ")), "-An"]
    }

    func programs() -> [String] {
        guard let t = try? String(contentsOfFile: appsFile, encoding: .utf8) else { return [] }
        return t.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    // MARK: launch

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)
        if anotherInstanceRunning() {
            notify("DPIGate is already running")
            exit(0)   // touches no setting and no child process
        }
        try? FileManager.default.createDirectory(
            atPath: (logPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil)
        }
        logHandle = FileHandle(forWritingAtPath: logPath)
        _ = try? logHandle?.seekToEnd()
        ensureAppsFile()
        ensureSitesFile()
        if let c = nonEmpty("DPIGATE_APP_DNS_CANDIDATES") {   // test hook: "name|ip|port;name|ip|port"
            candidates = c.split(separator: ";").compactMap {
                let f = $0.split(separator: "|").map(String.init)
                guard f.count == 3, let p = Int(f[2]) else { return nil }
                return DNSCandidate(name: f[0], addr: f[1], port: p)
            }
        }
        dnsResults = candidates.map { DNSResult(cand: $0) }

        statusItem = NSStatusItem.make()
        buildMenu()
        refreshUI()
        installSignalHandlers()
        refreshAutostartPath()

        // A previous crash may have left proxy settings behind; undo them first.
        if FileManager.default.fileExists(atPath: stateFile) {
            log("app: stale state file found, running restore")
            runBlocking(["restore"])
        }
        runMeasurement()
        Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.checkSiteListChanged() }
        let action = nonEmpty("DPIGATE_APP_ACTION")
        if env["DPIGATE_APP_AUTOSTART"] == "1" {
            pendingAction = action
            start()
        } else if let a = action {
            runAction(a)
        }
    }

    /// Only one app per user: a held lock file in the state folder (this is what the tests use, each with its own
    /// STATE_DIR), and, with the default state folder, any other running copy of this bundle.
    var lockFD: Int32 = -1
    func anotherInstanceRunning() -> Bool {
        try? FileManager.default.createDirectory(atPath: stateDir, withIntermediateDirectories: true)
        lockFD = open(stateDir + "/app.lock", O_CREAT | O_RDWR, 0o600)
        if lockFD >= 0 && flock(lockFD, LOCK_EX | LOCK_NB) != 0 { return true }
        if nonEmpty("STATE_DIR") == nil, let bid = Bundle.main.bundleIdentifier {
            let me = ProcessInfo.processInfo.processIdentifier
            return NSRunningApplication.runningApplications(withBundleIdentifier: bid).contains { $0.processIdentifier != me }
        }
        return false
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
        m.delegate = self
        statusLine.isEnabled = false
        m.addItem(statusLine)
        toggleItem.target = self
        m.addItem(toggleItem)
        m.addItem(.separator())
        dnsItem.submenu = NSMenu()
        m.addItem(dnsItem)
        m.addItem(.separator())
        let edit = NSMenuItem(title: "Edit Program Filters (apps launched via DPIGate)", action: #selector(editPrograms), keyEquivalent: "")
        edit.target = self
        m.addItem(edit)
        launchItem.submenu = NSMenu()
        m.addItem(launchItem)
        bypassItem.target = self
        m.addItem(bypassItem)
        siteItem.target = self
        siteItem.toolTip = "On: DPI tricks only for the sites in the list; everything else passes unchanged. Works with Bypass All (Safari, system-wide) and with Launch via DPIGate."
        m.addItem(siteItem)
        let editSites = NSMenuItem(title: "Edit Site List", action: #selector(editSites), keyEquivalent: "")
        editSites.target = self
        m.addItem(editSites)
        m.addItem(.separator())
        autostartItem.target = self
        m.addItem(autostartItem)
        m.addItem(.separator())
        let un = NSMenuItem(title: "Uninstall", action: #selector(uninstall), keyEquivalent: "")
        un.target = self
        m.addItem(un)
        m.addItem(.separator())
        let log = NSMenuItem(title: "Open Log", action: #selector(openLog), keyEquivalent: "")
        log.target = self
        m.addItem(log)
        let quit = NSMenuItem(title: "Exit", action: #selector(quit), keyEquivalent: "")
        quit.target = self
        m.addItem(quit)
        statusItem.menu = m
        refreshDynamicItems()
    }

    /// Items that depend on files or other processes are refreshed every time the menu opens.
    func menuNeedsUpdate(_ menu: NSMenu) { refreshDynamicItems() }

    func refreshDynamicItems() {
        bypassItem.state = bypassAll ? .on : .off
        siteItem.state = siteMode ? .on : .off
        autostartItem.state = FileManager.default.fileExists(atPath: agentPath) ? .on : .off
        rebuildDNSMenu()
        rebuildLaunchMenu()
    }

    func rebuildLaunchMenu() {
        guard let sub = launchItem.submenu else { return }
        sub.removeAllItems()
        sub.autoenablesItems = false
        let apps = programs()
        for path in apps {
            let name = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
            let exists = FileManager.default.fileExists(atPath: path)
            let i = NSMenuItem(title: exists ? name : name + " (not found)", action: #selector(launchProgram(_:)), keyEquivalent: "")
            i.target = self
            i.representedObject = path
            i.isEnabled = exists && state == .running
            sub.addItem(i)
        }
        if apps.isEmpty { sub.addItem(disabled("No programs - use Edit Program Filters")) }
        if state != .running {
            sub.addItem(.separator())
            sub.addItem(disabled("Turn DPIGate on to launch programs"))
        }
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
        rebuildLaunchMenu()
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

    // MARK: DNS

    func label(_ c: DNSCandidate) -> String { c.port == 53 ? c.addr : "\(c.addr):\(c.port)" }

    /// The index in use: the forced one, otherwise the fastest valid server of the last measurement.
    func effectiveDNSIndex() -> Int {
        let forced = configuredDNSIndex
        if forced >= 0 && forced < candidates.count { return forced }
        var best = -1
        for (i, r) in dnsResults.enumerated() where r.status == "ok" && (best < 0 || r.ms < dnsResults[best].ms) { best = i }
        return best
    }

    /// Value for DPIGATE_DNS (the proxy's own resolver); the script derives the system DNS from it.
    func dnsValue() -> String {
        let i = effectiveDNSIndex()
        return i >= 0 ? label(candidates[i]) : "1.1.1.1"
    }

    func rebuildDNSMenu() {
        guard let sub = dnsItem.submenu else { return }
        let sel = effectiveDNSIndex()
        if sel >= 0 { dnsItem.title = "DNS: " + candidates[sel].name }
        else if !measuredOnce { dnsItem.title = "DNS: detecting…" }
        else { dnsItem.title = "DNS: Cloudflare (fallback)" }
        sub.removeAllItems()
        sub.autoenablesItems = false
        for (i, r) in dnsResults.enumerated() {
            let t = r.ms >= 0 ? "\(r.ms)ms" : (r.status == "testing" ? "testing…" : "n/a")
            var title = "\(r.cand.name) \(r.cand.addr):\(r.cand.port) (\(t))"
            if r.status != "ok" && r.status != "testing" { title += " [\(r.status)]" }
            let it = NSMenuItem(title: title, action: #selector(selectDNS(_:)), keyEquivalent: "")
            it.target = self
            it.tag = i
            it.state = i == sel ? .on : .off
            sub.addItem(it)
        }
        sub.addItem(.separator())
        let auto = NSMenuItem(title: "Auto-detect (re-test)", action: #selector(autodetectDNS), keyEquivalent: "")
        auto.target = self
        auto.isEnabled = !measuring
        sub.addItem(auto)
    }

    @objc func selectDNS(_ item: NSMenuItem) {
        setConfig("dns_index", String(item.tag))
        rebuildDNSMenu()
        restartIfActive("DNS: \(candidates[item.tag].name)")
    }

    @objc func autodetectDNS() {
        setConfig("dns_index", "-1")
        runMeasurement { [weak self] in self?.restartIfActive("DNS auto-detected") }
    }

    /// Measures every candidate in the background; `then` runs on the main thread afterwards.
    func runMeasurement(then: (() -> Void)? = nil) {
        guard !measuring else { return }
        measuring = true
        dnsResults = candidates.map { DNSResult(cand: $0) }
        rebuildDNSMenu()
        let cands = candidates
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let res = measureDNS(cands)
            DispatchQueue.main.async {
                guard let s = self else { return }
                s.dnsResults = res
                s.measuring = false
                s.measuredOnce = true
                for r in res { s.log("dns: \(r.cand.name) \(r.cand.addr):\(r.cand.port) \(r.status) \(r.ms)ms") }
                s.rebuildDNSMenu()
                if s.pendingStart {
                    s.pendingStart = false
                    s.state = .stopped
                    s.start()
                }
                then?()
                if s.env["DPIGATE_APP_ACTION"] == "dns-detect" { s.finishAction() }
            }
        }
    }

    // MARK: settings that restart the proxy

    /// Applies a changed setting: a running proxy is stopped and started again with it.
    func restartIfActive(_ what: String) {
        guard child?.isRunning == true, state == .running || state == .starting else { return }
        notify("Restarting - \(what)")
        restartPending = true
        stop()
    }

    @objc func toggleBypass() {
        let on = !bypassAll
        setConfig("bypass_all", on ? "1" : "0")
        bypassItem.state = on ? .on : .off
        let mode = on ? "all traffic" : "per-program"
        if child?.isRunning == true { restartIfActive("bypass mode: \(mode)") } else { notify("Bypass mode: \(mode)") }
    }

    @objc func toggleSiteMode() {
        let on = !siteMode
        setConfig("site_mode", on ? "1" : "0")
        siteItem.state = on ? .on : .off
        let mode = on ? "only listed sites" : "all sites"
        if child?.isRunning == true { restartIfActive("tricks for \(mode)") } else { notify("DPI tricks: \(mode)") }
    }

    @objc func editSites() {
        ensureSitesFile()
        openCommand(["-e", sitesFile])
    }

    /// The list is read when the proxy starts; an edited list restarts a running proxy (checked every 2 s).
    func checkSiteListChanged() {
        guard siteMode, state == .running, child?.isRunning == true, let used = startedArgs, used != proxyArgs() else { return }
        restartIfActive("site list changed")
    }

    // MARK: program filters

    func openCommand(_ args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: nonEmpty("DPIGATE_APP_OPEN") ?? "/usr/bin/open")
        p.arguments = args
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { log("app: cannot run open: \(error)") }
    }

    @objc func editPrograms() {
        ensureAppsFile()
        openCommand(["-e", appsFile])
    }

    @objc func launchProgram(_ item: NSMenuItem) {
        if let path = item.representedObject as? String { launchProgram(path: path) }
    }

    /// Starts an app with the proxy: `open --env` hands the environment to LaunchServices
    /// (Electron's updater reads HTTPS_PROXY) and --proxy-server covers Chromium's own network stack.
    func launchProgram(path: String) {
        let name = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        if let bid = Bundle(url: URL(fileURLWithPath: path))?.bundleIdentifier,
           !NSRunningApplication.runningApplications(withBundleIdentifier: bid).isEmpty {
            notify("\(name) is already running - quit it first, then launch it via DPIGate")
            return
        }
        let url = "http://127.0.0.1:\(port)"
        log("app: launching \(path) via the proxy")
        openCommand(["-a", path, "--env", "HTTPS_PROXY=\(url)", "--env", "HTTP_PROXY=\(url)",
                     "--args", "--proxy-server=socks5://127.0.0.1:\(port)"])
    }

    // MARK: auto start

    @discardableResult
    func setAutostart(_ on: Bool) -> Bool {
        let fm = FileManager.default
        let uid = getuid()
        if on {
            let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
            let plist: [String: Any] = [
                "Label": agentLabel,
                "ProgramArguments": [exe],
                "RunAtLoad": true,
                "EnvironmentVariables": ["DPIGATE_APP_AUTOSTART": "1"],
            ]
            do {
                try fm.createDirectory(atPath: launchAgentsDir, withIntermediateDirectories: true)
                let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
                try data.write(to: URL(fileURLWithPath: agentPath), options: .atomic)
            } catch { log("app: cannot write \(agentPath): \(error)"); return false }
            // The agent is not loaded now (it would start a second copy); launchd reads it at the
            // next login. Clearing a "disabled" override makes sure that login still loads it.
            launchctl(["enable", "gui/\(uid)/\(agentLabel)"])
        } else {
            do { if fm.fileExists(atPath: agentPath) { try fm.removeItem(atPath: agentPath) } }
            catch { log("app: cannot remove \(agentPath): \(error)"); return false }
            // Unload a copy launchd may hold, except when launchd started this very process.
            if env["XPC_SERVICE_NAME"] != agentLabel { launchctl(["bootout", "gui/\(uid)/\(agentLabel)"]) }
        }
        return true
    }

    /// The agent stores the app's path; after the app was moved (build folder to ~/Applications) it is stale.
    func refreshAutostartPath() {
        guard FileManager.default.fileExists(atPath: agentPath),
              let d = NSDictionary(contentsOfFile: agentPath),
              let old = (d["ProgramArguments"] as? [String])?.first,
              let exe = Bundle.main.executablePath, old != exe else { return }
        log("app: Auto Start entry pointed to \(old), rewriting it")
        setAutostart(true)
    }

    func launchctl(_ args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: nonEmpty("LAUNCHCTL") ?? "/bin/launchctl")
        p.arguments = args
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run(); p.waitUntilExit() } catch { log("app: launchctl \(args.first ?? "") failed: \(error)") }
    }

    @objc func toggleAutostart() {
        let want = !FileManager.default.fileExists(atPath: agentPath)
        if setAutostart(want) { notify(want ? "Auto Start enabled" : "Auto Start disabled") }
        else { notify("Auto Start change failed - see log") }
        autostartItem.state = FileManager.default.fileExists(atPath: agentPath) ? .on : .off
    }

    // MARK: uninstall

    /// Removes a folder; the default folder goes completely, an overridden one only our own files.
    func wipe(_ dir: String, default def: String, files: [String]) {
        let fm = FileManager.default
        if dir == def { try? fm.removeItem(atPath: dir); return }
        for f in files { try? fm.removeItem(atPath: dir + "/" + f) }
        rmdir(dir)
    }

    @objc func uninstall() {
        if env["DPIGATE_APP_ASSUME_YES"] != "1" {
            NSApp.activate(ignoringOtherApps: true)
            let a = NSAlert()
            a.messageText = "Uninstall DPIGate?"
            a.informativeText = "DPIGate stops, your previous network settings are restored, and its settings, log and Auto Start entry are deleted. This permanently deletes DPIGate.app and its settings. This cannot be undone."
            a.addButton(withTitle: "Uninstall")
            a.addButton(withTitle: "Cancel")
            if a.runModal() != .alertFirstButtonReturn { return }
        }
        log("app: uninstalling")
        shutdownBlocking()
        if FileManager.default.fileExists(atPath: stateFile) { runBlocking(["restore"]) }
        setAutostart(false)
        wipe(configDir, default: defaultStateDir + "/config", files: ["config", "apps.txt", "sites.txt"])
        wipe(stateDir, default: defaultStateDir, files: ["state", "state.tmp", "app.lock"])
        wipe((logPath as NSString).deletingLastPathComponent, default: (defaultLogPath as NSString).deletingLastPathComponent,
             files: [(logPath as NSString).lastPathComponent])
        // Permanent delete, but only of this app's own bundle (never any other path).
        let bundle = Bundle.main.bundlePath
        if env["DPIGATE_APP_NO_DELETE"] != "1" {
            if bundle.hasSuffix("/DPIGate.app") && bundle == Bundle.main.bundleURL.path {
                do { try FileManager.default.removeItem(atPath: bundle) }
                catch { notify("Could not delete \(bundle) - delete it by hand") }
            } else {
                notify("DPIGate is not running from a DPIGate.app bundle - delete it by hand: \(bundle)")
            }
        }
        exit(0)
    }

    // MARK: test hook (DPIGATE_APP_ACTION): one action, then exit

    func runAction(_ a: String) {
        log("app: action \(a)")
        switch a {
        case "autostart-on": setAutostart(true); finishAction()
        case "autostart-off": setAutostart(false); finishAction()
        case "uninstall": uninstall()
        case "site-toggle": toggleSiteMode()   // stays running; the test stops the app itself
        case "dns-detect": break   // finishes when the measurement does
        default:
            if a.hasPrefix("launch:") { launchProgram(path: String(a.dropFirst(7))); DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.finishAction() } }
            else { log("app: unknown action \(a)"); finishAction() }
        }
    }

    func finishAction() {
        shutdownBlocking()
        exit(0)
    }

    // MARK: child process

    func log(_ s: String) { logWrite(Data((s + "\n").utf8)) }

    func logWrite(_ d: Data) {
        logLock.lock()
        logHandle?.write(d)
        logLock.unlock()
    }

    func start() {
        guard state == .stopped else { return }
        if configuredDNSIndex < 0 && !measuredOnce {
            // Auto DNS: wait for the first measurement, then start with the fastest valid server.
            pendingStart = true
            state = .starting
            refreshUI()
            return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        let extra = proxyArgs()
        startedArgs = extra
        p.arguments = [scriptPath, "run"] + (bypassAll ? [] : ["--no-system-proxy"]) + extra
        var e = env
        e["DPIGATE_DNS"] = dnsValue()
        p.environment = e
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
            self?.logWrite(d)
            if !seen, String(decoding: d, as: UTF8.self).contains("running on") {
                seen = true
                DispatchQueue.main.async {
                    guard let s = self, s.generation == gen, s.state == .starting else { return }
                    s.state = .running
                    s.refreshUI()
                    if let a = s.pendingAction { s.pendingAction = nil; s.runAction(a) }
                }
            }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async { self?.childExited(gen, status: proc.terminationStatus) }
        }
        log("app: starting \(scriptPath) run" + (bypassAll ? "" : " --no-system-proxy") + (extra.isEmpty ? "" : " " + extra.joined(separator: " ")) + " (DNS \(dnsValue()))")
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
        if wasUserStop {
            log("app: stopped")
            if restartPending { restartPending = false; failures = []; start() }
            return
        }
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
        if pendingStart { pendingStart = false; state = .stopped; refreshUI(); return }
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
        restartPending = false
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
    /// DPIGate's own logo (menubar.png + @2x in the bundle, 18x18 pt, in colour); drawn faded when off.
    /// Falls back to the SF Symbol shield if the files are missing.
    static func logo(on: Bool) -> NSImage? {
        guard let dir = Bundle.main.resourcePath,
              let base = NSImage(contentsOfFile: dir + "/menubar.png") else { return nil }
        if let x2 = NSImage(contentsOfFile: dir + "/menubar@2x.png"), let rep = x2.representations.first {
            base.addRepresentation(rep)
        }
        let out = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { r in
            base.draw(in: r, from: .zero, operation: .sourceOver, fraction: on ? 1.0 : 0.35)
            return true
        }
        out.isTemplate = false
        return out
    }
    func setIcon(on: Bool) {
        if let img = NSStatusItem.logo(on: on) {
            button?.image = img
            button?.title = ""
            return
        }
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

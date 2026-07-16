import SwiftUI
import AppKit
import Security
import ApplicationServices
import Combine
import Sparkle
import IOKit

/// Stabiel toestel-id (hardware-UUID) van deze Mac. Wordt bij activatie meegestuurd zodat de server
/// een lifetime-sleutel aan één apparaat kan binden.
private func deviceIdentifier() -> String {
    let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    defer { if service != 0 { IOObjectRelease(service) } }
    guard service != 0,
          let property = IORegistryEntryCreateCFProperty(service, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue(),
          let uuid = property as? String else {
        return "unknown"
    }
    return uuid
}

private func L(_ key: String) -> String {
    let localized = Bundle.main.localizedString(forKey: key, value: nil, table: nil)
    if localized != key { return localized }
    guard let path = Bundle.main.path(forResource: "en", ofType: "lproj"),
          let englishBundle = Bundle(path: path) else { return key }
    return englishBundle.localizedString(forKey: key, value: key, table: nil)
}

private func LF(_ key: String, _ arguments: CVarArg...) -> String {
    String(format: L(key), locale: Locale.current, arguments: arguments)
}

struct PendingSession: Identifiable, Hashable {
    let id: String
    let key: String
    let title: String
    let cwd: String
    let resetDate: Date
    let resetLabel: String
    let origin: SessionOrigin
    let processIdentifier: Int32?
}

enum SessionOrigin: String, Hashable {
    case vscode
    case cli
    case unknown

    var label: String {
        switch self {
        case .vscode: return "VS Code Extension"
        case .cli: return "Claude CLI"
        case .unknown: return "VS Code Extension"
        }
    }
}

struct ClaudeAppChat: Identifiable, Hashable {
    let id: String
    let title: String
    let resetDate: Date?
    let conversationID: String?
    let recencyRank: Int

    init(id: String, title: String, resetDate: Date?, conversationID: String? = nil, recencyRank: Int = .max) {
        self.id = id
        self.title = title
        self.resetDate = resetDate
        self.conversationID = conversationID
        self.recencyRank = recencyRank
    }

    var resetLabel: String {
        guard let resetDate else { return L("Nog geen actieve limiet gedetecteerd") }
        let formatter = DateFormatter()
        formatter.locale = Locale.current
        formatter.setLocalizedDateFormatFromTemplate("EEE d MMM HH:mm")
        return LF("Reset: %@", formatter.string(from: resetDate))
    }
}

struct ClaudeAppCodeSession: Identifiable, Hashable {
    let id: String
    let title: String
    let titleOccurrence: Int
    let resetDate: Date?
    let recencyRank: Int

    var resetLabel: String {
        guard let resetDate else { return L("Nog geen actieve limiet gedetecteerd") }
        let formatter = DateFormatter()
        formatter.locale = Locale.current
        formatter.setLocalizedDateFormatFromTemplate("EEE d MMM HH:mm")
        return LF("Reset: %@", formatter.string(from: resetDate))
    }
}

struct ClaudeAppScanResult {
    let chats: [ClaudeAppChat]
    let resetDate: Date?
    let triggeringChatID: String?
    let accessibilityTrusted: Bool
    let appRunning: Bool
}

enum ChatSource: String, CaseIterable, Identifiable {
    case code = "VS Code Extension"
    case desktop = "Claude App"
    case appCode = "Claude App Code"
    case cli = "Claude CLI"
    var id: String { rawValue }
}

struct RuntimeAvailability {
    let vsCodeRunning: Bool
    let vsCodeExtensionRunning: Bool
    let claudeCLIRunning: Bool

    static func detect() -> RuntimeAvailability {
        let vsCodeRunning = !NSRunningApplication.runningApplications(
            withBundleIdentifier: "com.microsoft.VSCode"
        ).isEmpty
        var vsCodeExtensionRunning = false
        var claudeCLIRunning = false
        let sessionsRoot = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".claude/sessions", isDirectory: true)
        let files = (try? FileManager.default.contentsOfDirectory(
            at: sessionsRoot,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        for file in files where file.pathExtension == "json" {
            guard let data = try? Data(contentsOf: file),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let processNumber = object["pid"] as? NSNumber,
                  kill(processNumber.int32Value, 0) == 0 else { continue }
            let entrypoint = (object["entrypoint"] as? String ?? "").lowercased()
            if entrypoint.contains("vscode") { vsCodeExtensionRunning = true }
            if entrypoint == "cli" || entrypoint.contains("terminal") { claudeCLIRunning = true }
        }
        return RuntimeAvailability(
            vsCodeRunning: vsCodeRunning,
            vsCodeExtensionRunning: vsCodeRunning && vsCodeExtensionRunning,
            claudeCLIRunning: claudeCLIRunning
        )
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let date: Date
    let message: String
}

struct ResumeResult {
    let succeeded: Bool
    let message: String
}

// Steun de maker wanneer de app gratis vanuit de broncode is gebouwd (eigenaarmodus).
let coffeeURLString = "https://buymeacoffee.com/socialista"

enum LicenseStatus: Equatable {
    case ownerMode
    case trial(expiresAt: Date)
    case expired
    case licensed(email: String?)
    case subscriptionLapsed
    case activating
    case error(String)
}

enum SecureStore {
    private static let service = "nl.marvin.claude-resumer"

    static func read(_ account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func write(_ value: String, account: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [kSecValueData as String: data]
        if SecItemUpdate(query as CFDictionary, attributes as CFDictionary) == errSecItemNotFound {
            var newItem = query
            newItem[kSecValueData as String] = data
            SecItemAdd(newItem as CFDictionary, nil)
        }
    }

    static func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

private struct LicenseVerificationResponse: Decodable {
    let valid: Bool
    let email: String?
    let message: String?
    // "lifetime" bij een oude eenmalige aankoop, anders de Stripe-abonnementstatus.
    let status: String?
}

private enum ClosedLidController {
    struct StartResult {
        let succeeded: Bool
        let message: String
    }

    static func start(appPID: Int32, stateURL: URL, stopURL: URL, logURL: URL) -> StartResult {
        guard let monitorURL = Bundle.main.resourceURL?.appendingPathComponent("closed_lid_monitor.sh"),
              FileManager.default.isExecutableFile(atPath: monitorURL.path) else {
            return StartResult(succeeded: false, message: L("De gesloten-modusbewaker ontbreekt in deze appbuild."))
        }

        let command = [
            "/bin/sh", shellQuote(monitorURL.path),
            String(appPID), String(getuid()),
            shellQuote(stateURL.path), shellQuote(stopURL.path)
        ].joined(separator: " ") + " >" + shellQuote(logURL.path) + " 2>&1 </dev/null &"
        let escapedCommand = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = "do shell script \"\(escapedCommand)\" with administrator privileges"

        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", appleScript]
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return StartResult(succeeded: false, message: LF("De beheerdersprompt kon niet worden geopend: %@", error.localizedDescription))
        }
        guard process.terminationStatus == 0 else {
            let detail = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let message = detail?.isEmpty == false ? detail! : L("De beheerdersprompt is geannuleerd.")
            return StartResult(succeeded: false, message: message)
        }

        for _ in 0..<30 {
            Thread.sleep(forTimeInterval: 0.2)
            if FileManager.default.fileExists(atPath: stateURL.path), sleepIsDisabled() {
                return StartResult(succeeded: true, message: L("Gesloten modus is ingeschakeld."))
            }
        }
        requestStop(stopURL)
        return StartResult(succeeded: false, message: L("macOS heeft de gesloten modus niet geactiveerd. De oorspronkelijke instellingen worden hersteld."))
    }

    static func requestStop(_ stopURL: URL) {
        try? Data("stop\n".utf8).write(to: stopURL, options: .atomic)
    }

    static func isOnExternalPower() -> Bool {
        commandOutput("/usr/bin/pmset", ["-g", "batt"]).contains("AC Power")
    }

    static func batteryPercentage() -> Int? {
        let output = commandOutput("/usr/bin/pmset", ["-g", "batt"])
        guard let match = output.range(of: #"\d+%"#, options: .regularExpression) else { return nil }
        return Int(output[match].dropLast())
    }

    static func isClamshellClosed() -> Bool {
        commandOutput("/usr/sbin/ioreg", ["-r", "-k", "AppleClamshellState", "-d", "4"])
            .contains("AppleClamshellState\" = Yes")
    }

    static func sleepIsDisabled() -> Bool {
        commandOutput("/usr/bin/pmset", ["-g"]).contains("SleepDisabled\t\t1") ||
            commandOutput("/usr/bin/pmset", ["-g"]).contains("SleepDisabled 1")
    }

    private static func commandOutput(_ executable: String, _ arguments: [String]) -> String {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

@MainActor
final class ResumerModel: ObservableObject {
    @Published var sessions: [PendingSession] = []
    @Published var claudeAppChats: [ClaudeAppChat] = []
    @Published var claudeAppCodeSessions: [ClaudeAppCodeSession] = []
    @Published var claudeAppResetDate: Date?
    @Published var claudeAccessibilityTrusted = AXIsProcessTrusted()
    @Published var claudeAppRunning = false
    @Published var vsCodeRunning = false
    @Published var vsCodeExtensionRunning = false
    @Published var claudeCLIRunning = false
    @Published var selectedChatSource: ChatSource = .desktop
    @Published var logs: [LogEntry] = []
    @Published var isEnabled: Bool {
        didSet { UserDefaults.standard.set(isEnabled, forKey: "isEnabled") }
    }
    @Published var launchAtLogin: Bool = LoginService.isInstalled {
        didSet {
            guard launchAtLogin != LoginService.isInstalled else { return }
            do {
                if launchAtLogin { try LoginService.install() }
                else { LoginService.uninstall() }
                addLog(L(launchAtLogin ? "Opstarten bij inloggen ingeschakeld" : "Opstarten bij inloggen uitgeschakeld"))
            } catch {
                addLog(LF("Kon opstartinstelling niet wijzigen: %@", error.localizedDescription))
                launchAtLogin = LoginService.isInstalled
            }
        }
    }
    @Published var keepMacAwake: Bool {
        didSet {
            UserDefaults.standard.set(keepMacAwake, forKey: "keepMacAwake")
            updateWakeLock()
            if hasStarted {
                addLog(L(keepMacAwake ? "Mac wakker houden ingeschakeld" : "Mac wakker houden uitgeschakeld"))
            }
        }
    }
    @Published private(set) var wakeLockActive = false
    @Published var prompt: String {
        didSet { UserDefaults.standard.set(prompt, forKey: "prompt") }
    }
    @Published var isScanning = false
    @Published var detectionStale = false
    @Published var runningSessionIDs: Set<String> = []
    @Published var runningClaudeChatIDs: Set<String> = []
    @Published var runningClaudeAppCodeIDs: Set<String> = []
    @Published var licenseStatus: LicenseStatus = .ownerMode
    @Published var showCoffeePopup = false
    private var didOfferCoffee = false
    @Published var licenseKeyInput = ""
    @Published var showHelp = false
    @Published var showLicense = false
    @Published var showClosedLidWarning = false
    @Published private(set) var closedLidModeEnabled = false
    @Published private(set) var closedLidModeTransitioning = false
    @Published private(set) var closedLidIsClosed = false
    @Published private(set) var closedLidModeMessage = L("Gesloten modus staat uit.")

    private var timer: Timer?
    private var closedLidTimer: Timer?
    private var hasStarted = false
    private var wakeProcess: Process?
    private var closedLidStateURL: URL?
    private var closedLidStopURL: URL?
    private var handled: [String: String]
    @Published private var excludedCodeSessionKeys: Set<String>
    @Published private var selectedClaudeChatIDs: Set<String>
    @Published private var selectedClaudeAppCodeIDs: Set<String>
    private var lastClaudeAppChatCount = -1
    private var lastClaudeAppCodeCount = -1
    private var lastAttempts: [String: Date] = [:]
    private let gracePeriod: TimeInterval = 30
    private let trialDuration: TimeInterval = 24 * 60 * 60
    // Abonnement: hoe vaak we opnieuw bij de server controleren of het abonnement nog actief is,
    // en hoe lang de app zonder geslaagde controle (offline of tijdens Stripe-herincasso) blijft werken.
    private let licenseRevalidateInterval: TimeInterval = 24 * 60 * 60
    private let licenseGracePeriod: TimeInterval = 7 * 24 * 60 * 60
    private var isRevalidatingLicense = false

    var licensingEnabled: Bool {
        Bundle.main.object(forInfoDictionaryKey: "LicensingEnabled") as? Bool ?? false
    }

    var hasAccess: Bool {
        switch licenseStatus {
        case .ownerMode, .trial, .licensed: return true
        case .expired, .subscriptionLapsed, .activating, .error: return false
        }
    }

    var licenseTitle: String {
        switch licenseStatus {
        case .ownerMode: return L("Eigenaarmodus")
        case .trial: return L("Gratis proefperiode")
        case .expired: return L("Proefperiode verlopen")
        case .licensed: return L("Licentie actief")
        case .subscriptionLapsed: return L("Abonnement verlopen")
        case .activating: return L("Licentie controleren")
        case .error: return L("Licentie niet geactiveerd")
        }
    }

    var licenseDetail: String {
        switch licenseStatus {
        case .ownerMode:
            return L("Licentiecontrole staat uit voor deze lokale ontwikkelaarsbuild.")
        case .trial(let expiresAt):
            let remaining = max(0, expiresAt.timeIntervalSinceNow)
            let hours = Int(ceil(remaining / 3600))
            return hours > 1 ? LF("Nog ongeveer %d uur gratis te gebruiken.", hours) : L("Minder dan één uur gratis gebruik resterend.")
        case .expired:
            return L("Start een abonnement om chats weer automatisch te hervatten.")
        case .licensed(let email):
            return email.map { LF("Geactiveerd voor %@.", $0) } ?? L("Deze Mac heeft een geldige licentie.")
        case .subscriptionLapsed:
            return L("Je abonnement is niet meer actief. Verleng het om automatisch hervatten te blijven gebruiken.")
        case .activating:
            return L("De licentiesleutel wordt veilig gecontroleerd.")
        case .error(let message):
            return message
        }
    }

    init() {
        let defaults = UserDefaults.standard
        self.isEnabled = defaults.object(forKey: "isEnabled") as? Bool ?? true
        self.keepMacAwake = defaults.object(forKey: "keepMacAwake") as? Bool ?? false
        let savedPrompt = defaults.string(forKey: "prompt")
        self.prompt = savedPrompt == nil || savedPrompt == "Ga door met de taak vanaf waar je werd onderbroken."
            ? L("Ga door met de taak vanaf waar je werd onderbroken.")
            : savedPrompt!
        self.handled = defaults.dictionary(forKey: "handled") as? [String: String] ?? [:]
        self.excludedCodeSessionKeys = Set(defaults.stringArray(forKey: "excludedCodeSessionKeys") ?? [])
        self.selectedClaudeChatIDs = Set(defaults.stringArray(forKey: "selectedClaudeChatIDs") ?? [])
        self.selectedClaudeAppCodeIDs = Set(defaults.stringArray(forKey: "selectedClaudeAppCodeIDs") ?? [])
        refreshLicenseStatus()
    }

    func start() {
        guard !hasStarted else { return }
        hasStarted = true
        refreshLicenseStatus()
        do {
            if try LoginService.migrateLegacyServiceIfNeeded() {
                launchAtLogin = true
                addLog(L("Oude achtergrondservice vervangen door de Mac-app"))
            }
        } catch {
            addLog(LF("Kon oude achtergrondservice niet vervangen: %@", error.localizedDescription))
        }
        addLog(L("Claude Resumer gestart"))
        updateWakeLock()
        if keepMacAwake { addLog(L("Mac blijft wakker zolang Claude Resumer actief is")) }
        scan()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.scan() }
        }
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.scan() }
        }
        for notification in [NSWorkspace.didLaunchApplicationNotification, NSWorkspace.didTerminateApplicationNotification] {
            NSWorkspace.shared.notificationCenter.addObserver(
                forName: notification, object: nil, queue: .main
            ) { [weak self] _ in
                Task { @MainActor in self?.refreshRuntimeAvailability() }
            }
        }
        NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshAccessibilityPermission() }
        }
    }

    func scan() {
        guard !isScanning else { return }
        refreshLicenseStatus()
        refreshClosedLidModeStatus()
        isScanning = true
        let handledKeys = Set(handled.keys)
        Task.detached {
            let scan = SessionScanner.findPendingSessions()
            let found = scan.sessions
            let claudeAppResult = ClaudeAppScanner.scan()
            let claudeAppCodeResult = ClaudeAppCodeScanner.scan(resetDate: claudeAppResult.resetDate)
            let availability = RuntimeAvailability.detect()
            await MainActor.run {
                self.sessions = found.sorted { $0.resetDate < $1.resetDate }
                self.updateClaudeApp(result: claudeAppResult)
                self.updateClaudeAppCode(sessions: claudeAppCodeResult)
                self.updateRuntimeAvailability(availability)
                self.updateDetectionHealth(unrecognizedLimits: scan.unrecognizedLimits)
                self.isScanning = false
                if self.isEnabled && self.hasAccess {
                    let now = Date()
                    for session in found where
                        now.timeIntervalSince(session.resetDate) >= self.gracePeriod &&
                        now.timeIntervalSince(session.resetDate) < 86_400 &&
                        !handledKeys.contains(session.key) &&
                        self.isCodeSessionSelected(session) &&
                        now.timeIntervalSince(self.lastAttempts[session.key] ?? .distantPast) >= 300 &&
                        !self.runningSessionIDs.contains(session.id) {
                        self.resume(session)
                    }
                    self.resumeSelectedClaudeAppChats(now: now)
                    self.resumeSelectedClaudeAppCodeSessions(now: now)
                }
            }
        }
    }

    private func updateDetectionHealth(unrecognizedLimits: Int) {
        let stale = unrecognizedLimits > 0
        if stale != detectionStale {
            detectionStale = stale
            if stale {
                addLog(L("Limiet gevonden met een onbekende indeling. Werk Claude Resumer bij."))
            }
        }
    }

    func refreshRuntimeAvailability() {
        Task.detached {
            let availability = RuntimeAvailability.detect()
            let claudeRunning = !NSRunningApplication.runningApplications(
                withBundleIdentifier: "com.anthropic.claudefordesktop"
            ).isEmpty
            await MainActor.run {
                self.updateRuntimeAvailability(availability)
                self.claudeAppRunning = claudeRunning
            }
        }
    }

    private func updateRuntimeAvailability(_ availability: RuntimeAvailability) {
        vsCodeRunning = availability.vsCodeRunning
        vsCodeExtensionRunning = availability.vsCodeExtensionRunning
        claudeCLIRunning = availability.claudeCLIRunning
    }

    func isSourceAvailable(_ source: ChatSource) -> Bool {
        switch source {
        case .code: return vsCodeExtensionRunning
        case .desktop, .appCode: return claudeAppRunning
        case .cli: return claudeCLIRunning
        }
    }

    func sourceUnavailableMessage(_ source: ChatSource) -> String {
        switch source {
        case .code:
            return vsCodeRunning
                ? L("VS Code draait, maar er is geen actieve Claude Extension-sessie.")
                : L("VS Code draait niet. Open VS Code en start een chat in de Claude Extension.")
        case .desktop:
            return L("Claude App draait niet. Open Claude om App-chats te bekijken.")
        case .appCode:
            return L("Claude App draait niet. Open Claude en kies Code om Code-sessies te bekijken.")
        case .cli:
            return L("Er draait geen Claude CLI-sessie. Start claude in Terminal of de VS Code-terminal.")
        }
    }

    func openSource(_ source: ChatSource) {
        switch source {
        case .code:
            NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/Visual Studio Code.app"))
        case .desktop:
            openClaudeApp()
        case .appCode:
            showClaudeAppCode()
        case .cli:
            NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app"))
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.refreshRuntimeAvailability() }
    }

    func isCodeSessionSelected(_ session: PendingSession) -> Bool {
        !excludedCodeSessionKeys.contains(session.key)
    }

    func setCodeSession(_ session: PendingSession, selected: Bool) {
        if selected { excludedCodeSessionKeys.remove(session.key) }
        else { excludedCodeSessionKeys.insert(session.key) }
        UserDefaults.standard.set(Array(excludedCodeSessionKeys), forKey: "excludedCodeSessionKeys")
    }

    func sessions(for source: ChatSource) -> [PendingSession] {
        switch source {
        case .cli:
            return sessions.filter { $0.origin == .cli }
        case .code:
            return sessions.filter { $0.origin != .cli }
        case .desktop, .appCode:
            return []
        }
    }

    func selectAllSessions(in source: ChatSource, selected: Bool) {
        for session in sessions(for: source) { setCodeSession(session, selected: selected) }
    }

    func selectedSessionCount(in source: ChatSource) -> Int {
        sessions(for: source).filter(isCodeSessionSelected).count
    }

    func isClaudeChatSelected(_ chat: ClaudeAppChat) -> Bool {
        selectedClaudeChatIDs.contains(chat.id)
    }

    func setClaudeChat(_ chat: ClaudeAppChat, selected: Bool) {
        if selected { selectedClaudeChatIDs.insert(chat.id) }
        else { selectedClaudeChatIDs.remove(chat.id) }
        saveClaudeChatSelection()
    }

    func selectAllClaudeChats(_ selected: Bool) {
        if selected { selectedClaudeChatIDs.formUnion(claudeAppChats.map(\.id)) }
        else { selectedClaudeChatIDs.subtract(claudeAppChats.map(\.id)) }
        saveClaudeChatSelection()
    }

    var selectedClaudeChatCount: Int {
        claudeAppChats.filter(isClaudeChatSelected).count
    }

    func isClaudeAppCodeSelected(_ session: ClaudeAppCodeSession) -> Bool {
        selectedClaudeAppCodeIDs.contains(session.id)
    }

    func setClaudeAppCodeSession(_ session: ClaudeAppCodeSession, selected: Bool) {
        if selected { selectedClaudeAppCodeIDs.insert(session.id) }
        else { selectedClaudeAppCodeIDs.remove(session.id) }
        saveClaudeAppCodeSelection()
    }

    func selectAllClaudeAppCodeSessions(_ selected: Bool) {
        if selected { selectedClaudeAppCodeIDs.formUnion(claudeAppCodeSessions.map(\.id)) }
        else { selectedClaudeAppCodeIDs.subtract(claudeAppCodeSessions.map(\.id)) }
        saveClaudeAppCodeSelection()
    }

    var selectedClaudeAppCodeCount: Int {
        claudeAppCodeSessions.filter(isClaudeAppCodeSelected).count
    }

    func showClaudeAppCode() {
        openClaudeApp()
        Task.detached {
            let shown = ClaudeAppCodeAutomation.showCodeHome()
            if shown { try? await Task.sleep(nanoseconds: 1_000_000_000) }
            await MainActor.run { self.scan() }
        }
    }

    func requestAccessibilityPermission() {
        let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
        _ = AXIsProcessTrustedWithOptions([key: true] as CFDictionary)
        claudeAccessibilityTrusted = AXIsProcessTrusted()
        if !claudeAccessibilityTrusted,
           let settingsURL = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(settingsURL)
        }
        addLog(L(claudeAccessibilityTrusted ? "Toegankelijkheidstoegang is actief" : "Toegankelijkheidstoegang is aangevraagd"))
        pollAccessibilityPermission()
    }

    private func refreshAccessibilityPermission() {
        let trusted = AXIsProcessTrusted()
        guard trusted != claudeAccessibilityTrusted else { return }
        claudeAccessibilityTrusted = trusted
        if trusted {
            addLog(L("Toegankelijkheidstoegang is actief"))
            scan()
        }
    }

    private func pollAccessibilityPermission(attempt: Int = 0) {
        refreshAccessibilityPermission()
        if claudeAccessibilityTrusted || attempt >= 60 { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.pollAccessibilityPermission(attempt: attempt + 1)
        }
    }

    func openClaudeApp() {
        NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/Claude.app"))
    }

    private func updateWakeLock() {
        if keepMacAwake {
            guard wakeProcess?.isRunning != true else {
                wakeLockActive = true
                return
            }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/caffeinate")
            process.arguments = ["-i", "-w", String(getpid())]
            do {
                try process.run()
                wakeProcess = process
                wakeLockActive = true
            } catch {
                wakeProcess = nil
                wakeLockActive = false
                if hasStarted { addLog(LF("Kon de Mac niet wakker houden: %@", error.localizedDescription)) }
            }
        } else {
            if wakeProcess?.isRunning == true { wakeProcess?.terminate() }
            wakeProcess = nil
            wakeLockActive = false
        }
    }

    func enableClosedLidMode() {
        guard !closedLidModeEnabled, !closedLidModeTransitioning else { return }

        let token = UUID().uuidString.lowercased()
        let base = URL(fileURLWithPath: "/var/tmp", isDirectory: true)
        let stateURL = base.appendingPathComponent("nl.marvin.claude-resumer.\(getuid()).\(token).state")
        let stopURL = base.appendingPathComponent("nl.marvin.claude-resumer.\(getuid()).\(token).stop")
        let logURL = base.appendingPathComponent("nl.marvin.claude-resumer.\(getuid()).\(token).log")
        closedLidStateURL = stateURL
        closedLidStopURL = stopURL
        closedLidModeTransitioning = true
        closedLidModeMessage = L("Wachten op toestemming van de beheerder...")
        addLog(L("Gesloten modus wordt aangezet"))

        Task.detached {
            let result = ClosedLidController.start(
                appPID: getpid(),
                stateURL: stateURL,
                stopURL: stopURL,
                logURL: logURL
            )
            await MainActor.run {
                self.closedLidModeTransitioning = false
                self.closedLidModeEnabled = result.succeeded
                self.closedLidModeMessage = result.message
                if result.succeeded {
                    self.refreshClosedLidModeStatus()
                    self.startClosedLidStatusTimer()
                    self.addLog(L("Gesloten modus actief, energiemodus volgt de klepstand"))
                } else {
                    self.closedLidStateURL = nil
                    self.closedLidStopURL = nil
                    self.addLog(LF("Gesloten modus niet geactiveerd: %@", result.message))
                }
            }
        }
    }

    func disableClosedLidMode(reason: String = L("handmatig uitgeschakeld")) {
        guard closedLidModeEnabled || closedLidModeTransitioning else { return }
        if let stopURL = closedLidStopURL { ClosedLidController.requestStop(stopURL) }
        closedLidModeEnabled = false
        closedLidModeTransitioning = true
        closedLidModeMessage = L("Oorspronkelijke energie-instellingen worden hersteld...")
        addLog(LF("Gesloten modus wordt hersteld: %@", reason))
        waitForClosedLidRestore()
    }

    private func startClosedLidStatusTimer() {
        closedLidTimer?.invalidate()
        closedLidTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshClosedLidModeStatus() }
        }
    }

    private func waitForClosedLidRestore(attempt: Int = 0) {
        let stateStillExists = closedLidStateURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false
        if !stateStillExists || attempt >= 30 {
            closedLidModeTransitioning = false
            closedLidTimer?.invalidate()
            closedLidTimer = nil
            closedLidStateURL = nil
            closedLidStopURL = nil
            closedLidModeMessage = stateStillExists
                ? L("Herstel duurt langer dan verwacht. Controleer de energie-instellingen van macOS.")
                : L("Gesloten modus staat uit. De oorspronkelijke energie-instellingen zijn hersteld.")
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            self.waitForClosedLidRestore(attempt: attempt + 1)
        }
    }

    private func refreshClosedLidModeStatus() {
        guard closedLidModeEnabled else { return }
        guard let stateURL = closedLidStateURL,
              FileManager.default.fileExists(atPath: stateURL.path),
              ClosedLidController.sleepIsDisabled() else {
            closedLidModeEnabled = false
            closedLidModeTransitioning = false
            closedLidTimer?.invalidate()
            closedLidTimer = nil
            let batteryIsLow = !ClosedLidController.isOnExternalPower() &&
                (ClosedLidController.batteryPercentage() ?? 100) <= 10
            closedLidModeMessage = batteryIsLow
                ? L("Bij 10% batterij automatisch gestopt. De Mac kan nu normaal slapen.")
                : L("Gesloten modus is gestopt en de oorspronkelijke instellingen zijn hersteld.")
            addLog(closedLidModeMessage)
            closedLidStateURL = nil
            closedLidStopURL = nil
            return
        }

        closedLidIsClosed = ClosedLidController.isClamshellClosed()
        if closedLidIsClosed && (
            ProcessInfo.processInfo.thermalState == .serious ||
            ProcessInfo.processInfo.thermalState == .critical
        ) {
            disableClosedLidMode(reason: L("Mac werd te warm"))
            closedLidModeMessage = L("Voor de veiligheid uitgeschakeld wegens hoge temperatuur.")
            return
        }
        closedLidModeMessage = closedLidIsClosed
            ? L("MacBook is dicht: slaapstand is geblokkeerd en Low Power Mode is actief.")
            : L("Scherm is open: je oorspronkelijke energiemodus is actief. Dichtklappen blijft toegestaan.")
    }

    func resumeClaudeAppNow(_ chat: ClaudeAppChat) {
        guard hasAccess else {
            showLicense = true
            return
        }
        guard let resetDate = chat.resetDate, Date() >= resetDate else { return }
        resumeClaudeAppChat(chat)
    }

    private func updateClaudeApp(result: ClaudeAppScanResult) {
        claudeAppChats = result.chats.sorted {
            if $0.recencyRank != $1.recencyRank { return $0.recencyRank < $1.recencyRank }
            return $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
        }
        claudeAppResetDate = result.resetDate
        claudeAccessibilityTrusted = result.accessibilityTrusted
        claudeAppRunning = result.appRunning
        if lastClaudeAppChatCount != result.chats.count {
            if !result.chats.isEmpty {
                addLog(result.chats.count == 1
                    ? L("1 recente Claude App-chat gevonden")
                    : LF("%d recente Claude App-chats gevonden", result.chats.count))
            }
            lastClaudeAppChatCount = result.chats.count
        }
    }

    private func updateClaudeAppCode(sessions: [ClaudeAppCodeSession]) {
        claudeAppCodeSessions = sessions.sorted {
            if $0.recencyRank != $1.recencyRank { return $0.recencyRank < $1.recencyRank }
            return $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
        }
        if lastClaudeAppCodeCount != sessions.count {
            if !sessions.isEmpty {
                addLog(sessions.count == 1
                    ? L("1 Claude App Code-sessie gevonden")
                    : LF("%d Claude App Code-sessies gevonden", sessions.count))
            }
            lastClaudeAppCodeCount = sessions.count
        }
    }

    private func resumeSelectedClaudeAppChats(now: Date) {
        for chat in claudeAppChats where isClaudeChatSelected(chat) {
            guard let resetDate = chat.resetDate,
                  now.timeIntervalSince(resetDate) >= gracePeriod,
                  now.timeIntervalSince(resetDate) < 86_400,
                  !handled.keys.contains(claudeHandledKey(chat)),
                  !runningClaudeChatIDs.contains(chat.id) else { continue }
            resumeClaudeAppChat(chat)
        }
    }

    private func resumeClaudeAppChat(_ chat: ClaudeAppChat) {
        guard !runningClaudeChatIDs.contains(chat.id) else { return }
        runningClaudeChatIDs.insert(chat.id)
        addLog(LF("Claude App-chat ‘%@’ wordt geopend", chat.title))
        let promptToSend = prompt
        Task.detached {
            let result = ClaudeAppAutomation.openAndSubmit(chat: chat, prompt: promptToSend)
            await MainActor.run {
                self.runningClaudeChatIDs.remove(chat.id)
                if result.succeeded {
                    self.handled[self.claudeHandledKey(chat)] = ISO8601DateFormatter().string(from: Date())
                    self.saveHandled()
                }
                self.addLog(result.message)
            }
        }
    }

    private func claudeHandledKey(_ chat: ClaudeAppChat) -> String {
        let reset = Int(chat.resetDate?.timeIntervalSince1970 ?? 0)
        return "claude-app:\(chat.id):\(reset)"
    }

    private func saveClaudeChatSelection() {
        UserDefaults.standard.set(Array(selectedClaudeChatIDs), forKey: "selectedClaudeChatIDs")
    }

    func resumeClaudeAppCodeNow(_ session: ClaudeAppCodeSession) {
        guard hasAccess else {
            showLicense = true
            return
        }
        guard let resetDate = session.resetDate, Date() >= resetDate else { return }
        resumeClaudeAppCodeSession(session)
    }

    private func resumeSelectedClaudeAppCodeSessions(now: Date) {
        for session in claudeAppCodeSessions where isClaudeAppCodeSelected(session) {
            guard let resetDate = session.resetDate,
                  now.timeIntervalSince(resetDate) >= gracePeriod,
                  now.timeIntervalSince(resetDate) < 86_400,
                  !handled.keys.contains(claudeAppCodeHandledKey(session)),
                  !runningClaudeAppCodeIDs.contains(session.id) else { continue }
            resumeClaudeAppCodeSession(session)
        }
    }

    private func resumeClaudeAppCodeSession(_ session: ClaudeAppCodeSession) {
        guard !runningClaudeAppCodeIDs.contains(session.id) else { return }
        runningClaudeAppCodeIDs.insert(session.id)
        addLog(LF("Claude App Code-sessie ‘%@’ wordt geopend", session.title))
        let promptToSend = prompt
        Task.detached {
            let result = ClaudeAppCodeAutomation.openAndSubmit(session: session, prompt: promptToSend)
            await MainActor.run {
                self.runningClaudeAppCodeIDs.remove(session.id)
                if result.succeeded {
                    self.handled[self.claudeAppCodeHandledKey(session)] = ISO8601DateFormatter().string(from: Date())
                    self.saveHandled()
                }
                self.addLog(result.message)
            }
        }
    }

    private func claudeAppCodeHandledKey(_ session: ClaudeAppCodeSession) -> String {
        let reset = Int(session.resetDate?.timeIntervalSince1970 ?? 0)
        return "claude-app-code:\(session.id):\(reset)"
    }

    private func saveClaudeAppCodeSelection() {
        UserDefaults.standard.set(Array(selectedClaudeAppCodeIDs), forKey: "selectedClaudeAppCodeIDs")
    }

    func resumeNow(_ session: PendingSession) {
        guard hasAccess else {
            showLicense = true
            addLog(L("Hervatten geblokkeerd: activeer eerst een licentie"))
            return
        }
        guard Date() >= session.resetDate else { return }
        handled.removeValue(forKey: session.key)
        lastAttempts.removeValue(forKey: session.key)
        saveHandled()
        guard !runningSessionIDs.contains(session.id) else { return }
        runningSessionIDs.insert(session.id)
        addLog(session.origin == .cli
            ? LF("Sessie %@ wordt geopend in Terminal", session.id)
            : LF("Sessie %@ wordt geopend in VS Code", session.id))
        let promptToSend = prompt
        Task.detached {
            let result = session.origin == .cli
                ? TerminalAutomation.openAndSubmit(session: session, prompt: promptToSend)
                : VSCodeAccessibilityAutomation.openAndSubmit(
                    session: session,
                    prompt: promptToSend,
                    requestPermission: true
                )
            await MainActor.run {
                self.runningSessionIDs.remove(session.id)
                self.addLog(result.message)
                if !result.succeeded {
                    self.addLog(L("De achtergrondmethode blijft beschikbaar bij de automatische hervatpoging"))
                }
            }
        }
    }

    private func resume(_ session: PendingSession) {
        guard !runningSessionIDs.contains(session.id) else { return }
        runningSessionIDs.insert(session.id)
        lastAttempts[session.key] = Date()
        handled[session.key] = ISO8601DateFormatter().string(from: Date())
        saveHandled()
        addLog(LF("Sessie %@ wordt hervat", session.id))

        let promptToSend = prompt
        Task.detached {
            let result: ResumeResult
            if session.origin == .cli {
                result = TerminalAutomation.openAndSubmit(session: session, prompt: promptToSend)
            } else {
                let accessibilityResult = VSCodeAccessibilityAutomation.openAndSubmit(
                    session: session,
                    prompt: promptToSend,
                    requestPermission: false
                )
                result = accessibilityResult.succeeded
                    ? accessibilityResult
                    : ClaudeRunner.run(session: session, prompt: promptToSend)
            }
            await MainActor.run {
                self.runningSessionIDs.remove(session.id)
                if !result.succeeded {
                    self.handled.removeValue(forKey: session.key)
                    self.saveHandled()
                }
                self.addLog(result.message)
                self.scan()
            }
        }
    }

    private func saveHandled() {
        UserDefaults.standard.set(handled, forKey: "handled")
    }

    private func licenseLastVerifiedDate() -> Date? {
        guard let stored = SecureStore.read("licenseLastVerifiedAt") else { return nil }
        return ISO8601DateFormatter().date(from: stored)
    }

    private func setLicenseLastVerified(_ date: Date) {
        SecureStore.write(ISO8601DateFormatter().string(from: date), account: "licenseLastVerifiedAt")
    }

    private func licenseLastCheckedDate() -> Date? {
        guard let stored = SecureStore.read("licenseLastCheckedAt") else { return nil }
        return ISO8601DateFormatter().date(from: stored)
    }

    private func setLicenseLastChecked(_ date: Date) {
        SecureStore.write(ISO8601DateFormatter().string(from: date), account: "licenseLastCheckedAt")
    }

    func refreshLicenseStatus() {
        guard licensingEnabled else {
            licenseStatus = .ownerMode
            return
        }
        if let key = SecureStore.read("licenseKey") {
            let email = SecureStore.read("licenseEmail")
            // Eenmalige (lifetime) aankoop: blijft altijd geldig, net als in de vorige versie.
            if SecureStore.read("licenseLifetime") == "1" {
                licenseStatus = .licensed(email: email)
            } else if SecureStore.read("licenseInactive") == "1" {
                // Server heeft dit abonnement expliciet als niet-actief gemarkeerd: geen respijtperiode.
                licenseStatus = .subscriptionLapsed
            } else if let verifiedAt = licenseLastVerifiedDate() {
                // Abonnement: geldig zolang de laatste geslaagde controle binnen de respijtperiode valt.
                licenseStatus = Date().timeIntervalSince(verifiedAt) < licenseGracePeriod
                    ? .licensed(email: email)
                    : .subscriptionLapsed
            } else {
                // Sleutel aanwezig maar nog nooit gecontroleerd op dit toestel: start de respijtperiode nu
                // en laat de achtergrondcontrole hieronder de status bevestigen.
                setLicenseLastVerified(Date())
                licenseStatus = .licensed(email: email)
            }
            maybeRevalidateLicense(key: key)
            return
        }
        let formatter = ISO8601DateFormatter()
        let startedAt: Date
        if let stored = SecureStore.read("trialStartedAt"), let date = formatter.date(from: stored) {
            startedAt = date
        } else {
            startedAt = Date()
            SecureStore.write(formatter.string(from: startedAt), account: "trialStartedAt")
        }
        let expiresAt = startedAt.addingTimeInterval(trialDuration)
        licenseStatus = Date() < expiresAt ? .trial(expiresAt: expiresAt) : .expired
    }

    /// Toont eenmalig per start een vriendelijke koffie-vraag wanneer de app gratis vanuit
    /// de broncode draait (eigenaarmodus). Betalende gebruikers zien dit nooit.
    func offerCoffeeIfNeeded() {
        guard case .ownerMode = licenseStatus, !didOfferCoffee else { return }
        didOfferCoffee = true
        showCoffeePopup = true
    }

    /// Controleert het abonnement opnieuw bij de server, maar hoogstens één keer per interval.
    /// Lifetime-licenties worden nooit opnieuw gecontroleerd.
    func maybeRevalidateLicense(key: String) {
        guard licensingEnabled else { return }
        if SecureStore.read("licenseLifetime") == "1" { return }
        // Throttle op het laatste controlemoment (ook na een afgewezen of mislukte controle),
        // zodat de server niet bij elke scan opnieuw wordt bevraagd.
        if let checkedAt = licenseLastCheckedDate(),
           Date().timeIntervalSince(checkedAt) < licenseRevalidateInterval {
            return
        }
        revalidateLicense(key: key)
    }

    /// Vraagt de server of het abonnement nog actief is en werkt de status/respijtperiode bij.
    /// Bij een netwerkfout blijft de status ongemoeid, zodat de respijtperiode de toegang bepaalt.
    func revalidateLicense(key: String) {
        guard licensingEnabled, !isRevalidatingLicense else { return }
        guard let base = Bundle.main.object(forInfoDictionaryKey: "LicenseServerURL") as? String,
              !base.isEmpty,
              let url = URL(string: base)?.appendingPathComponent("api/verify") else { return }
        isRevalidatingLicense = true
        // Meteen stempelen, zodat de throttle ook geldt na een afgewezen of mislukte controle.
        setLicenseLastChecked(Date())
        Task.detached {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.timeoutInterval = 15
            request.httpBody = try? JSONSerialization.data(withJSONObject: ["licenseKey": key, "deviceId": deviceIdentifier()])
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
                let result = try? JSONDecoder().decode(LicenseVerificationResponse.self, from: data)
                await MainActor.run {
                    self.isRevalidatingLicense = false
                    if statusCode == 200, result?.valid == true {
                        // Abonnement (of lifetime) actief: markering opheffen, respijtperiode verversen, toegang bevestigen.
                        SecureStore.delete("licenseInactive")
                        self.setLicenseLastVerified(Date())
                        if result?.status == "lifetime" { SecureStore.write("1", account: "licenseLifetime") }
                        if let email = result?.email { SecureStore.write(email, account: "licenseEmail") }
                        self.licenseStatus = .licensed(email: result?.email ?? SecureStore.read("licenseEmail"))
                    } else if (statusCode == 403 || statusCode == 400), SecureStore.read("licenseLifetime") != "1" {
                        // 403 = abonnement niet meer actief, 400 = sleutel ongeldig. Beide zijn een definitief
                        // oordeel van de server: markeren en meteen vergrendelen, zodat de respijtperiode de
                        // toegang niet opnieuw verleent.
                        SecureStore.write("1", account: "licenseInactive")
                        self.licenseStatus = .subscriptionLapsed
                        self.addLog(L("Abonnement is niet meer actief"))
                    }
                    // Overige fouten (5xx, netwerk): niets wijzigen; de respijtperiode bepaalt de toegang.
                }
            } catch {
                await MainActor.run { self.isRevalidatingLicense = false }
            }
        }
    }

    func activateLicense() {
        let key = licenseKeyInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else {
            licenseStatus = .error(L("Vul eerst je licentiesleutel in."))
            return
        }
        guard let base = Bundle.main.object(forInfoDictionaryKey: "LicenseServerURL") as? String,
              !base.isEmpty,
              let url = URL(string: base)?.appendingPathComponent("api/verify") else {
            licenseStatus = .error(L("De licentieserver is nog niet ingesteld in deze build."))
            return
        }
        licenseStatus = .activating
        Task.detached {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.timeoutInterval = 15
            request.httpBody = try? JSONSerialization.data(withJSONObject: ["licenseKey": key, "deviceId": deviceIdentifier()])
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
                let result = try JSONDecoder().decode(LicenseVerificationResponse.self, from: data)
                await MainActor.run {
                    if statusCode == 200 && result.valid {
                        SecureStore.write(key, account: "licenseKey")
                        if let email = result.email { SecureStore.write(email, account: "licenseEmail") }
                        SecureStore.delete("licenseInactive")
                        self.setLicenseLastVerified(Date())
                        self.setLicenseLastChecked(Date())
                        // Onthoud of dit een lifetime-licentie is; dan hoeft er nooit opnieuw gecontroleerd te worden.
                        if result.status == "lifetime" {
                            SecureStore.write("1", account: "licenseLifetime")
                        } else {
                            SecureStore.delete("licenseLifetime")
                        }
                        self.licenseKeyInput = ""
                        self.licenseStatus = .licensed(email: result.email)
                        self.addLog(L("Licentie succesvol geactiveerd"))
                    } else {
                        self.licenseStatus = .error(result.message ?? L("Deze licentiesleutel is niet geldig."))
                    }
                }
            } catch {
                await MainActor.run {
                    self.licenseStatus = .error(L("Controle mislukt. Controleer je internetverbinding en probeer opnieuw."))
                }
            }
        }
    }

    func openPurchasePage() {
        let configured = Bundle.main.object(forInfoDictionaryKey: "PurchaseURL") as? String
        let fallback = Bundle.main.object(forInfoDictionaryKey: "LicenseServerURL") as? String
        guard let value = [configured, fallback].compactMap({ $0 }).first(where: { !$0.isEmpty }),
              let url = URL(string: value) else { return }
        NSWorkspace.shared.open(url)
    }

    func handleIncomingURL(_ url: URL) {
        guard url.scheme?.lowercased() == "claude-resumer",
              url.host?.lowercased() == "activate",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let key = components.queryItems?.first(where: { $0.name == "key" })?.value,
              key.hasPrefix("CR1.") else {
            addLog(L("Ongeldige activatielink genegeerd"))
            return
        }
        licenseKeyInput = key
        showLicense = true
        addLog(L("Licentiesleutel ontvangen via de website"))
        if licensingEnabled { activateLicense() }
    }

    func addLog(_ message: String) {
        logs.insert(LogEntry(date: Date(), message: message), at: 0)
        if logs.count > 100 { logs.removeLast(logs.count - 100) }
        LogFile.write(message)
    }
}

enum SessionScanner {
    private struct RuntimeSession {
        let origin: SessionOrigin
        let processIdentifier: Int32
    }

    private struct InitialMetadata {
        var title: String?
        var firstPrompt: String?
        var origin: SessionOrigin = .unknown
    }

    private struct LimitMatch {
        let hour: Int
        let minute: Int
        let ampm: String
        let zone: String?
    }

    struct ScanResult {
        let sessions: [PendingSession]
        // Number of rate-limit entries whose reset time we could not parse.
        // A value above zero means Claude's wording likely changed and detection
        // needs an update, so it can be surfaced instead of failing silently.
        let unrecognizedLimits: Int
    }

    // The entry is already known to be a rate-limit error (error == "rate_limit"),
    // so the matcher only extracts the reset time and stays tolerant of the
    // surrounding wording: it anchors on "resets", accepts an optional "at",
    // optional minutes, "am"/"pm" with or without periods, and an optional zone.
    private static let limitPattern =
        #"resets\s+(?:at\s+)?(\d{1,2})(?::(\d{2}))?\s*([ap])\.?m\.?\b(?:\s*\(([^)]+)\))?"#

    static func findPendingSessions() -> ScanResult {
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".claude/projects")
        guard let projectFolders = try? FileManager.default.contentsOfDirectory(
            at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
        ) else { return ScanResult(sessions: [], unrecognizedLimits: 0) }

        let runtimes = runtimeSessions()
        var sessions: [PendingSession] = []
        var unrecognized = 0
        for folder in projectFolders {
            guard let files = try? FileManager.default.contentsOfDirectory(
                at: folder,
                includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) else { continue }
            for file in files where file.pathExtension == "jsonl" {
                guard isRecent(file) else { continue }
                let outcome = parseTail(file, runtimes: runtimes)
                if let session = outcome.session { sessions.append(session) }
                if outcome.unrecognized { unrecognized += 1 }
            }
        }
        return ScanResult(sessions: sessions, unrecognizedLimits: unrecognized)
    }

    private static func isRecent(_ file: URL) -> Bool {
        let values = try? file.resourceValues(forKeys: [.contentModificationDateKey])
        guard let modified = values?.contentModificationDate else { return false }
        return Date().timeIntervalSince(modified) < 172_800
    }

    private static func parseTail(_ file: URL, runtimes: [String: RuntimeSession]) -> (session: PendingSession?, unrecognized: Bool) {
        let initial = initialMetadata(of: file)
        guard let handle = try? FileHandle(forReadingFrom: file) else { return (nil, false) }
        defer { try? handle.close() }
        let end = (try? handle.seekToEnd()) ?? 0
        let maxBytes: UInt64 = 4 * 1_024 * 1_024
        let start = end > maxBytes ? end - maxBytes : 0
        try? handle.seek(toOffset: start)
        guard let data = try? handle.readToEnd(),
              let text = String(data: data, encoding: .utf8) else { return (nil, false) }

        var lastLimit: PendingSession?
        var laterActivity = false
        var sawUnparsedLimit = false
        var latestTitle = initial.title
        var origin = initial.origin
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        for (index, line) in lines.enumerated() {
            if start > 0 && index == 0 { continue }
            guard let data = line.data(using: .utf8),
                  let entry = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            let entryText = messageText(entry)
            if entry["type"] as? String == "ai-title", let title = entry["aiTitle"] as? String {
                latestTitle = title
            }
            if let entrypoint = entry["entrypoint"] as? String {
                origin = sessionOrigin(entrypoint)
            }
            if entry["error"] as? String == "rate_limit" {
                if let match = firstMatch(in: entryText),
                   let timestamp = entry["timestamp"] as? String,
                   let reset = resetDate(match: match, timestamp: timestamp) {
                    let sessionID = entry["sessionId"] as? String ?? file.deletingPathExtension().lastPathComponent
                    guard let cwd = originalCWD(of: file) ?? entry["cwd"] as? String else { continue }
                    let runtime = runtimes[sessionID]
                    if let runtime, runtime.origin != .unknown { origin = runtime.origin }
                    let label = format(reset, zone: match.zone)
                    let fallbackTitle = initial.firstPrompt.map(shortTitle)
                    let genericTitle = origin == .cli
                        ? LF("Claude CLI-chat %@", String(sessionID.prefix(8)))
                        : LF("VS Code-chat %@", String(sessionID.prefix(8)))
                    lastLimit = PendingSession(
                        id: sessionID,
                        key: "\(sessionID):\(timestamp)",
                        title: latestTitle ?? fallbackTitle ?? genericTitle,
                        cwd: cwd,
                        resetDate: reset,
                        resetLabel: label,
                        origin: origin,
                        processIdentifier: runtime?.processIdentifier
                    )
                    laterActivity = false
                    sawUnparsedLimit = false
                } else {
                    // A genuine rate-limit entry whose reset time we could not read:
                    // treat it as a signal that Claude's format may have changed.
                    sawUnparsedLimit = true
                }
            } else if lastLimit != nil, isMeaningfulActivity(entry) {
                laterActivity = true
            }
        }
        return (laterActivity ? nil : lastLimit, sawUnparsedLimit && !laterActivity)
    }

    private static func runtimeSessions() -> [String: RuntimeSession] {
        let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude/sessions", isDirectory: true)
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return [:] }
        var sessions: [String: RuntimeSession] = [:]
        for file in files where file.pathExtension == "json" {
            guard let data = try? Data(contentsOf: file),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let sessionID = object["sessionId"] as? String,
                  let processNumber = object["pid"] as? NSNumber else { continue }
            let entrypoint = object["entrypoint"] as? String ?? ""
            sessions[sessionID] = RuntimeSession(
                origin: sessionOrigin(entrypoint),
                processIdentifier: processNumber.int32Value
            )
        }
        return sessions
    }

    private static func initialMetadata(of file: URL) -> InitialMetadata {
        guard let handle = try? FileHandle(forReadingFrom: file) else { return InitialMetadata() }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: 2 * 1_024 * 1_024),
              let text = String(data: data, encoding: .utf8) else { return InitialMetadata() }
        var metadata = InitialMetadata()
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let lineData = line.data(using: .utf8),
                  let entry = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] else { continue }
            if entry["type"] as? String == "ai-title", let title = entry["aiTitle"] as? String {
                metadata.title = title
            }
            if let entrypoint = entry["entrypoint"] as? String {
                metadata.origin = sessionOrigin(entrypoint)
            }
            if metadata.firstPrompt == nil,
               entry["type"] as? String == "user",
               (entry["origin"] as? [String: Any])?["kind"] as? String == "human" {
                let prompt = messageText(entry).trimmingCharacters(in: .whitespacesAndNewlines)
                if !prompt.isEmpty { metadata.firstPrompt = prompt }
            }
        }
        return metadata
    }

    private static func sessionOrigin(_ entrypoint: String) -> SessionOrigin {
        let value = entrypoint.lowercased()
        if value.contains("vscode") || value.contains("ide") { return .vscode }
        if value == "cli" || value.contains("terminal") { return .cli }
        return .unknown
    }

    private static func shortTitle(_ value: String) -> String {
        let oneLine = value.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if oneLine.count <= 72 { return oneLine }
        return String(oneLine.prefix(69)) + "..."
    }

    private static func originalCWD(of file: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: file) else { return nil }
        defer { try? handle.close() }
        let data = try? handle.read(upToCount: 256 * 1_024)
        guard let data, let text = String(data: data, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            guard let lineData = line.data(using: .utf8),
                  let entry = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any],
                  let cwd = entry["cwd"] as? String else { continue }
            return cwd
        }
        return nil
    }

    private static func isMeaningfulActivity(_ entry: [String: Any]) -> Bool {
        guard let type = entry["type"] as? String else { return false }
        if type == "assistant" { return entry["error"] == nil }
        guard type == "user" else { return false }
        if let origin = entry["origin"] as? [String: Any], origin["kind"] as? String == "task-notification" {
            return false
        }
        return entry["promptSource"] as? String != "sdk"
    }

    private static func messageText(_ entry: [String: Any]) -> String {
        guard let message = entry["message"] as? [String: Any],
              let content = message["content"] else { return "" }
        if let text = content as? String { return text }
        guard let blocks = content as? [[String: Any]] else { return "" }
        return blocks.compactMap { $0["text"] as? String }.joined(separator: "\n")
    }

    private static func firstMatch(in text: String) -> LimitMatch? {
        guard let regex = try? NSRegularExpression(pattern: limitPattern, options: [.caseInsensitive]) else { return nil }
        guard let result = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else { return nil }
        func capture(_ index: Int) -> String? {
            guard let range = Range(result.range(at: index), in: text) else { return nil }
            return String(text[range])
        }
        guard let hourText = capture(1), let hour = Int(hourText),
              let ampm = capture(3) else { return nil }
        let minute = capture(2).flatMap(Int.init) ?? 0
        let zone = capture(4)?.trimmingCharacters(in: .whitespaces)
        return LimitMatch(hour: hour, minute: minute, ampm: ampm, zone: zone)
    }

    private static func resetDate(match: LimitMatch, timestamp: String) -> Date? {
        guard let event = parseISO(timestamp) else { return nil }
        let zone = resolveTimeZone(match.zone, isoTimestamp: timestamp)
        var hour = match.hour % 12
        if match.ampm.lowercased().hasPrefix("p") { hour += 12 }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        var parts = calendar.dateComponents([.year, .month, .day], from: event)
        parts.hour = hour
        parts.minute = match.minute
        parts.second = 0
        guard var reset = calendar.date(from: parts) else { return nil }
        if reset <= event { reset = calendar.date(byAdding: .day, value: 1, to: reset) ?? reset }
        return reset
    }

    // Resolve the printed zone tolerantly. Claude usually prints an IANA name
    // (America/New_York), but may print an abbreviation (PST) that
    // TimeZone(identifier:) rejects, or omit the zone entirely. In every case we
    // fall back to the offset embedded in the event timestamp, which reflects the
    // user's own clock, rather than dropping the limit.
    private static func resolveTimeZone(_ raw: String?, isoTimestamp: String) -> TimeZone {
        if let raw, !raw.isEmpty {
            if let zone = TimeZone(identifier: raw) { return zone }
            if let zone = TimeZone(abbreviation: raw.uppercased()) { return zone }
            if let zone = extraZoneAbbreviations[raw.uppercased()] { return zone }
        }
        if let zone = zoneFromISOOffset(isoTimestamp) { return zone }
        return .current
    }

    // Common zone abbreviations that TimeZone(abbreviation:) does not know.
    private static let extraZoneAbbreviations: [String: TimeZone] = [
        "PT": TimeZone(identifier: "America/Los_Angeles"),
        "MT": TimeZone(identifier: "America/Denver"),
        "CT": TimeZone(identifier: "America/Chicago"),
        "ET": TimeZone(identifier: "America/New_York"),
        "CEST": TimeZone(identifier: "Europe/Amsterdam"),
        "CET": TimeZone(identifier: "Europe/Amsterdam"),
        "BST": TimeZone(identifier: "Europe/London")
    ].compactMapValues { $0 }

    private static func zoneFromISOOffset(_ value: String) -> TimeZone? {
        if value.hasSuffix("Z") || value.hasSuffix("z") { return TimeZone(identifier: "UTC") }
        guard let match = value.range(
            of: #"([+-])(\d{2}):?(\d{2})$"#, options: .regularExpression
        ) else { return nil }
        let offset = value[match]
        let sign = offset.hasPrefix("-") ? -1 : 1
        let digits = offset.dropFirst().filter(\.isNumber)
        guard digits.count == 4,
              let hours = Int(digits.prefix(2)),
              let minutes = Int(digits.suffix(2)) else { return nil }
        return TimeZone(secondsFromGMT: sign * (hours * 3600 + minutes * 60))
    }

    private static func parseISO(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }

    private static func format(_ date: Date, zone: String?) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale.current
        if let zone, let resolved = TimeZone(identifier: zone) ?? TimeZone(abbreviation: zone.uppercased()) {
            formatter.timeZone = resolved
        }
        formatter.setLocalizedDateFormatFromTemplate("EEE d MMM HH:mm")
        return formatter.string(from: date)
    }
}

enum ClaudeAppScanner {
    private struct CachedConversation {
        let id: String
        let title: String
    }

    private struct VisibleChats {
        var titles: [String: String] = [:]
        var recencyRanks: [String: Int] = [:]
    }

    private static let bundleIdentifier = "com.anthropic.claudefordesktop"
    private static let chatPattern = #"/chat/([0-9a-fA-F-]{36})"#
    private static let limitPattern = #"chat_conversations/([0-9a-fA-F-]{36})/completion.*?\\"resetsAt\\":(\d+)"#
    private static let storedTitleKey = "claudeAppConversationTitles"

    static func scan() -> ClaudeAppScanResult {
        let trusted = AXIsProcessTrusted()
        let runningApp = NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).first
        let limit = latestLimit()
        var titles: [String: String] = [:]
        var recencyRanks: [String: Int] = [:]
        let cachedConversations = indexedDBConversations()
        for (rank, conversation) in cachedConversations.enumerated() {
            titles[conversation.id] = conversation.title
            recencyRanks[conversation.id] = rank
        }
        if titles.isEmpty, trusted, let runningApp {
            let visible = visibleChatTitles(
                processIdentifier: runningApp.processIdentifier,
                triggeringChatID: limit?.chatID
            )
            titles = visible.titles
            recencyRanks = visible.recencyRanks
        }

        var storedTitles = storedConversationTitles().filter { isConversationID($0.key) && isRealChatTitle($0.value) }
        for (id, title) in titles where isConversationID(id) && isRealChatTitle(title) {
            storedTitles[id] = normalizedChatTitle(title)
        }
        if let triggerID = limit?.chatID {
            if titles[triggerID] == nil, let storedTitle = storedTitles[triggerID] {
                titles[triggerID] = storedTitle
            } else if let visibleTitle = titles[triggerID], isRealChatTitle(visibleTitle) {
                let normalized = normalizedChatTitle(visibleTitle)
                titles[triggerID] = normalized
                storedTitles[triggerID] = normalized
            } else {
                titles.removeValue(forKey: triggerID)
            }
            if let triggerTitle = titles[triggerID] {
                let duplicateIDs = titles.compactMap { id, title in
                    id.hasPrefix("title:") && title.caseInsensitiveCompare(triggerTitle) == .orderedSame ? id : nil
                }
                if let duplicateRank = duplicateIDs.compactMap({ recencyRanks[$0] }).min() {
                    recencyRanks[triggerID] = duplicateRank
                } else if recencyRanks[triggerID] == nil {
                    recencyRanks[triggerID] = -1
                }
                for duplicateID in duplicateIDs {
                    titles.removeValue(forKey: duplicateID)
                    recencyRanks.removeValue(forKey: duplicateID)
                }
            }
        }
        saveConversationTitles(storedTitles)

        var chats = titles.map { id, title in
            ClaudeAppChat(
                id: id,
                title: title,
                resetDate: limit?.resetDate,
                conversationID: id.hasPrefix("title:") ? nil : id,
                recencyRank: recencyRanks[id] ?? .max
            )
        }
        if let triggerID = limit?.chatID,
           !chats.contains(where: { $0.conversationID == triggerID }) {
            chats.append(ClaudeAppChat(
                id: triggerID,
                title: L("Huidige Claude App-chat"),
                resetDate: limit?.resetDate,
                conversationID: triggerID,
                recencyRank: -1
            ))
        }
        return ClaudeAppScanResult(
            chats: chats,
            resetDate: limit?.resetDate,
            triggeringChatID: limit?.chatID,
            accessibilityTrusted: trusted,
            appRunning: runningApp != nil
        )
    }

    private static func latestLimit() -> (chatID: String, resetDate: Date)? {
        let logURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/Claude/claude.ai-web.log")
        guard let handle = try? FileHandle(forReadingFrom: logURL) else { return nil }
        defer { try? handle.close() }
        let end = (try? handle.seekToEnd()) ?? 0
        let maxBytes: UInt64 = 4 * 1_024 * 1_024
        try? handle.seek(toOffset: end > maxBytes ? end - maxBytes : 0)
        guard let data = try? handle.readToEnd(),
              let text = String(data: data, encoding: .utf8),
              let regex = try? NSRegularExpression(pattern: limitPattern) else { return nil }
        let matches = regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
        let now = Date()
        for match in matches.reversed() {
            guard let idRange = Range(match.range(at: 1), in: text),
                  let timeRange = Range(match.range(at: 2), in: text),
                  let epoch = TimeInterval(text[timeRange]) else { continue }
            let resetDate = Date(timeIntervalSince1970: epoch)
            guard resetDate.timeIntervalSince(now) > -86_400,
                  resetDate.timeIntervalSince(now) < 8 * 86_400 else { continue }
            return (String(text[idRange]), resetDate)
        }
        return nil
    }

    private static func visibleChatTitles(processIdentifier: pid_t, triggeringChatID: String?) -> VisibleChats {
        let root = AXUIElementCreateApplication(processIdentifier)
        AXUIElementSetMessagingTimeout(root, 5)
        AXUIElementSetAttributeValue(root, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(root, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
        let windowFrame = primaryWindow(of: root).flatMap(frame)
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()
        var chats: [String: String] = [:]
        var recencyRanks: [String: Int] = [:]
        var sidebarCandidates: [(title: String, frame: CGRect)] = []

        while index < queue.count, visited.count < 12_000 {
            let element = queue[index]
            index += 1
            let hash = CFHash(element)
            guard visited.insert(hash).inserted else { continue }

            if let rawURL = stringAttribute(kAXURLAttribute as CFString, element: element),
               let chatID = chatID(in: rawURL),
               let title = directLabel(element), isRealChatTitle(title) {
                chats[chatID] = normalizedChatTitle(title)
            }
            if let role = stringAttribute(kAXRoleAttribute as CFString, element: element),
               [kAXStaticTextRole as String, "AXLink", kAXButtonRole as String].contains(role),
               let title = directLabel(element), let elementFrame = frame(element),
               isUsefulLabel(title) {
                sidebarCandidates.append((title, elementFrame))
            }
            queue.append(contentsOf: childElements(element))
        }

        if let windowFrame {
            let pinnedLabels = Set(["pinned", "vastgezet", "fijados", "épinglés", "angeheftet", "fixados", "置顶", "закрепленные"])
            let recentLabels = Set(["recents", "recent", "recientes", "récents", "zuletzt", "recentes", "最近", "недавние"])
            let pinnedY = sidebarCandidates.first(where: { pinnedLabels.contains($0.title.lowercased()) })?.frame.minY
            let recentsY = sidebarCandidates.first(where: { recentLabels.contains($0.title.lowercased()) })?.frame.minY
            let startY = recentsY ?? pinnedY ?? (windowFrame.minY + 180)
            let endY = windowFrame.maxY - 135
            let ignored = Set([
                "home", "code", "new", "projects", "artifacts", "scheduled", "dispatch", "customize",
                "design", "relaunch to update", "beta"
            ]).union(pinnedLabels).union(recentLabels)
            if let triggeringChatID,
               let current = sidebarCandidates.first(where: { sidebar in
                   sidebar.frame.midX < windowFrame.minX + 480 &&
                   sidebar.frame.minY > startY &&
                   sidebar.frame.maxY < endY &&
                   sidebarCandidates.contains(where: { main in
                       main.title == sidebar.title &&
                       main.frame.midX >= windowFrame.minX + 480 &&
                       main.frame.minY < windowFrame.minY + 190
                   })
               }) {
                chats[triggeringChatID] = normalizedChatTitle(current.title)
            }
            let recentCandidates = sidebarCandidates.filter { candidate in
                let title = candidate.title.trimmingCharacters(in: .whitespacesAndNewlines)
                let lower = title.lowercased()
                return candidate.frame.midX < windowFrame.minX + 480 &&
                    candidate.frame.minY > startY && candidate.frame.maxY < endY &&
                    !ignored.contains(lower) && !lower.hasPrefix("v1.") && isRealChatTitle(title)
            }
            .sorted {
                if abs($0.frame.minY - $1.frame.minY) > 1 { return $0.frame.minY < $1.frame.minY }
                return $0.frame.minX < $1.frame.minX
            }

            for candidate in recentCandidates {
                let title = candidate.title.trimmingCharacters(in: .whitespacesAndNewlines)
                let normalized = normalizedChatTitle(title)
                let rank = recencyRanks.count
                if let existingID = chats.first(where: { $0.value.caseInsensitiveCompare(normalized) == .orderedSame })?.key {
                    recencyRanks[existingID] = min(recencyRanks[existingID] ?? .max, rank)
                } else {
                    let id = "title:\(stableIdentifier(normalized))"
                    chats[id] = normalized
                    recencyRanks[id] = rank
                }
            }
        }
        return VisibleChats(titles: chats, recencyRanks: recencyRanks)
    }

    private static func storedConversationTitles() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: storedTitleKey) as? [String: String] ?? [:]
    }

    private static func saveConversationTitles(_ titles: [String: String]) {
        let valid = titles.filter { isConversationID($0.key) && isRealChatTitle($0.value) }
        UserDefaults.standard.set(valid, forKey: storedTitleKey)
    }

    private static func indexedDBConversations() -> [CachedConversation] {
        guard let wireData = indexedDBWireData() else { return [] }
        return conversationRecords(in: wireData)
    }

    static func indexedDBWireData() -> Data? {
        let blobRoot = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Claude/IndexedDB/https_claude.ai_0.indexeddb.blob", isDirectory: true)
        let keys: Set<URLResourceKey> = [.contentModificationDateKey, .fileSizeKey, .isRegularFileKey]
        guard let enumerator = FileManager.default.enumerator(
            at: blobRoot,
            includingPropertiesForKeys: Array(keys),
            options: [.skipsHiddenFiles]
        ) else { return nil }

        var candidates: [(url: URL, date: Date)] = []
        for case let url as URL in enumerator {
            guard let values = try? url.resourceValues(forKeys: keys),
                  values.isRegularFile == true,
                  let date = values.contentModificationDate,
                  let size = values.fileSize,
                  size > 3, size <= 24 * 1_024 * 1_024 else { continue }
            candidates.append((url, date))
        }

        for candidate in candidates.sorted(by: { $0.date > $1.date }).prefix(4) {
            guard let data = try? Data(contentsOf: candidate.url, options: [.mappedIfSafe]) else { continue }
            if data.count >= 3, data[data.startIndex] == 0xFF,
               data[data.startIndex + 1] == 0x11, data[data.startIndex + 2] == 0x02 {
                guard let expanded = snappyUncompress(data.dropFirst(3)) else { continue }
                return expanded
            } else {
                return data
            }
        }
        return nil
    }

    private static func snappyUncompress(_ compressed: Data.SubSequence) -> Data? {
        let input = Array(compressed)
        var index = 0
        guard let expectedValue = readVarint(input, index: &index),
              expectedValue > 0, expectedValue <= 64 * 1_024 * 1_024 else { return nil }
        let expected = Int(expectedValue)
        var output: [UInt8] = []
        output.reserveCapacity(expected)

        while index < input.count, output.count < expected {
            let tag = input[index]
            index += 1
            let type = tag & 0x03
            if type == 0 {
                let encodedLength = Int(tag >> 2)
                let length: Int
                if encodedLength < 60 {
                    length = encodedLength + 1
                } else {
                    let byteCount = encodedLength - 59
                    guard byteCount > 0, byteCount <= 4, index + byteCount <= input.count else { return nil }
                    var value = 0
                    for offset in 0..<byteCount { value |= Int(input[index + offset]) << (8 * offset) }
                    index += byteCount
                    length = value + 1
                }
                guard length >= 0, index + length <= input.count, output.count + length <= expected else { return nil }
                output.append(contentsOf: input[index..<(index + length)])
                index += length
                continue
            }

            let length: Int
            let offset: Int
            if type == 1 {
                guard index < input.count else { return nil }
                length = 4 + Int((tag >> 2) & 0x07)
                offset = (Int(tag & 0xE0) << 3) | Int(input[index])
                index += 1
            } else if type == 2 {
                guard index + 2 <= input.count else { return nil }
                length = 1 + Int(tag >> 2)
                offset = Int(input[index]) | (Int(input[index + 1]) << 8)
                index += 2
            } else {
                guard index + 4 <= input.count else { return nil }
                length = 1 + Int(tag >> 2)
                offset = Int(input[index]) | (Int(input[index + 1]) << 8) |
                    (Int(input[index + 2]) << 16) | (Int(input[index + 3]) << 24)
                index += 4
            }
            guard offset > 0, offset <= output.count, output.count + length <= expected else { return nil }
            for _ in 0..<length { output.append(output[output.count - offset]) }
        }
        guard output.count == expected else { return nil }
        return Data(output)
    }

    static func readVarint(_ bytes: [UInt8], index: inout Int) -> UInt64? {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        while index < bytes.count, shift < 64 {
            let byte = bytes[index]
            index += 1
            value |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return value }
            shift += 7
        }
        return nil
    }

    private static func conversationRecords(in data: Data) -> [CachedConversation] {
        let bytes = Array(data)
        let uuidPrefix = [UInt8](arrayLiteral: 0x22, 0x04) + Array("uuid".utf8) + [0x22, 0x24]
        let namePrefix = [UInt8](arrayLiteral: 0x22, 0x04) + Array("name".utf8)
        let summaryPrefix = [UInt8](arrayLiteral: 0x22, 0x07) + Array("summary".utf8)
        var index = 0
        var seen = Set<String>()
        var conversations: [CachedConversation] = []

        while index + uuidPrefix.count + 36 < bytes.count {
            guard matches(uuidPrefix, in: bytes, at: index) else {
                index += 1
                continue
            }
            var cursor = index + uuidPrefix.count
            guard cursor + 36 <= bytes.count,
                  let id = String(bytes: bytes[cursor..<(cursor + 36)], encoding: .ascii),
                  isConversationID(id) else {
                index += 1
                continue
            }
            cursor += 36
            guard matches(namePrefix, in: bytes, at: cursor) else {
                index += 1
                continue
            }
            cursor += namePrefix.count
            guard cursor < bytes.count else { break }
            let stringTag = bytes[cursor]
            cursor += 1
            guard let lengthValue = readVarint(bytes, index: &cursor),
                  lengthValue <= 2_048 else {
                index += 1
                continue
            }
            let length = Int(lengthValue)
            guard cursor + length <= bytes.count else { break }
            let raw = Array(bytes[cursor..<(cursor + length)])
            let title: String?
            if stringTag == 0x22 {
                title = String(bytes: raw, encoding: .isoLatin1)
            } else if stringTag == 0x53 {
                title = String(bytes: raw, encoding: .utf8)
            } else if stringTag == 0x63, raw.count.isMultiple(of: 2) {
                var units: [UInt16] = []
                units.reserveCapacity(raw.count / 2)
                for offset in stride(from: 0, to: raw.count, by: 2) {
                    units.append(UInt16(raw[offset]) | (UInt16(raw[offset + 1]) << 8))
                }
                title = String(decoding: units, as: UTF16.self)
            } else {
                title = nil
            }
            cursor += length
            guard matches(summaryPrefix, in: bytes, at: cursor),
                  let title, isRealChatTitle(title), seen.insert(id).inserted else {
                index += 1
                continue
            }
            conversations.append(CachedConversation(id: id, title: normalizedChatTitle(title)))
            index = cursor + summaryPrefix.count
        }
        return Array(conversations.prefix(100))
    }

    private static func matches(_ pattern: [UInt8], in bytes: [UInt8], at index: Int) -> Bool {
        guard index >= 0, index + pattern.count <= bytes.count else { return false }
        for offset in pattern.indices where bytes[index + offset] != pattern[offset] { return false }
        return true
    }

    private static func isConversationID(_ value: String) -> Bool {
        guard value.count == 36,
              let regex = try? NSRegularExpression(pattern: #"^[0-9a-fA-F-]{36}$"#) else { return false }
        return regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) != nil
    }

    private static func isRealChatTitle(_ value: String) -> Bool {
        let clean = normalizedChatTitle(value)
        let ignored = Set([
            "claude", "copy", "kopiëren", "kopieren", "share", "delen", "delete", "verwijderen",
            "edit", "bewerken", "more", "meer", "open", "close", "sluiten", "retry", "opnieuw",
            "download", "menu", "options", "opties", "rename", "hernoemen"
        ])
        return isUsefulLabel(clean) && clean.caseInsensitiveCompare("Claude") != .orderedSame &&
            !clean.lowercased().hasPrefix("claude app-chat ") && !ignored.contains(clean.lowercased())
    }

    private static func normalizedChatTitle(_ value: String) -> String {
        var clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.hasSuffix(" - Claude") { clean.removeLast(" - Claude".count) }
        return clean.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func stableIdentifier(_ value: String) -> String {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return String(hash, radix: 16)
    }

    private static func chatID(in value: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: chatPattern),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
              let range = Range(match.range(at: 1), in: value) else { return nil }
        return String(value[range])
    }

    private static func directLabel(_ element: AXUIElement) -> String? {
        for attribute in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute] {
            if let value = stringAttribute(attribute as CFString, element: element), isUsefulLabel(value) {
                return value
            }
        }
        return nil
    }

    private static func isUsefulLabel(_ value: String) -> Bool {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return !clean.isEmpty && clean.count <= 180 && !clean.contains("/chat/") && clean.lowercased() != "link"
    }

    private static func stringAttribute(_ name: CFString, element: AXUIElement) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, name, &value) == .success,
              let value else { return nil }
        if let string = value as? String { return string }
        if let url = value as? URL { return url.absoluteString }
        return nil
    }

    private static func focusedWindow(of application: AXUIElement) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(application, kAXFocusedWindowAttribute as CFString, &value) == .success,
              let value else { return nil }
        return unsafeBitCast(value, to: AXUIElement.self)
    }

    private static func primaryWindow(of application: AXUIElement) -> AXUIElement? {
        if let focused = focusedWindow(of: application) { return focused }
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(application, kAXWindowsAttribute as CFString, &value) == .success,
              let windows = value as? [AXUIElement] else { return nil }
        return windows.first(where: { frame($0) != nil }) ?? windows.first
    }

    private static func frame(_ element: AXUIElement) -> CGRect? {
        var positionValue: CFTypeRef?
        var sizeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &positionValue) == .success,
              AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &sizeValue) == .success,
              let positionValue, let sizeValue,
              CFGetTypeID(positionValue) == AXValueGetTypeID(),
              CFGetTypeID(sizeValue) == AXValueGetTypeID() else { return nil }
        var point = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(unsafeBitCast(positionValue, to: AXValue.self), .cgPoint, &point),
              AXValueGetValue(unsafeBitCast(sizeValue, to: AXValue.self), .cgSize, &size) else { return nil }
        return CGRect(origin: point, size: size)
    }

    private static func childElements(_ element: AXUIElement) -> [AXUIElement] {
        var combined: [AXUIElement] = []
        for attribute in [kAXChildrenAttribute, kAXWindowsAttribute, kAXVisibleChildrenAttribute] {
            var value: CFTypeRef?
            if AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success,
               let children = value as? [AXUIElement] {
                combined.append(contentsOf: children)
            }
        }
        return combined
    }
}

enum ClaudeAppCodeScanner {
    private struct CachedCodeSession {
        let id: String
        let title: String
        let updatedAt: Date?
        let sourceOffset: Int
    }

    private static let bundleIdentifier = "com.anthropic.claudefordesktop"
    private static let storedKey = "claudeAppCodeVisibleSessions"

    static func scan(resetDate: Date?) -> [ClaudeAppCodeSession] {
        let records = cachedCodeSessions()
        if AXIsProcessTrusted(),
           let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).first {
            let titles = visibleCodeSessionTitles(
                processIdentifier: app.processIdentifier,
                knownTitles: Set(records.map { $0.title.lowercased() })
            )
            if !titles.isEmpty {
                let sessions = mapVisibleTitles(titles, to: records, resetDate: resetDate)
                save(sessions)
                return sessions
            }
        }
        return storedSessions(resetDate: resetDate)
    }

    private static func cachedCodeSessions() -> [CachedCodeSession] {
        guard let data = ClaudeAppScanner.indexedDBWireData() else { return [] }
        let bytes = Array(data)
        let recordPrefix = [UInt8](arrayLiteral: 0x22, 0x04) + Array("type".utf8) +
            [0x22, 0x07] + Array("session".utf8) + [0x22, 0x02] + Array("id".utf8)
        let titlePrefix = [UInt8](arrayLiteral: 0x22, 0x05) + Array("title".utf8)
        let updatedPrefix = [UInt8](arrayLiteral: 0x22, 0x0A) + Array("updated_at".utf8)
        var index = 0
        var records: [String: CachedCodeSession] = [:]

        while index + recordPrefix.count < bytes.count {
            guard matches(recordPrefix, in: bytes, at: index) else {
                index += 1
                continue
            }
            var cursor = index + recordPrefix.count
            guard let id = readSerializedString(bytes, index: &cursor),
                  id.hasPrefix("session_"),
                  matches(titlePrefix, in: bytes, at: cursor) else {
                index += 1
                continue
            }
            cursor += titlePrefix.count
            guard let title = readSerializedString(bytes, index: &cursor),
                  !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                index += 1
                continue
            }
            let recordEnd = min(bytes.count, cursor + 5_000)
            var updatedAt: Date?
            if let updatedIndex = firstIndex(of: updatedPrefix, in: bytes, range: cursor..<recordEnd) {
                var valueIndex = updatedIndex + updatedPrefix.count
                if let value = readSerializedString(bytes, index: &valueIndex) {
                    updatedAt = parseISO(value)
                }
            }
            let record = CachedCodeSession(id: id, title: title, updatedAt: updatedAt, sourceOffset: index)
            if let existing = records[id] {
                if (record.updatedAt ?? .distantPast) > (existing.updatedAt ?? .distantPast) {
                    records[id] = record
                }
            } else {
                records[id] = record
            }
            index = cursor
        }
        return records.values.sorted {
            if ($0.updatedAt ?? .distantPast) != ($1.updatedAt ?? .distantPast) {
                return ($0.updatedAt ?? .distantPast) > ($1.updatedAt ?? .distantPast)
            }
            return $0.sourceOffset < $1.sourceOffset
        }
    }

    private static func visibleCodeSessionTitles(processIdentifier: pid_t, knownTitles: Set<String>) -> [String] {
        guard !knownTitles.isEmpty else { return [] }
        let application = AXUIElementCreateApplication(processIdentifier)
        AXUIElementSetMessagingTimeout(application, 5)
        AXUIElementSetAttributeValue(application, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(application, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
        let root = focusedWindow(of: application) ?? application
        let windowFrame = frame(of: root)
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()
        var candidates: [(title: String, frame: CGRect)] = []

        while index < queue.count, visited.count < 16_000 {
            let element = queue[index]
            index += 1
            guard visited.insert(CFHash(element)).inserted else { continue }
            if stringAttribute(kAXRoleAttribute as CFString, element: element) == (kAXButtonRole as String),
               let title = directLabel(element)?.trimmingCharacters(in: .whitespacesAndNewlines),
               let elementFrame = frame(of: element),
               windowFrame.map({ elementFrame.midX < $0.minX + 480 }) ?? true {
                if knownTitles.contains(title.lowercased()) {
                    candidates.append((title, elementFrame))
                }
            }
            queue.append(contentsOf: childElements(element))
        }
        guard !candidates.isEmpty else { return [] }
        return candidates.sorted {
            if abs($0.frame.minY - $1.frame.minY) > 1 { return $0.frame.minY < $1.frame.minY }
            return $0.frame.minX < $1.frame.minX
        }.map(\.title)
    }

    private static func mapVisibleTitles(
        _ titles: [String],
        to records: [CachedCodeSession],
        resetDate: Date?
    ) -> [ClaudeAppCodeSession] {
        let recordsByTitle = Dictionary(grouping: records, by: { $0.title.lowercased() })
        var occurrences: [String: Int] = [:]
        return titles.enumerated().map { rank, title in
            let key = title.lowercased()
            let occurrence = occurrences[key, default: 0]
            occurrences[key] = occurrence + 1
            let matching = recordsByTitle[key] ?? []
            let record = matching.indices.contains(occurrence) ? matching[occurrence] : nil
            let id = record?.id ?? "visible:\(stableIdentifier(title)):\(occurrence)"
            return ClaudeAppCodeSession(
                id: id,
                title: title,
                titleOccurrence: occurrence,
                resetDate: resetDate,
                recencyRank: rank
            )
        }
    }

    private static func save(_ sessions: [ClaudeAppCodeSession]) {
        let rows: [[String: Any]] = sessions.map {
            ["id": $0.id, "title": $0.title, "occurrence": $0.titleOccurrence, "rank": $0.recencyRank]
        }
        UserDefaults.standard.set(rows, forKey: storedKey)
    }

    private static func storedSessions(resetDate: Date?) -> [ClaudeAppCodeSession] {
        guard let rows = UserDefaults.standard.array(forKey: storedKey) as? [[String: Any]] else { return [] }
        return rows.compactMap { row in
            guard let id = row["id"] as? String, let title = row["title"] as? String else { return nil }
            return ClaudeAppCodeSession(
                id: id,
                title: title,
                titleOccurrence: (row["occurrence"] as? NSNumber)?.intValue ?? 0,
                resetDate: resetDate,
                recencyRank: (row["rank"] as? NSNumber)?.intValue ?? .max
            )
        }
    }

    private static func readSerializedString(_ bytes: [UInt8], index: inout Int) -> String? {
        guard index < bytes.count else { return nil }
        let tag = bytes[index]
        index += 1
        guard let lengthValue = ClaudeAppScanner.readVarint(bytes, index: &index), lengthValue <= 16_384 else { return nil }
        let length = Int(lengthValue)
        guard index + length <= bytes.count else { return nil }
        let raw = Array(bytes[index..<(index + length)])
        index += length
        if tag == 0x22 { return String(bytes: raw, encoding: .isoLatin1) }
        if tag == 0x53 { return String(bytes: raw, encoding: .utf8) }
        if tag == 0x63, raw.count.isMultiple(of: 2) {
            var units: [UInt16] = []
            units.reserveCapacity(raw.count / 2)
            for offset in stride(from: 0, to: raw.count, by: 2) {
                units.append(UInt16(raw[offset]) | (UInt16(raw[offset + 1]) << 8))
            }
            return String(decoding: units, as: UTF16.self)
        }
        return nil
    }

    private static func firstIndex(of pattern: [UInt8], in bytes: [UInt8], range: Range<Int>) -> Int? {
        guard !pattern.isEmpty, range.lowerBound >= 0, range.upperBound <= bytes.count else { return nil }
        var index = range.lowerBound
        while index + pattern.count <= range.upperBound {
            if matches(pattern, in: bytes, at: index) { return index }
            index += 1
        }
        return nil
    }

    private static func matches(_ pattern: [UInt8], in bytes: [UInt8], at index: Int) -> Bool {
        guard index >= 0, index + pattern.count <= bytes.count else { return false }
        for offset in pattern.indices where bytes[index + offset] != pattern[offset] { return false }
        return true
    }

    private static func parseISO(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }

    private static func stableIdentifier(_ value: String) -> String {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return String(hash, radix: 16)
    }

    private static func directLabel(_ element: AXUIElement) -> String? {
        for attribute in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute] {
            if let value = stringAttribute(attribute as CFString, element: element),
               !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
               value.count <= 180 {
                return value
            }
        }
        return nil
    }

    private static func stringAttribute(_ name: CFString, element: AXUIElement) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, name, &value) == .success else { return nil }
        return value as? String
    }

    private static func focusedWindow(of application: AXUIElement) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(application, kAXFocusedWindowAttribute as CFString, &value) == .success,
              let value else { return nil }
        return unsafeBitCast(value, to: AXUIElement.self)
    }

    private static func frame(of element: AXUIElement) -> CGRect? {
        var positionValue: CFTypeRef?
        var sizeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &positionValue) == .success,
              AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &sizeValue) == .success,
              let positionValue, let sizeValue,
              CFGetTypeID(positionValue) == AXValueGetTypeID(),
              CFGetTypeID(sizeValue) == AXValueGetTypeID() else { return nil }
        var point = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(unsafeBitCast(positionValue, to: AXValue.self), .cgPoint, &point),
              AXValueGetValue(unsafeBitCast(sizeValue, to: AXValue.self), .cgSize, &size) else { return nil }
        return CGRect(origin: point, size: size)
    }

    private static func childElements(_ element: AXUIElement) -> [AXUIElement] {
        var combined: [AXUIElement] = []
        for attribute in [kAXChildrenAttribute, kAXWindowsAttribute, kAXVisibleChildrenAttribute] {
            var value: CFTypeRef?
            if AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success,
               let children = value as? [AXUIElement] {
                combined.append(contentsOf: children)
            }
        }
        return combined
    }
}

enum ClaudeAppAutomation {
    private static let bundleIdentifier = "com.anthropic.claudefordesktop"
    static let operationLock = NSLock()

    static func openAndSubmit(chat: ClaudeAppChat, prompt: String) -> ResumeResult {
        operationLock.lock()
        defer { operationLock.unlock() }

        guard AXIsProcessTrusted() else {
            return ResumeResult(succeeded: false, message: L("Toegankelijkheidstoegang is nodig voor Claude App"))
        }
        guard FileManager.default.fileExists(atPath: "/Applications/Claude.app") else {
            return ResumeResult(succeeded: false, message: L("Claude App is niet gevonden in Apps"))
        }
        if let conversationID = chat.conversationID {
            guard let url = URL(string: "claude://claude.ai/chat/\(conversationID)"),
                  NSWorkspace.shared.open(url) else {
                return ResumeResult(succeeded: false, message: L("Kon de Claude App-chat niet openen"))
            }
        } else {
            guard NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/Claude.app")) else {
                return ResumeResult(succeeded: false, message: L("Kon Claude App niet openen"))
            }
        }

        Thread.sleep(forTimeInterval: 2.5)
        guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).first else {
            return ResumeResult(succeeded: false, message: L("Claude App is niet gestart"))
        }
        app.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])

        if chat.conversationID == nil {
            var chatElement: AXUIElement?
            for _ in 0..<6 {
                chatElement = findChatElement(titled: chat.title, processIdentifier: app.processIdentifier)
                if chatElement != nil { break }
                Thread.sleep(forTimeInterval: 0.8)
            }
            guard let chatElement else {
                return ResumeResult(succeeded: false, message: LF("Kon ‘%@’ niet terugvinden in Claude Recents", chat.title))
            }
            focusAndClick(chatElement)
            Thread.sleep(forTimeInterval: 1.5)
        }

        var composer: AXUIElement?
        for _ in 0..<6 {
            composer = findComposer(processIdentifier: app.processIdentifier)
            if composer != nil { break }
            Thread.sleep(forTimeInterval: 0.8)
        }
        guard let composer else {
            return ResumeResult(succeeded: false, message: LF("Kon het invoerveld van ‘%@’ niet vinden", chat.title))
        }
        focusAndClick(composer)
        Thread.sleep(forTimeInterval: 0.25)
        guard replaceText(in: composer, with: prompt),
              submitMessage(processIdentifier: app.processIdentifier, composer: composer, prompt: prompt) else {
            return ResumeResult(succeeded: false, message: L("Kon het hervatbericht niet in Claude App versturen"))
        }
        return ResumeResult(succeeded: true, message: LF("Claude App-chat ‘%@’ is hervat", chat.title))
    }

    private static func findChatElement(titled title: String, processIdentifier: pid_t) -> AXUIElement? {
        let application = AXUIElementCreateApplication(processIdentifier)
        AXUIElementSetMessagingTimeout(application, 5)
        AXUIElementSetAttributeValue(application, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        let root = focusedWindow(of: application) ?? application
        let windowFrame = frame(of: root)
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()

        while index < queue.count, visited.count < 12_000 {
            let element = queue[index]
            index += 1
            guard visited.insert(CFHash(element)).inserted else { continue }
            if let label = directLabel(element),
               label.trimmingCharacters(in: .whitespacesAndNewlines) == title,
               let elementFrame = frame(of: element),
               windowFrame.map({ elementFrame.midX < $0.minX + 480 }) ?? true {
                return element
            }
            queue.append(contentsOf: childElements(element))
        }
        return nil
    }

    static func findComposer(processIdentifier: pid_t) -> AXUIElement? {
        let application = AXUIElementCreateApplication(processIdentifier)
        AXUIElementSetMessagingTimeout(application, 5)
        AXUIElementSetAttributeValue(application, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(application, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
        let root = focusedWindow(of: application) ?? application
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()
        var candidates: [(element: AXUIElement, frame: CGRect)] = []

        while index < queue.count, visited.count < 12_000 {
            let element = queue[index]
            index += 1
            let hash = CFHash(element)
            guard visited.insert(hash).inserted else { continue }
            if let role = stringAttribute(kAXRoleAttribute as CFString, element: element),
               role == (kAXTextAreaRole as String) || role == (kAXTextFieldRole as String),
               let frame = frame(of: element), frame.width >= 240, frame.height >= 18 {
                candidates.append((element, frame))
            }
            queue.append(contentsOf: childElements(element))
        }
        return candidates.max { left, right in
            if abs(left.frame.maxY - right.frame.maxY) > 5 { return left.frame.maxY < right.frame.maxY }
            return left.frame.width < right.frame.width
        }?.element
    }

    private static func focusedWindow(of application: AXUIElement) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(application, kAXFocusedWindowAttribute as CFString, &value) == .success,
              let value else { return nil }
        return unsafeBitCast(value, to: AXUIElement.self)
    }

    static func focusAndClick(_ element: AXUIElement) {
        AXUIElementSetAttributeValue(element, kAXFocusedAttribute as CFString, kCFBooleanTrue)
        guard let frame = frame(of: element),
              let source = CGEventSource(stateID: .hidSystemState) else { return }
        let point = CGPoint(x: frame.midX, y: frame.midY)
        let down = CGEvent(mouseEventSource: source, mouseType: .leftMouseDown, mouseCursorPosition: point, mouseButton: .left)
        let up = CGEvent(mouseEventSource: source, mouseType: .leftMouseUp, mouseCursorPosition: point, mouseButton: .left)
        down?.post(tap: .cghidEventTap)
        up?.post(tap: .cghidEventTap)
    }

    private static func frame(of element: AXUIElement) -> CGRect? {
        var positionValue: CFTypeRef?
        var sizeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &positionValue) == .success,
              AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &sizeValue) == .success,
              let positionValue, let sizeValue,
              CFGetTypeID(positionValue) == AXValueGetTypeID(),
              CFGetTypeID(sizeValue) == AXValueGetTypeID() else { return nil }
        var point = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(unsafeBitCast(positionValue, to: AXValue.self), .cgPoint, &point),
              AXValueGetValue(unsafeBitCast(sizeValue, to: AXValue.self), .cgSize, &size) else { return nil }
        return CGRect(origin: point, size: size)
    }

    static func replaceText(in element: AXUIElement, with text: String) -> Bool {
        if AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, text as CFString) == .success {
            Thread.sleep(forTimeInterval: 0.2)
            return true
        }
        return replaceFocusedText(with: text)
    }

    private static func replaceFocusedText(with text: String) -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let selectDown = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
              let selectUp = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false),
              let textDown = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
              let textUp = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false) else { return false }
        selectDown.flags = .maskCommand
        selectUp.flags = .maskCommand
        selectDown.post(tap: .cghidEventTap)
        selectUp.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.1)
        let units = Array(text.utf16)
        units.withUnsafeBufferPointer { buffer in
            textDown.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
            textUp.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
        }
        textDown.post(tap: .cghidEventTap)
        textUp.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.15)
        return true
    }

    static func submitMessage(processIdentifier: pid_t, composer: AXUIElement, prompt: String) -> Bool {
        let composerFrame = frame(of: composer)
        for _ in 0..<8 {
            if let button = findSendButton(processIdentifier: processIdentifier, composerFrame: composerFrame) {
                if AXUIElementPerformAction(button, kAXPressAction as CFString) != .success {
                    focusAndClick(button)
                }
                return waitForSubmittedMessage(processIdentifier: processIdentifier, prompt: prompt)
            }
            Thread.sleep(forTimeInterval: 0.15)
        }
        guard postReturn() else { return false }
        return waitForSubmittedMessage(processIdentifier: processIdentifier, prompt: prompt)
    }

    private static func findSendButton(processIdentifier: pid_t, composerFrame: CGRect?) -> AXUIElement? {
        let application = AXUIElementCreateApplication(processIdentifier)
        AXUIElementSetMessagingTimeout(application, 5)
        AXUIElementSetAttributeValue(application, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        let root = focusedWindow(of: application) ?? application
        let sendLabels = [
            "send message", "verzend bericht", "enviar mensaje", "envoyer le message",
            "nachricht senden", "enviar mensagem", "发送消息", "отправить сообщение"
        ]
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()
        while index < queue.count, visited.count < 12_000 {
            let element = queue[index]
            index += 1
            guard visited.insert(CFHash(element)).inserted else { continue }
            if stringAttribute(kAXRoleAttribute as CFString, element: element) == (kAXButtonRole as String),
               let label = directLabel(element)?.lowercased(),
               sendLabels.contains(where: { label.contains($0) }),
               let buttonFrame = frame(of: element),
               composerFrame.map({
                   buttonFrame.midX > $0.maxX - 100 &&
                   buttonFrame.midY > $0.minY - 25 && buttonFrame.midY < $0.maxY + 90
               }) ?? true {
                return element
            }
            queue.append(contentsOf: childElements(element))
        }
        return nil
    }

    private static func waitForSubmittedMessage(processIdentifier: pid_t, prompt: String) -> Bool {
        let expected = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        for _ in 0..<12 {
            Thread.sleep(forTimeInterval: 0.2)
            guard let currentComposer = findComposer(processIdentifier: processIdentifier),
                  let value = stringAttribute(kAXValueAttribute as CFString, element: currentComposer) else { continue }
            if value.trimmingCharacters(in: .whitespacesAndNewlines) != expected { return true }
        }
        return false
    }

    private static func postReturn() -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false) else { return false }
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }

    private static func stringAttribute(_ name: CFString, element: AXUIElement) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, name, &value) == .success else { return nil }
        return value as? String
    }

    private static func directLabel(_ element: AXUIElement) -> String? {
        for attribute in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute] {
            if let value = stringAttribute(attribute as CFString, element: element),
               !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
               value.count <= 180 {
                return value
            }
        }
        return nil
    }

    private static func childElements(_ element: AXUIElement) -> [AXUIElement] {
        var combined: [AXUIElement] = []
        for attribute in [kAXChildrenAttribute, kAXWindowsAttribute, kAXVisibleChildrenAttribute] {
            var value: CFTypeRef?
            if AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success,
               let children = value as? [AXUIElement] {
                combined.append(contentsOf: children)
            }
        }
        return combined
    }
}

enum ClaudeAppCodeAutomation {
    private static let bundleIdentifier = "com.anthropic.claudefordesktop"

    static func showCodeHome() -> Bool {
        ClaudeAppAutomation.operationLock.lock()
        defer { ClaudeAppAutomation.operationLock.unlock() }
        return showCodeHomeLocked()
    }

    static func openAndSubmit(session: ClaudeAppCodeSession, prompt: String) -> ResumeResult {
        ClaudeAppAutomation.operationLock.lock()
        defer { ClaudeAppAutomation.operationLock.unlock() }

        guard AXIsProcessTrusted() else {
            return ResumeResult(succeeded: false, message: L("Toegankelijkheidstoegang is nodig voor Claude App"))
        }
        guard FileManager.default.fileExists(atPath: "/Applications/Claude.app") else {
            return ResumeResult(succeeded: false, message: L("Claude App is niet gevonden in Apps"))
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/Claude.app"))
        guard showCodeHomeLocked(),
              let app = runningClaudeApp() else {
            return ResumeResult(succeeded: false, message: L("Kon Code in Claude App niet openen"))
        }

        var sessionElement: AXUIElement?
        for _ in 0..<8 {
            sessionElement = findSessionElement(
                titled: session.title,
                occurrence: session.titleOccurrence,
                processIdentifier: app.processIdentifier
            )
            if sessionElement != nil { break }
            Thread.sleep(forTimeInterval: 0.6)
        }
        guard let sessionElement else {
            return ResumeResult(succeeded: false, message: LF("Kon Code-sessie ‘%@’ niet terugvinden in Claude App", session.title))
        }
        ClaudeAppAutomation.focusAndClick(sessionElement)
        Thread.sleep(forTimeInterval: 1.8)

        var composer: AXUIElement?
        for _ in 0..<8 {
            composer = ClaudeAppAutomation.findComposer(processIdentifier: app.processIdentifier)
            if composer != nil { break }
            Thread.sleep(forTimeInterval: 0.6)
        }
        guard let composer else {
            return ResumeResult(succeeded: false, message: LF("Kon het invoerveld van Code-sessie ‘%@’ niet vinden", session.title))
        }
        ClaudeAppAutomation.focusAndClick(composer)
        Thread.sleep(forTimeInterval: 0.25)
        guard ClaudeAppAutomation.replaceText(in: composer, with: prompt),
              ClaudeAppAutomation.submitMessage(
                processIdentifier: app.processIdentifier,
                composer: composer,
                prompt: prompt
              ) else {
            return ResumeResult(succeeded: false, message: L("Kon het hervatbericht niet in Claude App Code versturen"))
        }
        return ResumeResult(succeeded: true, message: LF("Claude App Code-sessie ‘%@’ is hervat", session.title))
    }

    private static func showCodeHomeLocked() -> Bool {
        guard AXIsProcessTrusted() else { return false }
        var app: NSRunningApplication?
        for _ in 0..<10 {
            app = runningClaudeApp()
            if app != nil { break }
            Thread.sleep(forTimeInterval: 0.3)
        }
        guard let app else { return false }
        app.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        for _ in 0..<8 {
            if let button = findCodeButton(processIdentifier: app.processIdentifier) {
                ClaudeAppAutomation.focusAndClick(button)
                Thread.sleep(forTimeInterval: 0.8)
                return true
            }
            Thread.sleep(forTimeInterval: 0.4)
        }
        return false
    }

    private static func runningClaudeApp() -> NSRunningApplication? {
        NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier).first
    }

    private static func findCodeButton(processIdentifier: pid_t) -> AXUIElement? {
        let application = configuredApplication(processIdentifier)
        let root = focusedWindow(of: application) ?? application
        let windowFrame = frame(of: root)
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()
        while index < queue.count, visited.count < 16_000 {
            let element = queue[index]
            index += 1
            guard visited.insert(CFHash(element)).inserted else { continue }
            if stringAttribute(kAXRoleAttribute as CFString, element: element) == (kAXButtonRole as String),
               directLabel(element)?.caseInsensitiveCompare("Code") == .orderedSame,
               let elementFrame = frame(of: element),
               windowFrame.map({
                   elementFrame.midX < $0.minX + 480 && elementFrame.maxY < $0.minY + 210
               }) ?? true {
                return element
            }
            queue.append(contentsOf: childElements(element))
        }
        return nil
    }

    private static func findSessionElement(
        titled title: String,
        occurrence: Int,
        processIdentifier: pid_t
    ) -> AXUIElement? {
        let application = configuredApplication(processIdentifier)
        let root = focusedWindow(of: application) ?? application
        let windowFrame = frame(of: root)
        var queue = [root]
        var index = 0
        var visited = Set<CFHashCode>()
        var candidates: [(element: AXUIElement, frame: CGRect)] = []
        while index < queue.count, visited.count < 16_000 {
            let element = queue[index]
            index += 1
            guard visited.insert(CFHash(element)).inserted else { continue }
            if stringAttribute(kAXRoleAttribute as CFString, element: element) == (kAXButtonRole as String),
               directLabel(element)?.trimmingCharacters(in: .whitespacesAndNewlines) == title,
               let elementFrame = frame(of: element),
               windowFrame.map({ elementFrame.midX < $0.minX + 480 }) ?? true {
                candidates.append((element, elementFrame))
            }
            queue.append(contentsOf: childElements(element))
        }
        let sorted = candidates.sorted { $0.frame.minY < $1.frame.minY }
        guard sorted.indices.contains(occurrence) else { return nil }
        return sorted[occurrence].element
    }

    private static func configuredApplication(_ processIdentifier: pid_t) -> AXUIElement {
        let application = AXUIElementCreateApplication(processIdentifier)
        AXUIElementSetMessagingTimeout(application, 5)
        AXUIElementSetAttributeValue(application, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(application, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
        return application
    }

    private static func directLabel(_ element: AXUIElement) -> String? {
        for attribute in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute] {
            if let value = stringAttribute(attribute as CFString, element: element),
               !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
               value.count <= 180 {
                return value
            }
        }
        return nil
    }

    private static func stringAttribute(_ name: CFString, element: AXUIElement) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, name, &value) == .success else { return nil }
        return value as? String
    }

    private static func focusedWindow(of application: AXUIElement) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(application, kAXFocusedWindowAttribute as CFString, &value) == .success,
              let value else { return nil }
        return unsafeBitCast(value, to: AXUIElement.self)
    }

    private static func frame(of element: AXUIElement) -> CGRect? {
        var positionValue: CFTypeRef?
        var sizeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &positionValue) == .success,
              AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &sizeValue) == .success,
              let positionValue, let sizeValue,
              CFGetTypeID(positionValue) == AXValueGetTypeID(),
              CFGetTypeID(sizeValue) == AXValueGetTypeID() else { return nil }
        var point = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(unsafeBitCast(positionValue, to: AXValue.self), .cgPoint, &point),
              AXValueGetValue(unsafeBitCast(sizeValue, to: AXValue.self), .cgSize, &size) else { return nil }
        return CGRect(origin: point, size: size)
    }

    private static func childElements(_ element: AXUIElement) -> [AXUIElement] {
        var combined: [AXUIElement] = []
        for attribute in [kAXChildrenAttribute, kAXWindowsAttribute, kAXVisibleChildrenAttribute] {
            var value: CFTypeRef?
            if AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success,
               let children = value as? [AXUIElement] {
                combined.append(contentsOf: children)
            }
        }
        return combined
    }
}

enum ClaudeRunner {
    static func run(session: PendingSession, prompt: String) -> ResumeResult {
        guard FileManager.default.fileExists(atPath: session.cwd) else {
            return ResumeResult(succeeded: false, message: LF("Projectmap bestaat niet meer voor sessie %@", session.id))
        }
        guard let executable = executablePath() else {
            return ResumeResult(succeeded: false, message: L("Claude CLI niet gevonden. Installeer of update Claude Code."))
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.currentDirectoryURL = URL(fileURLWithPath: session.cwd)
        process.arguments = [
            "--print", "--resume", session.id,
            "--output-format", "json", prompt
        ]
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = "\(FileManager.default.homeDirectoryForCurrentUser.path)/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        process.environment = environment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                return ResumeResult(succeeded: true, message: LF("Sessie %@ is succesvol hervat", session.id))
            }
            let detail = output.suffix(500).replacingOccurrences(of: "\n", with: " ")
            return ResumeResult(succeeded: false, message: LF("Sessie %@ stopte met code %d: %@", session.id, process.terminationStatus, String(detail)))
        } catch {
            return ResumeResult(succeeded: false, message: LF("Kon sessie %@ niet starten: %@", session.id, error.localizedDescription))
        }
    }

    static func executablePath() -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates = ["\(home)/.local/bin/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}

enum TerminalAutomation {
    static func openAndSubmit(session: PendingSession, prompt: String) -> ResumeResult {
        guard FileManager.default.fileExists(atPath: session.cwd) else {
            return ResumeResult(succeeded: false, message: LF("Projectmap bestaat niet meer voor sessie %@", session.id))
        }
        guard let executable = ClaudeRunner.executablePath() else {
            return ResumeResult(succeeded: false, message: L("Claude CLI niet gevonden. Installeer of update Claude Code."))
        }

        let cleanPrompt = oneLine(prompt)
        if let processIdentifier = session.processIdentifier, kill(processIdentifier, 0) == 0 {
            if let tty = terminalTTY(processIdentifier: processIdentifier),
               sendToMacTerminal(tty: tty, prompt: cleanPrompt) {
                return ResumeResult(succeeded: true, message: LF("Sessie %@ is hervat in de bestaande Terminal-tab", session.id))
            }
            if isHostedByVSCode(processIdentifier: processIdentifier),
               VSCodeTerminalAutomation.focusAndSubmit(cwd: session.cwd, prompt: cleanPrompt) {
                return ResumeResult(succeeded: true, message: LF("Sessie %@ is hervat in de bestaande VS Code-terminal", session.id))
            }
        }

        let encodedPrompt = Data(cleanPrompt.utf8).base64EncodedString()
        let promptArgument = "$(/bin/echo '\(encodedPrompt)' | /usr/bin/base64 -D)"
        let command = "cd \(shellQuote(session.cwd)) && exec \(shellQuote(executable)) --resume \(shellQuote(session.id)) \"\(promptArgument)\""
        let script = "tell application \"Terminal\"\nactivate\ndo script \"\(appleScriptEscape(command))\"\nend tell"
        guard runAppleScript(script) == 0 else {
            return ResumeResult(succeeded: false, message: LF("Kon sessie %@ niet in Terminal openen", session.id))
        }
        return ResumeResult(succeeded: true, message: LF("Sessie %@ is geopend in een nieuw Terminal-venster", session.id))
    }

    private static func sendToMacTerminal(tty: String, prompt: String) -> Bool {
        let script = """
        tell application "Terminal"
            repeat with terminalWindow in windows
                repeat with terminalTab in tabs of terminalWindow
                    if (tty of terminalTab) is "\(appleScriptEscape(tty))" then
                        set selected tab of terminalWindow to terminalTab
                        set index of terminalWindow to 1
                        activate
                        do script "\(appleScriptEscape(prompt))" in terminalTab
                        return "sent"
                    end if
                end repeat
            end repeat
            return "missing"
        end tell
        """
        return runAppleScript(script, expectedOutput: "sent") == 0
    }

    private static func terminalTTY(processIdentifier: Int32) -> String? {
        let output = commandOutput("/bin/ps", ["-p", String(processIdentifier), "-o", "tty="])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !output.isEmpty, output != "??" else { return nil }
        return output.hasPrefix("/dev/") ? output : "/dev/\(output)"
    }

    private static func isHostedByVSCode(processIdentifier: Int32) -> Bool {
        var current = processIdentifier
        for _ in 0..<8 where current > 1 {
            let line = commandOutput("/bin/ps", ["-p", String(current), "-o", "ppid=", "-o", "command="])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if line.localizedCaseInsensitiveContains("Visual Studio Code") || line.contains("Code Helper") { return true }
            let fields = line.split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
            guard let first = fields.first, let parent = Int32(first), parent > 0, parent != current else { break }
            current = parent
        }
        return false
    }

    private static func runAppleScript(_ source: String, expectedOutput: String? = nil) -> Int32 {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", source]
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return process.terminationStatus }
            if let expectedOutput {
                let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return text == expectedOutput ? 0 : 1
            }
            return 0
        } catch {
            return 1
        }
    }

    private static func commandOutput(_ executable: String, _ arguments: [String]) -> String {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }

    private static func oneLine(_ value: String) -> String {
        value.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func appleScriptEscape(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
    }
}

enum VSCodeTerminalAutomation {
    static func focusAndSubmit(cwd: String, prompt: String) -> Bool {
        let code = "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
        guard FileManager.default.isExecutableFile(atPath: code) else { return false }
        let opener = Process()
        opener.executableURL = URL(fileURLWithPath: code)
        opener.arguments = ["-r", cwd]
        try? opener.run()
        opener.waitUntilExit()
        guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: "com.microsoft.VSCode").first else { return false }
        app.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        Thread.sleep(forTimeInterval: 0.8)
        guard postShortcut(virtualKey: 35, flags: [.maskCommand, .maskShift]) else { return false }
        Thread.sleep(forTimeInterval: 0.35)
        guard postText("Terminal: Focus Terminal"), postReturn() else { return false }
        Thread.sleep(forTimeInterval: 0.7)
        return postText(prompt) && postReturn()
    }

    private static func postShortcut(virtualKey: CGKeyCode, flags: CGEventFlags) -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: virtualKey, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: virtualKey, keyDown: false) else { return false }
        down.flags = flags
        up.flags = flags
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }

    private static func postText(_ text: String) -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false) else { return false }
        let units = Array(text.utf16)
        units.withUnsafeBufferPointer { buffer in
            down.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
            up.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
        }
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }

    private static func postReturn() -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false) else { return false }
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }
}

enum VSCodeAccessibilityAutomation {
    private static let operationLock = NSLock()

    static func openAndSubmit(session: PendingSession, prompt: String, requestPermission: Bool) -> ResumeResult {
        operationLock.lock()
        defer { operationLock.unlock() }

        let code = "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
        guard FileManager.default.isExecutableFile(atPath: code) else {
            return ResumeResult(succeeded: false, message: L("Visual Studio Code is niet gevonden"))
        }
        let project = Process()
        project.executableURL = URL(fileURLWithPath: code)
        project.arguments = [session.cwd]
        do {
            try project.run()
            project.waitUntilExit()
        } catch {
            return ResumeResult(succeeded: false, message: L("Kon het VS Code-project niet activeren"))
        }

        Thread.sleep(forTimeInterval: 1)
        var components = URLComponents()
        components.scheme = "vscode"
        components.host = "anthropic.claude-code"
        components.path = "/open"
        components.queryItems = [URLQueryItem(name: "session", value: session.id)]
        guard let url = components.url else {
            return ResumeResult(succeeded: false, message: L("Kon de Claude-chat niet selecteren"))
        }
        let opener = Process()
        opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        opener.arguments = [url.absoluteString]
        do {
            try opener.run()
            opener.waitUntilExit()
        } catch {
            return ResumeResult(succeeded: false, message: L("Kon de Claude-chat niet openen"))
        }
        Thread.sleep(forTimeInterval: 1.5)

        let trusted: Bool
        if requestPermission {
            let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
            trusted = AXIsProcessTrustedWithOptions([key: true] as CFDictionary)
        } else {
            trusted = AXIsProcessTrusted()
        }
        guard trusted else {
            return ResumeResult(succeeded: false, message: L("Toegankelijkheidstoegang is niet ingeschakeld"))
        }
        guard postText(prompt) else {
            return ResumeResult(succeeded: false, message: L("Kon het bericht niet via Toegankelijkheid invullen"))
        }
        Thread.sleep(forTimeInterval: 0.2)
        guard postReturn() else {
            return ResumeResult(succeeded: false, message: L("Kon het bericht niet via Toegankelijkheid versturen"))
        }
        return ResumeResult(succeeded: true, message: LF("Hervatbericht via Toegankelijkheid verstuurd voor %@", session.title))
    }

    private static func postText(_ text: String) -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false) else { return false }
        let units = Array(text.utf16)
        units.withUnsafeBufferPointer { buffer in
            down.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
            up.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
        }
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }

    private static func postReturn() -> Bool {
        guard let source = CGEventSource(stateID: .hidSystemState),
              let down = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: 36, keyDown: false) else { return false }
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
        return true
    }
}

enum LogFile {
    static let url = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/Claude Resumer/resumer.log")

    static func write(_ message: String) {
        let formatter = ISO8601DateFormatter()
        let line = "\(formatter.string(from: Date())) \(message)\n"
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        if let data = line.data(using: .utf8) { try? handle.write(contentsOf: data) }
    }
}

enum LoginService {
    static let label = "nl.marvin.claude-resumer"
    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }
    static var isInstalled: Bool { FileManager.default.fileExists(atPath: plistURL.path) }

    static func migrateLegacyServiceIfNeeded() throws -> Bool {
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let arguments = plist["ProgramArguments"] as? [String],
              arguments.contains(where: { $0.contains("claude_resume.py") }) else { return false }
        try install()
        return true
    }

    static func install() throws {
        let appPath = Bundle.main.bundlePath
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": ["/usr/bin/open", appPath],
            "RunAtLoad": true
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try FileManager.default.createDirectory(at: plistURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: plistURL, options: .atomic)
        reload()
    }

    static func uninstall() {
        let domain = "gui/\(getuid())"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["bootout", domain, plistURL.path]
        try? process.run()
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: plistURL)
    }

    private static func reload() {
        let domain = "gui/\(getuid())"
        let bootout = Process()
        bootout.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        bootout.arguments = ["bootout", domain, plistURL.path]
        try? bootout.run()
        bootout.waitUntilExit()
        let bootstrap = Process()
        bootstrap.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        bootstrap.arguments = ["bootstrap", domain, plistURL.path]
        try? bootstrap.run()
        bootstrap.waitUntilExit()
    }
}

struct ContentView: View {
    @EnvironmentObject var model: ResumerModel

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color.indigo.opacity(0.18), Color.cyan.opacity(0.08), Color.clear],
                startPoint: .topLeading, endPoint: .bottomTrailing
            ).ignoresSafeArea()
            Circle().fill(Color.purple.opacity(0.10)).frame(width: 360).blur(radius: 70).offset(x: 330, y: -270)

            ScrollView {
            VStack(alignment: .leading, spacing: 16) {
            HStack {
                ZStack {
                    RoundedRectangle(cornerRadius: 15).fill(.ultraThinMaterial)
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable().scaledToFit().clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
                }.frame(width: 58, height: 58).shadow(color: .indigo.opacity(0.18), radius: 16, y: 8)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Claude Resumer").font(.largeTitle.weight(.semibold))
                    Text("Kies welke VS Code-, Claude App-, App Code- en CLI-sessies doorgaan")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button { model.showHelp = true } label: {
                    Label("Help", systemImage: "questionmark.circle")
                }
                Button { model.showLicense = true } label: {
                    Label(model.licenseTitle, systemImage: model.hasAccess ? "checkmark.seal.fill" : "lock.fill")
                }
                Button { model.scan() } label: {
                    Label("Vernieuwen", systemImage: "arrow.clockwise")
                }.disabled(model.isScanning)
            }

            if model.closedLidModeEnabled {
                HStack(spacing: 14) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.title2)
                        .foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("GESLOTEN MODUS INGESCHAKELD")
                            .font(.headline.weight(.heavy))
                            .foregroundStyle(.orange)
                        Text(model.closedLidModeMessage)
                            .font(.subheadline)
                    }
                    Spacer()
                    Button("Nu uitschakelen") { model.disableClosedLidMode() }
                        .buttonStyle(.borderedProminent)
                        .tint(.orange)
                }
                .padding(16)
                .background(.orange.opacity(0.14), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(.orange.opacity(0.8), lineWidth: 2))
            }

            if model.detectionStale {
                HStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.title3)
                        .foregroundStyle(.yellow)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Een limietmelding werd niet herkend")
                            .font(.subheadline.weight(.semibold))
                        Text("Claude lijkt de indeling van de limietmelding te hebben gewijzigd. Werk Claude Resumer bij zodat automatisch hervatten blijft werken.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                }
                .padding(14)
                .background(.yellow.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(.yellow.opacity(0.6), lineWidth: 1))
            }

            HStack(spacing: 10) {
                WorkflowStep(number: "1", title: "Detecteert", detail: "Vindt chats die op hun limiet wachten", icon: "magnifyingglass")
                WorkflowStep(number: "2", title: "Wacht", detail: "Leest de exacte resettijd van Claude", icon: "clock")
                WorkflowStep(number: "3", title: "Hervat", detail: "Opent alleen de chats die jij kiest", icon: "play.fill")
            }

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label(L(model.isEnabled && model.hasAccess ? "Automatisch hervatten actief" : "Automatisch hervatten niet actief"), systemImage: model.isEnabled && model.hasAccess ? "bolt.circle.fill" : "pause.circle.fill")
                        .font(.headline).foregroundStyle(model.isEnabled && model.hasAccess ? .green : .secondary)
                    Spacer()
                    Toggle("", isOn: $model.isEnabled).labelsHidden().toggleStyle(.switch).disabled(!model.hasAccess)
                }
                Toggle("Start bij inloggen op deze Mac", isOn: $model.launchAtLogin)
                Toggle("Houd Mac wakker zolang Claude Resumer actief is", isOn: $model.keepMacAwake)
                if model.keepMacAwake {
                    Label(
                        L(model.wakeLockActive ? "Sluimerstand wordt voorkomen, het beeldscherm mag wel uitgaan." : "De wakkerhoudfunctie kon niet worden gestart."),
                        systemImage: model.wakeLockActive ? "sun.max.fill" : "exclamationmark.triangle.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(model.wakeLockActive ? Color.secondary : Color.orange)
                }
                Divider()
                HStack(alignment: .center, spacing: 12) {
                    Image(systemName: "laptopcomputer")
                        .font(.title2)
                        .foregroundStyle(model.closedLidModeEnabled ? .orange : .indigo)
                        .frame(width: 30)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Geavanceerde gesloten MacBook-modus").font(.subheadline.bold())
                        Text("Blijft actief na dichtklappen, gebruikt dan Low Power Mode en stopt op batterij automatisch bij 10%.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.closedLidModeTransitioning {
                        ProgressView().controlSize(.small)
                    } else if model.closedLidModeEnabled {
                        Button("Uitschakelen") { model.disableClosedLidMode() }
                            .buttonStyle(.bordered)
                    } else {
                        Button("Instellen...") { model.showClosedLidWarning = true }
                            .buttonStyle(.bordered)
                    }
                }
                if model.closedLidModeTransitioning || model.closedLidModeMessage != L("Gesloten modus staat uit.") {
                    Label(
                        model.closedLidModeMessage,
                        systemImage: model.closedLidModeEnabled ? "checkmark.circle.fill" : "info.circle.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(model.closedLidModeEnabled ? Color.orange : Color.secondary)
                }
                Divider()
                Text("Bericht dat wordt verstuurd").font(.subheadline.bold())
                TextField("Hervatbericht", text: $model.prompt).textFieldStyle(.plain)
                    .padding(10).background(.black.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                Label("‘Nu hervatten’ wordt actief zodra de gedetecteerde limiet is gereset.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(16)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(.white.opacity(0.16)))
            .shadow(color: .black.opacity(0.08), radius: 24, y: 12)

            LicenseStatusCard()

            ChatSelectionPanel()

            VStack(alignment: .leading, spacing: 8) {
                Text("Activiteit").font(.headline)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 5) {
                        ForEach(model.logs) { entry in
                            HStack(alignment: .firstTextBaseline) {
                                Text(entry.date, style: .time).foregroundStyle(.secondary).monospacedDigit()
                                Text(entry.message).textSelection(.enabled)
                            }.font(.caption)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(height: 100).padding(8).background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
            }
            }
            .padding(22)
            }
        }
        .frame(minWidth: 780, minHeight: 760)
        .sheet(isPresented: $model.showHelp) {
            HelpView().environmentObject(model)
        }
        .sheet(isPresented: $model.showLicense) {
            LicenseView().environmentObject(model)
        }
        .sheet(isPresented: $model.showClosedLidWarning) {
            ClosedLidWarningView().environmentObject(model)
        }
        .alert(L("Trakteer de maker op een koffie"), isPresented: $model.showCoffeePopup) {
            Button(L("Koffie kopen")) {
                if let url = URL(string: coffeeURLString) { NSWorkspace.shared.open(url) }
            }
            Button(L("Later"), role: .cancel) {}
        } message: {
            Text(L("Je draait een gratis build vanuit de broncode. Claude Resumer is gemaakt door één ontwikkelaar. Vind je het nuttig, overweeg dan een kleine bijdrage via Buy Me a Coffee."))
        }
    }
}

struct ClosedLidWarningView: View {
    @EnvironmentObject var model: ResumerModel
    @Environment(\.dismiss) private var dismiss
    @State private var hasConfirmed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 34))
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Waarschuwing: gesloten MacBook-modus")
                        .font(.title2.bold())
                    Text("Lees dit voordat je de beveiligde slaapstand van macOS aanpast.")
                        .foregroundStyle(.secondary)
                }
            }

            Text("Deze geavanceerde functie gebruikt de niet door Apple gedocumenteerde instelling ‘pmset disablesleep’. Je MacBook blijft hierdoor werken wanneer je hem dichtklapt.")
                .font(.body.weight(.medium))

            VStack(alignment: .leading, spacing: 12) {
                WarningPoint(
                    icon: "thermometer.medium",
                    title: "Warmte en ventilatie",
                    text: "Gebruik de MacBook alleen op een harde, vrije en goed geventileerde ondergrond. Stop hem nooit actief in een tas, hoes, bed of bank."
                )
                WarningPoint(
                    icon: "battery.25",
                    title: "Werkt ook zonder lader",
                    text: "Op batterij blijft de modus werken. Bij 10% of minder wordt hij automatisch uitgeschakeld, zodat een dichtgeklapte Mac weer normaal kan slapen."
                )
                WarningPoint(
                    icon: "leaf.fill",
                    title: "Energiebesparing volgt het scherm",
                    text: "Met het scherm dicht gebruikt macOS Low Power Mode. Zodra je het scherm opent, wordt exact je eerdere energiemodus teruggezet."
                )
                WarningPoint(
                    icon: "arrow.uturn.backward.circle.fill",
                    title: "Automatisch herstel",
                    text: "Bij uitschakelen, stoppen van Claude Resumer of hoge temperatuur herstelt de bewaker de oorspronkelijke instellingen."
                )
            }
            .padding(14)
            .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))

            Toggle("Ik begrijp dat mijn Mac actief en mogelijk warm blijft terwijl hij dichtgeklapt is.", isOn: $hasConfirmed)
                .toggleStyle(.checkbox)
                .font(.subheadline.bold())

            Text("macOS vraagt hierna om je beheerderswachtwoord. Claude Resumer bewaart dit wachtwoord niet.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Button("Annuleren") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Inschakelen met beheerdersrechten") {
                    dismiss()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                        model.enableClosedLidMode()
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
                .disabled(!hasConfirmed)
            }
        }
        .padding(26)
        .frame(width: 620)
        .interactiveDismissDisabled(model.closedLidModeTransitioning)
    }
}

struct WarningPoint: View {
    let icon: String
    let title: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(.orange).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(L(title)).font(.subheadline.bold())
                Text(L(text)).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct WorkflowStep: View {
    let number: String
    let title: String
    let detail: String
    let icon: String

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle().fill(.indigo.opacity(0.16))
                Image(systemName: icon).foregroundStyle(.indigo)
            }.frame(width: 34, height: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(number). \(L(title))").font(.subheadline.bold())
                Text(L(detail)).font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

struct ChatSelectionPanel: View {
    @EnvironmentObject var model: ResumerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Chats kiezen").font(.headline)
                Spacer()
                Text("Automatisch hervatten per chat").font(.caption).foregroundStyle(.secondary)
            }
            SourceSelector()

            if !model.isSourceAvailable(model.selectedChatSource) {
                SourceUnavailableNotice(source: model.selectedChatSource)
            } else if model.selectedChatSource == .desktop {
                ClaudeAppChatSelectionView()
            } else if model.selectedChatSource == .appCode {
                ClaudeAppCodeSelectionView()
            } else {
                CodeChatSelectionView(source: model.selectedChatSource)
            }
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(.white.opacity(0.13)))
    }
}

struct SourceSelector: View {
    @EnvironmentObject var model: ResumerModel

    var body: some View {
        HStack(spacing: 3) {
            ForEach(ChatSource.allCases) { source in
                let available = model.isSourceAvailable(source)
                let selected = model.selectedChatSource == source
                Button {
                    model.selectedChatSource = source
                } label: {
                    HStack(spacing: 5) {
                        Circle()
                            .fill(available ? Color.green : Color.secondary.opacity(0.55))
                            .frame(width: 6, height: 6)
                        Text(L(source.rawValue))
                            .font(.caption.weight(selected ? .semibold : .medium))
                            .lineLimit(1)
                            .minimumScaleFactor(0.72)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 7)
                    .padding(.horizontal, 5)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(available ? (selected ? Color.primary : Color.secondary) : Color.secondary.opacity(0.7))
                .background(
                    selected ? Color.white.opacity(available ? 0.16 : 0.07) : Color.clear,
                    in: RoundedRectangle(cornerRadius: 7, style: .continuous)
                )
                .disabled(!available)
                .opacity(available ? 1 : 0.58)
                .help(available ? L("Bron is actief") : model.sourceUnavailableMessage(source))
            }
        }
        .padding(3)
        .background(.black.opacity(0.13), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.white.opacity(0.08)))
    }
}

struct SourceUnavailableNotice: View {
    @EnvironmentObject var model: ResumerModel
    let source: ChatSource

    private var actionTitle: String {
        switch source {
        case .code: return L("Open VS Code")
        case .desktop, .appCode: return L("Open Claude")
        case .cli: return L("Open Terminal")
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.title3)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(LF("%@ draait niet", L(source.rawValue)))
                    .font(.subheadline.bold())
                Text(model.sourceUnavailableMessage(source))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(actionTitle) { model.openSource(source) }
                .buttonStyle(.borderedProminent)
        }
        .padding(12)
        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(.orange.opacity(0.25)))
    }
}

struct CodeChatSelectionView: View {
    @EnvironmentObject var model: ResumerModel
    let source: ChatSource

    private var visibleSessions: [PendingSession] { model.sessions(for: source) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(LF("%d wachtend, %d geselecteerd", visibleSessions.count, model.selectedSessionCount(in: source)))
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Alles") { model.selectAllSessions(in: source, selected: true) }.buttonStyle(.plain)
                Button("Geen") { model.selectAllSessions(in: source, selected: false) }.buttonStyle(.plain)
            }
            if visibleSessions.isEmpty {
                EmptyChatState(
                    icon: "checkmark.circle",
                    title: source == .cli ? "Geen wachtende Claude CLI-sessies" : "Geen wachtende VS Code Extension-chats",
                    detail: "Nieuwe limietmeldingen verschijnen hier automatisch."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(visibleSessions) { session in
                            SessionRow(session: session)
                        }
                    }
                    .padding(8)
                }
                .frame(height: min(300, max(185, CGFloat(visibleSessions.count) * 92 + 16)))
                .background(.black.opacity(0.07), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).stroke(.white.opacity(0.08)))
            }
        }
    }
}

struct ClaudeAppChatSelectionView: View {
    @EnvironmentObject var model: ResumerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(LF("%d recent, %d geselecteerd", model.claudeAppChats.count, model.selectedClaudeChatCount))
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Alles") { model.selectAllClaudeChats(true) }.buttonStyle(.plain)
                    .disabled(model.claudeAppChats.isEmpty)
                Button("Geen") { model.selectAllClaudeChats(false) }.buttonStyle(.plain)
                    .disabled(model.claudeAppChats.isEmpty)
            }

            if !model.claudeAccessibilityTrusted {
                HStack {
                    Label("Toegankelijkheidstoegang is nodig om een gekozen chat te openen en te bedienen.", systemImage: "hand.raised.fill")
                        .font(.caption).foregroundStyle(.orange)
                    Spacer()
                    Button("Toestaan") { model.requestAccessibilityPermission() }
                }
                .padding(10)
                .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
            } else if !model.claudeAppRunning {
                HStack {
                    Text("Open Claude App om je recente chats in te laden.").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Claude openen") {
                        model.openClaudeApp()
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { model.scan() }
                    }
                }
            }

            if let resetDate = model.claudeAppResetDate {
                Label(LF("Gedeelde limiet reset %@.", resetDate.formatted(date: .abbreviated, time: .shortened)), systemImage: "clock.badge.checkmark")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Nog geen actieve Claude App-limiet gevonden. Je selectie blijft bewaard.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if model.claudeAppChats.isEmpty {
                EmptyChatState(
                    icon: "bubble.left.and.bubble.right",
                    title: "Geen Claude App-chats gevonden",
                    detail: "Open Claude op Home, zorg dat Recents zichtbaar is en klik op Vernieuwen."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(model.claudeAppChats) { chat in
                            ClaudeAppChatRow(chat: chat)
                        }
                    }
                    .padding(8)
                }
                .frame(height: min(300, max(185, CGFloat(model.claudeAppChats.count) * 76 + 16)))
                .background(.black.opacity(0.07), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).stroke(.white.opacity(0.08)))
            }
        }
    }
}

struct ClaudeAppCodeSelectionView: View {
    @EnvironmentObject var model: ResumerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(LF("%d zichtbaar, %d geselecteerd", model.claudeAppCodeSessions.count, model.selectedClaudeAppCodeCount))
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Open Code") { model.showClaudeAppCode() }.buttonStyle(.plain)
                Button("Alles") { model.selectAllClaudeAppCodeSessions(true) }.buttonStyle(.plain)
                    .disabled(model.claudeAppCodeSessions.isEmpty)
                Button("Geen") { model.selectAllClaudeAppCodeSessions(false) }.buttonStyle(.plain)
                    .disabled(model.claudeAppCodeSessions.isEmpty)
            }

            if !model.claudeAccessibilityTrusted {
                HStack {
                    Label("Toegankelijkheidstoegang is nodig om een gekozen chat te openen en te bedienen.", systemImage: "hand.raised.fill")
                        .font(.caption).foregroundStyle(.orange)
                    Spacer()
                    Button("Toestaan") { model.requestAccessibilityPermission() }
                }
                .padding(10)
                .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
            } else if !model.claudeAppRunning {
                HStack {
                    Text("Open Claude App op Code om de zichtbare sessies in te laden.")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Claude Code openen") { model.showClaudeAppCode() }
                }
            }

            if let resetDate = model.claudeAppResetDate {
                Label(LF("Gedeelde limiet reset %@.", resetDate.formatted(date: .abbreviated, time: .shortened)), systemImage: "clock.badge.checkmark")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Nog geen actieve Claude App-limiet gevonden. Je selectie blijft bewaard.", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if model.claudeAppCodeSessions.isEmpty {
                EmptyChatState(
                    icon: "chevron.left.forwardslash.chevron.right",
                    title: "Geen Claude App Code-sessies geladen",
                    detail: "Open Code in Claude App en klik daarna op Vernieuwen. Alleen de sessies uit de Code-zijbalk worden getoond."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(model.claudeAppCodeSessions) { session in
                            ClaudeAppCodeSessionRow(session: session)
                        }
                    }
                    .padding(8)
                }
                .frame(height: min(300, max(185, CGFloat(model.claudeAppCodeSessions.count) * 76 + 16)))
                .background(.black.opacity(0.07), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).stroke(.white.opacity(0.08)))
            }
        }
    }
}

struct EmptyChatState: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 7) {
            Image(systemName: icon).font(.system(size: 30)).foregroundStyle(.secondary)
            Text(L(title)).font(.headline)
            Text(L(detail)).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 135)
        .background(.black.opacity(0.07), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).stroke(.white.opacity(0.08)))
    }
}

struct LicenseStatusCard: View {
    @EnvironmentObject var model: ResumerModel

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: model.hasAccess ? "checkmark.seal.fill" : "lock.fill")
                .font(.title2)
                .foregroundStyle(model.hasAccess ? .green : .orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.licenseTitle).font(.subheadline.bold())
                Text(model.licenseDetail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button(L(model.hasAccess ? "Licentie bekijken" : "Ontgrendelen")) { model.showLicense = true }
                .buttonStyle(.bordered)
        }
        .padding(12)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(.white.opacity(0.12)))
    }
}

struct HelpView: View {
    @EnvironmentObject var model: ResumerModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Image(nsImage: NSApp.applicationIconImage).resizable().scaledToFit().frame(width: 54, height: 54)
                VStack(alignment: .leading) {
                    Text("Hoe Claude Resumer werkt").font(.title.bold())
                    Text("Van limietmelding naar automatisch hervatte chat").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Gereed") { dismiss() }.keyboardShortcut(.cancelAction)
            }

            HelpSection(icon: "eye.fill", title: "1. Detectie blijft lokaal op je Mac", text: "Voor de VS Code-extensie en CLI leest de app ~/.claude/projects. Voor Claude App gebruikt hij lokale appgegevens en de zichtbare chat- en Code-sessies. Cookies en accounttokens worden niet uitgelezen.")
            HelpSection(icon: "clock.badge.checkmark.fill", title: "2. De resettijd komt rechtstreeks uit Claude", text: "Na een sessielimiet bewaart Claude zelf de resettijd. De app controleert iedere minuut en wacht voor de zekerheid nog 30 seconden.")
            HelpSection(icon: "checklist.checked", title: "3. Jij kiest welke chats doorgaan", text: "Kies VS Code Extension, Claude App, Claude App Code of Claude CLI en vink alleen de gewenste sessies aan. Niet-geselecteerde sessies worden nooit automatisch geopend.")
            HelpSection(icon: "rectangle.stack.badge.play.fill", title: "4. Iedere bron krijgt de juiste route", text: "De VS Code-extensie en beide Claude App-omgevingen worden via Toegankelijkheidstoegang bediend. Claude CLI gebruikt de bestaande Terminal of VS Code-terminal wanneer die nog open is. Na slaapstand controleert de app opnieuw.")

            Divider()
            Text("Goed om te weten").font(.headline)
            Text(L("Claude kan nog steeds om toestemming of extra informatie vragen. Claude Resumer schakelt geen beveiligingscontroles uit en kan een taak niet voltooien wanneer menselijke invoer nodig is."))
                .foregroundStyle(.secondary)
            Text(L("Met ‘Houd Mac wakker’ voorkom je alleen automatische sluimerstand terwijl de app draait. Het beeldscherm kan wel uitgaan. De aparte geavanceerde gesloten modus kan slaap bij dichtklappen voorkomen, gebruikt Low Power Mode wanneer de klep dicht is en stopt op batterij automatisch bij 10%."))
                .foregroundStyle(.secondary)
            Text(L("De gesloten modus gebruikt een niet door Apple gedocumenteerde pmset-instelling en vereist beheerdersrechten. Gebruik een actieve, dichtgeklapte Mac nooit in een tas of op een zachte ondergrond. Bij openen, uitschakelen of stoppen van de app worden je eerdere energie-instellingen hersteld."))
                .foregroundStyle(.secondary)
            HStack {
                Button("Open logbestand") { NSWorkspace.shared.open(LogFile.url) }
                if let supportURL = URL(string: "mailto:support@clauderesumer.com") {
                    Link(destination: supportURL) {
                        Label("support@clauderesumer.com", systemImage: "envelope")
                    }
                }
                Spacer()
                Button("Licentie en proefperiode") {
                    dismiss()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { model.showLicense = true }
                }.buttonStyle(.borderedProminent)
            }
        }
        .padding(26)
        .frame(width: 640)
    }
}

struct HelpSection: View {
    let icon: String
    let title: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon).font(.title2).foregroundStyle(.indigo).frame(width: 30)
            VStack(alignment: .leading, spacing: 4) {
                Text(L(title)).font(.headline)
                Text(L(text)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct LicenseView: View {
    @EnvironmentObject var model: ResumerModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Claude Resumer activeren").font(.title.bold())
                    Text(model.licenseDetail).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Gereed") { dismiss() }.keyboardShortcut(.cancelAction)
            }

            HStack(spacing: 12) {
                LicenseBenefit(icon: "clock.arrow.circlepath", text: "Automatisch hervatten")
                LicenseBenefit(icon: "rectangle.stack", text: "Onbeperkt chats")
                LicenseBenefit(icon: "arrow.triangle.2.circlepath", text: "Maandelijks opzegbaar")
            }

            if case .licensed = model.licenseStatus {
                Label("Deze Mac is geactiveerd", systemImage: "checkmark.seal.fill")
                    .font(.title3.bold()).foregroundStyle(.green)
            } else if case .ownerMode = model.licenseStatus {
                VStack(alignment: .leading, spacing: 10) {
                    Label("Eigenaarmodus is actief in deze ontwikkelaarsbuild", systemImage: "hammer.fill")
                        .foregroundStyle(.secondary)
                    if let url = URL(string: coffeeURLString) {
                        Link(destination: url) {
                            Label(L("Trakteer de maker op een koffie"), systemImage: "cup.and.saucer.fill")
                        }
                    }
                }
            } else {
                TextField("CR1.licentiesleutel", text: $model.licenseKeyInput)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                HStack {
                    Button("Abonnement starten") { model.openPurchasePage() }
                    Spacer()
                    if case .activating = model.licenseStatus { ProgressView().controlSize(.small) }
                    Button("Activeer sleutel") { model.activateLicense() }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.licenseKeyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }

            Divider()
            Text(L("Je krijgt 24 uur volledige toegang vanaf de eerste start. Na het abonneren verschijnt de sleutel direct op de betaalbevestiging. Bewaar hem bij je wachtwoordmanager."))
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(26)
        .frame(width: 580)
    }
}

struct LicenseBenefit: View {
    let icon: String
    let text: String

    var body: some View {
        VStack(spacing: 7) {
            Image(systemName: icon).font(.title2).foregroundStyle(.indigo)
            Text(L(text)).font(.caption.bold()).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 76)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }
}

struct SessionRow: View {
    @EnvironmentObject var model: ResumerModel
    let session: PendingSession

    private func isDue(at date: Date) -> Bool { date >= session.resetDate }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 5)) { timeline in
            row(isDue: isDue(at: timeline.date))
        }
    }

    private func row(isDue: Bool) -> some View {
        HStack(spacing: 12) {
            Toggle("", isOn: Binding(
                get: { model.isCodeSessionSelected(session) },
                set: { model.setCodeSession(session, selected: $0) }
            ))
            .labelsHidden()
            .toggleStyle(.checkbox)
            .help(L("Automatisch hervatten"))
            Image(systemName: isDue ? "play.circle.fill" : "clock.fill")
                .font(.title2).foregroundStyle(isDue ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(session.title).font(.headline)
                Text("\(session.origin.label) · \(URL(fileURLWithPath: session.cwd).lastPathComponent)")
                    .font(.subheadline).foregroundStyle(.secondary)
                Text(session.cwd).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text(LF("Reset: %@", session.resetLabel)).font(.caption)
            }
            Spacer()
            if model.runningSessionIDs.contains(session.id) {
                ProgressView().controlSize(.small)
            } else {
                Button("Nu hervatten") { model.resumeNow(session) }
                    .disabled(!isDue)
            }
        }
        .padding(10)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).stroke(.white.opacity(0.09)))
    }
}

struct ClaudeAppChatRow: View {
    @EnvironmentObject var model: ResumerModel
    let chat: ClaudeAppChat

    private func isDue(at date: Date) -> Bool {
        guard let resetDate = chat.resetDate else { return false }
        return date >= resetDate
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 5)) { timeline in
            row(isDue: isDue(at: timeline.date))
        }
    }

    private func row(isDue: Bool) -> some View {
        HStack(spacing: 12) {
            Toggle("", isOn: Binding(
                get: { model.isClaudeChatSelected(chat) },
                set: { model.setClaudeChat(chat, selected: $0) }
            ))
            .labelsHidden()
            .toggleStyle(.checkbox)
            .help(L("Automatisch hervatten"))
            Image(systemName: chat.resetDate == nil ? "bubble.left.fill" : (isDue ? "play.circle.fill" : "clock.fill"))
                .font(.title2)
                .foregroundStyle(chat.resetDate == nil ? Color.secondary : (isDue ? Color.green : Color.orange))
            VStack(alignment: .leading, spacing: 3) {
                Text(chat.title).font(.headline).lineLimit(1)
                Text("Claude App").font(.subheadline).foregroundStyle(.secondary)
                Text(chat.resetLabel).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if model.runningClaudeChatIDs.contains(chat.id) {
                ProgressView().controlSize(.small)
            } else {
                Button("Nu hervatten") { model.resumeClaudeAppNow(chat) }
                    .disabled(!isDue)
            }
        }
        .padding(10)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).stroke(.white.opacity(0.09)))
    }
}

struct ClaudeAppCodeSessionRow: View {
    @EnvironmentObject var model: ResumerModel
    let session: ClaudeAppCodeSession

    private func isDue(at date: Date) -> Bool {
        guard let resetDate = session.resetDate else { return false }
        return date >= resetDate
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 5)) { timeline in
            row(isDue: isDue(at: timeline.date))
        }
    }

    private func row(isDue: Bool) -> some View {
        HStack(spacing: 12) {
            Toggle("", isOn: Binding(
                get: { model.isClaudeAppCodeSelected(session) },
                set: { model.setClaudeAppCodeSession(session, selected: $0) }
            ))
            .labelsHidden()
            .toggleStyle(.checkbox)
            .help(L("Automatisch hervatten"))
            Image(systemName: session.resetDate == nil ? "chevron.left.forwardslash.chevron.right" : (isDue ? "play.circle.fill" : "clock.fill"))
                .font(.title2)
                .foregroundStyle(session.resetDate == nil ? Color.secondary : (isDue ? Color.green : Color.orange))
            VStack(alignment: .leading, spacing: 3) {
                Text(session.title).font(.headline).lineLimit(1)
                Text("Claude App Code").font(.subheadline).foregroundStyle(.secondary)
                Text(session.resetLabel).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if model.runningClaudeAppCodeIDs.contains(session.id) {
                ProgressView().controlSize(.small)
            } else {
                Button("Nu hervatten") { model.resumeClaudeAppCodeNow(session) }
                    .disabled(!isDue)
            }
        }
        .padding(10)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).stroke(.white.opacity(0.09)))
    }
}

struct MenuBarView: View {
    @EnvironmentObject var model: ResumerModel
    @EnvironmentObject var updater: UpdaterController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if model.closedLidModeEnabled {
                Label("GESLOTEN MODUS INGESCHAKELD", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline.weight(.heavy))
                    .foregroundStyle(.orange)
                Text(model.closedLidModeMessage).font(.caption)
                Button("Gesloten modus nu uitschakelen") { model.disableClosedLidMode() }
                    .buttonStyle(.borderedProminent)
                    .tint(.orange)
                Divider()
            }
            Text(L(model.isEnabled && model.hasAccess ? "Automatisch hervatten is actief" : "Automatisch hervatten staat niet actief"))
                .font(.headline)
            Text(model.licenseTitle).font(.caption).foregroundStyle(.secondary)
            Text(LF(
                "%d VS Code-chats, %d CLI-sessies, %d App-chats, %d App Code-sessies",
                model.sessions(for: .code).count,
                model.sessions(for: .cli).count,
                model.claudeAppChats.count,
                model.claudeAppCodeSessions.count
            ))
                .foregroundStyle(.secondary)
            Divider()
            Button("Open Claude Resumer") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            Button("Nu controleren") { model.scan() }
            Toggle("Houd Mac wakker", isOn: $model.keepMacAwake)
            if !model.closedLidModeEnabled {
                Button("Gesloten modus instellen...") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                    model.showClosedLidWarning = true
                }
            }
            Button("Help en uitleg") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
                model.showHelp = true
            }
            Button(L("Controleer op updates…")) { updater.checkForUpdates() }
                .disabled(!updater.canCheckForUpdates)
            Divider()
            Button("Stop Claude Resumer") { NSApplication.shared.terminate(nil) }
        }.padding(12).frame(width: 270)
    }
}

/// Beheert de Sparkle-updater en houdt bij of er nu op updates gecontroleerd kan worden.
final class UpdaterController: ObservableObject {
    private let controller: SPUStandardUpdaterController
    @Published var canCheckForUpdates = false

    init() {
        // startingUpdater: true plant automatisch geplande controles (SUScheduledCheckInterval uit Info.plist).
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheckForUpdates)
    }

    func checkForUpdates() {
        controller.updater.checkForUpdates()
    }
}

@main
struct ClaudeResumerApp: App {
    @StateObject private var model = ResumerModel()
    @StateObject private var updater = UpdaterController()

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(model)
                .environmentObject(updater)
                .onAppear { model.start(); model.offerCoffeeIfNeeded() }
                .onOpenURL { model.handleIncomingURL($0) }
        }
        .defaultSize(width: 820, height: 820)
        .commands {
            CommandGroup(after: .appInfo) {
                Button(L("Controleer op updates…")) { updater.checkForUpdates() }
                    .disabled(!updater.canCheckForUpdates)
            }
        }

        MenuBarExtra {
            MenuBarView().environmentObject(model).environmentObject(updater)
        } label: {
            Image(systemName: model.closedLidModeEnabled ? "exclamationmark.triangle.fill" : (model.isEnabled ? "clock.arrow.circlepath" : "clock.badge.xmark"))
        }
        .menuBarExtraStyle(.window)
    }
}

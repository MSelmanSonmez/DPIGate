param(
    [switch]$NoTray,
    [switch]$NoDnsDetect,
    [switch]$TrayMode,
    [int]$GoodbyePid,
    [string]$DnsLabel,
    [string]$ProgramsList,
    [string]$IconPath,
    [int]$CurrentDnsIndex = -1,
    [string]$DnsCandidatesInfo = '',
    [int]$ForceDnsIndex = -1,
    [string]$StartScriptPath = '',
    # Name of a Main-created ManualReset EventWaitHandle that Tray Mode opens
    # and sets once it is genuinely up (job object assigned + icon visible).
    # Main blocks on it before returning, so goodbyedpi.exe is never left
    # running with no tray icon to stop it. Empty = no handshake requested
    # (a hand-run -TrayMode, or Main failed to create the event at all).
    [string]$ReadyEvent = '',
    [switch]$BypassAll,
    [switch]$NoBypassAll,
    [int]$BypassAllCurrent = 0,
    [switch]$PersistOnSuccess,
    [switch]$PersistFailed
)

$ErrorActionPreference = 'Stop'

# =============================================================================
# Settings persistence ($env:LOCALAPPDATA\GoodbyeDPI-Plus\settings, KEY=VALUE)
# Mirrors linux/start.sh's _config_get + linux/tray.py's _load_settings /
# _save_setting. Missing file, missing key, or an unparseable value always
# falls back to the caller's default - never throws. Last matching line wins.
#
# The only writer is Main, and only after its own health check confirms
# goodbyedpi actually came up, gated by -PersistOnSuccess (see Main below).
# Tray Mode never writes directly: its restart handlers always pass
# -PersistOnSuccess on the replacement's command line, so a failed restart
# never touches this file and the file always holds the last known-good
# choice - a manual CLI run without -PersistOnSuccess (e.g. a developer
# testing -ForceDnsIndex 2) writes nothing.
# =============================================================================
# $env:LOCALAPPDATA can be empty (odd service contexts, stripped/sandboxed
# environments); Join-Path on a null/empty -Path throws a
# ParameterBindingValidationException that $ErrorActionPreference = 'Stop'
# turns fatal, taking the whole script - including Tray Mode - down with it.
# Fall back to GetFolderPath (same idiom install.ps1 already uses for
# 'Programs'/'Startup'), and if even that comes back empty, disable
# persistence rather than throw: $script:SettingsFile stays $null, every
# reader below degrades to its default, and Set-GdpiSettings reports failure.
$script:SettingsFile = $null
$localAppData = $env:LOCALAPPDATA
if ([string]::IsNullOrWhiteSpace($localAppData)) {
    try { $localAppData = [Environment]::GetFolderPath('LocalApplicationData') } catch { $localAppData = $null }
}
if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
    $script:SettingsFile = Join-Path $localAppData 'GoodbyeDPI-Plus\settings'
}

function Get-GdpiSettingRaw {
    param([string]$Key)
    $val = $null
    try {
        if ($script:SettingsFile -and (Test-Path -LiteralPath $script:SettingsFile)) {
            foreach ($line in Get-Content -LiteralPath $script:SettingsFile -ErrorAction Stop) {
                if ($line -match "^\s*$([regex]::Escape($Key))\s*=\s*(.*)$") {
                    $val = $matches[1].Trim()
                }
            }
        }
    } catch { }
    return $val
}

function Get-GdpiSettingInt {
    param([string]$Key, [int]$Default)
    $raw = Get-GdpiSettingRaw -Key $Key
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
    $parsed = 0
    if ([int]::TryParse($raw, [ref]$parsed)) { return $parsed }
    return $Default
}

function Get-GdpiSettingBool {
    param([string]$Key, [bool]$Default)
    $raw = Get-GdpiSettingRaw -Key $Key
    if ($raw -eq '1') { return $true }
    if ($raw -eq '0') { return $false }
    return $Default
}

# Returns $true on a confirmed write, $false on any failure; all keys in
# $Settings are merged into the existing file and committed in a single
# atomic temp-file + rename, so a partial write can never leave
# FORCE_DNS_INDEX and BYPASS_ALL out of sync; callers must check the result
# because the Auto Start scheduled task carries no flags (this file is the
# only way a choice survives reboot).
function Set-GdpiSettings {
    param([System.Collections.IDictionary]$Settings)
    if (-not $script:SettingsFile) { return $false }
    $tmpPath = $null
    try {
        $dir = Split-Path -Parent $script:SettingsFile
        if (-not (Test-Path -LiteralPath $dir)) {
            # -ErrorAction Stop: this function's correctness must not depend
            # on the ambient $ErrorActionPreference set ~700 lines away at
            # the top of the file - a failed New-Item must reach the catch
            # below on its own, not merely because something else happens to
            # be strict right now.
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        }
        $merged = [ordered]@{}
        if (Test-Path -LiteralPath $script:SettingsFile) {
            foreach ($line in Get-Content -LiteralPath $script:SettingsFile -ErrorAction SilentlyContinue) {
                if ($line -match '^\s*([^=\s]+)\s*=\s*(.*)$') {
                    $merged[$matches[1]] = $matches[2]
                }
            }
        }
        foreach ($k in $Settings.Keys) {
            $merged[$k] = [string]$Settings[$k]
        }
        $tmpPath = "$script:SettingsFile.tmp"
        $lines = foreach ($k in $merged.Keys) { "$k=$($merged[$k])" }
        [System.IO.File]::WriteAllLines($tmpPath, [string[]]$lines)
        # -ErrorAction Stop: same reasoning as New-Item above - a failed
        # Move-Item must throw into the catch on its own merits, not because
        # $ErrorActionPreference happens to be 'Stop' at the top of the file.
        Move-Item -LiteralPath $tmpPath -Destination $script:SettingsFile -Force -ErrorAction Stop
        return $true
    } catch {
        # Best-effort cleanup so a failed write doesn't leave "settings.tmp"
        # litter next to the real file. Never let this mask the real
        # failure: swallow any error from the cleanup itself.
        if ($tmpPath) {
            try { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue } catch { }
        }
        return $false
    }
}

# =============================================================================
# Auto-start safety gate
# =============================================================================
# The tray's "Auto Start" toggle registers a logon task with -RunLevel
# Highest: fully elevated, at every logon, with no UAC prompt, and its action
# is "powershell.exe -File <start.ps1>". If that script sits somewhere a
# standard user can write - an extracted ZIP in Downloads, a copy on the
# Desktop - then anyone (or anything) running as that user can rewrite
# start.ps1 and have it executed at high integrity at the next logon. That is
# a straight UAC bypass and a persistence primitive, so the task must never
# point at a user-writable path.
#
# The test is the real DACL rather than a path prefix. "Under Program Files"
# is only a proxy for "protected", and a misconfigured Program Files
# subdirectory (an installer that granted Users:M, a folder restored from
# backup without inheriting) would sail through a prefix check while being
# just as exploitable. Path containment is kept purely as the fallback for
# when the ACL genuinely cannot be read.
#
# Known limitation: parent directories are NOT walked. Write access on a
# parent would allow renaming the whole tree into place, but the default ACLs
# on %ProgramFiles% and its ancestors already prevent that, and walking the
# chain risks refusing legitimate installs on domain-managed hosts.
#
# windows\install.ps1 carries an identical copy of this function for its
# -TaskOnly path - the two task-registration sites must agree.
function Test-GdpiPathIsProtected {
    param([Parameter(Mandatory = $true)][string]$Path)

    # Compared by SID, never by account name: this behaves identically on
    # non-English Windows and needs no name resolution at all (no
    # domain-controller round-trip, nothing to fail on an offline machine).
    $trustedSids = @(
        'S-1-5-18',                                                        # NT AUTHORITY\SYSTEM
        'S-1-5-32-544',                                                    # BUILTIN\Administrators
        'S-1-3-0',                                                         # CREATOR OWNER
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'   # TrustedInstaller
    )
    # Rights that let a principal change what the logon task will execute.
    # 0x10000000 / 0x40000000 are GENERIC_ALL / GENERIC_WRITE: the inherit-only
    # ACEs on %ProgramFiles% carry generic bits rather than specific ones, so a
    # mask of specific rights alone would silently miss them.
    # WriteAttributes / WriteExtendedAttributes are deliberately excluded -
    # they cannot alter file content and are granted broadly enough to cause
    # false refusals.
    $writeMask =
        [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
        [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        0x10000000 -bor 0x40000000

    # Both the file and its directory: rewriting start.ps1 in place and
    # replacing it through the directory are the same attack.
    $targets = @((Split-Path -Parent $Path), $Path) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if (-not $targets) { return $false }

    $aclChecked = $false
    foreach ($target in $targets) {
        $rules = $null
        try {
            # Asking for SecurityIdentifier returns the ACEs already as SIDs,
            # so there is no NTAccount translation step that can fail.
            $rules = (Get-Acl -LiteralPath $target -ErrorAction Stop).GetAccessRules(
                $true, $true, [System.Security.Principal.SecurityIdentifier])
        } catch {
            continue    # unreadable DACL - the path fallback below covers it
        }
        $aclChecked = $true
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (([int]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
            if ($trustedSids -notcontains $rule.IdentityReference.Value) { return $false }
        }
    }
    if ($aclChecked) { return $true }

    # Fallback, reached only when no DACL could be read on either target:
    # accept a path physically inside Program Files / Windows, nothing else.
    $roots = @(
        [Environment]::GetFolderPath('ProgramFiles'),
        ${env:ProgramFiles(x86)},
        $env:ProgramW6432,
        $env:SystemRoot
    ) | Where-Object { $_ }
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $false }
    foreach ($root in $roots) {
        $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if ($full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# =============================================================================
# Tray Mode - standalone tray icon process
# =============================================================================
if ($TrayMode) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # These $script:-prefixed assignments are technically no-ops: a script
    # invoked via -File already runs at script scope by default, so e.g.
    # $script:ProgramsList and the bare param $ProgramsList are the same
    # storage cell, and a WinForms Add_Click closure below would read the
    # bare param name correctly with no copy present at all. Kept anyway as
    # explicit documentation of which values the closures rely on, and as a
    # safety net if this block is ever refactored into a function (where the
    # distinction would start to matter).
    $script:ProgramsList    = $ProgramsList
    $script:GoodbyePid      = $GoodbyePid
    $script:notify          = $null
    $script:StartScriptPath = $StartScriptPath
    $script:bypassAllEnabled = ($BypassAllCurrent -ne 0)
    # The user's DNS *preference* (-1 = auto-detect), as resolved by the CLI
    # vs persisted precedence block in Main before the tray was spawned - NOT
    # $CurrentDnsIndex, which is just whatever auto-detect happened to pick.
    # Every restart below must carry this so a knob the user didn't touch
    # doesn't silently change value.
    $script:forceDnsIndex   = $ForceDnsIndex

    # =============================================================================
    # Orphan prevention - Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    # =============================================================================
    # Every place below that stops goodbyedpi.exe (Exit, Invoke-GdpiRestart,
    # Uninstall) does it from a handler running INSIDE this process's own
    # message loop. None of that runs if this tray host itself is hard-killed
    # - Task Manager "End task", taskkill, closing the window from Windows+Tab
    # Task View, or a crash all tear the process down without ever reaching a
    # Click handler, FormClosed, or so much as a CLR finally block. goodbyedpi
    # then keeps running orphaned, with no UI left to stop it.
    # Application.ApplicationExit, PowerShell.Exiting, and a console Ctrl
    # handler are all equally useless here - a hard kill runs none of them
    # either, so none of that is worth wiring up as the real fix.
    #
    # The one mechanism the kernel enforces regardless of how this process
    # dies: put goodbyedpi.exe in a Job Object with
    # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. As long as this process keeps the
    # job handle open, goodbyedpi.exe stays a member; the instant Windows
    # closes this process's handles - for ANY reason, graceful or not - the
    # kernel tears down every remaining process still in the job. No handler
    # has to run for this to work; that is the whole point.
    #
    # Add-Type is guarded because re-defining an identical type in the same
    # PowerShell session throws. -TrayMode never actually re-enters an
    # existing session in normal use (each tray is its own process), but
    # guard it anyway rather than assume that stays true.
    if (-not ('GdpiJobObject' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class GdpiJobObject {
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
    const int JobObjectExtendedLimitInformation = 9;
    const uint PROCESS_TERMINATE = 0x0001;
    const uint PROCESS_SET_QUOTA = 0x0100;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    // Creates a job with KILL_ON_JOB_CLOSE and assigns the given process id
    // to it. Returns the job handle on success - the caller owns it and must
    // keep it open for as long as it wants the target process tied to its
    // own lifetime - or IntPtr.Zero on any failure. Never throws: every
    // Win32 call is checked and any failure just tears down what was opened
    // so far and returns Zero, so a P/Invoke problem can never crash or
    // block the caller.
    public static IntPtr CreateKillOnCloseJobForProcess(int processId) {
        IntPtr hJob = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero;
        try {
            hJob = CreateJobObject(IntPtr.Zero, null);
            if (hJob == IntPtr.Zero) return IntPtr.Zero;

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr infoPtr = Marshal.AllocHGlobal(length);
            try {
                Marshal.StructureToPtr(info, infoPtr, false);
                if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, infoPtr, (uint)length)) {
                    CloseHandle(hJob);
                    return IntPtr.Zero;
                }
            } finally {
                Marshal.FreeHGlobal(infoPtr);
            }

            // PROCESS_SET_QUOTA is required by AssignProcessToJobObject itself
            // (not just PROCESS_TERMINATE) - this runs elevated so both are
            // expected to succeed against goodbyedpi.exe, but a denial here
            // must degrade gracefully rather than throw.
            hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA, false, processId);
            if (hProcess == IntPtr.Zero) {
                CloseHandle(hJob);
                return IntPtr.Zero;
            }

            if (!AssignProcessToJobObject(hJob, hProcess)) {
                // Rare on Windows 8+ (nested jobs are allowed), but a process
                // already in a job created without break-away permission can
                // still refuse this on older systems - degrade gracefully.
                CloseHandle(hJob);
                return IntPtr.Zero;
            }

            return hJob;
        } catch {
            if (hJob != IntPtr.Zero) { try { CloseHandle(hJob); } catch { } }
            return IntPtr.Zero;
        } finally {
            if (hProcess != IntPtr.Zero) { try { CloseHandle(hProcess); } catch { } }
        }
    }
}
'@
    }

    # Create the job and assign goodbyedpi to it immediately, before this
    # process does anything else that could exit early.
    #
    # $script:trayJobHandle keeps the raw job handle referenced for the rest
    # of this process's life - this is deliberate, not incidental. The
    # handle is a plain IntPtr, not a .NET SafeHandle, so the GC was never
    # going to close it out from under us on its own; the $script: scoping
    # here exists to make that lifetime requirement explicit and to survive
    # any future refactor that moves this block into a function. Never call
    # CloseHandle on this from anywhere else in Tray Mode, and never let it
    # go out of scope early - closing it while goodbyedpi.exe should still be
    # running is exactly the orphan bug this block exists to prevent. It is
    # only ever allowed to close the way it's meant to: implicitly, when
    # Windows tears down this process's handles because the process itself
    # is gone.
    $script:trayJobHandle = [IntPtr]::Zero
    # Write-Host below goes to a hidden console nobody reads. Remember the
    # failure so the balloon right after the icon becomes visible can tell
    # the user their one guarantee against an orphaned goodbyedpi.exe is not
    # in force on this run.
    $script:jobFailed = $false
    try {
        $script:trayJobHandle = [GdpiJobObject]::CreateKillOnCloseJobForProcess($script:GoodbyePid)
    } catch {
        $script:trayJobHandle = [IntPtr]::Zero
    }
    if ($script:trayJobHandle -eq [IntPtr]::Zero) {
        # Not fatal - this is the belt, not the only thing holding the pants
        # up: Exit / Invoke-GdpiRestart / Uninstall all still Stop-Process
        # goodbyedpi.exe directly on their own paths below. Only a hard kill
        # of this tray host is left uncovered if this failed.
        $script:jobFailed = $true
        Write-Host '[tray] WARN: could not create kill-on-close job for goodbyedpi.exe - if this tray is force-killed (Task Manager, taskkill, etc.) goodbyedpi.exe may be left running. Exit/Restart/Uninstall from the tray menu still stop it normally.'
    }

    # =============================================================================
    # Terminal teardown - stop goodbyedpi.exe AND release the WinDivert driver
    # =============================================================================
    # Every path that stops goodbyedpi.exe does it with a hard kill:
    # Stop-Process -Force is TerminateProcess, and so is the Job Object's
    # kill-on-close above. Neither delivers a signal, so goodbyedpi.exe's own
    # cleanup (sigint_handler -> deinit_all -> WinDivertShutdown /
    # WinDivertClose, goodbyedpi.c) NEVER runs on any exit this tray can
    # trigger.
    #
    # Packet filtering does stop regardless - the kernel closes the WinDivert
    # handles when the process dies - but the WinDivert *kernel driver
    # service* is a separate object with its own lifetime, and nothing ever
    # stopped it. It stays loaded and RUNNING with no user left, which is
    # exactly what makes "I closed the tray but something is still running in
    # the background" literally true: `sc query WinDivert` reports RUNNING
    # long after the last goodbyedpi.exe is gone.
    #
    # uninstall.ps1 already does this (its `sc.exe stop WinDivert`), so the
    # driver was only ever released on a full uninstall - never on a normal
    # tray Exit. This function closes that gap for the terminal exits.
    #
    # NOT used by Invoke-GdpiRestart: a restart re-opens the driver
    # immediately, so unloading it there would only add latency and a window
    # in which the replacement can fail to acquire it.
    function Stop-GdpiEngine {
        try { Stop-Process -Id $script:GoodbyePid -Force -ErrorAction SilentlyContinue } catch { }
        # A stray instance from an earlier run keeps a handle open and would
        # make the driver stop below fail, so clear those too.
        try {
            Get-Process -Name 'goodbyedpi' -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
        } catch { }

        # Process teardown is asynchronous and the driver refuses to stop
        # while any handle is still open - give the kernel a moment to reap
        # them. This blocks the UI thread, which is fine on a path whose whole
        # purpose is to tear this window down; capped so a wedged process
        # cannot hang the exit.
        try {
            $deadline = [DateTime]::UtcNow.AddSeconds(2)
            while ([DateTime]::UtcNow -lt $deadline) {
                if (-not (Get-Process -Name 'goodbyedpi' -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 100
            }
        } catch { }

        # Only ever unload OUR copy. WinDivert is a shared component - other
        # software (and a second GoodbyeDPI install elsewhere) can have the
        # same service loaded from a different binary, and stopping that would
        # break them. sc.exe qc reports the registered BINARY_PATH_NAME, so
        # compare it against this install's own directory and leave anything
        # else alone.
        try {
            $appDir = if ($script:StartScriptPath) { Split-Path -Parent $script:StartScriptPath } else { $null }
            if ($appDir) {
                $qc = (& sc.exe qc WinDivert 2>$null | Out-String)
                if ($qc -and $qc.IndexOf($appDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    & sc.exe stop WinDivert 2>&1 | Out-Null
                }
            }
        } catch {
            # sc.exe needs administrator rights. The tray normally runs
            # elevated (goodbyedpi.exe cannot load WinDivert otherwise), but a
            # hand-run tray might not - leaving the driver loaded is no worse
            # than the behaviour this function replaced.
        }
    }

    # Kill goodbyedpi, hide this icon, and restart with the given full
    # argument string. Shared by all three restart-triggering menu actions
    # below so they stay deduplicated - do not copy this per handler.
    #
    # Deliberately does NOT persist, poll, or verify the replacement comes
    # up: Main (below) unconditionally kills every existing goodbyedpi
    # process AND every "-TrayMode" powershell process as its very first
    # actions - including this tray, mid-restart - so nothing running here
    # could ever observe a restart's outcome. Settings are written by Main
    # itself, only after ITS OWN health check passes (see "-PersistOnSuccess"
    # near the tray spawn below) - a failed start therefore never touches the
    # settings file, and the file always holds the last known-good choice.
    function Invoke-GdpiRestart {
        param([Parameter(Mandatory)][string]$RestartArgs)

        try {
            Stop-Process -Id $script:GoodbyePid -Force -ErrorAction SilentlyContinue
        } catch { }
        try {
            if ($script:notify) { $script:notify.Visible = $false }
        } catch { }
        $restartStr = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$($script:StartScriptPath)`" $RestartArgs -PersistOnSuccess"
        try {
            Start-Process -FilePath 'powershell.exe' -ArgumentList $restartStr -WindowStyle Hidden
        } catch { }
        [System.Windows.Forms.Application]::Exit()
    }

    # Parse DnsCandidatesInfo: "Name|Addr|Port|TimeMs|Status;Name|Addr|Port|TimeMs|Status;..."
    $script:dnsItems = @()
    if ($DnsCandidatesInfo) {
        foreach ($entry in $DnsCandidatesInfo.Split(';')) {
            if (-not $entry) { continue }
            $parts = $entry.Split('|')
            if ($parts.Count -ge 5) {
                $script:dnsItems += @{
                    Name   = $parts[0]
                    Addr   = $parts[1]
                    Port   = [int]$parts[2]
                    TimeMs = [int]$parts[3]
                    Status = $parts[4]
                }
            }
        }
    }
    $script:currentDnsIndex = $CurrentDnsIndex

    # Test-Path only proves the file exists, not that it is a loadable .ico:
    # a truncated/corrupt icon, or one locked by an installer still copying
    # it, makes the Icon constructor throw ArgumentException/IOException, and
    # under $ErrorActionPreference = 'Stop' that kills this whole tray host
    # before the icon is ever shown - leaving goodbyedpi.exe running with no
    # UI. The tray icon's appearance is not worth the process: fall back to
    # the stock system icon and keep going. Identical outcome to before
    # whenever the file is good.
    $icon = $null
    try {
        if (Test-Path -LiteralPath $IconPath) {
            $icon = New-Object System.Drawing.Icon($IconPath)
        }
    } catch { $icon = $null }
    if (-not $icon) { $icon = [System.Drawing.SystemIcons]::Application }

    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Icon    = $icon
    $notify.Text    = 'GoodByeDPI-Plus'
    $notify.Visible = $true
    $script:notify  = $notify

    # Tell Main it can stop waiting and return. This exact point is the
    # earliest one that proves both things Main actually cares about: the Job
    # Object above has already been assigned (goodbyedpi.exe is now tied to
    # this process's lifetime by the kernel) and the tray icon is visible, so
    # the user has a way to stop it. Anything that goes wrong further down
    # while building the menu needs no extra handling here - it kills this
    # host, and the Job Object takes goodbyedpi.exe down with it, which is
    # precisely the outcome Main's failure path would have forced anyway.
    # Every failure mode is swallowed: a tray that is up must never die
    # because it could not report that it is up.
    if ($ReadyEvent) {
        try {
            $evt = [System.Threading.EventWaitHandle]::OpenExisting($ReadyEvent)
            $null = $evt.Set()
            $evt.Dispose()
        } catch { }
    }

    $menu = New-Object System.Windows.Forms.ContextMenuStrip

    # DNS dropdown menu
    $dnsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $dnsMenuItem.Text = "DNS: $DnsLabel"

    # Add each candidate as a sub-item
    for ($i = 0; $i -lt $script:dnsItems.Count; $i++) {
        $item = $script:dnsItems[$i]
        $timeStr = if ($item.TimeMs -ge 0) { "$($item.TimeMs)ms" } else { 'n/a' }
        $label = "$($item.Name) $($item.Addr):$($item.Port) ($timeStr)"
        if ($item.Status -ne 'ok') {
            $label += " [$($item.Status)]"
        }
        $subItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $subItem.Text = $label
        $subItem.Tag = $i
        if ($i -eq $script:currentDnsIndex) {
            $subItem.Checked = $true
        }
        $subItem.Add_Click({
            $idx = [int]$this.Tag
            # Bypass mode is unaffected by a DNS pick - same flag both ways.
            $bypassArg = if ($script:bypassAllEnabled) { '-BypassAll' } else { '-NoBypassAll' }
            Invoke-GdpiRestart -RestartArgs "-ForceDnsIndex $idx $bypassArg"
        })
        [void]$dnsMenuItem.DropDownItems.Add($subItem)
    }

    # Separator + Auto-detect option in dropdown
    [void]$dnsMenuItem.DropDownItems.Add('-')

    $autoItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $autoItem.Text = 'Auto-detect (re-test)'
    $autoItem.Add_Click({
        $bypassArg = if ($script:bypassAllEnabled) { '-BypassAll' } else { '-NoBypassAll' }
        Invoke-GdpiRestart -RestartArgs "-ForceDnsIndex -1 $bypassArg"
    })
    [void]$dnsMenuItem.DropDownItems.Add($autoItem)

    [void]$menu.Items.Add($dnsMenuItem)

    [void]$menu.Items.Add('-')

    $editItem = $menu.Items.Add('Edit Program Filters')
    $editItem.Add_Click({
        try {
            Start-Process -FilePath $script:ProgramsList
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to open Program Filters:`r`n$_", 'GoodByeDPI-Plus', 'OK', 'Warning')
        }
    })

    # Bypass All Traffic toggle - when checked, goodbyedpi runs without
    # --only-programs (bypasses everything); when unchecked, only programs
    # in programs.txt are bypassed.
    $bypassAllItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $bypassAllItem.Text = 'Bypass All Traffic'
    $bypassAllItem.Checked = $script:bypassAllEnabled
    $bypassAllItem.Add_Click({
        $newState = -not $this.Checked
        $newBypassArg = if ($newState) { '-BypassAll' } else { '-NoBypassAll' }
        # Carry the DNS preference too (not $script:currentDnsIndex, which is
        # only the active pick) so toggling bypass mode can never change it -
        # -1 (auto-detect) travels as an explicit flag, same as the DNS items.
        Invoke-GdpiRestart -RestartArgs "-ForceDnsIndex $($script:forceDnsIndex) $newBypassArg"
    })
    [void]$menu.Items.Add($bypassAllItem)

    [void]$menu.Items.Add('-')

    # Auto Start toggle
    $autoStartItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $autoStartItem.Text = 'Auto Start'
    $taskName = 'GoodByeDPI-Plus'
    # -ErrorAction SilentlyContinue covers "task not found", but NOT the
    # ScheduledTasks module being absent entirely (Windows editions/images
    # that ship without it, or a stripped $env:PSModulePath): that surfaces
    # as a CommandNotFoundException raised before the cmdlet's parameters are
    # ever bound, which -ErrorAction cannot suppress, and which
    # $ErrorActionPreference = 'Stop' turns into a fatal error that kills the
    # tray host mid-build. Swallow it and leave .Checked at its default
    # $false - a wrong checkmark is survivable, a missing tray icon (with
    # goodbyedpi still running behind it) is not. The Add_Click handler below
    # keeps its own try/catch and reports failures to the user directly.
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            $autoStartItem.Checked = $true
        }
    } catch { }
    $autoStartItem.Add_Click({
        $taskName = 'GoodByeDPI-Plus'
        try {
            if ($this.Checked) {
                # Disable auto-start
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                $this.Checked = $false
                if ($script:notify) {
                    $script:notify.ShowBalloonTip(2000, 'GoodByeDPI-Plus', 'Auto-start disabled', [System.Windows.Forms.ToolTipIcon]::Info)
                }
            } else {
                # Enable auto-start
                # Refuse to point an elevated logon task at a script anyone
                # can rewrite. Leave the checkbox unticked and say why: the
                # tray, the bypass and every other menu item keep working,
                # only silent auto-start is withheld.
                if (-not (Test-GdpiPathIsProtected -Path $script:StartScriptPath)) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Auto Start cannot be enabled from this location.`r`n`r`n" +
                        "$($script:StartScriptPath)`r`n`r`n" +
                        "is in a directory that non-administrator accounts can write to. " +
                        "The logon task runs elevated with no UAC prompt, so enabling it " +
                        "here would let any program running as you replace the script and " +
                        "gain administrator rights at your next logon.`r`n`r`n" +
                        "Install with the Setup installer, or copy this folder under " +
                        "Program Files and start it from there.",
                        'GoodByeDPI-Plus', 'OK', 'Warning') | Out-Null
                    $this.Checked = $false
                    return
                }
                $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File `"$($script:StartScriptPath)`""
                $trigger = New-ScheduledTaskTrigger -AtLogOn
                $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
                $this.Checked = $true
                if ($script:notify) {
                    $script:notify.ShowBalloonTip(2000, 'GoodByeDPI-Plus', 'Auto-start enabled', [System.Windows.Forms.ToolTipIcon]::Info)
                }
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to toggle auto-start.`r`n$_`r`n`r`nMake sure you run as administrator.", 'GoodByeDPI-Plus', 'OK', 'Warning')
        }
    })
    [void]$menu.Items.Add($autoStartItem)

    [void]$menu.Items.Add('-')

    # Uninstall - confirm, then launch uninstall.ps1 elevated. uninstall.ps1
    # already self-elevates and kills the tray host + goodbyedpi, so don't
    # duplicate that here - just launch it and exit this tray cleanly.
    $uninstallItem = $menu.Items.Add('Uninstall')
    $uninstallItem.Add_Click({
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "This will remove GoodByeDPI-Plus (scheduled task, shortcuts) and stop goodbyedpi.`r`n`r`nContinue?",
            'GoodByeDPI-Plus', 'YesNo', 'Warning')
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        try {
            $appDir = Split-Path -Parent $script:StartScriptPath
            # An Inno Setup install leaves its own uninstaller (unins*.exe)
            # next to start.ps1. Running uninstall.ps1 in that case would drop
            # the scheduled task and the shortcuts but leave the installed
            # files and the "Apps & features" entry behind, so hand the job to
            # Inno when it is there - it runs uninstall.ps1 itself, first, via
            # [UninstallRun]. Without Inno (a plain install.ps1 layout) nothing
            # changes: uninstall.ps1 is launched directly, as before.
            $innoUninstaller = Get-ChildItem -LiteralPath $appDir -Filter 'unins*.exe' -File -ErrorAction SilentlyContinue |
                Sort-Object Name | Select-Object -First 1
            if ($innoUninstaller) {
                Start-Process -FilePath $innoUninstaller.FullName -Verb RunAs
            } else {
                $uninstallScript = Join-Path $appDir 'uninstall.ps1'
                Start-Process -FilePath 'powershell.exe' -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$uninstallScript`"" -Verb RunAs
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to launch uninstaller:`r`n$_", 'GoodByeDPI-Plus', 'OK', 'Warning')
            return
        }
        try {
            if ($script:notify) { $script:notify.Visible = $false }
        } catch { }
        [System.Windows.Forms.Application]::Exit()
    })

    [void]$menu.Items.Add('-')

    $exitItem = $menu.Items.Add('Exit')
    $exitItem.Add_Click({
        try {
            if ($script:notify) { $script:notify.Visible = $false }
        } catch { }
        try {
            # Not a bare Stop-Process: the driver has to come down with the
            # process, or the user closes the tray and WinDivert is still
            # loaded with nothing left to use it. See Stop-GdpiEngine above.
            Stop-GdpiEngine
        } catch { }
        [System.Windows.Forms.Application]::Exit()
    })

    $notify.ContextMenuStrip = $menu
    $notify.ShowBalloonTip(3000, 'GoodByeDPI-Plus', "Running - DNS: $DnsLabel", [System.Windows.Forms.ToolTipIcon]::Info)
    if ($PersistFailed) {
        # Main (below) sets this when it started successfully but its
        # post-health-check settings write failed. Main itself runs hidden
        # with no UI, so this is the first point where the user can actually
        # see the warning - the choice is still active for this session, but
        # will NOT survive a reboot.
        $notify.ShowBalloonTip(6000, 'GoodByeDPI-Plus', 'Warning: could not save your settings - they may not survive a reboot.', [System.Windows.Forms.ToolTipIcon]::Warning)
    }
    if ($script:jobFailed) {
        # Deliberately the LAST balloon in this block. Windows only ever
        # displays the most recent one, so whichever fires last is the only
        # one the user is actually left looking at - and this warning outranks
        # both of the above. "Running - DNS: ..." is a routine confirmation
        # and the -PersistFailed notice only costs a setting at next boot,
        # whereas this one means the kernel-enforced guarantee that
        # goodbyedpi.exe dies with this tray is NOT in force: force-close this
        # process and goodbyedpi keeps running with nothing left to stop it.
        # Placing it earlier looks correct but is useless in practice - the
        # menu build between here and there takes on the order of a second
        # (a cold ScheduledTasks module load alone is most of it), so an
        # earlier balloon is replaced roughly a second into its 6000ms and is
        # never really seen.
        try {
            $notify.ShowBalloonTip(6000, 'GoodByeDPI-Plus',
                'Warning: could not bind goodbyedpi.exe to this tray icon - it may keep running if the tray is force-closed.',
                [System.Windows.Forms.ToolTipIcon]::Warning)
        } catch { }
    }

    $exitForm = New-Object System.Windows.Forms.Form
    $exitForm.ShowInTaskbar = $false
    $exitForm.WindowState   = 'Minimized'
    $exitForm.Opacity       = 0
    # This form exists only to host ShowDialog()'s message pump below - it
    # is never meant to be seen or reachable. ShowInTaskbar=$false and
    # Opacity=0 only hide it from the taskbar and the naked eye; they do NOT
    # stop Windows from listing it in Task View (Windows+Tab) / Alt-Tab, and
    # that listing is more than cosmetic here: because Opacity=0 is
    # implemented as a layered window with LWA_ALPHA (not WS_EX_TRANSPARENT),
    # if the entry is ever activated from Task View, Windows un-minimizes
    # this form to a real, focused, on-screen rect that is fully
    # click-through-*less* - invisible but still eats clicks - until the user
    # Alt-Tabs away. The fix is to keep the form out of that list entirely so
    # there is never an entry to activate: FixedToolWindow makes WinForms add
    # WS_EX_TOOLWINDOW to the window's extended style in CreateParams, and
    # WS_EX_TOOLWINDOW is precisely the bit the shell's owner-chain walk
    # checks to exclude a window from Alt-Tab/Task View, regardless of
    # ShowInTaskbar or owner. FormBorderStyle also drives the caption/border
    # WinForms draws, but that's moot for a form that is always Minimized at
    # Opacity 0 and never shown. $exitForm.Text/.Icon below are kept anyway
    # (see next comment): with WS_EX_TOOLWINDOW set there is no longer any
    # normal UI surface that shows them - Task Manager's Processes tab takes
    # its name and icon from the host executable (powershell.exe), not from a
    # window's Text/Icon - but they cost nothing and keep the window honestly
    # labelled for anything that does read window text directly (window spies,
    # debuggers, accessibility tooling).
    $exitForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    # $icon is the same Icon already resolved above for the tray (custom
    # -IconPath, or SystemIcons.Application if that file is missing) -
    # reusing it costs nothing and never throws.
    $exitForm.Text = 'GoodByeDPI-Plus'
    $exitForm.Icon = $icon
    $exitForm.Add_FormClosed({
        try { if ($script:notify) { $script:notify.Visible = $false } } catch { }
        try { if ($script:notify) { $script:notify.Dispose() } } catch { }
    })
    $notify.Tag = $exitForm

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 500
    $timer.Add_Tick({
        try {
            $p = Get-Process -Id $script:GoodbyePid -ErrorAction SilentlyContinue
            if (-not $p) {
                if ($script:notify) {
                    $script:notify.ShowBalloonTip(3000, 'GoodByeDPI-Plus', 'goodbyedpi.exe exited unexpectedly', [System.Windows.Forms.ToolTipIcon]::Warning)
                }
                Start-Sleep -Milliseconds 2
                $timer.Stop()
                # goodbyedpi.exe is already gone, but if it died rather than
                # exiting cleanly it left the WinDivert driver loaded behind
                # it. This tray is closing either way, so release it here too
                # - otherwise this is the one terminal path that still leaks
                # a running driver.
                try { Stop-GdpiEngine } catch { }
                $exitForm.Close()
            }
        } catch { }
    })
    $timer.Start()

    [void]$exitForm.ShowDialog()
    exit
}

# =============================================================================
# Config
# =============================================================================
$enableTray      = $true
$autoDetectDns   = $true
$dnsTimeoutMs    = 800
$dnsTestDomain   = 'discord.com'
$blockPageRanges = @('195.175.254.')
$bypassMode      = '--auto-ttl --max-payload'

$dnsCandidates = @(
    @{ Name='Yandex';     Addr='77.88.8.8';      Port=1253; V6Addr='2a02:6b8::feed:0ff';    V6Port=1253 }
    @{ Name='Yandex';     Addr='77.88.8.8';      Port=53;   V6Addr='2a02:6b8::feed:0ff';    V6Port=53 }
    @{ Name='Cloudflare'; Addr='1.1.1.1';        Port=53;   V6Addr='2606:4700:4700::1111';  V6Port=53 }
    @{ Name='Quad9';      Addr='9.9.9.9';        Port=53;   V6Addr='2620:fe::fe';           V6Port=53 }
    @{ Name='AdGuard';    Addr='94.140.14.14';   Port=53;   V6Addr='2a10:50c0::ad1:ff';     V6Port=53 }
)
$fallbackDns = @{ Name='Yandex'; Addr='77.88.8.8'; Port=1253; V6Addr='2a02:6b8::feed:0ff'; V6Port=1253; TimeMs=0 }

# =============================================================================
# Setup
# =============================================================================
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$programsListPath = Join-Path $scriptDir 'programs.txt'
$iconPathResolved = Join-Path $scriptDir 'icon.ico'
$startScriptPathResolved = $MyInvocation.MyCommand.Path

# OS bitness, not process bitness - the tray can legitimately be launched
# from either the 32- or the 64-bit PowerShell. The old test sniffed
# $env:PROCESSOR_ARCHITEW6432, which is absent both in a native 64-bit
# process and on 32-bit Windows; an absent variable is $null, and
# `$null -ne ''` is TRUE, so 32-bit Windows was handed the x86_64 binary and
# goodbyedpi.exe could not start at all.
if ([Environment]::Is64BitOperatingSystem) {
    $arch = 'x86_64'
} else {
    $arch = 'x86'
}
$exePath = Join-Path $scriptDir "$arch\GoodbyeDPI.exe"

if ($NoTray)      { $enableTray    = $false }
if ($NoDnsDetect) { $autoDetectDns = $false }

# =============================================================================
# CLI vs persisted settings precedence
# An explicit CLI parameter always wins over the persisted value (mirrors
# linux/start.sh's *_FROM_CLI flags). -ForceDnsIndex defaults to -1, which is
# indistinguishable from "the user explicitly chose auto-detect" by value
# alone, so use $PSBoundParameters to tell "not passed" from "passed as -1".
# =============================================================================
if (-not $PSBoundParameters.ContainsKey('ForceDnsIndex')) {
    $ForceDnsIndex = Get-GdpiSettingInt -Key 'FORCE_DNS_INDEX' -Default -1
}

if ($PSBoundParameters.ContainsKey('NoBypassAll')) {
    $bypassAllEnabled = $false
} elseif ($PSBoundParameters.ContainsKey('BypassAll')) {
    $bypassAllEnabled = $true
} else {
    $bypassAllEnabled = Get-GdpiSettingBool -Key 'BYPASS_ALL' -Default $false
}

# =============================================================================
# DNS Functions
# =============================================================================

function Build-DnsQuery {
    param([string]$Domain)
    $b = [System.Collections.Generic.List[byte]]::new()
    $b.Add(0x12); $b.Add(0x34)
    $b.Add(0x01); $b.Add(0x00)
    $b.Add(0x00); $b.Add(0x01)
    $b.Add(0x00); $b.Add(0x00)
    $b.Add(0x00); $b.Add(0x00)
    $b.Add(0x00); $b.Add(0x00)
    foreach ($label in $Domain.Split('.')) {
        $b.Add([byte]$label.Length)
        $b.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
    }
    $b.Add(0x00)
    $b.Add(0x00); $b.Add(0x01)
    $b.Add(0x00); $b.Add(0x01)
    return $b.ToArray()
}

function Parse-DnsResponseA {
    param([byte[]]$Data)
    if ($Data.Length -lt 12) { return $null }
    $pos = 12
    while ($pos -lt $Data.Length -and $Data[$pos] -ne 0) {
        $pos += $Data[$pos] + 1
    }
    $pos += 5
    $answerCount = ($Data[6] -shl 8) -bor $Data[7]
    for ($i = 0; $i -lt $answerCount; $i++) {
        if ($pos -ge $Data.Length) { break }
        if ($Data[$pos] -band 0xC0) {
            $pos += 2
        } else {
            while ($pos -lt $Data.Length -and $Data[$pos] -ne 0) {
                $pos += $Data[$pos] + 1
            }
            $pos += 1
        }
        if ($pos + 10 -gt $Data.Length) { break }
        $type = ($Data[$pos] -shl 8) -bor $Data[$pos + 1]
        $pos += 8
        $rdLength = ($Data[$pos] -shl 8) -bor $Data[$pos + 1]
        $pos += 2
        if ($type -eq 1 -and $rdLength -eq 4 -and ($pos + 4) -le $Data.Length) {
            return "$($Data[$pos]).$($Data[$pos + 1]).$($Data[$pos + 2]).$($Data[$pos + 3])"
        }
        $pos += $rdLength
    }
    return $null
}

function Test-PoisonedIp {
    param([string]$Ip, [string[]]$BlockRanges)
    foreach ($range in $BlockRanges) {
        if ($Ip.StartsWith($range)) { return $true }
    }
    return $false
}

# Returns @{ Best=<hashtable>; Results=<array>; BestIndex=<int> }
# Each item in Results: @{ Name; Addr; Port; V6Addr; V6Port; TimeMs; Status }
function Find-FastestDns {
    $query = Build-DnsQuery $dnsTestDomain
    $states = [System.Collections.ArrayList]::new()

    foreach ($c in $dnsCandidates) {
        try {
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.Client.ReceiveTimeout = $dnsTimeoutMs
            $udp.Connect($c.Addr, $c.Port)
            $udp.Send($query, $query.Length) | Out-Null
            [void]$states.Add(@{ Udp = $udp; Server = $c; Ip = $null; TimeMs = -1 })
        } catch {
            [void]$states.Add(@{ Udp = $null; Server = $c; Ip = $null; TimeMs = -1; Error = $_.Exception.Message })
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $dnsTimeoutMs) {
        $anyPending = $false
        foreach ($s in $states) {
            if ($s.Ip -ne $null -or $s.Udp -eq $null) { continue }
            $anyPending = $true
            try {
                if ($s.Udp.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) {
                    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $data = $s.Udp.Receive([ref]$ep)
                    $s.TimeMs = $sw.ElapsedMilliseconds
                    $ip = Parse-DnsResponseA $data
                    if ($ip -and -not (Test-PoisonedIp $ip $blockPageRanges)) {
                        $s.Ip = $ip
                        Write-Host "[dns] $($s.Server.Name) $($s.Server.Addr):$($s.Server.Port) -> $ip ($($s.TimeMs)ms) OK"
                    } else {
                        $s.Ip = $null
                        $s.Status = if ($ip) { 'poisoned' } else { 'no-record' }
                        $label = if ($ip) { "$ip (poisoned)" } else { "no A record" }
                        Write-Host "[dns] $($s.Server.Name) $($s.Server.Addr):$($s.Server.Port) -> $label SKIP"
                    }
                }
            } catch { }
        }
        if (-not $anyPending) { break }
        Start-Sleep -Milliseconds 30
    }
    $sw.Stop()

    # Build results array (same order as $dnsCandidates)
    $results = @()
    for ($i = 0; $i -lt $dnsCandidates.Count; $i++) {
        $s = $states[$i]
        $status = 'ok'
        if ($s.Ip -eq $null) {
            if ($s.Udp -eq $null) {
                $status = 'unreachable'
            } elseif ($s.Status) {
                $status = $s.Status
            } else {
                $status = 'no-response'
            }
        }
        if ($s.Ip -eq $null -and $s.TimeMs -eq -1) {
            Write-Host "[dns] $($s.Server.Name) $($s.Server.Addr):$($s.Server.Port) -> no response SKIP"
        }
        $results += @{
            Name   = $s.Server.Name
            Addr   = $s.Server.Addr
            Port   = $s.Server.Port
            V6Addr = $s.Server.V6Addr
            V6Port = $s.Server.V6Port
            TimeMs = $s.TimeMs
            Status = $status
        }
    }

    foreach ($s in $states) {
        try { if ($s.Udp) { $s.Udp.Close() } } catch { }
    }

    # Find best (fastest valid)
    $bestIndex = -1
    $bestTimeMs = [int]::MaxValue
    for ($i = 0; $i -lt $results.Count; $i++) {
        if ($results[$i].Status -eq 'ok' -and $results[$i].TimeMs -ge 0 -and $results[$i].TimeMs -lt $bestTimeMs) {
            $bestIndex = $i
            $bestTimeMs = $results[$i].TimeMs
        }
    }

    if ($bestIndex -ge 0) {
        $best = $results[$bestIndex]
        Write-Host "[dns] Selected: $($best.Name) $($best.Addr):$($best.Port) ($($best.TimeMs)ms)"
    } else {
        Write-Host "[dns] No valid server found - using fallback: $($fallbackDns.Name) $($fallbackDns.Addr):$($fallbackDns.Port)"
        $bestIndex = 0
        $best = @{
            Name   = $fallbackDns.Name
            Addr   = $fallbackDns.Addr
            Port   = $fallbackDns.Port
            V6Addr = $fallbackDns.V6Addr
            V6Port = $fallbackDns.V6Port
            TimeMs = 0
            Status = 'fallback'
        }
        $results[0] = $best
    }

    return @{ Best = $best; Results = $results; BestIndex = $bestIndex }
}

# =============================================================================
# Main
# =============================================================================

# =============================================================================
# Serialize concurrent launches
# =============================================================================
# Two Mains can genuinely overlap in normal use - the Auto Start logon task
# firing while the user double-clicks the desktop shortcut is the common
# case. Both then run the kill sweep below, which takes out every
# goodbyedpi.exe by name AND every "-TrayMode" powershell process by command
# line, with no idea whose they are. Interleaved, Main #1's sweep lands on
# Main #2's brand-new tray host in the window before it has assigned its Job
# Object - so nothing is left to kill Main #2's goodbyedpi.exe, and nothing
# is left on screen to do it by hand. Exactly the orphan this file keeps
# trying to prevent.
#
# This lock SERIALIZES, it does not reject. "A new launch replaces the old
# one" is the product's existing and intended behaviour (that is what the
# sweep is for, and what every tray restart path depends on); the only thing
# wrong today is two launches doing it at the same time. So a second Main
# waits its turn, then proceeds normally and takes over.
#
# Global\ first so the lock also holds across sessions (the logon task and an
# interactive shortcut can land in different ones); Local\ is the fallback
# for contexts where the Global namespace is denied.
$script:startMutex     = $null
$script:startMutexHeld = $false
foreach ($mtxName in @('Global\GoodbyeDPI-Plus-Start', 'Local\GoodbyeDPI-Plus-Start')) {
    try {
        $script:startMutex = New-Object System.Threading.Mutex($false, $mtxName)
        break
    } catch {
        $script:startMutex = $null
    }
}
if ($script:startMutex) {
    try {
        $script:startMutexHeld = $script:startMutex.WaitOne(90000)
    } catch [System.Threading.AbandonedMutexException] {
        # A previous Main died while holding it. Windows hands the mutex to
        # us and reports the abandonment - abandoned means acquired, so this
        # is a successful wait, not a failure.
        $script:startMutexHeld = $true
    } catch {
        $script:startMutexHeld = $false
    }
    if (-not $script:startMutexHeld) {
        # 90s elapsed, or the wait itself failed. Starting unserialized is
        # strictly better than not starting at all - the pre-existing race is
        # the worst case, and it is the behaviour this file had all along.
        Write-Host '[start] WARN: timed out waiting for the previous launch - continuing anyway'
    }
}

# Released explicitly at every exit path below rather than from a try/finally
# wrapped around Main. Two reasons: Mutex ownership is thread-affine, so the
# release has to happen on the same thread that waited (which rules out
# Register-EngineEvent PowerShell.Exiting - its action runs on a different
# thread and ReleaseMutex would throw), and Main is a top-level script body
# with several bare `return`s that a single try/finally would have to be
# wrapped around wholesale. The failure mode of missing one is bounded
# anyway: if this process dies still holding the mutex, Windows marks it
# abandoned and the next waiter's AbandonedMutexException catch above treats
# that as acquired, so a crash can never wedge future launches.
function Release-GdpiStartLock {
    if ($script:startMutex) {
        if ($script:startMutexHeld) {
            try { $script:startMutex.ReleaseMutex() } catch { }
            $script:startMutexHeld = $false
        }
        try { $script:startMutex.Dispose() } catch { }
        $script:startMutex = $null
    }
}

# Kill existing goodbyedpi instances (prevent duplicates)
Get-Process -Name 'goodbyedpi' -ErrorAction SilentlyContinue | Stop-Process -Force

# Kill old tray processes (powershell.exe with -TrayMode in command line)
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*-TrayMode*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Check exe
if (-not (Test-Path -LiteralPath $exePath)) {
    # -ErrorAction Continue: under $ErrorActionPreference = 'Stop' (line 18),
    # a plain Write-Error is a terminating error and everything below it in
    # this block - including the MessageBox and the explicit return - would
    # never run. Continue keeps the message on the error stream (so a
    # scripted/redirected invocation still sees it) while letting execution
    # reach the dialog below.
    Write-Error "GoodbyeDPI.exe not found at $exePath" -ErrorAction Continue
    # Release BEFORE the dialog, not after: MessageBox::Show is modal and
    # blocks until someone clicks OK. Under the logon task the dialog can open
    # behind other windows and sit there unnoticed for as long as the user is
    # away, and every second of that is a second this process holds the
    # machine-wide start mutex - long enough to push a concurrent launch past
    # its 90s wait and into the unserialized path the lock exists to prevent.
    # Nothing below still needs the lock: no goodbyedpi and no tray were ever
    # started on this path.
    Release-GdpiStartLock
    if ($enableTray) {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("GoodbyeDPI.exe not found.`r`nReinstall GoodByeDPI-Plus.", 'GoodByeDPI-Plus', 'OK', 'Error')
    }
    return
}

# DNS detection
$dnsResults = $null
if ($autoDetectDns -or $ForceDnsIndex -ge 0) {
    try {
        $dnsResults = Find-FastestDns
    } catch {
        Write-Host "[dns] Detection failed: $_ - using fallback"
    }
}

# Determine which DNS to use
if ($ForceDnsIndex -ge 0 -and $ForceDnsIndex -lt $dnsCandidates.Count) {
    # Manual override from tray menu
    $c = $dnsCandidates[$ForceDnsIndex]
    $dns = @{ Name=$c.Name; Addr=$c.Addr; Port=$c.Port; V6Addr=$c.V6Addr; V6Port=$c.V6Port; TimeMs=0; Status='manual' }
    $currentDnsIndexResolved = $ForceDnsIndex
    Write-Host "[dns] Forced: $($dns.Name) $($dns.Addr):$($dns.Port)"
    # Build results from detection if available, otherwise build from candidates
    if (-not $dnsResults) {
        $dnsResults = @{ Best = $dns; Results = @(); BestIndex = $ForceDnsIndex }
        foreach ($c2 in $dnsCandidates) {
            $dnsResults.Results += @{ Name=$c2.Name; Addr=$c2.Addr; Port=$c2.Port; V6Addr=$c2.V6Addr; V6Port=$c2.V6Port; TimeMs=-1; Status='unknown' }
        }
        $dnsResults.Results[$ForceDnsIndex] = $dns
    }
} elseif ($dnsResults -and $dnsResults.Best) {
    $dns = $dnsResults.Best
    $currentDnsIndexResolved = $dnsResults.BestIndex
} else {
    $dns = $fallbackDns
    $currentDnsIndexResolved = 0
    $dnsResults = @{ Best = $dns; Results = @(); BestIndex = 0 }
    $dnsResults.Results += $dns
    for ($i = 1; $i -lt $dnsCandidates.Count; $i++) {
        $c = $dnsCandidates[$i]
        $dnsResults.Results += @{ Name=$c.Name; Addr=$c.Addr; Port=$c.Port; V6Addr=$c.V6Addr; V6Port=$c.V6Port; TimeMs=-1; Status='unknown' }
    }
}

# Build DnsCandidatesInfo string for tray
$dnsInfoParts = @()
foreach ($r in $dnsResults.Results) {
    $dnsInfoParts += "$($r.Name)|$($r.Addr)|$($r.Port)|$($r.TimeMs)|$($r.Status)"
}
$dnsCandidatesInfoResolved = $dnsInfoParts -join ';'

# Build params
$params = "--dns-addr $($dns.Addr) --dns-port $($dns.Port) --dnsv6-addr $($dns.V6Addr) --dnsv6-port $($dns.V6Port)"
if ($bypassMode) {
    $params = $params + " $bypassMode"
}
if ($bypassAllEnabled) {
    Write-Host '[start] Bypass All Traffic is ON - no --only-programs filter'
} else {
    # Per-program mode honours programs.txt exactly as it stands. An empty or
    # missing list means "bypass nothing" and is left that way - the mode is
    # the user's setting, and only the user may change it (mirrors
    # linux/start.sh's BYPASS_ALL=0 branch). Never silently promote a
    # missing file to bypass-all by omitting --only-programs.
    if (-not (Test-Path -LiteralPath $programsListPath)) {
        try {
            New-Item -ItemType File -Path $programsListPath | Out-Null
        } catch {
            Write-Host "[start] WARN: could not create $programsListPath - $_"
        }
    }
    $params = $params + " --only-programs `"$programsListPath`""
    $hasEntries = $false
    if (Test-Path -LiteralPath $programsListPath) {
        foreach ($line in (Get-Content -LiteralPath $programsListPath -ErrorAction SilentlyContinue)) {
            if ($line -match '\S' -and $line -notmatch '^\s*#') { $hasEntries = $true; break }
        }
    }
    if (-not $hasEntries) {
        Write-Host '[start] WARN: programs.txt is empty - per-program mode bypasses nothing'
    }
}

# Start goodbyedpi
$proc = Start-Process -FilePath $exePath -ArgumentList $params -WindowStyle Hidden -PassThru

# Health check
Start-Sleep -Milliseconds 500
if ($proc.HasExited) {
    # -ErrorAction Continue: see the exe-not-found check above - without it
    # this Write-Error is terminating and the MessageBox below (the only
    # user-facing feedback Main ever gives under -WindowStyle Hidden) never
    # runs.
    Write-Error "GoodbyeDPI.exe exited immediately. Run as administrator." -ErrorAction Continue
    # Released before the modal dialog for the reason given at the exe-missing
    # check above. goodbyedpi has already exited on its own here and no tray
    # was ever spawned, so the lock is protecting nothing at this point.
    Release-GdpiStartLock
    if ($enableTray) {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("GoodbyeDPI.exe failed to start.`r`nMake sure you run as administrator.", 'GoodByeDPI-Plus', 'OK', 'Error')
    }
    return
}

# Persist only now that goodbyedpi is confirmed up - never before an attempt.
# -PersistOnSuccess is passed only by the tray's own restart strings (see
# Invoke-GdpiRestart above), so a manual CLI run (e.g. a developer testing
# -ForceDnsIndex 2) never overwrites the user's stored preference, and an
# Auto Start boot (no flags; values already came FROM the file) never
# performs a pointless rewrite. Matches linux/tray.py being the sole writer.
$persistFailedResolved = $false
if ($PersistOnSuccess) {
    $writeOk = Set-GdpiSettings -Settings ([ordered]@{
        'FORCE_DNS_INDEX' = $ForceDnsIndex
        'BYPASS_ALL'       = $(if ($bypassAllEnabled) { '1' } else { '0' })
    })
    if (-not $writeOk) {
        $persistFailedResolved = $true
        # Main runs under -WindowStyle Hidden - nothing is visible here.
        # Write-Host/Write-Warning alone would never reach the user, so also
        # tell the about-to-spawn tray to raise a balloon once it is up (see
        # "-PersistFailed" in Tray Mode above). goodbyedpi itself is fine;
        # only the persisted choice is at risk of reverting at next boot.
        Write-Warning 'Could not save settings - the choice may not survive a reboot.'
    }
}

# Spawn tray process and exit (terminal closes, tray stays)
if ($enableTray) {
    $timeStr = if ($dns.TimeMs -gt 0) { "$($dns.TimeMs)ms" } else { 'fallback' }
    $dnsLabelResolved = "$($dns.Name) $($dns.Addr):$($dns.Port) ($timeStr)"
    $bypassAllCurrentArg = if ($bypassAllEnabled) { 1 } else { 0 }
    $persistFailedArg = if ($persistFailedResolved) { '-PersistFailed' } else { '' }

    # The handshake the tray host signals once it is genuinely up. A fresh
    # GUID per launch is the point of the name: a same-named event left over
    # from an earlier run (or one an unrelated process happens to hold) could
    # otherwise be already-signalled and satisfy the wait below instantly,
    # which would report success for a tray that never appeared - the exact
    # bug this whole block exists to catch. ManualReset so a signal that
    # arrives before we start waiting is not lost.
    #
    # Global\ matches the tray host's OpenExisting across sessions; if the
    # Global namespace is denied, fall back to Local\ (same session is the
    # normal case anyway, since Main spawns the tray itself). If even that
    # fails, $readyEventName goes empty - the tray is then launched without
    # -ReadyEvent and the wait is skipped entirely rather than failing a tray
    # that is probably fine.
    $readyEventName = "Global\GoodbyeDPI-Plus-TrayReady-$([guid]::NewGuid().ToString('N'))"
    $readyEvent = $null
    try {
        $readyEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, $readyEventName)
    } catch {
        $readyEventName = 'Local\GoodbyeDPI-Plus-TrayReady-' + [guid]::NewGuid().ToString('N')
        try {
            $readyEvent = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, $readyEventName)
        } catch {
            $readyEvent = $null
            $readyEventName = ''
        }
    }

    # Pass the resolved DNS *preference* (post CLI-vs-persisted precedence,
    # -1 = auto-detect) into Tray Mode so its restart paths can carry it
    # forward unchanged. Tray Mode exits before the precedence block runs
    # (see the "if ($TrayMode) { ... exit }" block above), so $ForceDnsIndex
    # arrives there exactly as passed here - never re-resolved.
    # -ReadyEvent goes before $persistFailedArg so the latter stays the final
    # token: it is '' when absent, and only a trailing empty expansion is
    # harmless in this string (anywhere else it would leave a stray gap
    # between a parameter name and its value).
    $trayStr = "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File `"$startScriptPathResolved`" -TrayMode -GoodbyePid $($proc.Id) -DnsLabel `"$dnsLabelResolved`" -ProgramsList `"$programsListPath`" -IconPath `"$iconPathResolved`" -CurrentDnsIndex $currentDnsIndexResolved -DnsCandidatesInfo `"$dnsCandidatesInfoResolved`" -StartScriptPath `"$startScriptPathResolved`" -BypassAllCurrent $bypassAllCurrentArg -ForceDnsIndex $ForceDnsIndex -ReadyEvent `"$readyEventName`" $persistFailedArg"
    # Guarded because under $ErrorActionPreference = 'Stop' a failed
    # Start-Process is terminating, and it would terminate us at the worst
    # possible moment: goodbyedpi.exe is already running by this line. AppLocker
    # or WDAC blocking powershell.exe, or an exhausted desktop heap, would
    # otherwise kill Main outright and leave exactly the orphan this whole
    # handshake exists to prevent - goodbyedpi running, no tray, no Job Object
    # binding the two, and a mutex abandoned rather than released. Instead:
    # record the failure as "no tray process" and fall through to the shared
    # -not $trayUp path below, which stops goodbyedpi, tells the user, and
    # releases the lock.
    $trayProc = $null
    try {
        $trayProc = Start-Process -FilePath 'powershell.exe' -ArgumentList $trayStr -WindowStyle Hidden -PassThru
    } catch {
        $trayProc = $null
        Write-Host "[start] ERROR: could not launch the tray process - $_"
    }

    $trayUp = $false
    # $trayProc being $null means the spawn never happened, so nothing will
    # ever signal the event - skip the wait entirely rather than burn the full
    # 60s deadline waiting on a process that does not exist.
    if ($readyEvent -and $trayProc) {
        # 60s, which is far more than the tray needs on a warm machine but is
        # the wrong number to shave: at logon the tray host's Add-Type has to
        # shell out to csc.exe to compile GdpiJobObject, on a cold disk, while
        # everything else in the user's startup is competing for it - that
        # alone can take double-digit seconds. The generous ceiling costs
        # nothing in the failure case because a tray host that actually died
        # is detected by HasExited on the very next 250ms tick, not by the
        # deadline; the deadline only covers a host that hangs without
        # exiting.
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $deadline) {
            if ($readyEvent.WaitOne(250)) { $trayUp = $true; break }
            if ($trayProc -and $trayProc.HasExited) { break }
        }
        try { $readyEvent.Dispose() } catch { }
    } else {
        try { if ($readyEvent) { $readyEvent.Dispose() } } catch { }
        if ($trayProc) {
            # No event could be created at all (both Global\ and Local\
            # refused), but the tray process itself did start. That missing
            # handle is our problem, not the user's - assume the tray is fine
            # rather than tear down a working goodbyedpi.exe over it.
            $trayUp = $true
        }
        # Otherwise the spawn failed outright: $trayUp stays $false and the
        # block below cleans up. There is no tray and never will be, which is
        # the one case we must never wave through.
    }

    if (-not $trayUp) {
        # The entire point of the handshake: goodbyedpi.exe must never be left
        # running with no tray icon to stop it. If the tray could not come up,
        # take goodbyedpi down with it and say so, rather than leave the user
        # with an invisible process they have no UI to find or kill.
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        try { if ($trayProc -and -not $trayProc.HasExited) { Stop-Process -Id $trayProc.Id -Force -ErrorAction SilentlyContinue } } catch { }
        # -ErrorAction Continue: same reasoning as the checks above - a
        # terminating Write-Error here would skip the MessageBox, which under
        # -WindowStyle Hidden is the only feedback the user ever gets.
        Write-Error 'Tray icon failed to start - goodbyedpi.exe was stopped.' -ErrorAction Continue
        # Released before the modal dialog, same reasoning as the two checks
        # above - and it matters most here, because this is the path most
        # likely to fire unattended at logon. Both processes the lock was
        # protecting are already dead (just above), so it has no job left;
        # holding it across an undismissed dialog would only starve the next
        # launch into running unserialized.
        Release-GdpiStartLock
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "The tray icon failed to start.`r`n`r`ngoodbyedpi.exe was stopped so it does not keep running invisibly in the background.`r`n`r`nTry launching GoodByeDPI-Plus again.",
            'GoodByeDPI-Plus', 'OK', 'Error')
        return
    }
}

# Held all the way to here on purpose. The lock's job is to keep a concurrent
# Main's kill sweep away from our tray host until that host is confirmed up
# and holding its Job Object - releasing any earlier would reopen exactly the
# race it exists to close. Also covers the -NoTray path, which skips the
# block above entirely and deliberately leaves goodbyedpi.exe running with no
# tray.
Release-GdpiStartLock

param(
    # Used by the Inno Setup installer's [UninstallRun] section: suppresses
    # the final "successfully uninstalled" MessageBox so the elevated,
    # waited-on child process launched from [UninstallRun] can never sit
    # blocked on a dialog nobody can click (Inno has no skipifsilent
    # equivalent for [UninstallRun]). Everything else - task removal,
    # shortcut removal, process/driver stop - runs exactly as before.
    [switch]$Silent
)

$ErrorActionPreference = 'Stop'

# Relaunch as administrator if not elevated (needed for sc.exe / killing protected process)
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    $relaunchArgs = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', $scriptPath)
    if ($Silent) { $relaunchArgs += '-Silent' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $relaunchArgs -Verb RunAs
    exit
}

# Remove scheduled tasks (both old and new names)
foreach ($taskName in @('GoodbyeDPI', 'GoodByeDPI-Plus', 'DPIGate')) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

# Remove Start Menu shortcut (current name and the GoodByeDPI-Plus one)
foreach ($lnkName in @('DPIGate.lnk', 'GoodByeDPI-Plus.lnk')) {
    $startMenuShortcut = Join-Path ([Environment]::GetFolderPath('Programs')) $lnkName
    if (Test-Path -LiteralPath $startMenuShortcut) {
        Remove-Item -LiteralPath $startMenuShortcut -Force
    }
}

# Remove leftover shortcut from the old VBScript-based version
$oldStartupShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'GoodbyeDPI.lnk'
if (Test-Path -LiteralPath $oldStartupShortcut) {
    Remove-Item -LiteralPath $oldStartupShortcut -Force
}

$appDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Kill tray host (powershell.exe running start.ps1) and goodbyedpi itself.
# The filter cannot match this script: "start.ps1" is not a substring of
# "uninstall.ps1", so neither this process nor its elevated relaunch is hit.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*start.ps1*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Stop-Process -Name 'goodbyedpi' -Force -ErrorAction SilentlyContinue

# Process teardown is asynchronous and WinDivert refuses to stop while any
# handle on it is still open. The old code killed the processes and called
# sc.exe stop in the very next statement, which could lose that race - and a
# still-running driver keeps x86_64\WinDivert64.sys locked, which is exactly
# what would stop Setup from deleting the install folder afterwards. Same
# wait that start.ps1's Stop-GdpiEngine already does.
$deadline = [DateTime]::UtcNow.AddSeconds(5)
while ([DateTime]::UtcNow -lt $deadline) {
    if (-not (Get-Process -Name 'goodbyedpi' -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 100
}

# Only unload OUR copy of the driver. WinDivert is a shared component under a
# fixed service name, so a second install (or unrelated software) can be the
# one that actually loaded it - stopping that would break them. sc.exe qc
# reports the registered binary path; if it does not point into this install,
# our own .sys is not the locked one anyway and there is nothing to release.
$qc = (& sc.exe qc WinDivert 2>$null | Out-String)
if ($qc -and $appDir -and $qc.IndexOf($appDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
    & sc.exe stop WinDivert 2>$null | Out-Null
}

# WinDivert also registers itself as an Event Log source, in a key that is
# separate from the service key and is NOT removed when the service is
# deregistered. Left alone it survives every uninstall, still pointing at a
# WinDivert64.sys that no longer exists. Scoped to this install for the same
# shared-component reason as above.
$evtKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\WinDivert'
try {
    $emf = (Get-ItemProperty -LiteralPath $evtKey -Name 'EventMessageFile' -ErrorAction SilentlyContinue).EventMessageFile
    if ($emf -and $appDir -and $emf.IndexOf($appDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Remove-Item -LiteralPath $evtKey -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch { }

# Per-user settings written by start.ps1 ($env:LOCALAPPDATA\DPIGate).
# Nothing ever removed this - not Inno, not this script - so it survived
# every uninstall path.
#
# $env:LOCALAPPDATA alone is not enough: this script self-elevates, and when
# a standard user elevates with a DIFFERENT admin account the environment
# belongs to that admin, not to the person whose settings need clearing.
# Win32_ComputerSystem.UserName is the interactive console user and is
# unaffected by elevation, so resolve their profile too and clear both.
# (install.ps1 already reasons the same way when it picks the task user.)
$settingsDirs = New-Object System.Collections.Generic.List[string]
if ($env:LOCALAPPDATA) {
    foreach ($dirName in @('DPIGate', 'GoodbyeDPI-Plus')) { $settingsDirs.Add((Join-Path $env:LOCALAPPDATA $dirName)) }
}
try {
    $interactiveUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
    if ($interactiveUser) {
        $sid = (New-Object Security.Principal.NTAccount($interactiveUser)).Translate([Security.Principal.SecurityIdentifier]).Value
        $profilePath = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -Name 'ProfileImagePath' -ErrorAction Stop).ProfileImagePath
        if ($profilePath) {
            foreach ($dirName in @('DPIGate', 'GoodbyeDPI-Plus')) { $settingsDirs.Add((Join-Path $profilePath "AppData\Local\$dirName")) }
        }
    }
} catch { }
# This runs elevated inside a user-writable folder: if the folder (or a file
# in it) is a junction/symlink, a recursive delete would follow it and wipe
# whatever it points at with admin rights. Delete only our own files, never
# through a reparse point, and drop the folder only when it is then empty.
function Test-ReparsePoint([string]$Path) {
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    } catch { return $true }
}
foreach ($settingsDir in ($settingsDirs | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $settingsDir)) { continue }
    if (Test-ReparsePoint $settingsDir) { continue }
    foreach ($fileName in @('settings', 'settings.tmp')) {
        $file = Join-Path $settingsDir $fileName
        if ((Test-Path -LiteralPath $file) -and -not (Test-ReparsePoint $file)) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not (Get-ChildItem -LiteralPath $settingsDir -Force -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $settingsDir -Force -ErrorAction SilentlyContinue
    }
}

if (-not $Silent) {
    # Loaded here, not at the top: the -Silent path (Inno's [UninstallRun])
    # shows no UI at all and Setup waits for this process, so there is no
    # reason to make it wait on WPF loading too.
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show("DPIGate has been successfully uninstalled.`r`n`r`nThe internet is freer now!", 'DPIGate', 'OK', 'Information')
}

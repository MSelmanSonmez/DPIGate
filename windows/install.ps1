param(
    # Used by the Inno Setup installer's [Run] section (gated on the
    # "autostart" task): performs ONLY the scheduled-task registration and
    # skips shortcut creation, the app launch, and the MessageBox, since
    # Inno itself already owns elevation, shortcuts, and the post-install
    # launch. The no-argument path below is unchanged.
    [switch]$TaskOnly,
    # Also used by the Inno installer: Inno owns shortcut creation through
    # its own [Icons] section and has no flag for a shortcut's "Run as
    # administrator" bit, so it calls back here once the icons exist. Does
    # ONLY that - no task registration, no shortcut creation, no launch and
    # no MessageBox.
    [switch]$ElevateShortcuts
)

$ErrorActionPreference = 'Stop'

# Relaunch as administrator if not elevated
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    $relaunchArgs = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', $scriptPath)
    if ($TaskOnly) { $relaunchArgs += '-TaskOnly' }
    if ($ElevateShortcuts) { $relaunchArgs += '-ElevateShortcuts' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $relaunchArgs -Verb RunAs
    exit
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$startPs1 = Join-Path $scriptDir 'start.ps1'
$iconPath = Join-Path $scriptDir 'icon.ico'

# =============================================================================
# "Run as administrator" on a .lnk
# =============================================================================
# goodbyedpi.exe loads the WinDivert kernel driver and a standard user simply
# cannot do that, so every shortcut that launches start.ps1 has to elevate.
# WScript.Shell cannot express this - its shortcut object exposes no such
# property - but it is one bit in the shell link header: MS-SHLLINK stores
# LinkFlags as a little-endian DWORD at offset 0x14, and RunAsUser is bit 13
# (0x00002000), i.e. mask 0x20 of the byte at offset 0x15. Setting it is
# exactly what ticking "Run as administrator" in the shortcut's Properties
# dialog does, so launching it raises the normal UAC prompt.
#
# Deliberately NOT self-elevation inside start.ps1: that would prompt on
# every code path that runs the script, including the logon scheduled task
# (which already runs elevated via RunLevel Highest and must stay silent).
function Set-ShortcutRunAsAdmin {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $bytes = [IO.File]::ReadAllBytes($Path)
    # Every shell link begins with HeaderSize = 0x0000004C. Refuse to patch
    # bytes into anything that is not one.
    if ($bytes.Length -lt 0x16) { return $false }
    if ([BitConverter]::ToUInt32($bytes, 0) -ne 0x4C) { return $false }
    if (($bytes[0x15] -band 0x20) -ne 0) { return $true }
    $bytes[0x15] = [byte]($bytes[0x15] -bor 0x20)
    [IO.File]::WriteAllBytes($Path, $bytes)
    return $true
}

# =============================================================================
# Auto-start safety gate
# =============================================================================
# The logon task registered further down runs with -RunLevel Highest: fully
# elevated, at every logon, with no UAC prompt, and its action is
# "powershell.exe -File <start.ps1>". If that script sits somewhere a standard
# user can write - an extracted ZIP in Downloads, a copy on the Desktop - then
# anyone (or anything) running as that user can rewrite start.ps1 and have it
# executed at high integrity at the next logon. That is a straight UAC bypass
# and a persistence primitive, so the task must never point at a user-writable
# path. Setup installs into {autopf} (Program Files) and is fine; this guard
# exists for the standalone/extracted-ZIP invocation of this script.
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
# windows\start.ps1 carries an identical copy of this function for the tray's
# "Auto Start" toggle - the two task-registration sites must agree.
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

if ($ElevateShortcuts) {
    # Inno's {autoprograms}/{autodesktop} resolve to the COMMON Start Menu and
    # desktop for an admin install (PrivilegesRequired=admin) and to the
    # per-user ones otherwise, and the desktop shortcut only exists when the
    # user ticked its optional task - so try every candidate and let
    # Set-ShortcutRunAsAdmin skip whichever is not there.
    foreach ($folder in @('CommonPrograms', 'Programs', 'CommonDesktopDirectory', 'Desktop')) {
        try {
            $dir = [Environment]::GetFolderPath($folder)
            if (-not $dir) { continue }
            Set-ShortcutRunAsAdmin -Path (Join-Path $dir 'GoodByeDPI-Plus.lnk') | Out-Null
        } catch { }
    }
    return
}

# Remove old scheduled tasks (migration from previous versions)
foreach ($taskName in @('GoodbyeDPI', 'GoodByeDPI-Plus')) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

if ($TaskOnly) {
    # Register the logon scheduled task only. Mirrors exactly what the
    # tray's own "Auto Start" toggle does (windows\start.ps1, the
    # $autoStartItem.Add_Click "Enable auto-start" branch): same task name,
    # same action/trigger/settings, so the tray checkbox and this installer
    # path cannot diverge. The one deliberate difference is the principal's
    # user (see below): the tray already runs inside the target user's own
    # session, whereas Setup may have been elevated with someone else's
    # credentials.
    $taskName = 'GoodByeDPI-Plus'

    # Refuse to point an elevated logon task at a script anyone can rewrite.
    # Skip ONLY the task here rather than failing the whole invocation: this
    # runs from Setup's [Run] section, everything else (files, shortcuts, the
    # elevation bit on the .lnk) has already succeeded, and the user is left
    # with a fully working manual install - just without silent auto-start,
    # which is exactly the part that would be unsafe.
    if (-not (Test-GdpiPathIsProtected -Path $startPs1)) {
        Write-Warning "Auto-start was NOT enabled."
        Write-Warning "  $startPs1"
        Write-Warning "is in a directory that non-administrator accounts can write to."
        Write-Warning "The logon task runs elevated with no UAC prompt, so registering it"
        Write-Warning "against that path would let any program running as you replace the"
        Write-Warning "script and gain administrator rights at your next logon."
        Write-Warning "Install with the Setup installer (built from windows\setup.iss), or"
        Write-Warning "copy this folder under %ProgramFiles% and re-run, then enable"
        Write-Warning "Auto Start from the tray icon."
        return
    }

    # Register for the user who is actually logged on - not for whoever
    # supplied the credentials at the UAC prompt. When a standard user runs
    # Setup and elevates with a different admin account, $env:USERNAME is that
    # admin, and an -AtLogOn task bound to it would simply never fire for the
    # person who installed the program. Win32_ComputerSystem.UserName is the
    # interactive console user and is unaffected by elevation; if it comes
    # back empty (no console session, e.g. some RDP setups) fall back to the
    # old behaviour.
    $taskUser = $env:USERNAME
    try {
        $interactiveUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($interactiveUser) { $taskUser = $interactiveUser }
    } catch { }
    $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File `"$startPs1`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $taskUser -LogonType Interactive -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force | Out-Null
    return
}

# WPF is only needed for the MessageBox that ends the interactive path, so it
# is loaded here rather than at the top: the -TaskOnly path above returns
# without any UI and should not pay for loading PresentationFramework.
Add-Type -AssemblyName PresentationFramework

# Remove leftover shortcut from the old VBScript-based version
$oldStartupShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'GoodbyeDPI.lnk'
if (Test-Path -LiteralPath $oldStartupShortcut) {
    Remove-Item -LiteralPath $oldStartupShortcut -Force
}

# Create Start Menu shortcut
$startMenuPath = Join-Path ([Environment]::GetFolderPath('Programs')) 'GoodByeDPI-Plus.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($startMenuPath)
$shortcut.TargetPath = 'powershell.exe'
$shortcut.Arguments = "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File `"$startPs1`""
$shortcut.WorkingDirectory = $scriptDir
if (Test-Path -LiteralPath $iconPath) {
    $shortcut.IconLocation = $iconPath
}
$shortcut.Description = 'GoodByeDPI-Plus - DPI bypass with per-program filtering'
$shortcut.Save()
# Must come after .Save(): WScript.Shell rewrites the whole .lnk there, so
# setting the bit first would simply be overwritten.
Set-ShortcutRunAsAdmin -Path $startMenuPath | Out-Null

# Launch GoodbyeDPI now (hidden, STA for tray)
Start-Process -FilePath 'powershell.exe' -ArgumentList "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File `"$startPs1`"" -WindowStyle Hidden

# Wait and verify goodbyedpi started
Start-Sleep -Seconds 3
$running = $false
if (Get-Process -Name 'goodbyedpi' -ErrorAction SilentlyContinue) {
    $running = $true
}

if ($running) {
    [System.Windows.MessageBox]::Show("GoodByeDPI-Plus is now running. Look for its icon in the system tray (near the clock).`r`n`r`nStart Menu shortcut created.`r`n`r`nTo enable auto-start at logon, right-click the tray icon and check 'Auto Start'.`r`n`r`nLong live freedom!", 'GoodByeDPI-Plus', 'OK', 'Information')
} else {
    [System.Windows.MessageBox]::Show("GoodByeDPI-Plus was installed but the process is not running.`r`n`r`nStart it manually from the Start Menu shortcut.`r`n`r`nIf it still fails, make sure you run as administrator.", 'GoodByeDPI-Plus', 'OK', 'Warning')
}

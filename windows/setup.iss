; DPIGate - Inno Setup script
;
; Builds a classic Next -> Next -> Finish installer for the Windows side.
; Compile with Inno Setup 6 (iscc.exe) from the repo root:
;
;   iscc windows\setup.iss
;
; Output lands in windows\setup\DPIGate-1.0.1-setup.exe - OutputDir
; below is relative to this .iss file's own directory, so "setup" means
; windows\setup, next to this script.
;
; All Source: paths below are relative to this .iss file's own directory
; (windows\), except the three that explicitly climb out with ..\ to reach
; the repo root (LICENSE, NOTICE, README.md).
;
; powershell.exe is always spelled out as {sys}\WindowsPowerShell\v1.0\...
; instead of a bare "powershell.exe": a bare name is resolved through PATH,
; and inside the 32-bit Setup process that resolution is WOW64-redirected to
; the 32-bit PowerShell in SysWOW64. {sys} is the real System32 directory in
; 64-bit install mode, so every entry point (wizard, shortcut, scheduled
; task) ends up on the same PowerShell.

[Setup]
; Fixed upgrade identity - generated once, must never change across
; releases or Windows will treat every build as an unrelated install.
AppId={{5D915276-0BDE-4B2F-B10D-D59243FD02CF}
AppName=DPIGate
AppVersion=1.0.1
AppPublisher=Selman Sönmez
AppPublisherURL=https://github.com/MSelmanSonmez/DPIGate
AppSupportURL=https://github.com/MSelmanSonmez/DPIGate/issues
AppUpdatesURL=https://github.com/MSelmanSonmez/DPIGate/releases
UninstallDisplayName=DPIGate 1.0.1
; File-version metadata for setup.exe itself. Without it the produced
; installer has a blank Details tab in Explorer, which users and reputation
; systems alike read as a bad sign.
VersionInfoVersion=1.0.1.0
VersionInfoCompany=Selman Sönmez
VersionInfoDescription=DPIGate Setup
VersionInfoProductName=DPIGate
; goodbyedpi.exe loads the WinDivert kernel driver - this cannot run as a
; standard user, so both install and uninstall require admin.
PrivilegesRequired=admin
DefaultDirName={autopf}\DPIGate
DisableProgramGroupPage=yes
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\icon.ico
OutputBaseFilename=DPIGate-1.0.1-setup
OutputDir=setup
LicenseFile=..\LICENSE
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "autostart"; Description: "Start DPIGate automatically at logon"; GroupDescription: "Startup:"

[Files]
; Explicit allowlist - this, not anything clever, is what keeps the
; installed folder clean. Ship runtime files only: no .c/.h/.rc, no
; Makefile, no utils\, no .manifest, nothing from linux/, no dev notes.
Source: "start.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
; The user's editable per-program filter list. onlyifdoesntexist keeps an
; edited copy across upgrades - that flag alone is what protects it, because
; an install-over-install never invokes the uninstaller, it just re-runs
; [Files].
;
; uninsneveruninstall was deliberately REMOVED: it only ever affected the
; uninstaller, and it was the single reason a completed uninstall still left
; C:\Program Files\DPIGate behind. Inno removes {app} automatically
; once it is empty, and this file was the only thing keeping it populated.
; An uninstall is now expected to leave nothing at all, which does mean the
; user's filter list goes with it - that is the intended behaviour, not an
; oversight.
Source: "programs.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "x86\*"; DestDir: "{app}\x86"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x86_64\*"; DestDir: "{app}\x86_64"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; Shortcuts from GoodByeDPI-Plus, the name before DPIGate. AppId is unchanged,
; so an upgrade reuses the old install folder but would leave these behind.
Type: files; Name: "{autoprograms}\GoodByeDPI-Plus.lnk"
Type: files; Name: "{autodesktop}\GoodByeDPI-Plus.lnk"

[Icons]
Name: "{autoprograms}\DPIGate"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File ""{app}\start.ps1"""; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"
Name: "{autodesktop}\DPIGate"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -STA -WindowStyle Hidden -File ""{app}\start.ps1"""; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
; Mark the shortcuts created by [Icons] above as "Run as administrator".
; goodbyedpi.exe loads the WinDivert kernel driver, which a standard user
; cannot do, so a plain click on an unelevated shortcut starts start.ps1,
; fails to start goodbyedpi.exe, and dies on its own "run as administrator"
; message box - no tray icon, nothing running. Inno has no [Icons] flag for
; that bit, hence the callback into install.ps1; [Run] executes after
; [Icons], so both shortcuts already exist by the time this runs.
; Not gated on any task: install.ps1 -ElevateShortcuts silently skips
; whichever of the two shortcuts is absent (the desktop one is optional).
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\install.ps1"" -ElevateShortcuts"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Configuring shortcuts..."
; Register the logon scheduled task, gated on the "autostart" task. Inno
; already owns elevation/shortcuts/launch, so install.ps1 -TaskOnly does
; ONLY the task registration - see the -TaskOnly block in install.ps1,
; which mirrors windows\start.ps1's tray "Auto Start" handler exactly.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\install.ps1"" -TaskOnly"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Registering auto-start..."
; Optional launch-now checkbox on the Setup Completed page.
;
; This launches the Start Menu SHORTCUT instead of repeating powershell.exe +
; start.ps1 here, so "launch now" and a later double-click on the shortcut
; are literally the same code path - one definition, no way for the two to
; drift apart. It has to come after the -ElevateShortcuts entry above, which
; is what puts the "run as administrator" bit on that shortcut.
;
; shellexec is required to run a .lnk at all (Inno cannot CreateProcess one),
; and it is also what makes that bit take effect - the same UAC prompt the
; user gets from the Start Menu.
;
; runasoriginaluser matters just as much: without it this entry inherits
; Setup's elevated token, which may belong to a DIFFERENT admin account than
; the person installing (standard user who supplied admin credentials at the
; UAC prompt). The tray would then run as that admin and write its settings
; to the wrong profile's LOCALAPPDATA, while the logon task registered by
; install.ps1 -TaskOnly is bound to the interactive user. Running as the
; original user and letting the shortcut do the elevating keeps every entry
; point on one account.
Filename: "{autoprograms}\DPIGate.lnk"; Description: "Launch DPIGate now"; Flags: postinstall nowait skipifsilent shellexec runasoriginaluser

[UninstallRun]
; [UninstallRun] entries execute as the first step of uninstallation -
; before Setup removes any files or registry entries - so this is safe to
; rely on to stop goodbyedpi.exe/tray and release the WinDivert driver
; before the app's own folder is deleted. Reuses uninstall.ps1 rather than
; duplicating its stop-processes/unregister-task logic here.
; -Silent suppresses uninstall.ps1's own closing MessageBox: [UninstallRun]
; has no skipifsilent equivalent, so without -Silent a /VERYSILENT
; uninstall would sit forever on a dialog nobody can click. Flags carry
; waituntilterminated (not nowait) so Setup genuinely waits for the real
; cleanup - not just for the process to be launched - before it starts
; deleting files. RunOnceId keeps a repeated entry (e.g. a repair run) from
; executing the cleanup twice.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""{app}\uninstall.ps1"" -Silent"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "GdpiUninstallCleanup"

[Code]
// Comments here use // on purpose: a Pascal { } comment ends at the FIRST
// closing brace, so any Inno constant inside it (app dir, sys dir) would
// silently terminate the comment and turn the rest into code.
//
// Installing over a running copy is the normal upgrade case, and it is the
// one case where the file copy can fail: goodbyedpi.exe runs out of the
// installed x86_64 (or x86) folder with WinDivert.dll loaded, so both files
// are locked and Inno would have to defer them to a reboot.
// PrepareToInstall runs after the wizard but before any file is touched -
// exactly the right moment to stop the old instance.
//
// The tray host is killed first on purpose: it owns goodbyedpi.exe through
// a Job Object (see windows\start.ps1), so if it outlived the upgrade it
// would keep pointing at a process that no longer exists. Only
// powershell.exe processes whose command line mentions start.ps1 are
// matched - Setup's own helpers never are.
//
// The $PID exclusion is not cosmetic: this very command line contains the
// literal text start.ps1, so without it the helper matches ITSELF and dies
// before it ever reaches goodbyedpi (verified against a live process list).
//
// Nothing running is not an error here (-ErrorAction SilentlyContinue), so
// a first-time install passes through this silently.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  NeedsRestart := False;
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
       '-NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq ''powershell.exe'' -and $_.ProcessId -ne $PID -and $_.CommandLine -like ''*start.ps1*'' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Stop-Process -Name goodbyedpi -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

# Windows guide

Full documentation for the Windows build. For a quick start see the
[main README](../README.md).

- [System tray](#system-tray)
- [DNS auto-detection](#dns-auto-detection)
- [Configuration](#configuration)
- [Checking that it works](#checking-that-it-works)
- [Building from source](#building-from-source)
- [Building the installer](#building-the-installer)
- [Uninstall](#uninstall)

---

## System tray

When `start.ps1` runs (manually or via the scheduled task), a tray icon appears
near the clock. Right-click it for:

| Item | What it does |
|---|---|
| `DNS: …` | Submenu of every tested DNS server with its response time; the active one is checkmarked. Click one to switch instantly (goodbyedpi restarts). Includes **Auto-detect (re-test)** |
| `Edit Program Filters` | Opens `programs.txt` in your editor; changes hot-reload in ~2 s |
| `Bypass All Traffic` | Toggle: run without `--only-programs` and bypass everything |
| `Auto Start` | Toggle: registers/removes the hidden `GoodByeDPI-Plus` logon task |
| `Uninstall` | Runs the uninstaller elevated (Inno Setup's own when present, otherwise `uninstall.ps1`) |
| `Exit` | Kills `goodbyedpi.exe` and removes the tray icon |

If `goodbyedpi.exe` crashes, the tray shows a warning balloon and cleans up.

Headless mode:

```powershell
powershell -ExecutionPolicy Bypass -File windows\start.ps1 -NoTray
```

Or set `$enableTray = $false` at the top of `windows\start.ps1`.

---

## DNS auto-detection

At every launch `start.ps1` tests several DNS servers and picks the **fastest
one that returns a non-poisoned answer**:

1. Queries `discord.com` (a commonly blocked domain) on all candidates **in parallel**.
2. Measures each response time.
3. Discards servers returning a known **ISP block-page IP** (e.g. `195.175.254.*` for Türk Telekom).
4. Picks the fastest valid server.
5. Falls back to **Yandex 77.88.8.8:1253** if none answers correctly.

| Server | Port | Provider |
|--------|------|----------|
| 77.88.8.8 | 1253 | Yandex (alt port) |
| 77.88.8.8 | 53 | Yandex (standard) |
| 1.1.1.1 | 53 | Cloudflare |
| 9.9.9.9 | 53 | Quad9 |
| 94.140.14.14 | 53 | AdGuard |

To use the hardcoded fallback instead:

```powershell
powershell -ExecutionPolicy Bypass -File windows\start.ps1 -NoDnsDetect
```

Or set `$autoDetectDns = $false`. The candidate list, timeout, test domain and
block-page ranges all live in the **Config** section at the top of `start.ps1`.

---

## Configuration

### Choosing which programs get bypassed

Open `windows\programs.txt`. One program per line, `#` starts a comment.

```
# Browsers
chrome.exe
msedge.exe
firefox.exe

# Discord
discord.exe
Vesktop.exe
```

**Matching rules** (case-insensitive):

- Entry **containing** a path separator (`\` or `/`) → matched as a substring of
  the full process path. `Google\Chrome\chrome.exe` matches
  `C:\Program Files\Google\Chrome\Application\chrome.exe`.
- Entry **without** a separator → matched against the file name only (exact).
  `chrome.exe` matches any `chrome.exe`; `chrome` matches nothing.

Changes apply within ~2 seconds — no restart (hot-reload).

### Adjusting bypass parameters

The Config section at the top of `windows\start.ps1`:

```powershell
$enableTray      = $true    # System tray icon
$autoDetectDns   = $true    # Auto-pick fastest non-poisoned DNS
$dnsTimeoutMs    = 800      # Per-batch DNS test timeout
$dnsTestDomain   = 'discord.com'
$blockPageRanges = @('195.175.254.')  # ISP block-page IPs to reject
$bypassMode      = '--auto-ttl --max-payload'  # SNI DPI bypass tricks
```

With auto-detection on, `--dns-addr` / `--dns-port` / `--dnsv6-addr` /
`--dnsv6-port` are set for you; with it off, the Yandex fallback is used.

`$bypassMode` controls the SNI-based bypass tricks applied to whitelisted
traffic. The default `--auto-ttl --max-payload` is a minimal working set that
defeats SNI inspection without provoking excessive Cloudflare challenges.
Alternatives: `-5` (adds `--reverse-frag`), `-9` (most aggressive), or an empty
string (DNS redirect only, for ISPs that only poison DNS).

> Some ISPs do **only** DNS poisoning; there an empty `$bypassMode` is enough.
> Many others (including several in Turkey) do DNS poisoning **and** SNI-based
> DPI, which needs the bypass tricks. Cloudflare bot verification may show up in
> `curl` tests but real browsers clear it via the JavaScript challenge.

### Supported arguments

Run `goodbyedpi.exe -h` for the full list. Added by this fork:

```
--only-programs <txtfile>  Apply DPI bypass tricks ONLY to traffic of programs
                            listed in the text file (one basename or path
                            substring per line). Other programs' traffic is
                            left untouched. # comments allowed.
--debug-proc               Print per-program gate decisions (first 300 packets).
```

All original GoodbyeDPI arguments (`-p`, `-q`, `-r`, `-s`, `-e`, `-f`,
`--dns-addr`, `--blacklist`, `-5`..`-9`, …) still work.

---

## Checking that it works

1. With GoodByeDPI-Plus **running**, open a previously blocked site in a whitelisted browser.
2. Tray icon → **Exit**, then reload — it should be blocked again.
3. Start it again from the Start Menu shortcut.

> **Not in a NAT'd virtual machine.** If the Windows guest runs behind
> VirtualBox NAT (or any user-mode NAT), the host's NAT stack terminates the
> guest's TCP connection and regenerates it, so the fragmentation, TTL and
> decoy packets never reach the ISP's DPI as sent. Nothing is bypassed and the
> test proves nothing. Shut the VM down and set Adapter 1 to a **Bridged
> Adapter** before testing.

### Debug mode

```powershell
.\windows\x86_64\goodbyedpi.exe --dns-addr 77.88.8.8 --dns-port 1253 --only-programs .\windows\programs.txt --debug-proc
```

This prints `[GATE] PASS` / `[GATE] BLOCK` for the first 300 packets.

> The `[GATE]` wording is about the **filter**, not the firewall: `PASS` = the
> program is on the list and the bypass **was applied**; `BLOCK` = it is not on
> the list and the packet went through untouched.

To see the DNS auto-detection output, run `start.ps1` from an **administrator**
terminal (not via the tray):

```powershell
powershell -ExecutionPolicy Bypass -File windows\start.ps1 -NoTray
```

---

## Building from source

### Prerequisites

- [MSYS2](https://www.msys2.org/) with `mingw-w64-x86_64-gcc`
- [WinDivert 2.2.0-A](https://reqrypt.org/download/WinDivert-2.2.0-A.zip) SDK (headers + libs)

### Build

In the **MSYS2 mingw64** terminal:

```bash
# x86_64
cd windows
make BIT64=1 \
  WINDIVERTHEADERS=/path/to/WinDivert-2.2.0-A/include \
  WINDIVERTLIBS=/path/to/WinDivert-2.2.0-A/x64

# x86
make CPREFIX=i686-w64-mingw32- \
  WINDIVERTHEADERS=/path/to/WinDivert-2.2.0-A/include \
  WINDIVERTLIBS=/path/to/WinDivert-2.2.0-A/x86
```

`goodbyedpi.exe` lands in `windows/`. Copy it next to `WinDivert.dll` and
`WinDivert64.sys` (or `WinDivert32.sys`) in `x86_64/` (or `x86/`).

CI builds both architectures on every push touching `windows/` — see
[.github/workflows/build.yml](../.github/workflows/build.yml).

---

## Building the installer

The Inno Setup script is `windows\setup.iss`:

1. Install [Inno Setup 6.3+](https://jrsoftware.org/isinfo.php) — the script uses
   `ArchitecturesInstallIn64BitMode=x64compatible`, which older 6.x rejects.
2. Run `iscc windows\setup.iss` from the repo root.
3. Output: `windows\setup\GoodByeDPI-Plus-2.0.0-setup.exe`.

The installer ships the prebuilt `x86\` and `x86_64\` binaries, the PowerShell
scripts and `programs.txt` — which is kept on upgrade, since it is your editable
filter list. Installing over a running copy is handled: Setup stops the tray host
and `goodbyedpi.exe` before writing files, and uninstalling runs `uninstall.ps1`
first to remove the scheduled task and release the WinDivert driver.

---

## Uninstall

Right-click the tray icon → **Uninstall**, or **Settings → Apps & features**.
Both run the same cleanup:

- Removes the scheduled task (current and legacy names)
- Kills the tray host (`powershell.exe` running `start.ps1`)
- Stops `goodbyedpi.exe`, waits for it to exit, then stops the WinDivert driver
- Removes WinDivert's orphaned Event Log registry key
- Deletes `%LOCALAPPDATA%\GoodbyeDPI-Plus`
- Removes the shortcuts and the install folder

Nothing is left behind — **including your edited `programs.txt`**, which is
deleted with the install folder. Back it up first if you want to keep it.

# GoodByeDPI-Plus

**Per-program DPI bypass for Windows and Linux.** A fork of
[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) that applies bypass tricks
*only* to the programs you choose — browsers, Discord, whatever you list —
while every other connection passes through untouched.

One-click install, a system tray to control it, automatic DNS selection, and a
filter list you can edit while it runs. The Linux side is a native port of the
same C engine (NFQUEUE + raw sockets instead of WinDivert), not a wrapper.

---

## Demo

**Windows** — installer, tray menu, DNS switching and the per-program filter list.

![GoodByeDPI-Plus on Windows](gif/windows.gif)

**Linux** — graphical installer, GTK tray, and the same filter list hot-reloading.

![GoodByeDPI-Plus on Linux](gif/linux.gif)

---

## Why this fork

| | Original | GoodByeDPI-Plus |
|---|---|---|
| Per-program whitelist | No — all traffic processed | **Yes** via `--only-programs` |
| Hot-reload of the list | — | **Yes** — edits apply in ~2 s, no restart |
| One-click auto-startup | `.cmd` scripts | **Installer** + hidden logon task |
| System tray | None | **Yes** — edit filters, switch DNS, toggle, stop |
| DNS auto-detection | Manual `--dns-addr` | **Yes** — tests 5 servers, picks fastest non-poisoned |
| Hidden background run | Console window visible | **Hidden** |
| SNI DPI bypass | Manual `-5`/`-9` flags | **Auto** via a config variable |
| Linux support | Windows only | **Yes** — native NFQUEUE port, same gate |

---

## Quick start

### Windows

1. Download the setup installer from the [latest release](../../releases).
2. Run the wizard. Tick **Start automatically at logon** if you want it on every boot.
3. Done — a tray icon appears near the clock. Right-click it to edit the
   whitelist, switch DNS, or stop.

To remove it: tray icon → **Uninstall**, or **Settings → Apps & features**.

> Everything is copied to `C:\Program Files\GoodByeDPI-Plus`, so the downloaded
> installer can be deleted afterwards. Launching elevates through UAC —
> `goodbyedpi.exe` needs admin rights to load the WinDivert driver.

### Linux

```bash
git clone https://github.com/SelmanBuilds/GoodByeDPI-Plus.git
cd GoodByeDPI-Plus/linux
sudo -v            # refresh the sudo timestamp first — avoids repeated prompts
./install.sh       # add --start to launch right away
```

Then start it from the application menu, or
`~/.local/share/GoodbyeDPI-Plus/start.sh`. Double-clicking `install.sh` in a file
manager opens a graphical wizard instead.

If anything ever looks wrong:
`~/.local/share/GoodbyeDPI-Plus/kill.sh` — it always restores connectivity.

---

## How it works

GoodbyeDPI-Plus learns **which process owns each connection** and gates the
bypass on that. On Windows this comes from WinDivert's FLOW layer; on Linux from
`sock_diag` plus an inode→PID cache over `/proc`. The `(5-tuple → PID → exe)`
result is cached in a hash map.

The packet loop then checks that map for every TCP/UDP packet. On the whitelist →
bypass tricks (fragmentation, fake packets, TTL games) are applied. Not on it →
the packet is reinjected untouched, at zero cost. Existing connections are
seeded at startup, so open browser tabs are not missed, and a watcher thread
re-reads the filter list ~2 s after you save it.

DNS is handled separately: on Windows `--dns-addr` redirect is exempt from the
gate so the system resolver still works; on Linux the system resolver's upstream
is repointed at a clean server when the current one turns out to be poisoned.

---

## Documentation

| | |
|---|---|
| [**Windows guide**](docs/windows.md) | tray, DNS auto-detection, configuration, filter syntax, building, installer, uninstall |
| [**Linux guide**](docs/linux.md) | architecture, requirements, install flags, tray, services, troubleshooting |

Added command-line arguments (both platforms):

```
--only-programs <txtfile>  Apply bypass tricks ONLY to programs listed in the
                            file (one basename or path substring per line).
--debug-proc               Print per-program gate decisions.
```

All original GoodbyeDPI arguments still work. Run `goodbyedpi -h` for the list.

---

## Repository layout

```
windows/   Windows build: goodbyedpi.c + proctrack.c (WinDivert), PowerShell
           launcher/tray, Inno Setup script, prebuilt x86 and x86_64 binaries
linux/     Linux port: packet_io_linux.c (NFQUEUE), rawsend_linux.c (raw socket),
           proctrack_linux.c (sock_diag), checksum.c, install.sh + GTK wizard,
           tray.py, nftables rules, service files, tests
docs/      Platform guides and internal design notes
.github/   CI: Windows x86/x86_64 build, install.sh --check-only on 9 distros
```

The bypass sources (`fakepackets.c`, `dnsredir.c`, `ttltrack.c`,
`blackwhitelist.c`, `utils/`) exist on both sides; `make check-sync` in `linux/`
detects drift between them.

---

## Credits

- **[ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)** — the original DPI circumvention utility this project forks.
- **[basil00/WinDivert](https://github.com/basil00/Divert)** — the packet capture/divert library behind the Windows build.
- **[keift/goodbyedpi](https://github.com/keift/goodbyedpi)** — inspiration for the one-click startup installer.
- **[bol-van/zapret](https://github.com/bol-van/zapret)** — reference for the NFQUEUE + raw-socket + fwmark approach used by the Linux port.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The core engine is derived from GoodbyeDPI, which is Apache-2.0. Apache-2.0 code
cannot be relicensed as MIT without dropping the patent grant and attribution
obligations that travel with every derivative work, so this fork stays Apache 2.0.

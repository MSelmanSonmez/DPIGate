# Linux guide

Full documentation for the Linux port. For a quick start see the
[main README](../README.md).

The port lives entirely in `linux/`. It is a real port of the C engine — same
bypass tricks, same per-program gate, same hot-reloadable filter list — not a
proxy or a wrapper around another tool.

- [How the port works](#how-the-port-works)
- [Requirements](#requirements)
- [Install](#install)
- [Running it](#running-it)
- [System tray](#system-tray)
- [Choosing which programs get bypassed](#choosing-which-programs-get-bypassed)
- [Autostart and services](#autostart-and-services)
- [Checking that it works](#checking-that-it-works)
- [Stopping the bypass](#stopping-the-bypass)
- [Uninstall](#uninstall)
- [Building from source](#building-from-source)
- [Troubleshooting](#troubleshooting)

---

## How the port works

There is no WinDivert on Linux, so these pieces are replaced:

| Windows | Linux |
|---------|-------|
| WinDivert NETWORK layer (capture / modify / reinject) | **NFQUEUE** via `libnetfilter_queue` (`packet_io_linux.c`) — `nfq_get_payload()` gives an in-place pointer, `nfq_set_verdict2()` returns the mangled packet |
| WinDivert fake-packet injection | **Raw socket** (`SOCK_RAW` + `IPPROTO_RAW`, `rawsend_linux.c`) with `SO_MARK = 0x40000000` |
| WinDivert FLOW layer (kernel `(5-tuple, PID)` notifications) | **`/proc/net/{tcp,udp}{,6}` seed + `sock_diag` (`NETLINK_INET_DIAG`) lookups + an inode→PID cache** built by periodically scanning `/proc/*/fd/*` (`proctrack_linux.c`) |
| `WinDivertHelperCalcChecksums` / `ParsePacket` | Own RFC 1071 implementation with IPv4/IPv6 pseudo-headers (`checksum.c`) |
| WinDivert filter string | **nftables or iptables rules** (`goodbyedpi.nft`, `lib/platform.sh`) |
| Windows service (SCM) | systemd (user or system unit), OpenRC or runit service |
| PowerShell tray | Python/GTK tray (`tray.py`), AyatanaAppIndicator3 → AppIndicator3 → `Gtk.StatusIcon` → headless |

The firewall rules put outbound TCP 80/443 and UDP 53 (plus the matching inbound
directions) into **NFQUEUE 200**, reject outbound UDP 443 to force browsers off
QUIC and onto TCP where the bypass works, and — critically — **skip** two classes
of traffic: loopback, and anything carrying fwmark `0x40000000`. That mark is what
goodbyedpi stamps on its own fake packets, so they can never re-enter the queue
(the callback checks the mark in software as a second layer). Root-owned sockets
(`meta skuid 0 return`) are also left alone, so NetworkManager's connectivity
check is not mangled into a false captive-portal warning.

The per-program gate is unchanged in shape: look up the 5-tuple in a hash map;
on a miss, ask `sock_diag` for the socket inode, translate inode → PID through
the cache, `readlink("/proc/<pid>/exe")`, and match. Matching considers the exe
path, `/proc/<pid>/comm`, and the full cmdline, and walks up to 4 levels of
parent processes — which is how Electron/Chromium network helper processes
inherit their parent's match.

`goodbyedpi` runs as **your user**, not root: `install.sh` (and `start.sh`) set
`cap_net_raw,cap_net_admin+ep` on the binary with `setcap`. Only loading the
firewall rules and setting capabilities need root, and those go through
`lib/platform.sh`, which picks whichever of `sudo`, `doas`, `pkexec` or `run0`
exists.

`lib/platform.sh` is the portability layer for everything else too: distro and
package-manager detection, firewall backend selection (nftables when usable,
otherwise iptables), init-system abstraction, privilege escalation, and process
lookup. It probes capabilities rather than package names, which is why the same
`install.sh` works across distributions.

---

## Requirements

- A kernel with netfilter/NFQUEUE support (`nfnetlink_queue`) — every mainstream
  distro kernel has it. x86_64 is what is tested.
- **Build:** `gcc`, `make`, `pkg-config`, and the development headers for
  `libnetfilter_queue`, `libnfnetlink`, `libmnl`.
- **Runtime:** `bash`, `nftables` **or** `iptables`, and `libcap` (for `setcap`).
- **Optional (tray + prompts):** `python3` with PyGObject/GTK 3 and
  AyatanaAppIndicator3 (or AppIndicator3), `libnotify`, `zenity`, `polkit`.
  Without them the bypass still works — run it with `--no-tray`.

`install.sh` installs all of this itself. It knows apt, dnf, yum, zypper, pacman,
apk, xbps, emerge and eopkg; on NixOS and other unknown/immutable hosts it prints
an exact manual recipe instead of guessing.

If you would rather install the packages yourself:

```bash
# Debian / Ubuntu / Linux Mint
sudo apt install gcc make pkg-config libnetfilter-queue-dev libnfnetlink-dev \
    libmnl-dev nftables iptables libcap2-bin \
    python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 libnotify-bin zenity

# Fedora / RHEL / Rocky / AlmaLinux
sudo dnf install gcc make pkgconf-pkg-config libnetfilter_queue-devel \
    libnfnetlink-devel libmnl-devel nftables iptables libcap \
    python3-gobject gtk3 libayatana-appindicator-gtk3 libnotify zenity

# Arch
sudo pacman -S base-devel pkgconf libnetfilter_queue libnfnetlink libmnl \
    nftables iptables libcap python-gobject gtk3 libayatana-appindicator
```

---

## Install

Get the sources on the target machine (`git clone`, or build a source tarball
with `linux/scripts/make-dist.sh`), then:

```bash
cd linux
./install.sh --check-only   # optional: probe distro/deps/build, change nothing
sudo -v                     # refresh the sudo timestamp (see below)
./install.sh                # build + install (add --start to launch right away)
```

`install.sh`, in order: installs missing dependencies → `make clean && make` →
copies the runtime files under `~/.local/share/GoodbyeDPI-Plus/` → seeds
`~/.config/GoodbyeDPI-Plus/ProgramFilters` (never overwriting an existing one) →
`setcap cap_net_raw,cap_net_admin+ep` on the binary → loads the firewall rules →
writes the application-menu entry. It does **not** start anything unless you pass
`--start`.

Two rules worth repeating:

- **Never run `sudo ./install.sh`.** The install is per-user; as root everything
  lands in `/root/.local/share` and nothing appears in your menu or tray.
- **Run `sudo -v` first.** `lib/platform.sh` runs every root command with
  `sudo -n` (non-prompting). With a stale timestamp it falls back to `pkexec`,
  which opens a *separate* graphical password dialog for each dependency /
  setcap / firewall step. One `sudo -v` and the rest is silent.

`--check-only` detects distro, package manager and init system, installs missing
dependencies, tries the build, then exits **without touching the system**.
A successful run ends with `[install] --check-only: distro detection, package
resolution, and build all OK.` Remaining `missing:` lines are real problems;
`warn:` lines are optional things such as tray or notification support.

### Graphical install wizard

Double-clicking `install.sh` in a file manager — or running it with no terminal
attached — opens a graphical wizard instead: **Welcome → License → Components →
Ready → Installing → Finished**, with a live install log and a "start after
install" checkbox. The components page offers: build from source, application
menu shortcut, autostart at login, system-wide service, start after install.

The wizard runs the very same `install.sh --cli` underneath, so the two paths
cannot drift apart. It needs PyGObject/GTK 3 (the tray's own dependency) and
falls back to a zenity wizard, then to reopening the text installer in a
terminal. Force either mode with `--gui` / `--cli`.

### install.sh flags

| Flag | What it does |
|---|---|
| `--check-only` | Probe distro/package manager/build only, then exit — no setcap, firewall, service, shortcut or notification |
| `--start` | Start the bypass (and tray) when the install finishes |
| `--no-build` | Skip `make` and install whatever binary is already present |
| `--assume-deps` | Skip dependency probing/auto-install |
| `--system` | Install a root/system service (systemd system unit, OpenRC or runit) instead of the default user-mode + XDG-autostart install |
| `--no-shortcut` | Skip the application-menu entry |
| `--autostart` | Add the login autostart entry |
| `--no-autostart` | Remove an existing login autostart entry |
| `--gui` / `--cli` | Force the graphical wizard / the text installer |

### What gets installed where

| Path | What |
|---|---|
| `~/.local/share/GoodbyeDPI-Plus/` | `goodbyedpi` binary, `start.sh`, `kill.sh`, `uninstall.sh`, `reaper.sh`, `tray.py`, `tray-launcher.sh`, `dns_detect.py`, `goodbyedpi.nft`, `goodbyedpi.service`, `icon.png`, `lib/`, logs |
| `~/.config/GoodbyeDPI-Plus/ProgramFilters` | the per-program filter list you edit |
| `~/.local/share/applications/goodbyedpi-plus.desktop` | menu entry (`Categories=Network;` only, so it appears once, under Internet/Network) |
| `~/.local/share/icons/hicolor/64x64/apps/goodbyedpi-plus.png` | menu/tray icon |
| `/usr/local/lib/GoodbyeDPI-Plus/`, `/etc/GoodbyeDPI-Plus/ProgramFilters` | additional root-mode layout, only with `--system` |

Because `uninstall.sh` is installed alongside the binary, you can remove the
program later even if you delete the source tree.

### Distro notes

The steps above are identical everywhere; these are the only real differences.

**Fedora / RHEL / Rocky / AlmaLinux.** firewalld is enabled by default and uses
the nftables backend. `goodbyedpi.nft` installs its own `inet goodbyedpi` table
with a separate hook priority and never touches firewalld's tables, so there is
**no need to stop firewalld**. But `firewall-cmd --reload` reloads every nftables
table from scratch, which removes the `inet goodbyedpi` table — if you reload
firewalld, run `start.sh` again. On Fedora 44 you may also see SELinux AVC
denials for `nft`; they are cosmetic (see [troubleshooting](#troubleshooting)).

**Linux Mint / Debian / Ubuntu.** Nothing special. On Mint 22 the `policykit-1`
package no longer exists and is skipped — harmless, since the `sudo -v` path does
not need pkexec.

**GNOME (any distro).** The tray needs the *AppIndicator and KStatusNotifierItem
Support* extension (ID 615); `install.sh` detects GNOME and prints the link if it
is missing. KDE Plasma, Cinnamon, MATE and Xfce need no extension.

---

## Running it

From the application menu ("DPIGate", under Internet/Network), or:

```bash
~/.local/share/GoodbyeDPI-Plus/start.sh
```

A password prompt appears because loading the firewall rules needs root. The tray
icon shows up in the panel afterwards; `goodbyedpi` itself keeps running as your
user thanks to its capabilities.

`start.sh` flags:

| Flag | What it does |
|---|---|
| (none) | DNS check + firewall rules + daemon + tray |
| `--no-tray` | No tray — bypass only (terminal and service use) |
| `--no-dns-detect` | Skip the DNS test, use the fallback |
| `--force-dns=N` | Force DNS candidate number N (0-based) |
| `--auto-dns` | Force auto-detection (overrides a saved manual choice) |
| `--bypass-all` / `--no-bypass-all` | Ignore / honour `ProgramFilters` |
| `--debug-proc[=N]` | Log per-program gate decisions (optionally N packets) |
| `--skip-nft` | Do not touch the firewall rules |
| `--foreground` | Run `goodbyedpi` in the foreground, no tray — for process supervisors (runit, manual s6/sysvinit wrapping) |
| `--restart` | Used by the tray when restarting: skips the "already running" guard |
| `--force-nat` | Start anyway when VirtualBox NAT is detected (`start.sh` otherwise refuses — see troubleshooting) |
| `--help` | Print the usage header |

Useful environment variables:

```bash
GDPI_FW_BACKEND=iptables ./start.sh   # force iptables (default: auto — nft when usable)
GDPI_PROGRAMS=/tmp/list ./start.sh    # use a different filter list for this run
BYPASS_MODE='-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --max-payload=1200' ./start.sh
```

`BYPASS_MODE` in `start.sh` holds the bypass trick set (default:
`-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --set-ttl 7
--wrong-seq --max-payload=1200`). The Linux binary takes the same arguments as
the Windows one plus `--queue <n>` (NFQUEUE number; `start.sh` passes 200, which
must match the firewall rules). Run `./goodbyedpi -h` for the full list.

**About DNS on Linux.** Unlike Windows, the port does *not* use `--dns-addr`
redirection: the firewall rules deliberately exempt loopback and root-owned
sockets, so systemd-resolved's queries never reach the queue and a redirect would
be a dead path. Instead `dns_detect.py` tests the candidate servers, and if your
*system* resolver turns out to be poisoned, `start.sh` points the system
resolver's upstream at the fastest clean server via `resolvectl` and records a
marker so `kill.sh` reverts it on exit.

---

## System tray

The tray runs as a separate Python/GTK process, as your user. Right-click it for:

| Item | What it does |
|---|---|
| `DNS: <name>` | Submenu listing the DNS candidates with measured latencies; picking one restarts the daemon with it |
| `Auto-detect (re-test)` | Re-runs the DNS test (the icon disappears and returns within ~5 s — normal) |
| `Edit Program Filters` | Opens `ProgramFilters` in your editor; the daemon re-reads it the moment you save |
| `Bypass All Traffic [ON]/[OFF]` | Turns the per-program filter off/on |
| `Auto Start [ON]/[OFF]` | Start at login (`~/.config/autostart/goodbyedpi-tray.desktop` plus a systemd `--user` unit) |
| `Uninstall` | Runs the uninstaller |
| `Exit` | Tears everything down: daemon, firewall rules and tray |

A watchdog checks every 2 seconds that the daemon is still alive; if it dies, the
tray cleans up the firewall rules and reports the tail of the log.

---

## Choosing which programs get bypassed

The list is `~/.config/GoodbyeDPI-Plus/ProgramFilters` (one entry per line, `#`
for comments), and it hot-reloads within ~2 seconds of saving — no restart. The
shipped file already covers the common browsers, Discord clients and chat apps.

Matching is case-insensitive, and a process matches when **any** of its identities
matches:

- Entries **without** a `/` are matched against the exe basename (exact),
  `/proc/<pid>/comm` (exact), and the full cmdline (as a whole `/`-delimited
  component). Example: `firefox`, `vesktop`.
- Entries **with** a `/` are matched as a substring of both the exe path and the
  cmdline. Example: `/usr/lib/vesktop/`.
- Parent processes are checked too (up to 4 levels), which covers Electron and
  Chromium helper processes that do the actual networking.

### Electron apps (Vesktop, Discord, Slack, …)

Electron apps run from a shared runtime — on Arch and Fedora the process exe is
`/usr/lib/electron<N>/electron`, and the only trace of the app is its `.asar`
argument. Both of these therefore match Vesktop:

```
# ~/.config/GoodbyeDPI-Plus/ProgramFilters
vesktop                     # bare name: matched as a whole path component of
                            # the cmdline ("… /usr/lib/vesktop/app.asar")
/usr/lib/vesktop/           # path entry: substring of exe OR cmdline
```

A bare name never matches a fragment of a hostname, so `curl https://discord.com/`
does not inherit the Discord app's bypass (`proctrack_test`: "url argument is not
an identity" vs "electron asar path is an identity").

Restart the Electron app after starting goodbyedpi — proctrack only matches new
connections. Snap and Flatpak builds may hide `/proc/<pid>/exe` behind the
sandbox; if a sandboxed app cannot be matched, use the tray's **Bypass All
Traffic** toggle.

---

## Autostart and services

**User mode (default).** No service is installed. Enable **Auto Start** in the
tray (or `./install.sh --autostart`) and login startup happens through
`~/.config/autostart/goodbyedpi-tray.desktop`, which runs `tray-launcher.sh`.
Where systemd is present the tray also installs a `--user` unit lazily, so this
works too:

```bash
systemctl --user enable --now goodbyedpi
systemctl --user disable --now goodbyedpi
```

The unit (`linux/goodbyedpi.service`) is a `oneshot` + `RemainAfterExit` unit that
runs `start.sh --no-tray` and stops with `kill.sh`, so the bypass is independent
of your GUI session.

> Autostart still needs root once per login for the firewall rules. If you miss
> or cancel that password prompt, the tray appears and the daemon runs but no
> packets are queued. `~/.local/share/GoodbyeDPI-Plus/tray-launcher.sh --check`
> reports the state (`Firewall: LOAD FAILED`); run `start.sh` from a terminal to
> fix it.

**System mode (`./install.sh --system`).** Files are staged to
`/usr/local/lib/GoodbyeDPI-Plus/` and `/etc/GoodbyeDPI-Plus/ProgramFilters`, and
a real service is installed for whichever init the host runs:

- **systemd** — a system unit running as root
- **OpenRC** — `linux/service/openrc/goodbyedpi`
- **runit** — `linux/service/runit/goodbyedpi/{run,finish}`

s6 and sysvinit have no shipped service definition; wrap the documented
foreground path yourself:

```bash
/usr/local/lib/GoodbyeDPI-Plus/start.sh --no-tray --foreground
```

---

## Checking that it works

```bash
grep -E 'loaded [0-9]+ programs|Block QUIC/HTTP3|NFQUEUE queue' \
     ~/.local/share/GoodbyeDPI-Plus/goodbyedpi.log
sudo nft list table inet goodbyedpi
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 8 https://www.google.com/
```

Expect `[proctrack] loaded <N> programs …`, `Block QUIC/HTTP3: 1` and
`NFQUEUE queue: 200` in the log; `tcp dport { 80, 443 }` and `udp dport 53`
rules with `queue … to 200` plus a `udp dport 443 … reject` rule in the nft
output; and `200` from curl.

Then open a previously blocked site in a browser. If it still does not load,
check that the program is actually on the list:

```bash
grep -n -i -E 'firefox|chrome|vesktop|discord' ~/.config/GoodbyeDPI-Plus/ProgramFilters
```

Add a line (executable name or path) and save — it takes effect immediately.

For a per-packet view, run `start.sh --debug-proc` and watch
`~/.local/share/GoodbyeDPI-Plus/goodbyedpi.log`. Remember the `[GATE]` wording is
about the filter, not the firewall: `PASS` = on the list = bypass applied,
`BLOCK` = not on the list = traffic left untouched.

**Do not test as root.** The `meta skuid 0 return` rule never queues root-owned
traffic, so `sudo curl`, a root browser or a root shell measure nothing.

---

## Stopping the bypass

```bash
~/.local/share/GoodbyeDPI-Plus/kill.sh          # firewall rules + daemon + tray
~/.local/share/GoodbyeDPI-Plus/kill.sh --nft    # firewall rules only
~/.local/share/GoodbyeDPI-Plus/kill.sh --proc   # daemon only
```

`kill.sh` **restores** connectivity, it never cuts it — when the table/chain is
gone the kernel simply accepts packets normally. It is the first thing to run if
anything looks wrong. The tray's **Exit** item does the same teardown.

---

## Uninstall

```bash
~/.local/share/GoodbyeDPI-Plus/uninstall.sh
```

(or `./uninstall.sh` from the source tree — same script). It stops the daemon and
tray, unloads the firewall rules, removes the service and autostart entries, the
menu entry and icon, and deletes both `~/.local/share/GoodbyeDPI-Plus/` and
`~/.config/GoodbyeDPI-Plus/` — **including your edited `ProgramFilters`**. Back it
up first if you want to keep it. The tray's **Uninstall** item runs the same
script.

---

## Building from source

```bash
cd linux
make                 # -> ./goodbyedpi
make clean
```

The Makefile is Linux-only and has no dependency on `windows/`. It resolves
`libnetfilter_queue`, `libmnl` and `libnfnetlink` through `pkg-config` and falls
back to plain `-l` flags.

Because the bypass sources (`fakepackets.c`, `dnsredir.c`, `ttltrack.c`,
`blackwhitelist.c`, `utils/`) exist on both sides, there is a drift check:

```bash
make check-sync      # compare against windows/ using .sync-checksums
make sync            # re-copy the pure-copy files from windows/
```

Test targets (each builds a standalone binary):

```bash
make checksum_test   # RFC 1071 checksums + parse_packet
make proctrack_test  # /proc/net parsing, inode cache, match rules
make rawsend_test    # raw-socket fake packet injection
make bypass_test     # fakepackets / dnsredir / ttltrack / blacklist logic
make smoke_test      # NFQUEUE passthrough
make settings-test   # settings persistence + password-dialog regressions
```

To produce a source-only tarball for another machine (no binaries, no object
files — the target builds them itself):

```bash
cd linux
./scripts/make-dist.sh      # -> <repo>/goodbyedpi-plus-linux.tar.gz
```

Unpack it on the target, `cd goodbyedpi-plus`, and continue from
[Install](#install).

CI runs `install.sh --check-only` in containers for Debian 12, Ubuntu 24.04,
Fedora 41/44, Rocky 9, Alpine 3.20, openSUSE Tumbleweed, Void and Arch on every
push that touches `linux/` — see
[.github/workflows/linux.yml](../.github/workflows/linux.yml).

---

## Troubleshooting

Logs: daemon `~/.local/share/GoodbyeDPI-Plus/goodbyedpi.log`,
privilege/firewall `~/.local/share/GoodbyeDPI-Plus/platform.log`.

| Symptom | Cause / fix |
|---|---|
| Internet is gone | `~/.local/share/GoodbyeDPI-Plus/kill.sh` — always safe, always first |
| Clicking the menu entry does nothing | Failures are reported as desktop notifications; to see the reason run `~/.local/share/GoodbyeDPI-Plus/start.sh` from a terminal |
| No tray icon on GNOME | Install the *AppIndicator and KStatusNotifierItem Support* extension (ID 615). Not needed on KDE/Cinnamon/MATE/Xfce |
| No tray icon on KDE/Wayland | `sudo dnf install -y libayatana-appindicator-gtk3` (or your distro's equivalent) and restart — the `Gtk.StatusIcon` fallback is invisible on Wayland |
| No tray icon, bypass works | PyGObject/AppIndicator missing: `python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1` (apt) or `python3-gobject gtk3 libayatana-appindicator-gtk3` (dnf). Otherwise use `--no-tray` |
| A separate password window at every step | Run `sudo -v`, then retry `install.sh`/`start.sh` within the timestamp window |
| `plat_run_root failed … via none` | Neither a fresh `sudo` nor `pkexec` is available: run `sudo -v` and retry |
| `nfq_create_queue(200) failed` | An old instance still owns the queue: `kill.sh`, then `start.sh`. If the log says `Operation not permitted`, the capabilities were lost: `sudo setcap cap_net_raw,cap_net_admin+ep ~/.local/share/GoodbyeDPI-Plus/goodbyedpi` |
| `missing: libnetfilter_queue/libnfnetlink/libmnl` | Install the dev packages listed in [requirements](#requirements), then re-run `./install.sh` |
| Firewall rule loading warning | Install `nftables` and/or `iptables` and retry. To force a backend: `GDPI_FW_BACKEND=iptables ./start.sh` |
| Bypass stopped after `firewall-cmd --reload` | The reload rebuilds every nftables table, dropping `inet goodbyedpi`. Run `start.sh` again |
| Auto Start is on but nothing is bypassed | The firewall load at login needs root; a missed password prompt leaves the daemon idle. Check with `tray-launcher.sh --check` (`Firewall: LOAD FAILED`) and run `start.sh` from a terminal |
| Blank menu icon | Log out and back in so the icon cache refreshes |
| `policykit-1` not found (Mint 22) | Harmless — it is skipped; the `sudo -v` path does not need pkexec |
| SELinux AVC denials for `nft` (Fedora 44) | Cosmetic: `/usr/bin/nft` is labelled `iptables_exec_t`, so the transition produces an `entrypoint` denial while the commands still work. For zero AVCs: `sudo ausearch -c '(nft)' --raw \| audit2allow -M my-nft && sudo semodule -X 300 -i my-nft.pp` |
| Nothing is bypassed while testing | You are probably testing as root — `meta skuid 0 return` never queues root-owned traffic. Test as your normal desktop user |
| A Snap/Flatpak app is never matched | The sandbox can hide `/proc/<pid>/exe`; use the tray's **Bypass All Traffic** toggle |
| `ERROR: VirtualBox NAT detected` / bypass works on bare metal but not in a VM | With NAT networking, VirtualBox's slirp stack terminates the guest's TCP stream and regenerates it host-side, so fragmentation/TTL/decoy packets never reach the ISP's DPI. Shut the VM down and switch Adapter 1 to a **Bridged Adapter**. `start.sh --force-nat` starts anyway, but the bypass will not work |

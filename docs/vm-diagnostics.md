> **Internal document — maintainer runbook for `linux/vm-diag.sh`.**
>
> Not part of the user documentation. It assumes a throwaway VM and describes
> steps (including passing a sudo password through the environment) that are
> unsafe on a real machine. End-user troubleshooting lives in
> [`README.md`](../README.md).

# In-VM diagnostics + fix runbook (Bug 2 / Bug 3)

This document is a diagnostic runbook to be followed **top to bottom** by an
AI agent running inside a virtual machine (Linux Mint / VirtualBox). Goals:

- **Bug 2** — `discord.com` and Vesktop are unreachable while the bypass is on.
- **Bug 3** — enabling "Bypass All Traffic" triggers a NetworkManager
  captive-portal warning and kills internet access.

Measurement tool: `./vm-diag.sh` (same directory). Every decision rests on the
`*_VERDICT` keys this tool produces — **do not guess, measure.**

## A0 — Prerequisites (all mandatory, in order)

1. **Do NOT be root.** If `id -u` prints `0`, STOP: the
   `meta skuid 0 return` rule in `goodbyedpi.nft` never puts root-owned
   traffic into the queue — every measurement taken as root (curl, python,
   browser) is invalid.
   Switch to the normal desktop user (`su - <user>`) and start over.
2. **Is the source tree up to date?** In the VM, from the project root
   (e.g. `~/DPIGate`), `cd linux` then:
   ```
   grep -c -- '--native-frag' start.sh
   ```
   Must be **≥ 1**. If it is `0`, STOP and tell the operator: the copy in the
   VM predates the fixes, they need to re-copy the tree.
3. **Set up a password-free flow.**
   ```
   export SUDO_PASSWORD='<VM user password>'
   ```
   Without this, every root call (`nft`, `setcap`, `tcpdump`) opens a separate
   password prompt and the agent blocks. **Security note:** this value will be
   visible in the agent's shell environment and probably in its logs — use only
   the password of a disposable virtual machine, never enter the password of a
   real machine. There is no alternative.
4. **Dependencies + build.**
   ```
   ./install.sh
   ```
   (installs dependencies, runs `make`, refreshes
   `~/.local/share/DPIGate/`). If `tcpdump` is missing:
   `sudo apt-get install -y tcpdump`.
5. **Emergency exit.** If internet access dies, always: `./kill.sh`.

## A1 — Measurement

```
./vm-diag.sh all
```

Output is appended to `~/gdpi-vm-diag.txt` (never overwritten). Every decision
from here on is made by reading the `*_VERDICT` lines in that file.

## A2 — Decision table

The first matching row applies; once applied, re-run the relevant subcommand
and verify.

| Observation | Action |
|---|---|
| `ENV_SRC_ROUND2=no` | STOP, tell the operator to re-copy the source tree. |
| `ENV_BIN=no` | Run `make`; if it errors, run `./install.sh` (installs dependencies). |
| `BASE_VERDICT=DNS_POISON` | Not fixable on the DPI side. Active connection name: `nmcli -t -f NAME connection show --active \| head -1`. Then `sudo nmcli connection modify "<NAME>" ipv4.dns "1.1.1.1 8.8.8.8" ipv4.ignore-auto-dns yes` and `sudo nmcli connection up "<NAME>"`. Re-run `./vm-diag.sh base`. |
| `BASE_VERDICT=IP_BLOCK` | Nothing goodbyedpi can do at the TCP level (IP null-routed/unreachable). Report it and go to A5. |
| `BASE_VERDICT=NO_BLOCK` | Bug 2 is not a network block. Run `./vm-diag.sh endpoints` + `./vm-diag.sh vesktop`, then go to A4. |
| `BASE_VERDICT=SNI_DPI` | Expected case. Look at the `WINNER` line (A3). |
| `ENV_NETMODE=vbox-nat` **and** `WIRE_VERDICT=GUEST_OK_DOWNSTREAM_NULLIFIES` | Root cause is the network mode. The guest fragments correctly, but VirtualBox NAT (slirp) terminates the guest's TCP stream and regenerates it on the host side, so the fragmentation/TTL/decoy packets never reach the ISP's DPI. **On the host side** (the agent cannot do this, the operator must): shut the VM down → Settings → Network → Adapter 1 → Attached to: **Bridged Adapter** → Name: the host's physical NIC → OK → start the VM. Then re-run `./vm-diag.sh base rungs`. |
| `WINNER=none` **and** `ENV_NETMODE=vbox-nat` | The bridged step above is mandatory; continuing without it is pointless. |
| `BA_VERDICT=DAEMON_DEAD` | `tail -30 ~/.local/share/DPIGate/goodbyedpi.log`. `nfq_create_queue … Operation not permitted` → `sudo setcap cap_net_raw,cap_net_admin+ep ./goodbyedpi`. `__stack_chk_fail`/`Aborted` → attach the log tail to the report, go to A5. |
| `BA_VERDICT=NOT_QUEUED` | Rules were not loaded: `cat ~/.local/share/DPIGate/platform.log` and `./lib/platform.sh fw-backend`. If nft fails, measure again with `GDPI_FW_BACKEND=iptables ./start.sh --no-tray --bypass-all`. |
| `BA_VERDICT=DNS_BROKEN` **and** `ENV_SYSDNS_LOOPBACK=no` | Take DNS out of the queue (dead path: `--dns-addr` is never used). In `goodbyedpi.nft`, delete the `udp dport 53 counter queue num 200 bypass` line in the output chain plus the 2-line comment above it, and the `udp sport 53 counter queue num 200 bypass` line in the input chain plus its comment. In `lib/platform.sh`, inside `_plat_fw_load_iptables`, delete the two lines containing `--dport 53` and `--sport 53` (`grep -n "53" lib/platform.sh` gives exactly those). Re-run `./vm-diag.sh bypassall`. |
| `BA_VERDICT=HTTP80_BROKEN` | Take port 80 out of the queue: in `goodbyedpi.nft`, `tcp dport { 80, 443 }` → `tcp dport 443`, `tcp sport { 80, 443 }` → `tcp sport 443`; in `lib/platform.sh`, delete the `--dport 80` and `--sport 80` lines; drop the `-f 2` flag in `start.sh:24` (`-e 2` stays). Rationale: HTTP-only sites are rare, keeping the internet alive is worth more. Re-run `./vm-diag.sh bypassall`. |
| `BA_VERDICT=ALL_TCP_BROKEN` **and** `ENV_NETMODE=vbox-nat` | The bridged step (above). |
| `BA_VERDICT=ALL_TCP_BROKEN` **and** `ENV_NETMODE≠vbox-nat` | Measure again with `./vm-diag.sh wire "-p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --max-payload=1200"` (R2 — no decoy packets). If it is still broken, write R2 into `start.sh:24`, attach `~/gdpi-vm-diag.txt` + the `wire` pcap to the report, and go to A5. |
| `WIRE_VERDICT=GUEST_NOT_MANGLING` | Packets never reach the daemon, or mangling is off: are `BA_BANNER_NATIVE`/`BA_BANNER_SNI` 1? If 0, `--native-frag --reverse-frag --frag-by-sni` is missing from `start.sh:24` → add it. If 1, look at `BA_COUNTERS` (if 0, apply the `NOT_QUEUED` row). |
| `VESK_LIST_HIT=no` | Add `VESK_EXE` to `linux/ProgramFilters`: if the path has no `/`, write the basename (e.g. `vesktop`); if it does, write the deepest directory containing the file with a trailing `/` (e.g. `/opt/Vesktop/`), as a single line. Nothing else is needed, since `start.sh` refreshes `~/.config/DPIGate/ProgramFilters` automatically whenever the source file is newer. Re-run `./vm-diag.sh vesktop`. |
| `EP_BLOCKED` is non-empty **and** `WINNER` exists | After writing the winning mode into `start.sh:24`, run `endpoints` again; if any endpoint still returns 000, put the list in the report. |
| `VESK_LIST_HIT=yes`, `EP_VERDICT=OK`, but Vesktop still will not start | The network side is clean. Run `vesktop` from a terminal and add the `VESK_STDERR` line plus the first 30 lines of `/tmp/gdpi-vesktop.log` to the report; this is now an application-side problem, not DPI. |

## A3 — Make the winning mode permanent

If `WINNER` is a rung (`R1`..`R8`), make the `BYPASS_MODE` line in
`linux/start.sh` match this template exactly:

```
BYPASS_MODE="${BYPASS_MODE:-<WINNER_MODE>}"
```

If `WINNER=R1` the file is already correct, change nothing. If `WINNER=none`
(and the bridged step was tried too), set the line to **R2** and record that
in the report:

```
BYPASS_MODE="${BYPASS_MODE:--p -q -f 2 -e 2 --native-frag --reverse-frag --frag-by-sni --max-payload=1200}"
```

## A4 — Refresh the installed copy and verify the real flow

In order:

1. `cd linux && ./install.sh`
2. Prove that per-program mode works in the installed copy:
   ```
   printf 'curl\n' > /tmp/pl.txt
   GDPI_PROGRAMS=/tmp/pl.txt ~/.local/share/DPIGate/start.sh --no-tray
   curl -sS -o /dev/null -w '%{http_code}\n' --max-time 12 https://discord.com/
   ```
   **2xx/3xx expected.** Then `./kill.sh`, `rm -f /tmp/pl.txt`.
3. Start normally (`~/.local/share/DPIGate/start.sh`) and open Vesktop;
   compare with the `./vm-diag.sh vesktop` output.
4. The single password prompt (Bug 1) is a human observation — in a **new**
   terminal:
   ```
   unset SUDO_PASSWORD
   cd linux && ./uninstall.sh   # exactly ONE password prompt expected
   ./install.sh                 # again exactly ONE password prompt
   ```
   If more than two prompts appear, attach
   `~/.local/share/DPIGate/platform.log` to the report.

## A5 — Report

Append this template to the end of `~/gdpi-vm-diag.txt` and give its contents
to the user:

```
ENVIRONMENT: ENV_NETMODE / ENV_FW_BACKEND / ENV_SYSDNS / ENV_SYSDNS_LOOPBACK
BASELINE   : BASE_VERDICT (+ BASE_TLS_DISCORD, BASE_TLS_EXAMPLE, BASE_RST)
BUG2       : WINNER, WINNER_MODE, WIRE_VERDICT, EP_VERDICT/EP_BLOCKED
BUG3       : BA_VERDICT (+ BA_DNS_VERDICT, BA_HTTP80, BA_HTTPS_GOOGLE, BA_CONN)
APPLIED FIXES: <rows applied from the decision table>
CHANGED FILES: <path:line list>
REMAINING ISSUE: <if any>
```

## Additional notes

- The `[GATE]` log wording is **inverted** with respect to the netfilter
  verdict: in the log, `PASS` = program is in the list = bypass **was
  applied**; `BLOCK` = not in the list = passed through raw/unprocessed. The
  `vesktop` subcommand repeats this reminder every time it runs.
- Every `vm-diag.sh` subcommand is self-contained and can be run over and over
  — each starts and ends with `kill.sh`, so nothing is left over from a
  previous run.
- Even if the script exits with an error, `trap ... EXIT` guarantees `kill.sh`
  is always called — it never leaves the VM without internet.

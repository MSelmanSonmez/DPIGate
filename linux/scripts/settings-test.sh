#!/bin/bash
# settings-test.sh - regression harness for the Linux settings/persistence and
# password-dialog-cancel guarantees.
#
# Runs the REAL start.sh / kill.sh / uninstall.sh / tray.py code against a
# sandbox $HOME, with every privilege-escalation and password-dialog binary
# removed from PATH. plat_root_acquire therefore fails deterministically, which
# is the exact code path a user takes by clicking Cancel on the password
# dialog - so "cancel" behaviour is testable without a GUI.
#
# Usage: ./scripts/settings-test.sh        (from linux/, or via `make settings-test`)
#
# Requires: a built ./goodbyedpi (run `make` first) and no running daemon.

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gdpi-settings-test.XXXXXX")"
SANDBOX="$ROOT/home"
APP="$ROOT/app"
trap 'rm -rf "$ROOT"' EXIT

pass=0; fail=0; skip=0
ok()   { printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n     expected: %s\n     actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); }
skp()  { printf '  SKIP  %s (%s)\n' "$1" "$2"; skip=$((skip+1)); }
eq()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
sect() { printf '\n+++ %s +++\n' "$1"; }

# -- Preconditions -----------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    echo "PRECONDITION FAILED: run as a normal user, not root."
    echo "  The whole point is to observe what happens when root is unobtainable."
    exit 2
fi
if pgrep -x goodbyedpi >/dev/null 2>&1; then
    echo "PRECONDITION FAILED: goodbyedpi is running."
    echo "  start.sh refuses a duplicate start, so its tests would abort early."
    echo "  Stop it first:  ~/.local/share/GoodbyeDPI-Plus/kill.sh"
    exit 2
fi
if [ ! -x "$REPO/goodbyedpi" ]; then
    echo "PRECONDITION FAILED: $REPO/goodbyedpi missing or not executable."
    echo "  Build it first:  make"
    exit 2
fi

# -- Sandbox -----------------------------------------------------------------
mkdir -p "$SANDBOX/.config" "$SANDBOX/.local/share" "$APP/lib" "$ROOT/bin"

# PATH holds only ordinary tools. sudo/doas/pkexec/run0 and every password
# dialog (zenity/kdialog/yad/qarma/systemd-ask-password) are deliberately
# absent, so plat_root_acquire returns 1 exactly as a cancelled dialog does.
for _b in bash sh cat cp mv rm ln ls sed awk cut tr sort head tail printf echo \
          mkdir rmdir chmod touch stat cmp diff wc readlink realpath dirname \
          basename env id getent pgrep pkill kill sleep timeout date find \
          xargs tee grep python3 nft iptables notify-send setcap getcap uname; do
    _p="$(command -v "$_b" 2>/dev/null)" && ln -sf "$_p" "$ROOT/bin/$_b"
done
export PATH="$ROOT/bin"
export HOME="$SANDBOX"
unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_RUNTIME_DIR SUDO_USER SUDO_PASSWORD PLAT_NOPROMPT SSH_ASKPASS SUDO_ASKPASS

for _f in start.sh kill.sh reaper.sh tray-launcher.sh uninstall.sh tray.py \
          dns_detect.py goodbyedpi.nft ProgramFilters; do
    cp "$REPO/$_f" "$APP/$_f"
done
cp "$REPO/lib/platform.sh" "$APP/lib/platform.sh"
chmod +x "$APP"/*.sh "$APP"/*.py
ln -sf "$REPO/goodbyedpi" "$APP/goodbyedpi"

CONFIG_DIR="$SANDBOX/.config/GoodbyeDPI-Plus"
DATA_DIR="$SANDBOX/.local/share/GoodbyeDPI-Plus"
SETTINGS="$CONFIG_DIR/settings"
FILTERS="$CONFIG_DIR/ProgramFilters"
STAMP="$CONFIG_DIR/.ProgramFilters.shipped"

# extract_fn FILE NAME -> the function's source, verbatim from the real file.
# Empty output means the function was renamed/reshaped: the caller must fail.
extract_fn() { sed -n "/^$2() {/,/^}/p" "$1"; }
# last_assign TRACE VAR -> value of the last traced `VAR=...` assignment.
last_assign() { sed -n "s/^+\{1,\} $2=\(.*\)$/\1/p" "$1" | tail -n1; }
# has_line FILE REGEX -> yes/no
has_line() { if sed -n "$2p" "$1" | read -r _; then echo yes; else echo no; fi; }

run_start() {   # run_start <args...> ; populates $ROOT/out and $ROOT/trace
    ( cd "$APP" && bash -x ./start.sh "$@" ) >"$ROOT/out" 2>"$ROOT/trace"
    echo $?
}

# -- T1  start.sh _config_get ------------------------------------------------
sect "T1 start.sh _config_get (extracted from the real file)"
CG="$(extract_fn "$APP/start.sh" _config_get)"
if [ -z "$CG" ]; then
    bad "_config_get is extractable" "a function body" "nothing - renamed?"
else
    ok "_config_get is extractable"
    mkdir -p "$CONFIG_DIR"
    printf 'BYPASS_ALL=1\nFORCE_DNS_INDEX=3\nEMPTY=\n' > "$SETTINGS"
    _cg() { ( set -e; SETTINGS_FILE="$SETTINGS"; eval "$CG"; _config_get "$1" "$2" ); }
    eq "present key"                 "1"    "$(_cg BYPASS_ALL 0)"
    eq "second key"                  "3"    "$(_cg FORCE_DNS_INDEX -1)"
    eq "missing key -> default"      "7"    "$(_cg NOPE 7)"
    eq "empty value -> default"      "5"    "$(_cg EMPTY 5)"
    printf 'BYPASS_ALL=0\nBYPASS_ALL=1\n' > "$SETTINGS"
    eq "last occurrence wins"        "1"    "$(_cg BYPASS_ALL 0)"
    printf '# BYPASS_ALL=1\n' > "$SETTINGS"
    eq "comments ignored"            "0"    "$(_cg BYPASS_ALL 0)"
    printf 'junk line\nBYPASS_ALL=1\n' > "$SETTINGS"
    eq "junk tolerated"              "1"    "$(_cg BYPASS_ALL 0)"
    rm -f "$SETTINGS"
    eq "missing file -> default"     "0"    "$(_cg BYPASS_ALL 0)"
fi

# -- T2  start.sh _has_entries -----------------------------------------------
sect "T2 start.sh _has_entries"
HE="$(extract_fn "$APP/start.sh" _has_entries)"
if [ -z "$HE" ]; then
    bad "_has_entries is extractable" "a function body" "nothing - renamed?"
else
    ok "_has_entries is extractable"
    _he() { ( eval "$HE"; if _has_entries "$1"; then echo yes; else echo no; fi ); }
    printf 'firefox\n'            > "$ROOT/f1"; eq "one entry"          "yes" "$(_he "$ROOT/f1")"
    : > "$ROOT/f2";                             eq "empty file"         "no"  "$(_he "$ROOT/f2")"
    printf '# only a comment\n'   > "$ROOT/f3"; eq "comments only"      "no"  "$(_he "$ROOT/f3")"
    printf '   \n\t\n'            > "$ROOT/f4"; eq "blanks only"        "no"  "$(_he "$ROOT/f4")"
    printf '\n# c\n  vesktop\n'   > "$ROOT/f5"; eq "indented entry"     "yes" "$(_he "$ROOT/f5")"
    eq "missing file"  "no"  "$(_he "$ROOT/nope")"
fi

# -- T3  empty ProgramFilters must NOT flip the mode -------------------------
sect "T3 empty ProgramFilters keeps per-program mode (no silent promotion)"
BLK="$(sed -n '/^if \[ "\$BYPASS_ALL" -eq 0 \]; then$/,/^fi$/p' "$APP/start.sh")"
if [ -z "$BLK" ]; then
    bad "mode block is extractable" "the BYPASS_ALL block" "nothing - reshaped?"
else
    ok "mode block is extractable"
    case "$BLK" in
        *"BYPASS_ALL=1"*) bad "block never promotes to bypass-all" "no BYPASS_ALL=1" "found one" ;;
        *)                ok  "block never promotes to bypass-all" ;;
    esac
    _mode() {   # _mode <bypass_all> <filters-file> -> "<mode>|<params>"
        (
            set -e
            BYPASS_ALL="$1"; PROGRAMS_LIST="$2"; CONFIG_DIR="$ROOT"; ICON_PATH=""
            PARAMS=()
            eval "$HE"
            die() { echo "DIED:$*" >&2; exit 9; }
            notify-send() { :; }
            eval "$BLK"
            printf '%s|%s\n' "$BYPASS_ALL" "${PARAMS[*]}"
        ) 2>/dev/null
    }
    printf 'firefox\n' > "$ROOT/pf_full"
    : > "$ROOT/pf_empty"
    rm -f "$ROOT/pf_absent"
    eq "populated list -> per-program + flag" "0|--only-programs $ROOT/pf_full" "$(_mode 0 "$ROOT/pf_full")"
    eq "EMPTY list  -> still per-program"     "0|--only-programs $ROOT/pf_empty" "$(_mode 0 "$ROOT/pf_empty")"
    eq "absent list -> created, per-program"  "0|--only-programs $ROOT/pf_absent" "$(_mode 0 "$ROOT/pf_absent")"
    eq "absent list is created on disk"       "yes" "$([ -f "$ROOT/pf_absent" ] && echo yes || echo no)"
    eq "bypass-all -> no --only-programs"     "1|" "$(_mode 1 "$ROOT/pf_empty")"
fi

# -- T4  start.sh adopts settings; CLI wins ----------------------------------
sect "T4 start.sh settings adoption + CLI precedence (real run)"
mkdir -p "$CONFIG_DIR"
printf 'firefox\n' > "$FILTERS"
printf 'BYPASS_ALL=1\nFORCE_DNS_INDEX=3\n' > "$SETTINGS"

rc="$(run_start --no-tray --no-dns-detect --skip-nft)"
eq "run stops at root acquire"        "1"  "$rc"
eq "  root refusal is explicit"       "yes" "$(case "$(cat "$ROOT/out" "$ROOT/trace")" in *"Root access required"*) echo yes;; *) echo no;; esac)"
eq "  BYPASS_ALL adopted from file"   "1"  "$(last_assign "$ROOT/trace" BYPASS_ALL)"
eq "  FORCE_DNS_INDEX adopted"        "3"  "$(last_assign "$ROOT/trace" FORCE_DNS_INDEX)"

run_start --no-tray --no-dns-detect --skip-nft --no-bypass-all >/dev/null
eq "--no-bypass-all overrides file"   "0"  "$(last_assign "$ROOT/trace" BYPASS_ALL)"
run_start --no-tray --no-dns-detect --skip-nft --auto-dns >/dev/null
eq "--auto-dns overrides file"        "-1" "$(last_assign "$ROOT/trace" FORCE_DNS_INDEX)"
run_start --no-tray --no-dns-detect --skip-nft --force-dns=1 >/dev/null
eq "--force-dns=N overrides file"     "1"  "$(last_assign "$ROOT/trace" FORCE_DNS_INDEX)"

printf 'BYPASS_ALL=banana\nFORCE_DNS_INDEX=../etc\n' > "$SETTINGS"
run_start --no-tray --no-dns-detect --skip-nft >/dev/null
eq "corrupt BYPASS_ALL -> 0"          "0"  "$(last_assign "$ROOT/trace" BYPASS_ALL)"
eq "corrupt DNS index -> -1"          "-1" "$(last_assign "$ROOT/trace" FORCE_DNS_INDEX)"

rm -f "$SETTINGS"
run_start --no-tray --no-dns-detect --skip-nft >/dev/null
eq "no settings file -> safe default" "0"  "$(last_assign "$ROOT/trace" BYPASS_ALL)"

# -- T5  ProgramFilters: seed once, never clobber user edits -----------------
sect "T5 ProgramFilters seeding never destroys user edits"
rm -rf "$CONFIG_DIR"; mkdir -p "$CONFIG_DIR"
run_start --no-tray --no-dns-detect --skip-nft >/dev/null
eq "absent -> seeded from shipped" "same" "$(cmp -s "$FILTERS" "$APP/ProgramFilters" && echo same || echo differs)"
eq "  stamp recorded"              "same" "$(cmp -s "$STAMP" "$APP/ProgramFilters" && echo same || echo differs)"

printf '# user cleared the list\n' > "$FILTERS"
run_start --no-tray --no-dns-detect --skip-nft >/dev/null
eq "user edit survives a restart"  "# user cleared the list" "$(cat "$FILTERS")"

printf 'newdefault\n' >> "$APP/ProgramFilters"
run_start --no-tray --no-dns-detect --skip-nft >/dev/null
eq "edited copy survives new defaults" "# user cleared the list" "$(cat "$FILTERS")"

cp "$APP/ProgramFilters" "$FILTERS"; cp "$APP/ProgramFilters" "$STAMP"
printf 'another\n' >> "$APP/ProgramFilters"
run_start --no-tray --no-dns-detect --skip-nft >/dev/null
eq "unmodified copy gets new defaults" "same" "$(cmp -s "$FILTERS" "$APP/ProgramFilters" && echo same || echo differs)"
eq "  refresh is announced" "yes" "$(case "$(cat "$ROOT/out" "$ROOT/trace")" in *"refreshed from shipped defaults"*) echo yes;; *) echo no;; esac)"

# -- T6  Cancelling the password dialog aborts the action --------------------
sect "T6 password-dialog cancel aborts (root unobtainable == cancelled)"

out="$(PLAT_NOPROMPT=1 bash -c '. "$1"; plat_askpass T P; echo "rc=$?"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "plat_askpass obeys PLAT_NOPROMPT" "rc=1" "$out"

# Pressing Cancel must END the request, not summon the next dialog in the
# chain. Fake providers: zenity reports Cancel (rc 1), kdialog would happily
# hand back a password if it were ever reached.
mkdir -p "$ROOT/dlg"
printf '#!/bin/bash\nexit %s\n' 1 > "$ROOT/dlg/zenity"
printf '#!/bin/bash\necho REACHED-SECOND-DIALOG\nexit 0\n' > "$ROOT/dlg/kdialog"
chmod +x "$ROOT/dlg/zenity" "$ROOT/dlg/kdialog"
out="$(PATH="$ROOT/dlg:$PATH" DISPLAY=:0 bash -c '. "$1"; pw="$(plat_askpass T P)"; echo "rc=$? pw=$pw"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "cancel stops the provider chain" "rc=2 pw=" "$out"   # rc 2 == user declined

# A provider that cannot run at all (crash/no display) must still fall through.
printf '#!/bin/bash\nexit 255\n' > "$ROOT/dlg/zenity"
out="$(PATH="$ROOT/dlg:$PATH" DISPLAY=:0 bash -c '. "$1"; pw="$(plat_askpass T P)"; echo "rc=$? pw=$pw"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "broken provider falls through"   "rc=0 pw=REACHED-SECOND-DIALOG" "$out"

# The decline must survive one layer up: plat_root_acquire used to answer
# "root acquired" by silently switching to pkexec after a cancelled dialog,
# which is what let a cancelled Exit kill the daemon anyway.
# Fake sudo: never passwordless, never accepts a password.
printf '#!/bin/bash\ncase "$1" in -n) exit 1;; esac\ncat >/dev/null 2>&1\nexit 1\n' > "$ROOT/dlg/sudo"
printf '#!/bin/bash\nexit 0\n' > "$ROOT/dlg/pkexec"
printf '#!/bin/bash\nexit 1\n' > "$ROOT/dlg/zenity"
chmod +x "$ROOT/dlg/sudo" "$ROOT/dlg/pkexec" "$ROOT/dlg/zenity"
rm -f "$ROOT/dlg/kdialog"
out="$(PATH="$ROOT/dlg:$PATH" DISPLAY=:0 bash -c '. "$1"; if plat_root_acquire; then echo acquired; else echo aborted; fi' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "cancel aborts root acquire"      "aborted"  "$out"

# ...but a host where nothing could ask must still reach pkexec, or headless
# installs would lose every privileged step.
rm -f "$ROOT/dlg/zenity"
out="$(PATH="$ROOT/dlg:$PATH" DISPLAY=:0 bash -c '. "$1"; plat_askpass() { return 1; }; if plat_root_acquire; then echo acquired; else echo aborted; fi' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "no prompt possible -> pkexec"    "acquired" "$out"
rm -f "$ROOT/dlg/sudo" "$ROOT/dlg/pkexec"

# -- T6b  Round 11 cancel matrix: display gating + decline rc 2 everywhere ---
sect "T6b display gating and decline propagation (round 11)"

# GUI providers are skipped without a display: nothing could ask -> rc 1,
# and plat_root_acquire still reaches pkexec (headless polkit installs).
printf '#!/bin/bash\nexit 1\n' > "$ROOT/dlg/zenity"
out="$(env -u DISPLAY -u WAYLAND_DISPLAY PATH="$ROOT/dlg:$PATH" bash -c '. "$1"; pw="$(plat_askpass T P)"; echo "rc=$? pw=$pw"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "GUI provider without display is skipped" "rc=1 pw=" "$out"

# systemd-ask-password: rc 1 (Cancel) is a decline, rc 124 (no agent) falls
# through. zenity/kdialog/yad/qarma are absent from this PATH, so the fake is
# the only provider and - with DISPLAY set - takes the agent branch.
mkdir -p "$ROOT/dlg/sysd"
printf '#!/bin/bash\nexit 1\n' > "$ROOT/dlg/sysd/systemd-ask-password"
chmod +x "$ROOT/dlg/sysd/systemd-ask-password"
out="$(env -u SSH_ASKPASS -u SUDO_ASKPASS DISPLAY=:0 PATH="$ROOT/dlg/sysd:$PATH" bash -c '. "$1"; pw="$(plat_askpass T P)"; echo "rc=$? pw=$pw"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "systemd-ask-password cancel is a decline" "rc=2 pw=" "$out"
printf '#!/bin/bash\nexit 124\n' > "$ROOT/dlg/sysd/systemd-ask-password"
chmod +x "$ROOT/dlg/sysd/systemd-ask-password"
out="$(env -u SSH_ASKPASS -u SUDO_ASKPASS DISPLAY=:0 PATH="$ROOT/dlg/sysd:$PATH" bash -c '. "$1"; pw="$(plat_askpass T P)"; echo "rc=$? pw=$pw"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "systemd-ask-password no-agent falls through" "rc=1 pw=" "$out"

# plat_run_root maps pkexec 126 / run0 125 to rc 2 (decline) and propagates
# it through the firewall layer - a cancelled prompt must never become
# "rules clean, carry on" or "try the other backend".
mkdir -p "$ROOT/dlg/root"
printf '#!/bin/bash\nexit 126\n' > "$ROOT/dlg/root/pkexec"
printf '#!/bin/bash\nexit 125\n' > "$ROOT/dlg/root/run0"
chmod +x "$ROOT/dlg/root/pkexec" "$ROOT/dlg/root/run0"
out="$(env -u SSH_ASKPASS -u SUDO_ASKPASS PATH="$ROOT/dlg/root:$PATH" bash -c '. "$1"; PLAT_ROOT_CMD=pkexec; plat_run_root true; echo "rc=$?"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "pkexec cancel -> plat_run_root rc 2" "rc=2" "$out"
out="$(env -u SSH_ASKPASS -u SUDO_ASKPASS PATH="$ROOT/dlg/root:$PATH" bash -c '. "$1"; PLAT_ROOT_CMD=run0; plat_run_root true; echo "rc=$?"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "run0 cancel -> plat_run_root rc 2" "rc=2" "$out"
out="$(env -u SSH_ASKPASS -u SUDO_ASKPASS PATH="$ROOT/dlg/root:$PATH" bash -c '. "$1"; PLAT_ROOT_CMD=pkexec; plat_fw_unload; echo "rc=$?"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "fw unload decline propagates rc 2" "rc=2" "$out"
out="$(env -u SSH_ASKPASS -u SUDO_ASKPASS PATH="$ROOT/dlg/root:$PATH" bash -c '. "$1"; PLAT_ROOT_CMD=pkexec; GDPI_FW_BACKEND=nft; plat_fw_load; echo "rc=$?"' _ "$APP/lib/platform.sh" 2>/dev/null)"
eq "fw load decline propagates rc 2 (no fallback)" "rc=2" "$out"

# kill.sh: a decline on the firewall-unload prompt aborts BEFORE the daemon
# is touched. (The fake pkexec makes plat_root_acquire succeed via the
# pkexec fallback, so the cancel happens mid-teardown, not at the gate.)
( cd "$APP" && env DISPLAY=:0 PATH="$ROOT/dlg/root:$PATH" ./kill.sh --nft ) >"$ROOT/kout3" 2>&1; rc=$?
eq "kill.sh: fw-unload cancel aborts"  "1"  "$rc"
eq "  says it was cancelled"  "yes" "$(case "$(cat "$ROOT/kout3")" in *"Kill cancelled"*) echo yes;; *) echo no;; esac)"
eq "  aborts BEFORE killing daemon" "no" "$(case "$(cat "$ROOT/kout3")" in *"stopping goodbyedpi"*) echo yes;; *) echo no;; esac)"

# start.sh: a decline at acquire dies with the cancel message BEFORE the
# kill region runs (the old daemon stays untouched).
mkdir -p "$ROOT/dlg/start"
printf '#!/bin/bash\ncase "$1" in -n) exit 1;; esac\ncat >/dev/null 2>&1\nexit 1\n' > "$ROOT/dlg/start/sudo"
printf '#!/bin/bash\nexit 1\n' > "$ROOT/dlg/start/zenity"
chmod +x "$ROOT/dlg/start/sudo" "$ROOT/dlg/start/zenity"
rm -f "$ROOT/dlg/start/pkexec" "$ROOT/dlg/start/run0"
( cd "$APP" && env DISPLAY=:0 PATH="$ROOT/dlg/start:$PATH" bash -x ./start.sh --no-tray --no-dns-detect --skip-nft ) >"$ROOT/sout" 2>"$ROOT/strace"; rc=$?
eq "start.sh: cancel aborts start"   "1"  "$rc"
eq "  says it was cancelled"         "yes" "$(case "$(cat "$ROOT/sout" "$ROOT/strace")" in *"Start cancelled"*) echo yes;; *) echo no;; esac)"
eq "  password prompt mentioned"     "yes" "$(case "$(cat "$ROOT/sout" "$ROOT/strace")" in *"password prompt was cancelled"*) echo yes;; *) echo no;; esac)"
eq "  daemon never started"          "no"  "$(case "$(cat "$ROOT/sout" "$ROOT/strace")" in *"goodbyedpi started"*) echo yes;; *) echo no;; esac)"
rm -f "$ROOT/dlg/sudo" "$ROOT/dlg/pkexec"

# kill.sh --nft touches neither processes nor the tray, so this is safe to run.
( cd "$APP" && ./kill.sh --nft ) >"$ROOT/kout" 2>&1; rc=$?
eq "kill.sh: cancel -> non-zero exit" "1" "$rc"
eq "  says it was cancelled"  "yes" "$(case "$(cat "$ROOT/kout")" in *"Kill cancelled"*) echo yes;; *) echo no;; esac)"
eq "  aborts BEFORE teardown" "no"  "$(case "$(cat "$ROOT/kout")" in *"firewall: removing"*) echo yes;; *) echo no;; esac)"

( cd "$APP" && PLAT_NOPROMPT=1 ./kill.sh --nft ) >"$ROOT/kout2" 2>&1; rc=$?
eq "kill.sh: PLAT_NOPROMPT -> proceeds" "0" "$rc"
eq "  best-effort teardown ran" "yes" "$(case "$(cat "$ROOT/kout2")" in *"firewall: removing"*) echo yes;; *) echo no;; esac)"

# uninstall.sh deletes the installation, so only its root gate is exercised.
UBLK="$(sed -n '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/p' "$APP/uninstall.sh")"
if [ -z "$UBLK" ]; then
    bad "uninstall root gate extractable" "the gate" "nothing - reshaped?"
else
    ok "uninstall root gate extractable"
    _ugate() { ( set -e; eval "$1"; eval "$UBLK"; echo proceeded ) 2>/dev/null; }
    eq "uninstall: cancel -> aborts"   ""           "$(_ugate 'plat_root_acquire() { return 1; }')"
    eq "uninstall: root ok -> proceeds" "proceeded" "$(_ugate 'plat_root_acquire() { return 0; }')"
    eq "uninstall: NOPROMPT -> proceeds" "proceeded" "$(_ugate 'PLAT_NOPROMPT=1; plat_root_acquire() { return 1; }')"
    gate_end="$(sed -n '/^if \[ "\$(id -u)" -ne 0 \]; then$/,/^fi$/=' "$APP/uninstall.sh" | tail -n1)"
    first_rm="$(sed -n '/rm -rf/=' "$APP/uninstall.sh" | head -n1)"
    if [ -n "$gate_end" ] && [ -n "$first_rm" ] && [ "$gate_end" -lt "$first_rm" ]; then
        ok "gate runs before any deletion"
    else
        bad "gate runs before any deletion" "gate < first rm -rf" "gate=$gate_end rm=$first_rm"
    fi
fi

# reaper.sh must never pop a dialog: the tray it watched is already dead.
case "$(cat "$APP/reaper.sh")" in
    *"PLAT_NOPROMPT=1"*) ok "reaper.sh declares PLAT_NOPROMPT" ;;
    *)                   bad "reaper.sh declares PLAT_NOPROMPT" "present" "absent" ;;
esac

# -- T7  tray.py: settings, revert, and noprompt plumbing --------------------
sect "T7 tray.py settings + cancel-revert + noprompt plumbing"
if ! python3 -c 'import gi' 2>/dev/null; then
    skp "tray.py behaviour" "python3-gi not installed"
else
cat > "$ROOT/killstub.sh" <<STUB
#!/bin/bash
printf '%s\n' "\${PLAT_NOPROMPT:-unset}" > "$ROOT/killenv"
exit \${STUB_RC:-0}
STUB
chmod +x "$ROOT/killstub.sh"

while IFS=$'\t' read -r verdict name exp act; do
    [ -z "${verdict:-}" ] && continue
    if [ "$verdict" = "PASS" ]; then ok "$name"; else bad "$name" "$exp" "$act"; fi
done < <(GDPI_START_SH="$APP/start.sh" XDG_CONFIG_HOME="$SANDBOX/.config" \
         python3 - "$APP" "$ROOT" <<'PY' 2>/dev/null
import os, sys, importlib.util
app, root = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("tray", os.path.join(app, "tray.py"))
tray = importlib.util.module_from_spec(spec); spec.loader.exec_module(tray)
res = []
def eq(n, e, a): res.append((n, e, a))
tray._save_setting("BYPASS_ALL", "1"); tray._save_setting("FORCE_DNS_INDEX", 4)
s = tray._load_settings()
eq("settings round-trip", ("1", "4"), (s.get("BYPASS_ALL"), s.get("FORCE_DNS_INDEX")))
tray._save_setting("BYPASS_ALL", "0"); s = tray._load_settings()
eq("one key updated, other kept", ("0", "4"), (s.get("BYPASS_ALL"), s.get("FORCE_DNS_INDEX")))
tray._arm_revert("BYPASS_ALL", tray._load_settings().get("BYPASS_ALL", "0"))
tray._save_setting("BYPASS_ALL", "1"); tray._run_revert()
eq("revert undoes the persisted choice", "0", tray._load_settings().get("BYPASS_ALL"))
tray._run_revert()
eq("second revert is a no-op", "0", tray._load_settings().get("BYPASS_ALL"))
envfile = os.path.join(root, "killenv")
tray.KILL_SH = os.path.join(root, "killstub.sh")
tray.kill_goodbyedpi(noprompt=True)
eq("noprompt=True sets PLAT_NOPROMPT", "1", open(envfile).read().strip())
tray.kill_goodbyedpi(noprompt=False)
eq("noprompt=False leaves it unset", "unset", open(envfile).read().strip())
os.environ["STUB_RC"] = "3"
tray._shutting_down = False; tray._restart_token = 0
eq("failed teardown reports False", False, tray._teardown())
eq("failed teardown re-arms the tray", False, tray._shutting_down)
for n, e, a in res:
    print(("PASS" if e == a else "FAIL") + "\t" + n + "\t" + repr(e) + "\t" + repr(a))
PY
)
fi

printf '\n=== RESULT: %d passed, %d failed, %d skipped ===\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]

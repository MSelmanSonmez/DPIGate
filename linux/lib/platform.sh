#!/bin/bash
# lib/platform.sh — DPIGate Linux portability layer.
#
# Single source of truth for: distro/package-manager detection, dependency
# install+check, dual firewall backend (nftables/iptables), privilege
# escalation, /proc-based process helpers (no procps dependency), init
# system abstraction (systemd/OpenRC/runit) and graphical-session discovery.
#
# Sourced by start.sh, kill.sh, uninstall.sh, install.sh, tray-launcher.sh.
# Invoked as a subprocess by tray.py (see the dispatch block at the bottom).
#
# set -e SAFE: every probe here uses `if cmd; then … fi` or `cmd || true`,
# never a bare command whose failure would abort a `set -e` caller.

[ -n "${PLAT_SH_LOADED:-}" ] && return 0
PLAT_SH_LOADED=1

# ── Exported constants ───────────────────────────────────────────────────────
PLAT_QUEUE_NUM="${PLAT_QUEUE_NUM:-200}"
PLAT_FWMARK="${PLAT_FWMARK:-0x40000000}"
PLAT_TABLE="goodbyedpi"          # nft table name
PLAT_IPT_CHAIN_OUT="GOODBYEDPI_OUT"
PLAT_IPT_CHAIN_IN="GOODBYEDPI_IN"
PLAT_LOG="${PLAT_LOG:-${XDG_DATA_HOME:-$HOME/.local/share}/DPIGate/platform.log}"

if [ ! -d "$(dirname "$PLAT_LOG")" ]; then
    mkdir -p "$(dirname "$PLAT_LOG")" 2>/dev/null || true
fi

# _PLAT_LIB_DIR = directory this file lives in (…/lib). APP_DIR/SCRIPT_DIR
# are normally already set by the sourcing caller (start.sh/install.sh use
# APP_DIR / SCRIPT_DIR respectively) — normalize so every plat_* function
# below can rely on a single $APP_DIR pointing at the app root.
_PLAT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${APP_DIR:=${SCRIPT_DIR:-}}"
if [ -z "$APP_DIR" ]; then
    APP_DIR="$(cd "$_PLAT_LIB_DIR/.." && pwd)"
fi

# ════════════════════════════════════════════════════════════════════════════
# Distro / package manager detection
# ════════════════════════════════════════════════════════════════════════════

plat_distro() {
    local id=""
    if [ -f /etc/os-release ]; then
        id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null || true)"
    fi
    if [ -z "$id" ]; then
        if [ -f /etc/arch-release ]; then id="arch"
        elif [ -f /etc/linuxmint/info ]; then id="linuxmint"
        elif [ -f /etc/debian_version ]; then id="debian"
        elif [ -f /etc/fedora-release ]; then id="fedora"
        fi
    fi
    if [ -n "$id" ]; then echo "$id"; else echo "unknown"; fi
}

plat_distro_like() {
    if [ -f /etc/os-release ]; then
        awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null || true
    fi
    return 0
}

plat_pkgmgr() {
    if command -v apt-get >/dev/null 2>&1; then echo apt; return 0; fi
    if command -v dnf >/dev/null 2>&1; then echo dnf; return 0; fi
    if command -v yum >/dev/null 2>&1; then echo yum; return 0; fi
    if command -v zypper >/dev/null 2>&1; then echo zypper; return 0; fi
    if command -v pacman >/dev/null 2>&1; then echo pacman; return 0; fi
    if command -v apk >/dev/null 2>&1; then echo apk; return 0; fi
    if command -v xbps-install >/dev/null 2>&1; then echo xbps; return 0; fi
    if command -v emerge >/dev/null 2>&1; then echo emerge; return 0; fi
    if command -v eopkg >/dev/null 2>&1; then echo eopkg; return 0; fi
    if command -v nix-env >/dev/null 2>&1; then echo nix; return 0; fi
    echo none
    return 0
}

_plat_print_manual_recipe() {
    if [ -f /etc/NIXOS ] || [ "$(plat_pkgmgr)" = "nix" ]; then
        echo "[platform] NixOS detected. Run:" >&2
        echo "  nix-shell -p gcc gnumake pkg-config libnetfilter_queue libnfnetlink libmnl libcap nftables --run './install.sh --assume-deps'" >&2
    elif [ -f /run/ostree-booted ]; then
        echo "[platform] ostree-based host detected (Silverblue/Kinoite/SteamOS-like). Run:" >&2
        echo "  toolbox create && toolbox run --container fedora-toolbox make -C linux" >&2
        echo "  then, on the host: ./install.sh --no-build" >&2
    else
        echo "[platform] no supported package manager found. Install manually:" >&2
        plat_deps_check >&2 || true
        echo "[platform] then re-run with: ./install.sh --assume-deps" >&2
    fi
}

# _plat_dnf_enable_el_repos — enable EPEL + CRB on RHEL-family hosts.
#
# libmnl-devel and libnfnetlink-devel live in CRB (named PowerTools on EL8) and
# libnetfilter_queue-devel comes from EPEL. Neither repository is enabled by
# default on Rocky, Alma, CentOS Stream, RHEL or Oracle Linux, which is why a
# plain "dnf install" there fails with nothing to match for the three -devel
# packages. Fedora carries all of them in its main repository and is skipped.
#
# Every step is best-effort: an offline or subscription-less host should still
# get as far as it can, and plat_deps_check has the final say on whether the
# capabilities are actually present.
_plat_dnf_enable_el_repos() {
    local id like repo
    id="$(plat_distro)"
    like="$(plat_distro_like)"

    case "$id" in
        fedora) return 0 ;;
        rhel|centos|rocky|almalinux|ol|oracle|scientific) ;;
        *)
            case " $like " in
                *rhel*|*centos*) ;;
                *) return 0 ;;
            esac
            ;;
    esac

    plat_run_root dnf install -y dnf-plugins-core || true
    plat_run_root dnf install -y epel-release || true

    # Repository name differs per release and per rebuild; the first one that
    # exists wins. dnf exits non-zero for a name it does not know.
    for repo in crb powertools \
                codeready-builder-for-rhel-9-x86_64-rpms \
                codeready-builder-for-rhel-8-x86_64-rpms \
                ol9_codeready_builder ol8_codeready_builder; do
        if plat_run_root dnf config-manager --set-enabled "$repo" >/dev/null 2>&1; then
            echo "[platform] enabled repository: $repo" >&2
            break
        fi
    done
    return 0
}


# plat_deps_install ROLE   ROLE = build|runtime|all
plat_deps_install() {
    local role="${1:-all}"
    local mgr; mgr="$(plat_pkgmgr)"
    local build_req="" run_req="" run_opt="" pre="" rc=0

    case "$mgr" in
        apt)
            build_req="gcc make pkg-config libnetfilter-queue-dev libnfnetlink-dev libmnl-dev"
            run_req="bash nftables iptables libcap2-bin"
            run_opt="libnotify-bin python3 python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 zenity policykit-1"
            ;;
        dnf)
            build_req="gcc make pkgconf-pkg-config libnetfilter_queue-devel libnfnetlink-devel libmnl-devel"
            run_req="bash nftables iptables libcap"
            run_opt="libnotify python3 python3-gobject gtk3 libayatana-appindicator-gtk3 libappindicator-gtk3 zenity polkit"
            ;;
        yum)
            pre="epel-release"
            build_req="gcc make pkgconfig libnetfilter_queue-devel libnfnetlink-devel libmnl-devel"
            run_req="bash nftables iptables libcap"
            run_opt="libnotify python3 python3-gobject gtk3 zenity polkit"
            ;;
        zypper)
            build_req="gcc make pkg-config libnetfilter_queue-devel libnfnetlink-devel libmnl-devel"
            run_req="bash nftables iptables libcap-progs"
            run_opt="libnotify-tools python3-gobject typelib-1_0-Gtk-3_0 typelib-1_0-AyatanaAppIndicator3-0_1 typelib-1_0-AppIndicator3-0_1 zenity polkit"
            ;;
        pacman)
            build_req="base-devel pkgconf libnetfilter_queue libnfnetlink libmnl"
            run_req="bash nftables iptables libcap"
            run_opt="libnotify python-gobject gtk3 libayatana-appindicator zenity polkit"
            ;;
        apk)
            build_req="build-base pkgconf linux-headers libnetfilter_queue-dev libnfnetlink-dev libmnl-dev"
            run_req="bash nftables iptables libcap"
            run_opt="libnotify py3-gobject3 gtk+3.0 zenity polkit"
            ;;
        xbps)
            build_req="gcc make pkgconf libnetfilter_queue-devel libnfnetlink-devel libmnl-devel"
            run_req="bash nftables iptables libcap-progs"
            run_opt="libnotify python3-gobject gtk+3 libayatana-appindicator zenity polkit"
            ;;
        emerge)
            build_req="sys-devel/gcc dev-build/make dev-build/pkgconf net-libs/libnetfilter_queue net-libs/libnfnetlink net-libs/libmnl"
            run_req="net-firewall/nftables net-firewall/iptables sys-libs/libcap"
            run_opt="x11-libs/libnotify dev-python/pygobject x11-libs/gtk+ dev-libs/libayatana-appindicator gnome-extra/zenity sys-auth/polkit"
            ;;
        eopkg)
            build_req="gcc make pkg-config libnetfilter-queue-devel libnfnetlink-devel libmnl-devel"
            run_req="bash nftables iptables libcap"
            run_opt="libnotify python3-gobject libgtk-3 zenity polkit"
            ;;
        nix|none)
            _plat_print_manual_recipe
            return 1
            ;;
        *)
            _plat_print_manual_recipe
            return 1
            ;;
    esac

    if [ "$mgr" = "yum" ] && [ -n "$pre" ]; then
        rc=0
        plat_run_root yum install -y "$pre" || rc=$?
        if [ "$rc" -eq 2 ]; then return 2; fi
    fi

    if [ "$mgr" = "dnf" ]; then
        _plat_dnf_enable_el_repos
    fi

    local pkgs=""
    case "$role" in
        build)   pkgs="$build_req" ;;
        runtime) pkgs="$run_req" ;;
        *)       pkgs="$build_req $run_req" ;;
    esac

    if [ -n "$pkgs" ]; then
        if [ "$mgr" = "apt" ]; then
            rc=0
            plat_run_root apt-get update -qq || rc=$?
            if [ "$rc" -eq 2 ]; then return 2; fi
        fi
        # One transaction first (fast, resolves conflicts as a set). If it
        # fails — a single renamed/absent package name aborts the whole
        # transaction on dnf/zypper — retry package by package so the rest
        # still lands. plat_deps_check below decides whether that was enough.
        # A decline (rc 2) is NOT retried: retrying would re-prompt after the
        # user said stop.
        rc=0
        _plat_pkg_install "$mgr" $pkgs || rc=$?
        if [ "$rc" -eq 2 ]; then return 2; fi
        if [ "$rc" -ne 0 ]; then
            echo "[platform] batch install failed — retrying package by package" >&2
            local p
            for p in $pkgs; do
                rc=0
                _plat_pkg_install "$mgr" "$p" || rc=$?
                if [ "$rc" -eq 2 ]; then return 2; fi
                if [ "$rc" -ne 0 ]; then
                    echo "[platform] WARN: cannot install '$p'" >&2
                fi
            done
        fi
    fi

    if [ "$role" != "build" ]; then
        local p
        for p in $run_opt; do
            rc=0
            _plat_pkg_install "$mgr" "$p" || rc=$?
            if [ "$rc" -eq 2 ]; then return 2; fi
        done
    fi

    # Report the CAPABILITY outcome, not the package-manager exit code: a
    # transaction can "succeed" while the compiler is still missing, and it
    # can fail on one optional name while everything required got installed.
    if [ "$role" = "runtime" ]; then
        return 0
    fi
    if plat_deps_check >/dev/null; then
        return 0
    fi
    echo "[platform] dependencies still missing after install:" >&2
    plat_deps_check | grep '^missing:' >&2 || true
    return 1
}

# _plat_pkg_install MGR PKG... — one manager-specific install invocation.
_plat_pkg_install() {
    local mgr="$1"; shift
    [ $# -gt 0 ] || return 0
    case "$mgr" in
        apt)    plat_run_root apt-get install -y "$@" ;;
        dnf)    plat_run_root dnf install -y "$@" ;;
        yum)    plat_run_root yum install -y "$@" ;;
        zypper) plat_run_root zypper --non-interactive install --no-recommends "$@" ;;
        pacman) plat_run_root pacman -S --needed --noconfirm "$@" ;;
        apk)    plat_run_root apk add --no-cache "$@" ;;
        xbps)   plat_run_root xbps-install -Sy "$@" ;;
        emerge) plat_run_root emerge --noreplace --quiet "$@" ;;
        eopkg)  plat_run_root eopkg install -y "$@" ;;
        *)      return 1 ;;
    esac
}

# plat_deps_check -> rc 0 when every REQUIRED capability probe passes.
# Probes capabilities, never package names — REQUIRED misses are prefixed
# "missing: ", OPTIONAL misses are prefixed "warn: " and never fail the rc.
plat_deps_check() {
    local ok=0
    local cc=""
    if command -v cc >/dev/null 2>&1; then cc=cc
    elif command -v gcc >/dev/null 2>&1; then cc=gcc
    elif command -v clang >/dev/null 2>&1; then cc=clang
    fi
    if [ -z "$cc" ]; then echo "missing: C compiler (cc/gcc/clang)"; ok=1; fi
    if ! command -v make >/dev/null 2>&1; then echo "missing: make"; ok=1; fi

    if [ -n "$cc" ]; then
        local tmpd; tmpd="$(mktemp -d 2>/dev/null || true)"
        if [ -n "$tmpd" ]; then
            cat > "$tmpd/probe.c" <<'EOF'
/* stdint.h FIRST: Fedora 44's libnetfilter_queue.h (1.0.5-13.fc44) uses
   uint8_t/uint16_t/uint32_t without including <stdint.h> itself, so a probe
   that opens with that header fails to compile even though the real build —
   whose .c files include <stdio.h>/<stdlib.h> first — is fine. Without this
   line plat_deps_check returns 1 on a fully provisioned Fedora host and
   install.sh aborts with "dependency resolution failed". */
#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libmnl/libmnl.h>
int main(void){ return 0; }
EOF
            local probe_ok=1 errlog="$tmpd/err.log"
            # Attempt 1: with pkg-config (query ALL three; distros differ
            # on whether libnfnetlink resolves transitively).
            if command -v pkg-config >/dev/null 2>&1 && [ "$probe_ok" -ne 0 ]; then
                local pc_cflags pc_libs
                pc_cflags="$(pkg-config --cflags libnetfilter_queue libnfnetlink libmnl 2>/dev/null || true)"
                pc_libs="$(pkg-config --libs libnetfilter_queue libnfnetlink libmnl 2>/dev/null || true)"
                [ -z "$pc_libs" ] && pc_libs="-lnetfilter_queue -lnfnetlink -lmnl"
                if "$cc" $pc_cflags "$tmpd/probe.c" $pc_libs -o "$tmpd/probe" 2>"$errlog"; then
                    probe_ok=0
                fi
            fi
            # Attempt 2: bare fallback — no pkg-config at all. Handles
            # distros where pkg-config returns conflicting flags or the
            # .pc files are in a non-standard location.
            if [ "$probe_ok" -ne 0 ]; then
                if "$cc" "$tmpd/probe.c" -lnetfilter_queue -lnfnetlink -lmnl -o "$tmpd/probe" 2>"$errlog"; then
                    probe_ok=0
                fi
            fi
            if [ "$probe_ok" -ne 0 ]; then
                echo "missing: libnetfilter_queue/libnfnetlink/libmnl (dev headers or libs)"
                [ -s "$errlog" ] && sed 's/^/  [compiler] /' "$errlog" >&2
                ok=1
            fi
            rm -rf "$tmpd"
        fi
    fi

    if ! command -v setcap >/dev/null 2>&1; then echo "missing: setcap (libcap)"; ok=1; fi
    if ! command -v nft >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then
        echo "missing: nft or iptables"; ok=1
    fi
    if ! command -v bash >/dev/null 2>&1; then echo "missing: bash"; ok=1; fi

    # OPTIONAL — warnings only, never fail the install.
    if ! command -v python3 >/dev/null 2>&1; then
        echo "warn: python3 missing — DNS auto-detect disabled"
    elif ! python3 -c 'import gi' >/dev/null 2>&1; then
        echo "warn: python3-gi missing — tray disabled"
    fi
    if ! command -v notify-send >/dev/null 2>&1; then echo "warn: notify-send missing"; fi
    # Only warn when NOTHING can escalate: pkexec/run0 prompt on their own and
    # systemd-ask-password covers hosts without a desktop dialog.
    if ! command -v zenity >/dev/null 2>&1 && ! command -v kdialog >/dev/null 2>&1 \
       && ! command -v yad >/dev/null 2>&1 && ! command -v qarma >/dev/null 2>&1 \
       && ! command -v systemd-ask-password >/dev/null 2>&1 \
       && ! command -v pkexec >/dev/null 2>&1 && ! command -v run0 >/dev/null 2>&1; then
        echo "warn: no password prompt available (zenity/kdialog/yad/systemd-ask-password/pkexec)"
    fi

    return "$ok"
}

# ════════════════════════════════════════════════════════════════════════════
# Privilege escalation
# ════════════════════════════════════════════════════════════════════════════

# plat_root_cmd -> echoes the escalation mechanism ("" when euid 0); rc 1
# when none is available. Result is cached in $PLAT_ROOT_CMD.
plat_root_cmd() {
    if [ -z "${PLAT_ROOT_CMD+set}" ]; then
        if [ "$(id -u)" = "0" ]; then
            PLAT_ROOT_CMD=""
        elif command -v sudo >/dev/null 2>&1 && { [ -n "${SUDO_PASSWORD:-}" ] || sudo -n true 2>/dev/null; }; then
            PLAT_ROOT_CMD="sudo"
        elif command -v doas >/dev/null 2>&1 && doas -n true 2>/dev/null; then
            PLAT_ROOT_CMD="doas"
        elif [ "${PLAT_NOPROMPT:-0}" = "1" ]; then
            PLAT_ROOT_CMD="none"
        elif command -v pkexec >/dev/null 2>&1 && \
             { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] || [ -t 0 ]; }; then
            # polkit has a text agent on a TTY, so a headless SSH install still
            # works; without either it would hang waiting for an agent.
            PLAT_ROOT_CMD="pkexec"
        elif command -v run0 >/dev/null 2>&1; then
            PLAT_ROOT_CMD="run0"
        else
            PLAT_ROOT_CMD="none"
        fi
    fi
    if [ "${PLAT_NOPROMPT:-0}" = "1" ]; then
        case "$PLAT_ROOT_CMD" in
            pkexec|run0) return 1 ;;
        esac
    fi
    if [ "$PLAT_ROOT_CMD" = "none" ]; then
        return 1
    fi
    echo "$PLAT_ROOT_CMD"
    return 0
}

# plat_run_root CMD... — runs CMD as root; stderr appended to $PLAT_LOG.
#   rc 0 - ran
#   rc 1 - failed / no escalation mechanism
#   rc 2 - the user was asked and DECLINED (pkexec dialog dismissed, run0
#          prompt cancelled). Callers must abort on rc 2 — it means "the
#          user said stop", never "try something else". Never silently
#          swallows failures with 2>/dev/null.
#
# Caveat: pkexec/run0 propagate the CHILD's exit code when authentication
# succeeds, so a child that itself exits 126 (pkexec) or 125 (run0) is
# indistinguishable from a dismissed dialog. Our root commands (nft, setcap,
# resolvectl, systemctl, install, package managers) never exit those codes.
plat_run_root() {
    local mech rc=0
    if ! mech="$(plat_root_cmd)"; then
        echo "plat_run_root failed (rc=1) via none: $*" | tee -a "$PLAT_LOG" >&2
        return 1
    fi
    case "$mech" in
        "")   "$@" 2>>"$PLAT_LOG" || rc=$? ;;
        sudo)
            if [ -n "${SUDO_PASSWORD:-}" ]; then
                printf '%s\n' "$SUDO_PASSWORD" | sudo -S "$@" 2>>"$PLAT_LOG" || rc=$?
            else
                sudo -n "$@" 2>>"$PLAT_LOG" || rc=$?
            fi
            ;;
        doas)   doas -n "$@" 2>>"$PLAT_LOG" || rc=$? ;;
        pkexec) pkexec "$@" 2>>"$PLAT_LOG" || rc=$?
            # pkexec(1): 126 = the dialog was dismissed / authorization
            # denied; 127 = no authentication agent could be reached.
            case "$rc" in 126) rc=2 ;; esac
            ;;
        run0)   run0 "$@" 2>>"$PLAT_LOG" || rc=$?
            # run0 (systemd-run): EXIT_CANCELED (125) = the user cancelled
            # the authentication prompt.
            case "$rc" in 125) rc=2 ;; esac
            ;;
    esac
    if [ "$rc" -eq 2 ]; then
        echo "plat_run_root: escalation prompt cancelled via $mech: $*" | tee -a "$PLAT_LOG" >&2
    elif [ "$rc" -ne 0 ]; then
        echo "plat_run_root failed (rc=$rc) via $mech: $*" | tee -a "$PLAT_LOG" >&2
    fi
    return "$rc"
}

# plat_askpass TITLE PROMPT -> echoes a password on stdout.
#   rc 0 - password on stdout
#   rc 2 - the user was asked and DECLINED (Cancel / closed the window)
#   rc 1 - nothing could ask (no provider installed, no display, no TTY)
# The 1/2 split matters: callers may substitute another escalation mechanism
# when nobody could be asked, but MUST abort when the user said no.
#
# PLAT_NOPROMPT=1 is a hard contract, not a hint: the caller is a context with
# nobody to answer (logout, ExecStop, the crash reaper, a background thread).
# It MUST be enforced here rather than only in plat_root_cmd, which merely
# refuses pkexec/run0 - without this the "silent" callers still popped a zenity
# dialog, and a cancelled dialog was then treated as "carry on anyway".
plat_askpass() {
    local title="${1:-DPIGate}" prompt="${2:-Password:}"
    local pw="" helper="" rc=0

    if [ "${PLAT_NOPROMPT:-0}" = "1" ]; then
        return 1
    fi

    # GUI providers require a graphical session. Without one they cannot show
    # anything, and their rc 1 (the decline signal when they RAN) must not be
    # misread as a decline: a headless SSH session would abort with "cancelled"
    # while no dialog was ever shown. Explicitly configured $SUDO_ASKPASS /
    # $SSH_ASKPASS are the user's own choice and stay honored headless.
    local have_gui=0
    if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
        have_gui=1
    fi

    # A provider that RAN and was dismissed means the user said no: stop right
    # there. Only a provider that could not run at all (not installed, no
    # display, crashed, no agent) may fall through to the next one. zenity,
    # kdialog, yad, qarma and the ssh-askpass helpers all exit 1 for Cancel,
    # so rc 1 is the decline signal and any other failure is "provider
    # unusable". Without this, cancelling simply summoned the next dialog.
    if [ "$have_gui" -eq 1 ] && command -v zenity >/dev/null 2>&1; then
        rc=0; pw="$(zenity --password --title="$title" 2>/dev/null)" || rc=$?
        if [ "$rc" -eq 0 ]; then printf '%s\n' "$pw"; return 0; fi
        if [ "$rc" -eq 1 ]; then return 2; fi
    fi
    if [ "$have_gui" -eq 1 ] && command -v kdialog >/dev/null 2>&1; then
        rc=0; pw="$(kdialog --title "$title" --password "$prompt" 2>/dev/null)" || rc=$?
        if [ "$rc" -eq 0 ]; then printf '%s\n' "$pw"; return 0; fi
        if [ "$rc" -eq 1 ]; then return 2; fi
    fi
    if [ "$have_gui" -eq 1 ]; then
        for helper in yad qarma; do
            if command -v "$helper" >/dev/null 2>&1; then
                rc=0
                pw="$("$helper" --title="$title" --entry --hide-text --text="$prompt" 2>/dev/null)" || rc=$?
                if [ "$rc" -eq 0 ]; then printf '%s\n' "$pw"; return 0; fi
                # yad also reports 252 when the window is closed outright.
                if [ "$rc" -eq 1 ] || [ "$rc" -eq 252 ]; then return 2; fi
            fi
        done
    fi
    # Distro ssh-askpass helpers (GUI) — same display gate as above.
    if [ "$have_gui" -eq 1 ]; then
        for helper in /usr/libexec/openssh/gnome-ssh-askpass \
                      /usr/libexec/openssh/x11-ssh-askpass \
                      /usr/lib/ssh/ssh-askpass /usr/bin/ssh-askpass \
                      /usr/bin/lxqt-openssh-askpass; do
            [ -x "$helper" ] || continue
            rc=0; pw="$("$helper" "$prompt" 2>/dev/null)" || rc=$?
            if [ "$rc" -eq 0 ] && [ -n "$pw" ]; then printf '%s\n' "$pw"; return 0; fi
            if [ "$rc" -eq 1 ]; then return 2; fi
        done
    fi
    # Explicitly configured askpass helpers: the convention is "print the
    # password on stdout" - exactly what we need, whatever session they run in.
    for helper in "${SUDO_ASKPASS:-}" "${SSH_ASKPASS:-}"; do
        [ -n "$helper" ] && [ -x "$helper" ] || continue
        rc=0; pw="$("$helper" "$prompt" 2>/dev/null)" || rc=$?
        if [ "$rc" -eq 0 ] && [ -n "$pw" ]; then printf '%s\n' "$pw"; return 0; fi
        if [ "$rc" -eq 1 ]; then return 2; fi
    done
    # systemd-ask-password: on a TTY it reads the terminal directly (reliable
    # headless); in a graphical session it queries the session's password
    # agent. rc 1 means the user declined in both modes. In the agent mode the
    # query also fails with rc 124 (timeout) when NO agent exists - that is
    # "provider unusable", fall through. Ships with systemd, so it is the
    # reliable last resort on Fedora/RHEL/openSUSE minimal installs.
    if command -v systemd-ask-password >/dev/null 2>&1; then
        rc=0
        if [ -t 0 ]; then
            pw="$(systemd-ask-password --icon=dialog-password "$prompt" 2>/dev/null)" || rc=$?
        elif [ "$have_gui" -eq 1 ]; then
            # --no-tty: never block waiting for a terminal to appear;
            # --timeout: without an agent the query would otherwise hang
            # forever (measured), time out and fall through instead.
            pw="$(systemd-ask-password --no-tty --timeout=15 --icon=dialog-password "$prompt" 2>/dev/null)" || rc=$?
        fi
        # No TTY and no GUI: the query cannot be shown at all - rc stays 0
        # with an empty pw, so both checks below fall past ("nothing could
        # ask"), keeping the pkexec/run0 fallback reachable.
        if [ "$rc" -eq 0 ]; then
            if [ -n "$pw" ]; then printf '%s\n' "$pw"; return 0; fi
        elif [ "$rc" -eq 1 ]; then
            return 2    # the user was asked and declined
        fi
        # rc 124 (no agent answered) or any other failure: unusable, fall through
    fi
    if [ -t 0 ]; then
        if read -rs -p "$prompt " pw; then
            echo >&2
            printf '%s\n' "$pw"; return 0
        fi
        # EOF (Ctrl-D) on the prompt is a decline, not "nothing could ask":
        # falling through to return 1 would hand the decision to pkexec/run0
        # and keep the operation going after the user said stop.
        return 2
    fi
    return 1
}

# plat_password_unexport - keep $SUDO_PASSWORD usable in THIS shell but drop
# it from the exported environment, so no forked child ever inherits it.
#
# Callers hand the credential over with an env prefix
# (`SUDO_PASSWORD=... start.sh`, see tray-launcher.sh / install.sh), which is
# convenient but marks the variable EXPORTED in the receiving shell - and from
# there every child inherits it. That included goodbyedpi and tray.py, both of
# which live for the whole desktop session with the user's plaintext password
# sitting in /proc/PID/environ, readable by any other process of that user.
# The daemon runs unprivileged when it has file capabilities, so that is not
# even a root-only file.
#
# unset drops the export attribute; the plain re-assignment recreates the
# value as a shell-local variable, which is all plat_run_root and
# plat_root_acquire ever needed - they are sourced functions running in this
# same shell, not children.
#
# Call this immediately after sourcing platform.sh, BEFORE anything forks.
# Note it cannot scrub the caller's OWN /proc/self/environ: the kernel keeps
# the original environment block from execve, and unsetenv only edits libc's
# copy. It bounds the exposure to this one short-lived process instead of
# every descendant for the whole session.
plat_password_unexport() {
    if [ -z "${SUDO_PASSWORD:-}" ]; then
        unset SUDO_PASSWORD 2>/dev/null || true
        return 0
    fi
    local _pw="$SUDO_PASSWORD"
    unset SUDO_PASSWORD
    SUDO_PASSWORD="$_pw"        # global, and no longer marked for export
    return 0
}

# plat_root_acquire - ensures subsequent plat_run_root calls work.
#   rc 0 - root is reachable afterwards (silently when we hold a password, or
#          through pkexec/run0, which prompt per call but DO work)
#   rc 2 - the user was asked and DECLINED; the operation must not happen
#   rc 1 - no escalation mechanism exists at all
# `! plat_root_acquire` catches both failures, which is what every teardown
# path wants. install.sh is the one caller that separates them: a decline
# aborts, while "no mechanism" still lays down the user-space files with a
# warning (a stock Fedora has no zenity and no TTY, yet polkit works).
# Opens AT MOST ONE password prompt; the probe phase itself opens none (the old
# `plat_run_root true` probe popped a pkexec window by itself).
# Sets SUDO_PASSWORD, does NOT export it - export is the caller's call.
plat_root_acquire() {
    if [ "$(id -u)" = "0" ]; then return 0; fi
    if [ -n "${SUDO_PASSWORD:-}" ]; then
        if printf '%s\n' "$SUDO_PASSWORD" | sudo -S -v 2>>"$PLAT_LOG"; then
            PLAT_ROOT_CMD="sudo"
            return 0
        fi
        SUDO_PASSWORD=""      # stale/wrong — fall through to the prompt
    fi
    # Passwordless sudo/doas — no prompt needed, detect and return.
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        PLAT_ROOT_CMD="sudo"
        return 0
    fi
    if command -v doas >/dev/null 2>&1 && doas -n true 2>/dev/null; then
        PLAT_ROOT_CMD="doas"
        return 0
    fi
    # Interactive prompt fallback (sudo only - doas has no stdin password mode)
    local pw rc
    if command -v sudo >/dev/null 2>&1; then
        for _ in 1 2; do
            rc=0
            pw="$(plat_askpass 'DPIGate' 'Enter your password to start DPI bypass:')" || rc=$?
            if [ "$rc" -eq 2 ]; then
                # The user was asked and said no. Escalating through pkexec
                # anyway would turn "Cancel" into "do it, just differently" -
                # which is exactly how a cancelled Exit still killed the
                # daemon. A decline is final.
                echo "[platform] password prompt cancelled by the user" >>"$PLAT_LOG"
                unset PLAT_ROOT_CMD
                return 2
            fi
            if [ "$rc" -ne 0 ]; then
                break     # nothing could ask - the pkexec fallback below may
            fi
            if printf '%s\n' "$pw" | sudo -S -v 2>>"$PLAT_LOG"; then
                SUDO_PASSWORD="$pw"
                PLAT_ROOT_CMD="sudo"
                return 0
            fi
        done
    fi
    # Nobody could be asked for a password (no zenity, no TTY, ...). pkexec and
    # run0 still escalate fine - they just prompt once per call. That is far
    # better than reporting "no root" and then failing every privileged step
    # (the Fedora failure mode: install did nothing). This is NOT reached after
    # a decline: that returns 1 above.
    unset PLAT_ROOT_CMD
    if plat_root_cmd >/dev/null 2>&1; then
        echo "[platform] using $(plat_root_cmd) for privileged steps (prompts per operation)" >&2
        return 0
    fi
    return 1
}

# ════════════════════════════════════════════════════════════════════════════
# Firewall backend (nftables + iptables)
# ════════════════════════════════════════════════════════════════════════════

# plat_fw_backend -> echoes nft|iptables|none
plat_fw_backend() {
    if [ -n "${GDPI_FW_BACKEND:-}" ]; then
        case "$GDPI_FW_BACKEND" in
            nft|iptables) echo "$GDPI_FW_BACKEND"; return 0 ;;
        esac
    fi
    if command -v nft >/dev/null 2>&1; then echo nft; return 0; fi
    if command -v iptables >/dev/null 2>&1; then echo iptables; return 0; fi
    echo none
    return 1
}

# plat_fw_preflight -> best-effort modprobe; rc 1 + diagnostic when
# /proc/net/netfilter is absent (genuinely unsupportable host).
plat_fw_preflight() {
    local rc=0
    plat_run_root sh -c 'for m in nfnetlink_queue nft_queue nf_tables xt_NFQUEUE xt_mark; do modprobe "$m" 2>/dev/null || true; done' >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 2 ]; then
        return 2    # user declined the prompt — propagate, never continue
    fi
    if [ ! -d /proc/net/netfilter ]; then
        echo "FATAL: kernel has no netfilter (CONFIG_NETFILTER_NETLINK_QUEUE missing)" >&2
        return 1
    fi
    return 0
}

_plat_nft_file() {
    if [ -n "${PLAT_NFT_FILE:-}" ] && [ -f "$PLAT_NFT_FILE" ]; then
        echo "$PLAT_NFT_FILE"; return 0
    fi
    local f
    for f in "$APP_DIR/goodbyedpi.nft" "$APP_DIR/../share/DPIGate/goodbyedpi.nft"; do
        if [ -f "$f" ]; then echo "$f"; return 0; fi
    done
    return 1
}

# QUIC/HTTP3 handling. The nft ruleset rejects outbound UDP 443 outright so a
# blocked client fails fast instead of waiting out a black hole; set
# PLAT_BLOCK_QUIC=0 (start.sh does this when BYPASS_MODE has no -q) to keep
# QUIC flowing.
_plat_block_quic() { [ "${PLAT_BLOCK_QUIC:-1}" = "1" ]; }

_plat_fw_load_nft() {
    local f
    if ! f="$(_plat_nft_file)"; then
        echo "[platform] goodbyedpi.nft not found" >&2
        return 1
    fi
    plat_run_root nft -f "$f" || return $?
    if ! _plat_block_quic; then
        # Drop the reject rule again — QUIC blocking was not requested.
        plat_run_root sh -c '
            h=$(nft -a list chain inet goodbyedpi output 2>/dev/null \
                | awk "/udp dport 443 counter .*reject/ {print \$NF; exit}")
            [ -n "$h" ] && nft delete rule inet goodbyedpi output handle "$h"
            exit 0' >/dev/null 2>&1 || true
    fi
    return 0
}

_plat_fw_load_iptables() {
    local q="$PLAT_QUEUE_NUM" mk="$PLAT_FWMARK" ipt quic=0
    if _plat_block_quic; then quic=1; fi
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        plat_run_root sh -c '
            ipt="$1"; q="$2"; mk="$3"; out="$4"; in="$5"; quic="$6"
            "$ipt" -t mangle -N "$out" 2>/dev/null || true
            "$ipt" -t mangle -N "$in"  2>/dev/null || true
            "$ipt" -t mangle -A "$out" -o lo -j RETURN
            "$ipt" -t mangle -A "$out" -m mark --mark "$mk/$mk" -j RETURN
            "$ipt" -t mangle -A "$out" -m owner --uid-owner 0 -j RETURN || true
            "$ipt" -t mangle -A "$out" -p tcp --dport 80  -j NFQUEUE --queue-num "$q" --queue-bypass
            "$ipt" -t mangle -A "$out" -p tcp --dport 443 -j NFQUEUE --queue-num "$q" --queue-bypass
            "$ipt" -t mangle -A "$out" -p udp --dport 53  -j NFQUEUE --queue-num "$q" --queue-bypass
            # mangle OUTPUT runs BEFORE filter OUTPUT: queueing UDP 443 here
            # would hand the packet to the daemon (which drops it) and the
            # REJECT below would never run. Only queue it when QUIC is allowed
            # to flow, i.e. when the daemon itself decides what to do with it.
            if [ "$quic" != "1" ]; then
                "$ipt" -t mangle -A "$out" -p udp --dport 443 -j NFQUEUE --queue-num "$q" --queue-bypass
            fi
            "$ipt" -t mangle -A "$in"  -i lo -j RETURN
            "$ipt" -t mangle -A "$in"  -m mark --mark "$mk/$mk" -j RETURN
            "$ipt" -t mangle -A "$in"  -p tcp --sport 80  -j NFQUEUE --queue-num "$q" --queue-bypass
            "$ipt" -t mangle -A "$in"  -p tcp --sport 443 -j NFQUEUE --queue-num "$q" --queue-bypass
            "$ipt" -t mangle -A "$in"  -p udp --sport 53  -j NFQUEUE --queue-num "$q" --queue-bypass
            "$ipt" -t mangle -I OUTPUT 1 -j "$out"
            "$ipt" -t mangle -I INPUT  1 -j "$in"
            # REJECT is a filter-table target, so the QUIC fast-fail rule lives
            # in its own filter chain (mangle cannot reject).
            if [ "$quic" = "1" ]; then
                "$ipt" -t filter -N GOODBYEDPI_QUIC 2>/dev/null || true
                "$ipt" -t filter -F GOODBYEDPI_QUIC 2>/dev/null || true
                "$ipt" -t filter -A GOODBYEDPI_QUIC -o lo -j RETURN
                "$ipt" -t filter -A GOODBYEDPI_QUIC -p udp --dport 443 \
                    -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
                "$ipt" -t filter -A GOODBYEDPI_QUIC -p udp --dport 443 \
                    -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || true
                "$ipt" -t filter -C OUTPUT -j GOODBYEDPI_QUIC 2>/dev/null || \
                    "$ipt" -t filter -I OUTPUT 1 -j GOODBYEDPI_QUIC
            fi
        ' sh "$ipt" "$q" "$mk" "$PLAT_IPT_CHAIN_OUT" "$PLAT_IPT_CHAIN_IN" "$quic" || return $?
    done
    return 0
}

_plat_fw_unload_iptables() {
    local ipt
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        plat_run_root sh -c '
            ipt="$1"; out="$2"; in="$3"
            "$ipt" -t mangle -D OUTPUT -j "$out" 2>/dev/null || true
            "$ipt" -t mangle -D INPUT  -j "$in"  2>/dev/null || true
            "$ipt" -t mangle -F "$out" 2>/dev/null || true
            "$ipt" -t mangle -F "$in"  2>/dev/null || true
            "$ipt" -t mangle -X "$out" 2>/dev/null || true
            "$ipt" -t mangle -X "$in"  2>/dev/null || true
            "$ipt" -t filter -D OUTPUT -j GOODBYEDPI_QUIC 2>/dev/null || true
            "$ipt" -t filter -F GOODBYEDPI_QUIC 2>/dev/null || true
            "$ipt" -t filter -X GOODBYEDPI_QUIC 2>/dev/null || true
        ' sh "$ipt" "$PLAT_IPT_CHAIN_OUT" "$PLAT_IPT_CHAIN_IN"
    done
    return 0
}

# plat_fw_is_loaded -> rc 0 when our rules are currently installed. Checks
# BOTH backends directly (not just plat_fw_backend()'s preference order):
# the backend actually loaded in the kernel can differ from what a fresh
# process would currently pick (GDPI_FW_BACKEND is a per-invocation env
# var, not persisted state), so trusting the preference order here would
# make unload blind to rules loaded by the other backend.
plat_fw_is_loaded() {
    if command -v nft >/dev/null 2>&1 && plat_run_root nft list table inet goodbyedpi >/dev/null 2>&1; then
        return 0
    fi
    if command -v iptables >/dev/null 2>&1 && plat_run_root iptables -t mangle -C OUTPUT -j "$PLAT_IPT_CHAIN_OUT" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# plat_fw_load -> idempotent; rc 0 when rules are in place afterwards.
plat_fw_load() {
    local backend rc
    if ! backend="$(plat_fw_backend)"; then
        echo "[platform] install nftables or iptables (see plat_deps_check)" >&2
        return 1
    fi
    if [ "$backend" = "nft" ]; then
        rc=0
        _plat_fw_load_nft || rc=$?
        if [ "$rc" -eq 0 ]; then return 0; fi
        if [ "$rc" -eq 2 ]; then
            # User declined the prompt - do NOT fall back to iptables, that
            # would summon a second dialog after the user said stop.
            return 2
        fi
        echo "[platform] nft load failed — falling back to iptables" >&2
        command -v iptables >/dev/null 2>&1 || return 1
    fi
    _plat_fw_load_iptables
}

# plat_fw_unload -> idempotent; rc 0 when rules are gone afterwards. Always
plat_fw_unload() {
    local rc=0
    if command -v nft >/dev/null 2>&1; then
        plat_run_root nft delete table inet goodbyedpi >/dev/null 2>&1 || rc=$?
        if [ "$rc" -eq 2 ]; then
            # User declined the prompt - propagate; callers abort instead of
            # reporting "rules clean" and carrying on with the teardown.
            echo "[platform] firewall unload cancelled by the user" >&2
            return 2
        fi
    fi
    if command -v iptables >/dev/null 2>&1 || command -v ip6tables >/dev/null 2>&1; then
        rc=0
        _plat_fw_unload_iptables || rc=$?
        if [ "$rc" -eq 2 ]; then
            return 2
        fi
    fi
    return 0
}

# ════════════════════════════════════════════════════════════════════════════
# Init system abstraction (systemd / OpenRC / runit)
# ════════════════════════════════════════════════════════════════════════════

plat_init_system() {
    if [ -n "${PLAT_FORCE_INIT:-}" ]; then echo "$PLAT_FORCE_INIT"; return 0; fi
    if [ -d /run/systemd/system ]; then echo systemd; return 0; fi
    if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
        echo openrc; return 0
    fi
    if command -v sv >/dev/null 2>&1 && { [ -d /var/service ] || [ -d /etc/runit ]; }; then
        echo runit; return 0
    fi
    echo none
    return 0
}

_plat_svdir() {
    if [ -d /var/service ]; then echo /var/service
    elif [ -d /etc/runit/runsvdir/default ]; then echo /etc/runit/runsvdir/default
    elif [ -d /etc/service ]; then echo /etc/service
    else echo /var/service
    fi
}

plat_service_available() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            [ "${PLAT_SERVICE_SYSTEM:-0}" = "1" ] && return 0
            [ -f "$APP_DIR/goodbyedpi.service" ] || [ -f "$APP_DIR/../share/DPIGate/goodbyedpi.service" ]
            ;;
        openrc) [ -f "$APP_DIR/service/openrc/goodbyedpi" ] ;;
        runit)  [ -f "$APP_DIR/service/runit/goodbyedpi/run" ] ;;
        *) return 1 ;;
    esac
}

_plat_svc_install_systemd_user() {
    local dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$dir"
    local src=""
    for src in "$APP_DIR/goodbyedpi.service" "$APP_DIR/../share/DPIGate/goodbyedpi.service"; do
        [ -f "$src" ] && break
    done
    if [ ! -f "$src" ]; then
        echo "[platform] goodbyedpi.service not found" >&2
        return 1
    fi
    cp "$src" "$dir/goodbyedpi.service"
    systemctl --user daemon-reload 2>>"$PLAT_LOG" || true
}

_plat_svc_install_systemd_system() {
    local unit="/etc/systemd/system/goodbyedpi.service" tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<'UNIT'
[Unit]
Description=DPIGate — DPI bypass with per-program filtering
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=GDPI_PROGRAMS=/etc/DPIGate/ProgramFilters
ExecStart=/usr/local/lib/DPIGate/start.sh --no-tray
ExecStop=/usr/local/lib/DPIGate/kill.sh

[Install]
WantedBy=multi-user.target
UNIT
    plat_run_root install -m644 "$tmp" "$unit" && rm -f "$tmp"
    plat_run_root systemctl daemon-reload
}

_plat_svc_install_openrc() {
    local src="$APP_DIR/service/openrc/goodbyedpi"
    if [ ! -f "$src" ]; then
        echo "[platform] openrc service definition not found" >&2
        return 1
    fi
    plat_run_root install -m755 "$src" /etc/init.d/goodbyedpi
}

_plat_svc_install_runit() {
    local run="$APP_DIR/service/runit/goodbyedpi/run" fin="$APP_DIR/service/runit/goodbyedpi/finish"
    if [ ! -f "$run" ] || [ ! -f "$fin" ]; then
        echo "[platform] runit service definition not found" >&2
        return 1
    fi
    plat_run_root mkdir -p /etc/sv/goodbyedpi
    plat_run_root install -m755 "$run" /etc/sv/goodbyedpi/run
    plat_run_root install -m755 "$fin" /etc/sv/goodbyedpi/finish
}

plat_service_install() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            if [ "${PLAT_SERVICE_SYSTEM:-0}" = "1" ]; then
                _plat_svc_install_systemd_system
            else
                _plat_svc_install_systemd_user
            fi
            ;;
        openrc) _plat_svc_install_openrc ;;
        runit)  _plat_svc_install_runit ;;
        *) return 1 ;;
    esac
}

plat_service_remove() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/goodbyedpi.service"
            plat_run_root rm -f /etc/systemd/system/goodbyedpi.service 2>/dev/null || true
            ;;
        openrc) plat_run_root rm -f /etc/init.d/goodbyedpi ;;
        runit)  plat_run_root rm -rf /etc/sv/goodbyedpi ;;
        *) return 1 ;;
    esac
}

plat_service_enable() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            if [ "${PLAT_SERVICE_SYSTEM:-0}" = "1" ]; then
                plat_run_root systemctl enable goodbyedpi.service
            else
                systemctl --user enable goodbyedpi.service 2>>"$PLAT_LOG"
            fi ;;
        openrc) plat_run_root rc-update add goodbyedpi default ;;
        runit)  plat_run_root ln -sfn /etc/sv/goodbyedpi "$(_plat_svdir)/goodbyedpi" ;;
        *) return 1 ;;
    esac
}

plat_service_disable() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            if [ "${PLAT_SERVICE_SYSTEM:-0}" = "1" ]; then
                plat_run_root systemctl disable goodbyedpi.service
            else
                systemctl --user disable goodbyedpi.service 2>>"$PLAT_LOG"
            fi ;;
        openrc) plat_run_root rc-update del goodbyedpi default ;;
        runit)  plat_run_root rm -f "$(_plat_svdir)/goodbyedpi" ;;
        *) return 1 ;;
    esac
}

plat_service_is_enabled() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            if [ "${PLAT_SERVICE_SYSTEM:-0}" = "1" ]; then
                systemctl is-enabled goodbyedpi.service >/dev/null 2>&1
            else
                systemctl --user is-enabled goodbyedpi.service >/dev/null 2>&1
            fi ;;
        openrc) rc-update show default 2>/dev/null | grep -qw goodbyedpi ;;
        runit)  [ -L "$(_plat_svdir)/goodbyedpi" ] ;;
        *) return 1 ;;
    esac
}

plat_service_stop() {
    local init; init="$(plat_init_system)"
    case "$init" in
        systemd)
            if [ "${PLAT_SERVICE_SYSTEM:-0}" = "1" ]; then
                plat_run_root systemctl stop goodbyedpi.service
            else
                systemctl --user stop goodbyedpi.service 2>>"$PLAT_LOG"
            fi ;;
        openrc) plat_run_root rc-service goodbyedpi stop ;;
        runit)  plat_run_root sv down goodbyedpi ;;
        *) return 1 ;;
    esac
}

# ════════════════════════════════════════════════════════════════════════════
# /proc-based process helpers — replace GNU procps (pgrep/pkill)
# ════════════════════════════════════════════════════════════════════════════

# plat_pids_comm NAME -> newline-separated PIDs whose /proc/PID/comm == NAME
plat_pids_comm() {
    local name="$1" d
    for d in /proc/[0-9]*; do
        [ -r "$d/comm" ] || continue
        if [ "$(cat "$d/comm" 2>/dev/null || true)" = "$name" ]; then
            echo "${d#/proc/}"
        fi
    done
    return 0
}

# plat_pids_cmdline [--] SUBSTR -> PIDs whose NUL-to-space cmdline contains
# SUBSTR. Accepts an optional leading "--" (pgrep-style option terminator)
# so callers can pass a SUBSTR that itself starts with "-" unambiguously.
plat_pids_cmdline() {
    [ "$1" = "--" ] && shift
    [ -n "${1:-}" ] || { echo "plat_pids_cmdline: empty pattern refused" >&2; return 2; }
    local substr="$1" d
    for d in /proc/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        if tr '\0' ' ' < "$d/cmdline" 2>/dev/null | grep -qF -- "$substr"; then
            echo "${d#/proc/}"
        fi
    done
    return 0
}

# plat_kill_cmdline SUBSTR [SIG] -> signals matching PIDs (default TERM);
# rc 0 when >=1 matched.
plat_kill_cmdline() {
    [ -n "${1:-}" ] || { echo "plat_kill_cmdline: empty pattern refused" >&2; return 2; }
    local substr="$1" sig="${2:-TERM}" n=0 p
    for p in $(plat_pids_cmdline "$substr"); do
        if kill -"$sig" "$p" 2>/dev/null; then n=$((n + 1)); fi
    done
    [ "$n" -gt 0 ]
}
# plat_gdpi_pids -> PIDs of real goodbyedpi daemons on OUR queue, newest first.
# comm must be exactly "goodbyedpi" (never a sudo/setsid wrapper) AND the
# cmdline must carry "--queue $PLAT_QUEUE_NUM", so an unrelated process that
# merely has "--queue" in its argv is never signalled.
plat_gdpi_pids() {
    local pid
    for pid in $(plat_pids_comm goodbyedpi | sort -rn); do
        if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null \
           | grep -qF -- "--queue $PLAT_QUEUE_NUM"; then
            echo "$pid"
        fi
    done
    return 0
}

# ════════════════════════════════════════════════════════════════════════════
# Graphical session discovery (desktop-list-free)
# ════════════════════════════════════════════════════════════════════════════

_plat_emit_session_vars() {
    local environ="$1" k v
    for k in DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR \
             XDG_CONFIG_HOME XDG_DATA_HOME XDG_CURRENT_DESKTOP; do
        v="$(tr '\0' '\n' < "$environ" 2>/dev/null | grep -m1 "^$k=" || true)"
        [ -n "$v" ] && echo "$v"
    done
    return 0
}

# plat_session_env USER -> prints KEY=VALUE lines for DISPLAY
# WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR XDG_CONFIG_HOME
# XDG_DATA_HOME XDG_CURRENT_DESKTOP. Three tiers, DE-agnostic.
plat_session_env() {
    local user="$1" uid
    uid="$(id -u "$user" 2>/dev/null || true)"
    [ -n "$uid" ] || return 1

    # Tier 1 — logind: first x11/wayland session owned by $user.
    if command -v loginctl >/dev/null 2>&1; then
        local sid props name type leader
        for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
            props="$(loginctl show-session "$sid" -p Name -p Type -p Leader 2>/dev/null || true)"
            name="$(printf '%s\n' "$props" | awk -F= '$1=="Name"{print $2}')"
            [ "$name" = "$user" ] || continue
            type="$(printf '%s\n' "$props" | awk -F= '$1=="Type"{print $2}')"
            case "$type" in x11|wayland) : ;; *) continue ;; esac
            leader="$(printf '%s\n' "$props" | awk -F= '$1=="Leader"{print $2}')"
            if [ -n "$leader" ] && [ -r "/proc/$leader/environ" ]; then
                _plat_emit_session_vars "/proc/$leader/environ" && return 0
            fi
        done
    fi

    # Tier 2 — /proc scan: first process owned by $uid with DISPLAY or
    # WAYLAND_DISPLAY set. DE-agnostic: covers Hyprland, i3, dwm, bspwm,
    # river, labwc, LXQt, COSMIC, deepin — everything a WM allowlist misses.
    local d owner
    for d in /proc/[0-9]*; do
        [ -r "$d/environ" ] || continue
        owner="$(stat -c %u "$d" 2>/dev/null || true)"
        [ "$owner" = "$uid" ] || continue
        if tr '\0' '\n' < "$d/environ" 2>/dev/null | grep -qE '^(DISPLAY|WAYLAND_DISPLAY)='; then
            _plat_emit_session_vars "$d/environ" && return 0
        fi
    done

    # Tier 3 — last resort.
    if [ -d "/run/user/$uid" ]; then
        echo "XDG_RUNTIME_DIR=/run/user/$uid"
        [ -e "/tmp/.X11-unix/X0" ] && echo "DISPLAY=:0"
        return 0
    fi
    return 1
}

# ════════════════════════════════════════════════════════════════════════════
# Subprocess dispatch — verb names are load-bearing (tray.py calls these).
# ════════════════════════════════════════════════════════════════════════════

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    verb="${1:-}"; shift || true
    case "$verb" in
        distro) plat_distro ;;
        pkgmgr) plat_pkgmgr ;;
        deps-install) plat_deps_install "$@" ;;
        deps-check) plat_deps_check ;;
        run-root) plat_run_root "$@" ;;
        askpass) plat_askpass "$@" ;;
        fw-backend) plat_fw_backend ;;
        gdpi-pids) plat_gdpi_pids ;;
        fw-load) plat_fw_load ;;
        fw-unload) plat_fw_unload ;;
        fw-is-loaded) plat_fw_is_loaded ;;
        init-system) plat_init_system ;;
        service-available)  plat_service_available ;;
        service-install)    plat_service_install ;;
        service-remove)     plat_service_remove ;;
        service-enable)     plat_service_enable ;;
        service-disable)    plat_service_disable ;;
        service-is-enabled) plat_service_is_enabled ;;
        service-stop)       plat_service_stop ;;
        pids-comm) plat_pids_comm "$@" ;;
        pids-cmdline) plat_pids_cmdline "$@" ;;
        kill-cmdline) plat_kill_cmdline "$@" ;;
        session-env) plat_session_env "$@" ;;
        *) echo "usage: platform.sh <verb> [args]" >&2; exit 2 ;;
    esac
fi

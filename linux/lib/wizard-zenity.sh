#!/bin/bash
# lib/wizard-zenity.sh — zenity fallback for the graphical setup wizard.
#
# Same page order as installer-gui.py (welcome → license → components →
# summary → progress → finish), for hosts that have zenity but no PyGObject.
# install.sh sources this file only when installer-gui.py cannot run; see
# _run_gui_wizard() there.
#
# Entry point:  wizard_zenity_main <path-to-install.sh> [preset flags ...]
# Returns:      0 install finished, 1 cancelled or install failed.
#
# set -e SAFE: every zenity call is `|| rc=$?` guarded — Cancel exits 1 and
# must abort the wizard, not the shell mid-page.

[ -n "${WIZARD_ZENITY_LOADED:-}" ] && return 0
WIZARD_ZENITY_LOADED=1

wizard_zenity_main() {
    local installer="$1"; shift
    local presets=("$@")
    local script_dir; script_dir="$(cd "$(dirname "$installer")" && pwd)"
    local title="DPIGate Setup"
    local icon="$script_dir/icon.png"
    local rc=0

    # ── 1. Welcome ──────────────────────────────────────────────────────────
    rc=0
    zenity --question --title="$title" --width=460 \
        --icon-name=network-server \
        --ok-label="Next" \
        --cancel-label="Cancel" \
        --text="This wizard installs DPIGate, a DPI bypass with per-program filtering, on this computer.\n\nClick Next to continue." \
        2>/dev/null || rc=$?
    [ "$rc" -eq 0 ] || return 1

    # ── 2. License ──────────────────────────────────────────────────────────
    local license=""
    for cand in "$script_dir/LICENSE" "$script_dir/../LICENSE"; do
        [ -f "$cand" ] && { license="$cand"; break; }
    done
    if [ -n "$license" ]; then
        rc=0
        zenity --text-info --title="$title" --width=680 --height=520 \
            --filename="$license" \
            --checkbox="I accept the terms of the license agreement" \
            --ok-label="Next" \
            --cancel-label="Cancel" \
            2>/dev/null || rc=$?
        [ "$rc" -eq 0 ] || return 1
    fi

    # ── 3. Components ───────────────────────────────────────────────────────
    # Preselection mirrors installer-gui.py: build + shortcut + launch on,
    # autostart/system service off unless the caller passed the flag.
    local sel_build=TRUE sel_shortcut=TRUE sel_autostart=FALSE sel_service=FALSE sel_launch=TRUE
    local p
    for p in "${presets[@]}"; do
        case "$p" in
            --no-build)     sel_build=FALSE ;;
            --no-shortcut)  sel_shortcut=FALSE ;;
            --autostart)    sel_autostart=TRUE ;;
            --system)       sel_service=TRUE ;;
        esac
    done

    local picked=""
    rc=0
    picked="$(zenity --list --checklist --title="$title" --width=620 --height=340 \
        --text="Choose what the installer should do." \
        --column="" --column="id" --column="Component" \
        --hide-column=2 --print-column=2 --separator=" " \
        --ok-label="Next" \
        --cancel-label="Cancel" \
        "$sel_build"     build     "Build from source (recommended)" \
        "$sel_shortcut"  shortcut  "Create an application-menu shortcut (Internet)" \
        "$sel_autostart" autostart "Start automatically at login" \
        "$sel_service"   service   "Install a system-wide service (advanced)" \
        "$sel_launch"    launch    "Launch when setup finishes" \
        2>/dev/null)" || rc=$?
    [ "$rc" -eq 0 ] || return 1

    # ── Options → install.sh flags (same mapping as installer-gui.py) ───────
    local args=("--cli")
    case " $picked " in *" build "*) ;; *) args+=("--no-build") ;; esac
    case " $picked " in *" shortcut "*) ;; *) args+=("--no-shortcut") ;; esac
    case " $picked " in
        *" autostart "*) args+=("--autostart") ;;
        *) args+=("--no-autostart") ;;
    esac
    case " $picked " in *" service "*) args+=("--system") ;; esac
    for p in "${presets[@]}"; do
        [ "$p" = "--assume-deps" ] && args+=("--assume-deps")
    done
    local do_launch=0
    case " $picked " in *" launch "*) do_launch=1 ;; esac

    # ── 4. Ready ────────────────────────────────────────────────────────────
    local data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/DPIGate"
    rc=0
    zenity --question --title="$title" --width=520 \
        --ok-label="Install" \
        --cancel-label="Back" \
        --text="Setup is ready to install.\n\nProgram files: $data_dir\nOptions: ${args[*]}" \
        2>/dev/null || rc=$?
    [ "$rc" -eq 0 ] || return 1

    # ── 5. Progress ─────────────────────────────────────────────────────────
    # zenity --progress consumes stdout; the install log doubles as the
    # progress text so a stuck step is visible instead of a frozen pulse.
    local logfile; logfile="$(mktemp -t gdpi-install-XXXXXX.log)"
    (
        GDPI_INSTALL_GUI=0 bash "$installer" "${args[@]}" 2>&1 | tee "$logfile"
        echo "${PIPESTATUS[0]}" > "$logfile.rc"
    ) | sed -u 's/^/# /' | zenity --progress --pulsate --auto-close --no-cancel \
            --title="$title" --width=520 \
            --text="Installing…" 2>/dev/null || true

    local install_rc=1
    [ -f "$logfile.rc" ] && install_rc="$(cat "$logfile.rc")"

    # ── 6. Finish ───────────────────────────────────────────────────────────
    if [ "$install_rc" = "0" ]; then
        zenity --info --title="$title" --width=460 \
            --ok-label="Finish" \
            --text="DPIGate has been installed successfully." 2>/dev/null || true
        rm -f "$logfile" "$logfile.rc"
        if [ "$do_launch" = "1" ] && [ -x "$data_dir/start.sh" ]; then
            ( cd "$data_dir" && setsid "$data_dir/start.sh" >/dev/null 2>&1 & ) || true
        fi
        return 0
    fi

    zenity --error --title="$title" --width=560 \
        --text="Setup failed (exit code $install_rc).\nLog: $logfile" \
        2>/dev/null || true
    return 1
}

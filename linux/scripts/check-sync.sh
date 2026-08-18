#!/bin/bash
# check-sync.sh — Drift detection between windows/ (Windows) and linux/ (Linux port)
#
# Compares SHA256 of COPY files in windows/ vs linux/ against .sync-checksums.
# Exit 0 = in sync, exit 1 = drift detected.
#
# Three drift cases:
#   - windows changed, linux copy old  → "run make sync"
#   - linux copy changed, windows old  → "manual edit? run make sync to overwrite"
#   - both changed                     → "manual merge required"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$ROOT_DIR/windows"
LINUX_DIR="$ROOT_DIR/linux"
CHECKSUMS="$LINUX_DIR/.sync-checksums"

if [[ ! -f "$CHECKSUMS" ]]; then
    echo "ERROR: .sync-checksums not found at $CHECKSUMS" >&2
    exit 1
fi

drift=0

# Skip comment/empty lines, process: <path> <src_sum> <linux_sum>
while read -r relpath recorded_src_sum recorded_linux_sum; do
    [[ -z "$relpath" || "$relpath" == \#* ]] && continue

    src_file="$SRC_DIR/$relpath"
    linux_file="$LINUX_DIR/$relpath"

    if [[ ! -f "$src_file" ]]; then
        echo "MISSING: windows/$relpath — deleted in windows/? Remove from .sync-checksums" >&2
        drift=1
        continue
    fi
    if [[ ! -f "$linux_file" ]]; then
        echo "MISSING: linux/$relpath — deleted in linux/? Run make sync to restore" >&2
        drift=1
        continue
    fi

    current_src_sum=$(sha256sum "$src_file" | awk '{print $1}')
    current_linux_sum=$(sha256sum "$linux_file" | awk '{print $1}')

    src_changed=0
    linux_changed=0

    [[ "$current_src_sum" != "$recorded_src_sum" ]] && src_changed=1
    [[ "$current_linux_sum" != "$recorded_linux_sum" ]] && linux_changed=1

    if [[ $src_changed -eq 1 && $linux_changed -eq 0 ]]; then
        echo "DRIFT: windows/$relpath updated, linux/$relpath is stale" >&2
        echo "       Run: make sync" >&2
        drift=1
    elif [[ $src_changed -eq 0 && $linux_changed -eq 1 ]]; then
        echo "DRIFT: linux/$relpath differs from windows/ — manual edit?" >&2
        echo "       Run: make sync to overwrite from windows/" >&2
        drift=1
    elif [[ $src_changed -eq 1 && $linux_changed -eq 1 ]]; then
        echo "DRIFT: both windows/$relpath and linux/$relpath changed" >&2
        echo "       Manual merge required" >&2
        drift=1
    fi
done < "$CHECKSUMS"

if [[ $drift -eq 0 ]]; then
    echo "OK: all COPY files in sync"
    exit 0
else
    echo "" >&2
    echo "DRIFT DETECTED — $drift file(s) out of sync. See messages above." >&2
    exit 1
fi

#!/bin/bash
# make-dist.sh — build a source-only distribution tarball for DPIGate.
#
# The tarball contains everything needed to build + install on a fresh
# Linux Mint / Debian / Fedora / Arch box EXCEPT prebuilt artifacts:
#   - C sources, headers, utils/, scripts/, Makefile
#   - runtime files: start.sh tray.py tray-launcher.sh dns_detect.py
#   - configs: goodbyedpi.nft goodbyedpi.service ProgramFilters icon.png
#   - install/uninstall scripts + the graphical wizard (installer-gui.py,
#     lib/wizard-zenity.sh — install.sh needs both to open a GUI when it is
#     double-clicked instead of run from a terminal)
#   - top-level docs: README.md LICENSE NOTICE
#
# Excluded: *.o, prebuilt binaries, __pycache__, .sync-checksums, test bins.
#
# Output: dpigate-linux-<distro-or-generic>.tar.gz (in repo root).

set -e

APP_NAME="dpigate"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINUX_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$LINUX_DIR/.." && pwd)"

OUT="${1:-$REPO_DIR/$APP_NAME-linux.tar.gz}"

# Stage a clean copy in a temp dir
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
DEST="$STAGE/$APP_NAME"
mkdir -p "$DEST"

# ── linux/ runtime + source ────────────────────────────────────────────────────
for f in \
    Makefile goodbyedpi.c goodbyedpi.h proctrack_linux.c proctrack_linux.h \
    packet_io_linux.c packet_io.h rawsend_linux.c rawsend_linux.h \
    checksum.c checksum.h fakepackets.c fakepackets.h dnsredir.c dnsredir.h \
    ttltrack.c ttltrack.h blackwhitelist.c blackwhitelist.h \
    proctrack_test.c rawsend_test.c checksum_test.c bypass_test.c smoke_test.c \
    start.sh tray.py tray-launcher.sh reaper.sh dns_detect.py ProgramFilters \
    goodbyedpi.nft goodbyedpi.service icon.png \
    install.sh installer-gui.py uninstall.sh kill.sh vm-diag.sh
do
    [ -f "$LINUX_DIR/$f" ] && cp "$LINUX_DIR/$f" "$DEST/"
done

# utils/ subdir (headers + sources)
mkdir -p "$DEST/utils"
cp "$LINUX_DIR"/utils/*.c "$LINUX_DIR"/utils/*.h "$DEST/utils/" 2>/dev/null || true

# lib/ subdir (portability layer — required at runtime by every consumer)
mkdir -p "$DEST/lib"
cp "$LINUX_DIR"/lib/*.sh "$DEST/lib/" 2>/dev/null || true

# service/ subdir (OpenRC + runit service definitions for install.sh --system)
mkdir -p "$DEST/service/openrc" "$DEST/service/runit/goodbyedpi"
cp "$LINUX_DIR/service/openrc/goodbyedpi" "$DEST/service/openrc/" 2>/dev/null || true
cp "$LINUX_DIR/service/runit/goodbyedpi/run" "$LINUX_DIR/service/runit/goodbyedpi/finish" \
    "$DEST/service/runit/goodbyedpi/" 2>/dev/null || true

# scripts/ subdir
mkdir -p "$DEST/scripts"
cp "$LINUX_DIR"/scripts/*.sh "$DEST/scripts/" 2>/dev/null || true

# ── top-level docs ────────────────────────────────────────────────────────────
for f in README.md LICENSE NOTICE; do
    [ -f "$REPO_DIR/$f" ] && cp "$REPO_DIR/$f" "$DEST/"
done

# Ensure scripts executable
chmod +x "$DEST"/*.sh "$DEST/scripts"/*.sh "$DEST/lib"/*.sh "$DEST/tray.py" \
    "$DEST/installer-gui.py" \
    "$DEST/service/openrc/goodbyedpi" "$DEST/service/runit/goodbyedpi"/* 2>/dev/null || true

# ── Pack ──────────────────────────────────────────────────────────────────────
tar -czf "$OUT" -C "$STAGE" "$APP_NAME"
echo "[dist] created $OUT ($(du -h "$OUT" | cut -f1))"

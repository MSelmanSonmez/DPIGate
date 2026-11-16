#!/bin/bash
# build-appimage.sh — build dpigate-<version>-x86_64.AppImage for the Linux port.
#
# Usage:  build-appimage.sh [OUTPUT_DIR]      (default: <repo>/dist)
#
# Environment:
#   APPIMAGETOOL=/path/to/appimagetool   (default: appimagetool on PATH)
#   APPIMAGE_EXTRACT_AND_RUN=1           passed through to appimagetool when it
#                                        cannot use FUSE (containers, CI)
#   APPIMAGE_RUNTIME_FILE=/path/runtime  local type 2 runtime, passed as
#                                        --runtime-file. Without it appimagetool
#                                        fetches the runtime from the network.
#
# Steps: build goodbyedpi, stage an AppDir from linux/ and pack it with
# appimagetool.
#
# Build-host needs: cc, make and the libnetfilter_queue, libnfnetlink and
# libmnl development packages (the binary must compile and link).
# Not bundled: the three libraries above are NOT copied into the AppImage. The
# machine that runs DPIGate needs their runtime packages (AppRun checks for
# them and names the packages if they are missing). Also not bundled: nftables
# or iptables, libcap, and for the tray python3 with PyGObject, GTK3 and
# AppIndicator.
#
# Exit codes: 0 built; 1 prerequisite or build error; 3 AppDir staged but
# appimagetool was not found, so no .AppImage was written.

set -euo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
LINUX_DIR="$(cd "$HERE/../.." && pwd)"
REPO_DIR="$(cd "$LINUX_DIR/.." && pwd)"
OUT_DIR="${1:-$REPO_DIR/dist}"

die() { echo "build-appimage: ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
for t in cc make tar cp awk sed; do need "$t"; done

# ── Version: the Linux port's own define (linux/goodbyedpi.c) ────────────────
VERSION="$(sed -n 's/^#define[[:space:]]\{1,\}DPIGATE_VERSION[[:space:]]\{1,\}"\([^"]*\)".*/\1/p' \
           "$LINUX_DIR/goodbyedpi.c" | head -n 1)"
[ -n "$VERSION" ] || die "cannot read DPIGATE_VERSION from linux/goodbyedpi.c"
echo "[build-appimage] version $VERSION"

# ── 1. Build the daemon ─────────────────────────────────────────────────────
BIN="$LINUX_DIR/goodbyedpi"
# Relink from scratch: a binary left over from an earlier link (with other
# flags) is not rebuilt by make when only the link command changed.
rm -f "$BIN"
make -C "$LINUX_DIR" -j"$(nproc 2>/dev/null || echo 1)" goodbyedpi
[ -x "$BIN" ] || die "make did not produce $BIN"

# ── 2. Stage the AppDir ─────────────────────────────────────────────────────
OUT_DIR="$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd)"
APPDIR="$OUT_DIR/appdir-build/DPIGate.AppDir"
rm -rf "$OUT_DIR/appdir-build"
mkdir -p "$APPDIR"

# Runtime payload: the linux/ tree, minus packaging, object files and the
# test binaries. install.sh picks the files it needs from here.
tar -C "$LINUX_DIR" \
    --exclude=./packaging --exclude='*.o' --exclude='./*_test' \
    --exclude=./goodbyedpi --exclude=./__pycache__ \
    -cf - . | tar -C "$APPDIR" -xf -
cp -L "$BIN" "$APPDIR/goodbyedpi"
chmod 0755 "$APPDIR/goodbyedpi"

install -m 0755 "$HERE/AppRun" "$APPDIR/AppRun"
install -m 0644 "$HERE/dpigate.desktop" "$APPDIR/dpigate.desktop"
install -m 0644 "$LINUX_DIR/icon.png" "$APPDIR/dpigate.png"
ln -sf dpigate.png "$APPDIR/.DirIcon"
printf '%s\n' "$VERSION" > "$APPDIR/VERSION"
echo "[build-appimage] AppDir staged: $APPDIR"

# ── 3. Pack the AppImage ────────────────────────────────────────────────────
TOOL="${APPIMAGETOOL:-$(command -v appimagetool || true)}"
if [ -z "$TOOL" ] || [ ! -x "$TOOL" ]; then
    echo "build-appimage: appimagetool not found. Set APPIMAGETOOL=/path/to/appimagetool." >&2
    echo "build-appimage: no .AppImage written; the AppDir is at $APPDIR" >&2
    exit 3
fi

OUT="$OUT_DIR/dpigate-$VERSION-x86_64.AppImage"
rm -f "$OUT"
RUNTIME_ARGS=()
if [ -n "${APPIMAGE_RUNTIME_FILE:-}" ]; then
    [ -f "$APPIMAGE_RUNTIME_FILE" ] || die "APPIMAGE_RUNTIME_FILE does not exist: $APPIMAGE_RUNTIME_FILE"
    RUNTIME_ARGS=(--runtime-file "$APPIMAGE_RUNTIME_FILE")
fi
ARCH=x86_64 "$TOOL" ${RUNTIME_ARGS[@]+"${RUNTIME_ARGS[@]}"} "$APPDIR" "$OUT"
[ -s "$OUT" ] || die "appimagetool did not produce $OUT"
chmod 0755 "$OUT"
echo "[build-appimage] wrote $OUT"
sha256sum "$OUT"

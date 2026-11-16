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
# Steps: build goodbyedpi with RUNPATH $ORIGIN/lib, stage an AppDir from
# linux/ plus the three shared libraries the daemon needs, then run
# appimagetool on it.
#
# Build-time needs: cc, make, pkg-config, readelf, ldd, and the libnetfilter_queue,
# libnfnetlink and libmnl development packages (so the binary links).
# Bundled into the AppImage: libnetfilter_queue, libnfnetlink, libmnl.
# NOT bundled (installed by install.sh / the distro): nftables or iptables,
# libcap, and for the tray python3 with PyGObject, GTK3 and AppIndicator.
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
for t in cc make pkg-config readelf ldd cp tar awk sed; do need "$t"; done

# ── Version: the Linux port's own define (linux/goodbyedpi.c) ────────────────
VERSION="$(sed -n 's/^#define[[:space:]]\{1,\}DPIGATE_VERSION[[:space:]]\{1,\}"\([^"]*\)".*/\1/p' \
           "$LINUX_DIR/goodbyedpi.c" | head -n 1)"
[ -n "$VERSION" ] || die "cannot read DPIGATE_VERSION from linux/goodbyedpi.c"
echo "[build-appimage] version $VERSION"

# ── 1. Build the daemon ─────────────────────────────────────────────────────
# Relink from scratch: make would not notice a changed link flag on an
# up-to-date binary, and the RUNPATH check below depends on it.
BIN="$LINUX_DIR/goodbyedpi"
rm -f "$BIN"
make -C "$LINUX_DIR" -j"$(nproc 2>/dev/null || echo 1)" goodbyedpi
[ -x "$BIN" ] || die "make did not produce $BIN"

RUNPATH_LINE="$(readelf -d "$BIN" | grep -E 'RUNPATH|RPATH' || true)"
case "$RUNPATH_LINE" in
    *'$ORIGIN/lib'*) ;;
    *) die "goodbyedpi has no \$ORIGIN/lib RUNPATH (got: ${RUNPATH_LINE:-none})" ;;
esac

# ── 2. Stage the AppDir ─────────────────────────────────────────────────────
OUT_DIR="$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd)"
APPDIR="$OUT_DIR/appdir-build/DPIGate.AppDir"
rm -rf "$OUT_DIR/appdir-build"
mkdir -p "$APPDIR/lib"

# Runtime payload: the linux/ tree, minus packaging, object files and the
# test binaries. install.sh picks the files it needs from here.
tar -C "$LINUX_DIR" \
    --exclude=./packaging --exclude='*.o' --exclude='./*_test' \
    --exclude=./goodbyedpi --exclude=./__pycache__ \
    -cf - . | tar -C "$APPDIR" -xf -
cp -L "$BIN" "$APPDIR/goodbyedpi"
chmod 0755 "$APPDIR/goodbyedpi"

# The three C libraries, resolved from the build host through ldd and copied
# under their SONAME, so the binary's NEEDED entries match the files.
LDD_OUT="$(ldd "$BIN")"
for lib in libnetfilter_queue libnfnetlink libmnl; do
    path="$(printf '%s\n' "$LDD_OUT" | awk -v n="$lib" '$1 ~ ("^" n "\\.so") && $3 ~ /^\// {print $3; exit}')"
    [ -n "$path" ] && [ -f "$path" ] || die "ldd did not resolve $lib (install its development package)"
    soname="$(readelf -d "$path" | sed -n 's/.*(SONAME).*\[\(.*\)\].*/\1/p' | head -n 1)"
    [ -n "$soname" ] || soname="$(basename "$path")"
    cp -L "$path" "$APPDIR/lib/$soname"
    echo "[build-appimage] bundled $soname  (from $path)"
done

install -m 0755 "$HERE/AppRun" "$APPDIR/AppRun"
install -m 0644 "$HERE/dpigate.desktop" "$APPDIR/dpigate.desktop"
install -m 0644 "$LINUX_DIR/icon.png" "$APPDIR/dpigate.png"
ln -sf dpigate.png "$APPDIR/.DirIcon"
printf '%s\n' "$VERSION" > "$APPDIR/VERSION"

# The bundled libraries must be what the daemon actually loads.
RESOLVED="$(LD_LIBRARY_PATH= ldd "$APPDIR/goodbyedpi")"
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"   # ldd lines start with a tab
    case "$line" in
        *'not found'*) die "AppDir daemon has an unresolved library: $line" ;;
        libnetfilter_queue*|libnfnetlink*|libmnl*)
            case "$line" in
                *"$APPDIR/lib/"*) ;;
                *) die "bundled library resolves outside the AppDir: $line" ;;
            esac ;;
    esac
done <<< "$RESOLVED"
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

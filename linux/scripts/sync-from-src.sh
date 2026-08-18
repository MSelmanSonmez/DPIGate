#!/bin/bash
# sync-from-src.sh — Copy COPY files from windows/ to linux/ and update .sync-checksums
#
# Only COPY files (listed in .sync-checksums) are synced.
# COPY+MODIFY (goodbyedpi.c, proctrack.c) and NEW files are NEVER touched.

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

synced=0

# Skip comment/empty lines, process: <path> <src_sum> <linux_sum>
while read -r relpath old_src_sum old_linux_sum; do
    [[ -z "$relpath" || "$relpath" == \#* ]] && continue

    src_file="$SRC_DIR/$relpath"
    linux_file="$LINUX_DIR/$relpath"

    if [[ ! -f "$src_file" ]]; then
        echo "SKIP: windows/$relpath not found — skipping" >&2
        continue
    fi

    mkdir -p "$(dirname "$linux_file")"
    cp "$src_file" "$linux_file"
    echo "SYNCED: windows/$relpath -> linux/$relpath"
    synced=$((synced + 1))
done < "$CHECKSUMS"

# Regenerate checksums
echo ""
echo "Updating .sync-checksums..."

{
    echo "# .sync-checksums — auto-generated, do NOT edit by hand"
    echo "# format: <relative_path> <sha256_src> <sha256_linux_copy>"
    echo "# COPY files only. COPY+MODIFY/NEW files EXCLUDED."
    echo ""

    while read -r relpath old_src_sum old_linux_sum; do
        [[ -z "$relpath" || "$relpath" == \#* ]] && continue
        src_file="$SRC_DIR/$relpath"
        linux_file="$LINUX_DIR/$relpath"
        if [[ -f "$src_file" && -f "$linux_file" ]]; then
            src_sum=$(sha256sum "$src_file" | awk '{print $1}')
            linux_sum=$(sha256sum "$linux_file" | awk '{print $1}')
            echo "$relpath $src_sum $linux_sum"
        fi
    done
} < "$CHECKSUMS" > "$CHECKSUMS.tmp"

mv "$CHECKSUMS.tmp" "$CHECKSUMS"

echo "Done. $synced file(s) synced, .sync-checksums updated."

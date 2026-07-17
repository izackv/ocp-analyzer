#!/usr/bin/env bash
#
# unpack-bundle.sh — restore a bundle packed by pack-bundle.sh back into its
# original directory tree.
#
# Accepts either the binary archive (<name>.tar.gz) or the base64 text
# version (<name>.tar.gz.b64). Verifies the .sha256 checksum when present.
#
# Usage:
#   ./unpack-bundle.sh FILE [DEST_DIR]     # DEST_DIR default: current dir
#
set -euo pipefail

FILE="${1:-}"; DEST="${2:-.}"
[ -n "$FILE" ] && [ -f "$FILE" ] || { echo "usage: $0 FILE [DEST_DIR]" >&2; exit 1; }
mkdir -p "$DEST"

# base64 text version? decode to a temp archive first
ARCHIVE="$FILE"
CLEANUP=""
case "$FILE" in
  *.b64)
    ARCHIVE="${FILE%.b64}"
    if [ -e "$ARCHIVE" ]; then
      ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/bundle.XXXXXX.tar.gz")"
      CLEANUP="$ARCHIVE"
    fi
    # GNU: base64 -d ; older macOS: base64 -D
    base64 -d < "$FILE" > "$ARCHIVE" 2>/dev/null || base64 -D < "$FILE" > "$ARCHIVE"
    echo "decoded : $FILE -> $ARCHIVE"
    ;;
esac

# checksum verification (best effort — warn loudly, don't block)
if [ -f "$ARCHIVE.sha256" ]; then
  EXPECT="$(awk '{print $1}' "$ARCHIVE.sha256")"
  if command -v sha256sum >/dev/null; then
    ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
  else
    ACTUAL="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
  fi
  if [ "$EXPECT" = "$ACTUAL" ]; then
    echo "checksum: OK"
  else
    echo "checksum: MISMATCH — archive may be corrupted or tampered with!" >&2
    exit 1
  fi
else
  echo "checksum: no .sha256 file found — skipping verification"
fi

tar -xzf "$ARCHIVE" -C "$DEST"
# no `| head -1` here: head exiting early SIGPIPEs GNU tar, which kills the
# script under pipefail; read the full listing instead
LISTING="$(tar -tzf "$ARCHIVE" 2>/dev/null)"
TOP="${LISTING%%$'\n'*}"; TOP="${TOP%%/*}"
if [ -n "$CLEANUP" ]; then rm -f "$CLEANUP"; fi
echo "unpacked into: $DEST/${TOP:+ (top-level dir: $TOP)}"

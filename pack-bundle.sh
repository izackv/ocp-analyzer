#!/usr/bin/env bash
#
# pack-bundle.sh — pack a review bundle (or any directory) into ONE file,
# easy to move between machines / through file-transfer gateways.
#
# Creates:
#   <dir>.tar.gz          the archive
#   <dir>.tar.gz.sha256   integrity checksum (verified by unpack-bundle.sh)
#   <dir>.tar.gz.b64      (only with --text) base64 text version — for paths
#                         where binary files can't pass (mail filters,
#                         copy/paste through a jump-host terminal)
#
# Usage:
#   ./pack-bundle.sh BUNDLE_DIR [--text]
#
set -euo pipefail

TEXT=0
DIR=""
for arg in "$@"; do
  case "$arg" in
    -t|--text) TEXT=1 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) DIR="${arg%/}" ;;
  esac
done
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "usage: $0 BUNDLE_DIR [--text]" >&2; exit 1; }

OUT="${DIR}.tar.gz"

# sha256 tool: Linux has sha256sum, macOS has shasum
sha() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"
  else shasum -a 256 "$1"; fi
}

tar -czf "$OUT" -C "$(dirname "$DIR")" "$(basename "$DIR")"
sha "$OUT" > "$OUT.sha256"
echo "packed : $OUT  ($(du -h "$OUT" | cut -f1 | tr -d ' '))"
echo "checksum: $OUT.sha256"

if [ "$TEXT" = "1" ]; then
  base64 < "$OUT" > "$OUT.b64"
  echo "text    : $OUT.b64  (base64 — survives text-only transfer)"
fi
echo "unpack with: ./unpack-bundle.sh $OUT"

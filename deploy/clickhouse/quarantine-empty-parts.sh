#!/usr/bin/env bash
# Moves MergeTree parts whose files are all zero-sized out of the ClickHouse
# data dir before the server starts. Such parts are left by a power loss and
# can exceed max_suspicious_broken_parts, which blocks the table from attaching.
# Run only while ClickHouse is stopped (see clickhouse-quarantine-empty-parts.service).
set -euo pipefail

CH_DATA="${CH_DATA:-/var/lib/clickhouse}"
QUARANTINE_ROOT="${QUARANTINE_ROOT:-$(dirname "$CH_DATA")/clickhouse-quarantine}"

[ -d "$CH_DATA/store" ] || exit 0

dest="$QUARANTINE_ROOT/empty-parts-$(date +%Y%m%d-%H%M%S)"
moved=0

while IFS= read -r -d '' checksums; do
  part="$(dirname "$checksums")"
  case "$part" in */detached/*) continue ;; esac
  if find "$part" -type f -size +0 -print -quit | grep -q .; then
    continue
  fi
  rel="${part#"$CH_DATA"/}"
  mkdir -p "$dest/$(dirname "$rel")"
  mv "$part" "$dest/$rel"
  moved=$((moved + 1))
done < <(find "$CH_DATA/store" -name checksums.txt -size 0 -print0)

if [ "$moved" -gt 0 ]; then
  echo "quarantined $moved empty parts to $dest"
fi

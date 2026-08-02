#!/usr/bin/env bash
# Snapshot Hermes' DURABLE state to a host-mirrored folder (~/hermes-state, which
# is mounted to hermes-sandbox/hermes-state/ on the host) so memory survives a VM
# crash / corruption / rebuild.
#
# SQLite DBs are copied with a CONSISTENT online backup into a local temp first
# (never sqlite-over-sshfs, never raw-cp a live DB), then the static file is
# placed on the host mount.
set -uo pipefail
SRC="$HOME/.hermes"
DST="${1:-$HOME/hermes-state}"
[ -d "$SRC" ] || { echo "no ~/.hermes yet"; exit 0; }
mkdir -p "$DST" || { echo "backup target $DST not writable (mount missing?)"; exit 1; }

# 1) SQLite databases — memory/state/projects/kanban — consistent online backup
for db in state.db projects.db kanban.db; do
  [ -f "$SRC/$db" ] || continue
  TMP="$(mktemp)"
  if python3 - "$SRC/$db" "$TMP" <<'PY'
import sys, sqlite3
s = sqlite3.connect(sys.argv[1], timeout=30)
d = sqlite3.connect(sys.argv[2])
with d:
    s.backup(d)
s.close(); d.close()
PY
  then cp -f "$TMP" "$DST/$db"; fi
  rm -f "$TMP"
done

# 2) File-based durable state (small): personality, config, memory, sessions, cron
for item in .env SOUL.md config.yaml .hermes_history memories sessions cron hooks pairing; do
  [ -e "$SRC/$item" ] || continue
  if [ -d "$SRC/$item" ] && command -v rsync >/dev/null 2>&1; then
    mkdir -p "$DST/$item"; rsync -a --delete "$SRC/$item/" "$DST/$item/" 2>/dev/null
  else
    rm -rf "$DST/$(basename "$item")" 2>/dev/null; cp -a "$SRC/$item" "$DST/" 2>/dev/null
  fi
done

date -u +%FT%TZ > "$DST/.last-backup"
echo "Hermes state backed up to $DST ($(date -u +%FT%TZ))"

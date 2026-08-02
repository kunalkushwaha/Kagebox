#!/usr/bin/env bash
# Restore Hermes' durable state from the host-mirrored backup (~/hermes-state)
# into ~/.hermes. Run on a fresh/rebuilt VM BEFORE Hermes starts (Hermes not
# running -> a plain copy is safe and consistent).
set -uo pipefail
SRC="${1:-$HOME/hermes-state}"
DST="$HOME/.hermes"
if [ ! -f "$SRC/.last-backup" ]; then
  echo "no prior Hermes state to restore (first run)"; exit 0
fi
mkdir -p "$DST"
for db in state.db projects.db kanban.db; do
  [ -f "$SRC/$db" ] && cp -a "$SRC/$db" "$DST/$db"
done
for item in .env SOUL.md config.yaml .hermes_history memories sessions cron hooks pairing; do
  [ -e "$SRC/$item" ] && cp -a "$SRC/$item" "$DST/"
done
echo "restored Hermes state from $SRC (backup dated $(cat "$SRC/.last-backup"))"

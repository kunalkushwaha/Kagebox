#!/usr/bin/env bash
# Read-only GPU hang watchdog for the 780M during a test load.
# No sudo needed (journalctl -k works via 'adm' group; sysfs is world-readable).
# Prints VRAM used each second and screams the instant an amdgpu hang/reset appears.
set -u
CARD=/sys/class/drm/card1/device
TOTAL_MIB=$(( $(cat "$CARD/mem_info_vram_total") / 1024 / 1024 ))
echo "VRAM total = ${TOTAL_MIB} MiB. Watching mem_info_vram_used + kernel amdgpu log. Ctrl-C to stop."
# Follow kernel log for the terminal-killing signatures, in the background.
journalctl -kf 2>/dev/null | grep --line-buffered -iE 'GPU Hang|MES failed|MODE2|reset begin|device wedged' \
  | while read -r line; do echo "*** AMDGPU HANG SIGNATURE: $line"; done &
GREP_PID=$!
trap 'kill $GREP_PID 2>/dev/null' EXIT
while true; do
  USED_MIB=$(( $(cat "$CARD/mem_info_vram_used") / 1024 / 1024 ))
  printf '%(%H:%M:%S)T  vram_used=%s MiB / %s MiB\n' -1 "$USED_MIB" "$TOTAL_MIB"
  sleep 1
done

#!/usr/bin/env bash
# The refresh job must survive a minimal environment.
# =============================================================================
# Regression test for a silent failure that disabled the allowlist refresh
# entirely. `nft` lives in /usr/sbin, which is NOT on cron's default PATH
# (/usr/bin:/bin). host-egress.sh guards with `command -v nft || die`, and the
# cron entry sent stderr to /dev/null — so every tick for weeks the job aborted
# with "nftables (nft) not installed on host" into the void.
#
# Two consequences, both invisible: allowlisted CDN hosts stopped tracking their
# rotating IPs, and after a host reboot (where the early boot unit resolves
# nothing because DNS is not up yet) the sandbox stayed FULLY SEALED until
# somebody ran `egress on` by hand.
#
# No root, no nft, no network — this pins the environment plumbing only.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SCRIPT="$ROOT/bridge/host-egress.sh"
pass=0; fail=0

ok()   { printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
check(){ if [ "$2" = yes ]; then ok "$1"; else bad "$1"; fi; }

printf '\nrefresh runs in a minimal environment\n\n'

# --- 1. the script sets PATH before it looks for nft ------------------------
# Match CODE only — the comment explaining this fix mentions `command -v nft`
# too, and matching that would compare against the wrong line.
path_ln=$(grep -n '^PATH=' "$SCRIPT" | head -1 | cut -d: -f1)
nft_ln=$(grep -n '^[^#]*command -v nft' "$SCRIPT" | head -1 | cut -d: -f1)
if [ -n "$path_ln" ] && [ -n "$nft_ln" ] && [ "$path_ln" -lt "$nft_ln" ]; then
  check "PATH is set before the 'command -v nft' guard" yes
else
  check "PATH is set before the 'command -v nft' guard (PATH@${path_ln:-none} nft@${nft_ln:-none})" no
fi

# --- 2. that PATH actually finds the tools the script needs -----------------
# Apply the script's own PATH line in an empty environment and look for the
# binaries. Uses the real line from the source, so it cannot drift.
path_line=$(grep -m1 '^PATH=' "$SCRIPT")
for bin in nft ip; do
  if env -i bash -c "$path_line; command -v $bin >/dev/null 2>&1"; then
    check "'$bin' resolves under the script's PATH in an empty env" yes
  else
    check "'$bin' resolves under the script's PATH in an empty env" no
  fi
done

# --- 3. the generated cron entry carries a usable PATH ----------------------
cron_tmpl=$(awk '/^install_cron\(\)/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT")
case "$cron_tmpl" in
  *"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"*)
    check "cron entry declares a PATH containing /usr/sbin" yes ;;
  *) check "cron entry declares a PATH containing /usr/sbin" no ;;
esac

# --- 4. the cron entry must not discard its own errors ----------------------
# A security control that fails silently is worse than one that is plainly off.
case "$cron_tmpl" in
  *"refresh >/dev/null 2>&1"*)
    check "cron entry does not send stderr to /dev/null" no ;;
  *logger*)
    check "cron entry does not send stderr to /dev/null" yes ;;
  *) check "cron entry routes its stderr somewhere visible" no ;;
esac

# --- 5. a unit exists to fill the set in once DNS is up ---------------------
REFRESH_UNIT="$ROOT/bridge/kagebox-egress-refresh.service"
if [ -f "$REFRESH_UNIT" ]; then
  check "post-network refresh unit exists" yes
  grep -q 'After=.*network-online.target' "$REFRESH_UNIT" \
    && check "refresh unit is ordered after network-online.target" yes \
    || check "refresh unit is ordered after network-online.target" no
  grep -q 'host-egress.sh refresh' "$REFRESH_UNIT" \
    && check "refresh unit invokes the refresh action" yes \
    || check "refresh unit invokes the refresh action" no
  grep -q '__EGRESS_PROFILE__' "$REFRESH_UNIT" \
    && check "refresh unit carries the operator's profile (no silent widening)" yes \
    || check "refresh unit carries the operator's profile (no silent widening)" no
else
  check "post-network refresh unit exists" no
fi

# --- 6. install_unit installs BOTH units ------------------------------------
inst=$(awk '/^install_unit\(\)/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT")
case "$inst" in
  *'$UNITS'*|*kagebox-egress-refresh.service*)
    check "install_unit installs the refresh unit too" yes ;;
  *) check "install_unit installs the refresh unit too" no ;;
esac

printf '\n  Summary: %d ok · %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

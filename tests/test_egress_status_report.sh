#!/usr/bin/env bash
# `status` must not lie about what is open.
# =============================================================================
# Regression test for a misreport that is worse than a crash: with 25
# destinations loaded, `egress status` printed
#
#   host egress: ON (... 25 allowlisted destination:port pair(s))
#     allowlisted external destinations: none (bridge + DNS only)
#
# The count was right; the listing said the box was sealed. The cause was
# `grep -oE 'elements = \{[^}]*\}'`, which only matches when the whole element
# list fits on ONE line — and `nft list set` wraps a long list over many. So
# the report flipped to "none" exactly when there was most to report.
#
# An operator reading that would believe the sandbox was bridge+DNS only. The
# fix routes the count AND the listing through one extraction (set_pairs), so
# they cannot disagree. This drives the REAL functions with `nft` stubbed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
SCRIPT="$ROOT/bridge/host-egress.sh"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok(){ printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad(){ printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }

# Pull the real set_pairs/set_count out of the script so they cannot drift.
{
  echo 'TABLE="inet kagebox_egress"'
  awk '/^set_pairs\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT"
  grep -m1 '^set_count() {' "$SCRIPT"
} > "$WORK/lib.sh"
grep -q 'set_pairs' "$WORK/lib.sh" || { echo "could not extract set_pairs()"; exit 1; }
grep -q 'set_count' "$WORK/lib.sh" || { echo "could not extract set_count()"; exit 1; }

printf '\nstatus reports what is actually in the set\n\n'

run_case() {   # $1 = label, $2 = fixture nft output, $3 = expected pair count
  local label="$1" fixture="$2" want="$3"
  ( eval "nft() { printf '%s\n' \"\$FIXTURE\"; }"
    export FIXTURE="$fixture"
    # shellcheck disable=SC1090
    source "$WORK/lib.sh"
    got_n=$(set_count)
    got_l=$(set_pairs | grep -c . )
    if [ "$got_n" != "$want" ]; then echo "COUNT:$got_n"; exit 1; fi
    if [ "$got_l" != "$want" ]; then echo "LIST:$got_l";  exit 1; fi
    exit 0
  ) >"$WORK/out" 2>&1 \
    && ok "$label" \
    || bad "$label (want $want, got $(cat "$WORK/out"))"
}

# --- the actual failure: nft wrapped the element list over several lines -----
WRAPPED='table inet kagebox_egress {
	set allow4 {
		type ipv4_addr . inet_service
		elements = { 20.43.161.105 . 443,
			     103.102.166.224 . 443,
			     149.154.166.110 . 443,
			     151.101.3.42 . 443,
			     151.101.67.42 . 443 }
	}
}'
run_case "wrapped multi-line element list is counted and listed" "$WRAPPED" 5

# --- the case that always worked: everything on one line --------------------
ONELINE='table inet kagebox_egress {
	set allow4 {
		type ipv4_addr . inet_service
		elements = { 20.43.161.105 . 443, 103.102.166.224 . 443 }
	}
}'
run_case "single-line element list still works" "$ONELINE" 2

# --- genuinely empty set: "none" must still be reachable --------------------
EMPTY='table inet kagebox_egress {
	set allow4 {
		type ipv4_addr . inet_service
	}
}'
run_case "empty set reports zero (so 'none' is honest, not a fallback)" "$EMPTY" 0

# --- the status branch must not resurrect the single-line match --------------
status_block=$(awk '/^  status\)/{f=1} f{print} f&&/^    ;;$/{exit}' "$SCRIPT")
case "$status_block" in
  *'elements = '*) bad "status no longer matches 'elements = {...}' on one line" ;;
  *) ok "status no longer matches 'elements = {...}' on one line" ;;
esac
case "$status_block" in
  *set_pairs*) ok "status lists via set_pairs (same source as the count)" ;;
  *) bad "status lists via set_pairs (same source as the count)" ;;
esac

printf '\n  Summary: %d ok · %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

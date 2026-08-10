#!/usr/bin/env bash
# Allowlist parsing invariant (issue #14)
# =============================================================================
# An allowlist entry names a SERVICE, not an address. `api.example.com` must not
# hand the sandbox every port that happens to live on the resolved IP — SSH,
# databases, mail, admin panels — which an `ip daddr @allow4 accept` rule did.
#
# This drives the REAL resolve_pairs() extracted from bridge/host-egress.sh
# (not a copy, so it cannot drift) with resolution stubbed, and asserts the
# (ip, port) pairs it feeds into the nft set. No root, no nft, no network —
# the ruleset itself needs a privileged host to exercise, but the parsing is
# where the bugs live and this pins it down.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

awk '/^DEFAULT_PORTS=/{print} /^resolve_pairs\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' \
  "$ROOT/bridge/host-egress.sh" > "$WORK/lib.sh"
grep -q 'resolve_pairs' "$WORK/lib.sh" || { echo "could not extract resolve_pairs()"; exit 1; }

# Stub name resolution: deterministic, offline.
resolve_one() {
  case "$1" in
    one.example)  printf '203.0.113.10\n' ;;
    two.example)  printf '203.0.113.20\n198.51.100.20\n' ;;
    nxdomain.example) : ;;                 # resolves to nothing
    *) printf '203.0.113.99\n' ;;
  esac
}
# shellcheck disable=SC1090
source "$WORK/lib.sh"

pass=0; fail=0
expect() { # name  allowlist-content  expected-pairs (sorted, newline sep)
  local name="$1" content="$2" want="$3" got
  ALLOWFILE="$WORK/allow.txt"; printf '%s\n' "$content" > "$ALLOWFILE"
  got="$(resolve_pairs 2>/dev/null)"
  if [ "$got" = "$want" ]; then printf '  [ok]   %s\n' "$name"; pass=$((pass+1))
  else
    printf '  [FAIL] %s\n' "$name"
    printf '     want: %s\n' "$(echo "$want" | tr '\n' '|')"
    printf '     got:  %s\n' "$(echo "$got"  | tr '\n' '|')"
    fail=$((fail+1))
  fi
}

echo "egress allowlist parsing (issue #14):"

expect "bare hostname -> default ports only, never all ports" \
  'one.example' \
  '203.0.113.10 . 443
203.0.113.10 . 80'

expect "explicit single port -> that port only" \
  'one.example:443' \
  '203.0.113.10 . 443'

expect "explicit port list -> exactly those ports" \
  'one.example:443,8443' \
  '203.0.113.10 . 443
203.0.113.10 . 8443'

expect "a non-default port does NOT drag in 443/80" \
  'one.example:9999' \
  '203.0.113.10 . 9999'

expect "multiple A records -> every address gets the ports" \
  'two.example:443' \
  '198.51.100.20 . 443
203.0.113.20 . 443'

expect "comments and blank lines ignored" \
  '# a comment

one.example:443' \
  '203.0.113.10 . 443'

expect "unresolvable host contributes nothing (fails closed)" \
  'nxdomain.example:443' \
  ''

expect "garbage port is skipped, valid sibling survives" \
  'one.example:443,notaport' \
  '203.0.113.10 . 443'

expect "out-of-range port is skipped" \
  'one.example:70000' \
  ''

expect "empty allowlist -> nothing allowed (bridge-only)" \
  '# nothing enabled' \
  ''

printf '\n  Summary: %d ok · %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

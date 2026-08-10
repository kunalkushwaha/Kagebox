#!/usr/bin/env bash
# Posture-reporting invariant (issue #11)
# =============================================================================
# Kagebox may never TELL you it is contained unless it observed containment.
#
# The bug this locks down: `cmd_setup` enabled egress non-fatally and then
# printed "✓ Sandbox ready. (egress: contained …)" unconditionally — so a
# declined sudo prompt ended with the words "egress: contained" on screen, and
# exit status 0. Every control in this project fails open; the reporting must
# not fail open too, or the user's only signal is wrong exactly when it matters.
#
# The test drives the REAL cmd_setup() extracted from `kagebox` (not a copy, so
# it cannot drift) with the expensive steps stubbed, and asserts the banner and
# exit status track the OBSERVED posture in all four combinations.
#
# Runs anywhere: no VM, no sudo, no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

awk '/^cmd_setup\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$ROOT/kagebox" > "$WORK/cmd_setup.sh"
[ -s "$WORK/cmd_setup.sh" ] || { echo "could not extract cmd_setup() from kagebox"; exit 1; }

msg() { printf '==> %s\n' "$*"; }
warn(){ printf '!! %s\n' "$*" >&2; }
die() { printf 'xx %s\n' "$*" >&2; exit 1; }
ensure_multipass(){ :; }; build_model(){ :; }; vm_launch(){ :; }
bridge_start(){ :; }; vm_provision(){ :; }
cmd_egress(){ return "${STUB_EGRESS_RC:-0}"; }
verify(){ return "${STUB_VERIFY_RC:-0}"; }
# shellcheck disable=SC1090
source "$WORK/cmd_setup.sh"

pass=0; fail=0
check() { # name  want_rc  must_contain  must_not_contain
  local name="$1" want_rc="$2" want="$3" notwant="$4" out rc ok=1
  out="$(cmd_setup 2>&1)"; rc=$?
  [ "$rc" = "$want_rc" ] || { ok=0; echo "   rc=$rc want=$want_rc"; }
  grep -qi -- "$want" <<<"$out" || { ok=0; echo "   missing: $want"; }
  if [ -n "$notwant" ] && grep -qi -- "$notwant" <<<"$out"; then
    ok=0; echo "   MUST NOT contain: $notwant"
  fi
  if [ "$ok" = 1 ]; then printf '  [ok]   %s\n' "$name"; pass=$((pass+1))
  else printf '  [FAIL] %s\n' "$name"; echo "$out" | sed 's/^/   | /'; fail=$((fail+1)); fi
}

echo "setup posture reporting (issue #11):"

STUB_EGRESS_RC=0 STUB_VERIFY_RC=0 \
  check "contained + verified -> ready banner, exit 0" 0 "Sandbox ready" ""

# The regression itself.
STUB_EGRESS_RC=1 STUB_VERIFY_RC=0 \
  check "containment FAILED -> says so, exits 1, never says 'ready'" 1 \
        "SECURITY CONTAINMENT IS NOT ENABLED" "Sandbox ready"

STUB_EGRESS_RC=0 STUB_VERIFY_RC=1 \
  check "boundary did NOT verify -> says so, exits 1, never says 'ready'" 1 \
        "BOUNDARY DID NOT VERIFY" "Sandbox ready"

# An explicit, documented opt-out may proceed — but must still not claim ready.
STUB_EGRESS_RC=1 STUB_VERIFY_RC=0 KAGEBOX_ALLOW_UNCONTAINED=1 \
  check "explicit opt-out -> exit 0, still warns, still never says 'ready'" 0 \
        "continuing anyway, uncontained" "Sandbox ready"

printf '\n  Summary: %d ok · %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

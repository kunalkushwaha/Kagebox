#!/usr/bin/env bash
# Egress profile invariant
# =============================================================================
# A profile is a named policy the operator picks. Two properties must hold or
# the whole idea is unsafe:
#
#   1. A profile is a STARTING POINT, never a ceiling — the operator's own
#      vm/egress-allowlist.txt is layered on top of whichever profile is active,
#      so switching to `sealed` for one risky job does not lose their entries.
#   2. Switching NARROWS when you ask it to. `sealed` must actually mean sealed,
#      including after a refresh or a reboot — the refresh timer and the boot
#      unit both have to carry the chosen profile, or they silently rebuild the
#      set from the DEFAULT and widen a sealed box behind your back.
#
# Drives the real profile plumbing extracted from bridge/host-egress.sh.
# No root, no nft, no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

{
  echo 'die(){ echo "die: $*" >&2; return 1; }'
  echo "HERE='$ROOT'"
  awk '/^# --- profiles/{f=1} /^# Emit `IP \. PORT`/{f=0} f' "$ROOT/bridge/host-egress.sh"
} > "$WORK/lib.sh"
grep -q 'allow_sources' "$WORK/lib.sh" || { echo "could not extract profile plumbing"; exit 1; }
# shellcheck disable=SC1090
source "$WORK/lib.sh" 2>/dev/null

PROFILE_DIR="$ROOT/vm/profiles"
ALLOWFILE="$WORK/user-allowlist.txt"
printf '# a user entry\nmy-own-host.example:443\n' > "$ALLOWFILE"

pass=0; fail=0
ck() { # name  actual  expected
  if [ "$2" = "$3" ]; then printf '  [ok]   %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s: got %s want %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}
entries() { PROFILE="$1" allow_sources 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$' | awk '{print $1}' | sort -u; }
has() { entries "$1" | grep -qx "$2" && echo yes || echo no; }

echo "egress profiles:"

ck "sealed adds no destinations of its own" "$(PROFILE=sealed allow_sources 2>/dev/null | grep -vcE '^[[:space:]]*#|^[[:space:]]*$|my-own-host')" "0"
ck "research includes a search endpoint"    "$(has research duckduckgo.com:443)" "yes"
ck "research does NOT include a registry"   "$(has research pypi.org:443)"       "no"
ck "dev extends research (search present)"  "$(has dev duckduckgo.com:443)"      "yes"
ck "dev adds registries"                    "$(has dev pypi.org:443)"            "yes"

echo
echo "the operator's own allowlist survives every profile:"
for p in sealed research dev; do
  ck "  layered under '$p'" "$(has "$p" my-own-host.example:443)" "yes"
done

echo
echo "switching narrows:"
ck "sealed has strictly fewer entries than research" \
   "$([ "$(entries sealed | wc -l)" -lt "$(entries research | wc -l)" ] && echo yes || echo no)" "yes"
ck "research has strictly fewer entries than dev" \
   "$([ "$(entries research | wc -l)" -lt "$(entries dev | wc -l)" ] && echo yes || echo no)" "yes"
ck "open contributes nothing (handled as no table at all)" \
   "$(PROFILE=open allow_sources 2>/dev/null | wc -l)" "0"

echo
echo "a profile name indexes a path, so it is constrained:"
# Exclude the user's own allowlist from the count — it is layered in on purpose
# and always present. What must be zero is the PROFILE's contribution.
ck "traversal name contributes no profile entries" \
   "$(PROFILE=../../etc allow_sources 2>/dev/null | grep -vcE '^[[:space:]]*#|^[[:space:]]*$|my-own-host')" "0"
ck "unknown profile fails closed (empty, not everything)" \
   "$(PROFILE=nosuchprofile allow_sources 2>/dev/null | grep -vcE '^[[:space:]]*#|^[[:space:]]*$|my-own-host')" "0"

echo
echo "the chosen profile survives refresh and reboot:"
ck "refresh cron carries EGRESS_PROFILE" \
   "$(grep -c "EGRESS_PROFILE='\$PROFILE'" "$ROOT/bridge/host-egress.sh")" "1"
ck "boot unit carries EGRESS_PROFILE" \
   "$(grep -c '^Environment=EGRESS_PROFILE=' "$ROOT/bridge/kagebox-egress.service")" "1"
ck "boot unit's profile is stamped at install time" \
   "$(grep -c '__EGRESS_PROFILE__' "$ROOT/bridge/host-egress.sh")" "1"

echo
echo "EVERY unquoted heredoc executes as root — no command substitution in any:"
# These heredocs are deliberately UNQUOTED so $TABLE/$IFACE/$SELF expand. That
# also means a backtick or dollar-paren anywhere inside one — including in a
# COMMENT — is run by the shell, as root, during `egress on`.
#
# This has now shipped TWICE. First: prose containing 'flags timeout' in
# backticks made sudo run `flags` as a command. Second: a comment added to the
# install_cron heredoc explaining that the job runs "through `bash`" made sudo
# run bash — dropping the operator into an interactive root shell on the host,
# and corrupting the cron file it was meant to write.
#
# The first fix pinned only the `nft -f - <<EOF` heredoc, which is exactly why
# the second one got through. Scan ALL of them: any `<<EOF` whose delimiter is
# not single-quoted. If you need prose with backticks, quote the delimiter.
subs="$(awk '
  /<<EOF/ && !/<<'"'"'EOF'"'"'/ { f=1; next }
  f && /^EOF$/                  { f=0; next }
  f && ($0 ~ /`/ || $0 ~ /\$\(/) { print NR": "$0 }
' "$ROOT/bridge/host-egress.sh")"
if [ -z "$subs" ]; then
  printf '  [ok]   no backticks or $(...) inside the root-executed heredoc\n'; pass=$((pass+1))
else
  printf '  [FAIL] command substitution inside the root-executed heredoc:\n'
  printf '%s\n' "$subs" | sed 's/^/         /'
  fail=$((fail+1))
fi

printf '\n  Summary: %d ok · %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

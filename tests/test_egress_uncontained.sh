#!/usr/bin/env bash
# Uncontained-guest invariant
# =============================================================================
# An exemption is the one place this project deliberately hands a guest the open
# internet. That is defensible only if the exemption is NARROW, EXPLICIT, and
# says so out loud. Three properties, and the whole idea is unsafe without them:
#
#   1. Exempt means exempt from the ALLOWLIST — not from everything. An exempt
#      guest must still be unable to reach its contained neighbours on the
#      bridge, or it becomes a pivot: a VM that browses hostile pages, sitting
#      one hop from the sandbox the allowlist was built to protect.
#   2. Exempt guests do NOT get the bridge gateway. That gateway injects host
#      credentials and authenticates nobody, so reaching it is holding the keys.
#   3. Only an address ON OUR BRIDGE can be exempted, and only as a literal
#      address. A CIDR would exempt whoever takes the next lease in that range;
#      a hostname would let a name lookup decide who is exempt.
#
# Drives the real functions and the REAL rendered ruleset from
# bridge/host-egress.sh. No root, no nft, no network.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ck() { # name  actual  expected
  if [ "$2" = "$3" ]; then printf '  [ok]   %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s: got %s want %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

# --- 1. parsing: who may be exempted -----------------------------------------
{
  echo 'die(){ echo "die: $*" >&2; return 1; }'
  echo 'SUBNET="10.85.206.0/24"'
  echo 'UNCONTAINEDFILE="'"$WORK"'/uncontained.txt"'
  sed -n '/^uncontained_addrs() {/,/^}/p' "$ROOT/bridge/host-egress.sh"
} > "$WORK/lib.sh"
grep -q 'uncontained_addrs' "$WORK/lib.sh" || { echo "could not extract uncontained_addrs"; exit 1; }
# shellcheck disable=SC1090
source "$WORK/lib.sh"

addrs() { printf '%s\n' "$1" > "$WORK/uncontained.txt"; uncontained_addrs 2>/dev/null; }

echo "who may be exempted:"
ck "a bare in-subnet IPv4 is accepted"   "$(addrs '10.85.206.174')"          "10.85.206.174"
ck "comments and blanks are ignored"     "$(addrs '# note
10.85.206.174   # browserai-1')"                                             "10.85.206.174"
ck "a CIDR is refused (would exempt future leases)" "$(addrs '10.85.206.0/24' | grep -c .)" "0"
ck "a hostname is refused (no name decides this)"   "$(addrs 'browserai-1.local' | grep -c .)" "0"
ck "a malformed quad is refused"                    "$(addrs '10.85.206' | grep -c .)"       "0"
ck "an address off our bridge is refused"           "$(addrs '8.8.8.8' | grep -c .)"         "0"
ck "the loopback trick is refused"                  "$(addrs '127.0.0.1' | grep -c .)"       "0"
ck "an empty file exempts nobody"                   "$(addrs '' | grep -c .)"                "0"

# --- 2. the ruleset actually rendered ----------------------------------------
echo
echo "what an exempt guest can and cannot reach:"
R="$WORK/rendered.nft"
BRIDGE_IFACE=mpqemubr0 BRIDGE_PORT=18080 bash "$ROOT/bridge/host-egress.sh" render > "$R" 2>/dev/null
ck "render works unprivileged (so CI can syntax-check it)" \
   "$([ -s "$R" ] && echo yes || echo no)" "yes"
ck "an uncontained4 set exists" "$(grep -c 'set uncontained4' "$R")" "1"

deny=$(grep -n 'ip saddr @uncontained4 ip daddr' "$R" | cut -d: -f1)
allow=$(grep -n 'ip saddr @uncontained4 accept' "$R" | cut -d: -f1)
ck "exempt guests are denied the bridge subnet" \
   "$([ -n "$deny" ] && echo yes || echo no)" "yes"
# ORDER IS THE CONTROL. nftables takes the first terminal verdict, so a bare
# accept placed above the subnet deny would swallow guest-to-guest traffic and
# the deny below it would never be reached. This assertion is the pivot check.
ck "the subnet deny comes BEFORE the blanket accept" \
   "$([ -n "$deny" ] && [ -n "$allow" ] && [ "$deny" -lt "$allow" ] && echo yes || echo no)" "yes"
ck "the blanket accept exists (exempt really does mean open internet)" \
   "$([ -n "$allow" ] && echo yes || echo no)" "yes"

# The gateway rule must EXCLUDE exempt guests. An unqualified 'tcp dport 18080
# accept' would hand a browser VM a credentialed proxy.
ck "the bridge gateway is closed to exempt guests" \
   "$(grep -c 'ip saddr != @uncontained4 tcp dport 18080 accept' "$R")" "1"
ck "no unqualified gateway accept remains" \
   "$(grep -cE '^\s*tcp dport 18080 accept' "$R")" "0"

# --- 3. the exemption must survive every path that rebuilds the table --------
echo
echo "an exemption survives refresh, boot and reboot:"
S="$ROOT/bridge/host-egress.sh"
ck "'on' loads exemptions"       "$(sed -n '/^  on)/,/^    ;;/p'      "$S" | grep -c 'load_uncontained')" "1"
ck "'refresh' reloads exemptions" "$(sed -n '/^  refresh)/,/^    ;;/p' "$S" | grep -c 'load_uncontained')" "1"
ck "'boot' loads exemptions"      "$(sed -n '/^  boot)/,/^    ;;/p'    "$S" | grep -c 'load_uncontained')" "1"
ck "the refresh cron carries EGRESS_UNCONTAINED" \
   "$(grep -c "EGRESS_UNCONTAINED='\$UNCONTAINEDFILE'" "$S")" "1"

# --- 4. it has to SAY so ------------------------------------------------------
echo
echo "status tells the truth about exemptions:"
ck "status reports exempt guests"        "$(grep -c 'UNCONTAINED guests' "$S")" "1"
ck "status says so when there are none"  "$(grep -c 'uncontained guests: none' "$S")" "1"
# Read back from the KERNEL, never from the file. The file is intent; the set is
# policy. If a lease moved, the two disagree and only one of them is enforcing.
ck "status reads the kernel set, not the file" \
   "$(sed -n '/^uncontained_set() {/,/^}/p' "$S" | grep -c 'nft list set')" "1"

# --- 5. the repo default exempts nobody --------------------------------------
echo
echo "shipped default:"
ck "vm/egress-uncontained.txt exists"    "$([ -f "$ROOT/vm/egress-uncontained.txt" ] && echo yes || echo no)" "yes"
ck "it ships with no active entries"     \
   "$(grep -vE '^\s*#|^\s*$' "$ROOT/vm/egress-uncontained.txt" | grep -c .)" "0"

printf '\n  Summary: %d ok · %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

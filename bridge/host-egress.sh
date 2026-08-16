#!/usr/bin/env bash
# Host-side egress allowlist for Kagebox sandbox VMs.
# =====================================================================
# Enforced on the HOST via nftables (issue #2). The agent runs as root INSIDE
# the VM, so any control applied in the guest is advisory — it can `nft flush
# ruleset` its own firewall away. The guest cannot reach host nftables at all,
# so a control applied here survives a full guest compromise. This is the
# authoritative egress control; the in-guest `vm/egress-apply.sh` is only
# defence-in-depth.
#
# Scope: only traffic on the multipass bridge interface is touched. The base
# chains stay `policy accept` and merely `jump` to a guest chain for that one
# interface, where the drop lives. Because a `drop` verdict in any nftables
# base chain is final (an `accept` is not), this table is authoritative even
# alongside multipass's or Docker's own forward rules — and it leaves the
# host's LAN, Docker bridges, and the host's own traffic completely alone.
#
#   guest -> internet   : routed, hits the host `forward` hook -> allowlist
#   guest -> host svc   : hits the host `input`   hook -> bridge + DNS/DHCP only (#4)
#   guest IPv6 egress   : dropped — the allowlist set is v4-only, so v6 would
#                         otherwise bypass it entirely (#8)
#
# NOT a complete exfiltration control even when ON: the guest can still reach
# the bridge gateway (by design) and the host's DNS resolver, so DNS tunnelling
# and provider-proxied bytes remain possible. It blocks bulk exfiltration and
# direct C2. See SECURITY.md.
#
# Run as root (kagebox invokes it via sudo):
#   host-egress.sh {on|off|refresh|status}
set -uo pipefail
# nft and ip live in /usr/sbin, which is NOT on cron's default PATH
# (/usr/bin:/bin). Without this the refresh job died at the `command -v nft`
# check below on every tick, with stderr discarded — so the allowlist silently
# stopped tracking rotating CDN IPs, and after a reboot (where the boot run
# resolves nothing because DNS is not up yet) the box stayed sealed forever
# instead of healing on the next tick. Set it here rather than only in the cron
# file, so ANY minimal-environment caller is safe.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH
ACTION="${1:-status}"
IFACE="${BRIDGE_IFACE:-mpqemubr0}"
PORT="${BRIDGE_PORT:-18080}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ALLOWFILE="${EGRESS_ALLOWFILE:-$HERE/vm/egress-allowlist.txt}"
TABLE="inet kagebox_egress"                 # dedicated table — never share/collide
CRONFILE="/etc/cron.d/kagebox-egress"

die() { echo "host-egress: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (use: sudo $0 $ACTION)"
command -v nft >/dev/null 2>&1 || die "nftables (nft) not installed on host"
# These values are interpolated into the ruleset; validate them so a bad
# kagebox.env can't produce a parse error that leaves us with no table.
case "$PORT"  in ''|*[!0-9]*)          die "BRIDGE_PORT must be numeric (got '$PORT')";; esac
case "$IFACE" in ''|*[!A-Za-z0-9._-]*) die "BRIDGE_IFACE has invalid characters (got '$IFACE')";; esac

GW="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1)"
# Scratch variables used by the `grant` action (this script runs with `set -u`).
secs=""; elems=""; granted=""; spec=""; gh=""; gp=""; gips=""; gip=""; gport=""

# --- allowlist resolution --------------------------------------------------
# Resolve via the SAME resolver the guest uses (multipass dnsmasq on the bridge
# IP) so the IPs we pin match the answers the guest actually dials — otherwise
# host-vs-guest DNS divergence silently drops CDN/anycast traffic. Fall back to
# host getent only if dig or the bridge resolver is unavailable.
resolve_one() {
  local h="$1" ips=""
  if [ -n "$GW" ] && command -v dig >/dev/null 2>&1; then
    ips=$(dig +short +time=2 +tries=1 A "$h" "@$GW" 2>/dev/null | grep -E '^[0-9.]+$')
  fi
  [ -z "$ips" ] && ips=$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}')
  printf '%s\n' "$ips" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u
}

# Allowlist entries are `hostname[:port[,port...]]`. A bare hostname means the
# default ports below — allowlisting a name should not hand the agent every
# service that happens to share that address (#14). Note this does nothing about
# CDN fronting: a shared front-end IP still serves many unrelated hostnames on
# :443. What it closes is the NON-web surface on those addresses — SSH,
# databases, mail, admin panels — which an IP-only rule silently permitted.
DEFAULT_PORTS="${EGRESS_DEFAULT_PORTS:-443,80}"

# --- profiles (#: named policies) --------------------------------------------
# A profile is a starting point, never a ceiling: the user's own allowlist is
# always layered ON TOP of it, so switching to `sealed` for one risky job does
# not lose the entries they added, and switching to `dev` does not silently
# drop them either.
PROFILE="${EGRESS_PROFILE:-research}"
PROFILE_DIR="${EGRESS_PROFILE_DIR:-$HERE/vm/profiles}"
# The name indexes a path, so constrain it before it can climb out of the dir.
case "$PROFILE" in
  ''|*[!a-z0-9_-]*) die "EGRESS_PROFILE '$PROFILE' is not a valid profile name" ;;
esac

# Emit the profile's entries, following one `# extends: <profile>` header so
# `dev` can build on `research` without duplicating it. Depth-guarded: a cycle
# would otherwise loop forever with the door open.
profile_lines() {
  local name="$1" depth="${2:-0}" file="$PROFILE_DIR/$1.txt" parent
  [ "$depth" -gt 4 ] && { echo "host-egress: WARNING: profile 'extends' nested too deep at '$name' — stopping" >&2; return 0; }
  case "$name" in *[!a-z0-9_-]*) echo "host-egress: WARNING: ignoring bad profile name '$name'" >&2; return 0 ;; esac
  [ -f "$file" ] || { echo "host-egress: WARNING: profile '$name' not found at $file — treating as empty (sealed)" >&2; return 0; }
  parent="$(sed -n 's/^#[[:space:]]*extends:[[:space:]]*\([a-z0-9_-]*\).*/\1/p' "$file" | head -1)"
  [ -n "$parent" ] && profile_lines "$parent" $((depth+1))
  cat "$file"
}

# Every source of allowlist entries, profile first then the user's own.
allow_sources() {
  [ "$PROFILE" = open ] && return 0          # `open` means no table at all
  profile_lines "$PROFILE"
  [ -f "$ALLOWFILE" ] && cat "$ALLOWFILE"
  return 0
}

# Emit `IP . PORT` pairs, one per line, for the nft concat set.
resolve_pairs() {
  local entry h ports got ip p
  allow_sources | grep -vE '^[[:space:]]*#|^[[:space:]]*$' | awk '{print $1}' | sort -u | while read -r entry; do
    case "$entry" in
      *:*) h="${entry%%:*}"; ports="${entry#*:}" ;;
      *)   h="$entry";       ports="$DEFAULT_PORTS" ;;
    esac
    got=$(resolve_one "$h")
    [ -z "$got" ] && { echo "host-egress: WARNING: '$h' resolved to no IPv4 (v6-only or DNS failure) — NOT allowlisted" >&2; continue; }
    for ip in $got; do
      case "$ip" in ''|*[!0-9.]*) continue ;; esac
      # shellcheck disable=SC2086
      for p in $(echo "$ports" | tr ',' ' '); do
        case "$p" in ''|*[!0-9]*) echo "host-egress: WARNING: '$entry' has a non-numeric port '$p' — skipped" >&2; continue ;; esac
        [ "$p" -ge 1 ] 2>/dev/null && [ "$p" -le 65535 ] 2>/dev/null || continue
        printf '%s . %s\n' "$ip" "$p"
      done
    done
  done | sort -u
}

load_set() {   # (re)populate allow4; surface errors instead of swallowing them
  local pairs; pairs=$(resolve_pairs)
  nft flush set $TABLE allow4 || die "could not flush allow4 set (is the table loaded?)"
  if [ -n "$pairs" ]; then
    nft add element $TABLE allow4 "{ $(echo "$pairs" | paste -sd, -) }" \
      || echo "host-egress: WARNING: some allowlist entries failed to load into the set" >&2
  fi
}

set_count() {  # (ip,port) pairs actually present in the set, not merely resolved
  nft list set $TABLE allow4 2>/dev/null \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3} \. [0-9]+' | sort -u | wc -l
}

# --- best-effort: make ON authoritative over flows opened while OFF ---------
flush_conntrack() {
  command -v conntrack >/dev/null 2>&1 || {
    echo "host-egress: note: 'conntrack' tool not installed — pre-existing flows are not torn down; enable egress BEFORE starting the agent for full effect" >&2
    return 0; }
  local net; net=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' \
                   "$(ip -4 -o addr show dev "$IFACE" | awk '{print $4; exit}')" 2>/dev/null)
  [ -n "$net" ] && conntrack -D -s "$net" >/dev/null 2>&1 || true
}

build_table() {
  # ONE atomic nft transaction: create-if-absent, delete, recreate. If any line
  # fails, nft rolls the WHOLE thing back and the currently-enforcing table is
  # left intact — a load failure can never leave us table-less (fail-open).
  nft -f - <<EOF
add table $TABLE
delete table $TABLE
table $TABLE {
  set allow4 { type ipv4_addr . inet_service; }
  # Temporary, human-approved grants (#13). Separate from allow4 so the refresh
  # timer — which flushes and repopulates allow4 — cannot wipe a live window,
  # and so a grant can never be mistaken for permanent policy.
  #
  # 'flags timeout' puts expiry in the KERNEL: each element carries its own
  # lifetime and the kernel drops it when it runs out. The window therefore
  # closes even if the warden is killed -9, the host is under load, or userspace
  # never runs again. That is a stronger guarantee than any userspace cleanup.
  # NOTE: this heredoc is UNQUOTED so the table/iface variables expand, which
  # means shell command substitution in here RUNS AS ROOT. Keep prose in this
  # block free of backticks and dollar-paren. A test asserts it.
  set grant4 { type ipv4_addr . inet_service; flags timeout; }

  # --- guest -> beyond-host (routed/NAT'd): the containment control ---------
  chain forward {
    type filter hook forward priority 10; policy accept;
    iifname "$IFACE" jump guest_egress
  }
  chain guest_egress {
    ct state established,related accept
    # Allowlisted DESTINATION AND PORT, not merely destination (#14). UDP is
    # matched too so QUIC/HTTP-3 to an allowlisted :443 keeps working; anything
    # on a port that was not asked for falls through to the drop below.
    ip daddr . tcp dport @allow4 accept
    ip daddr . udp dport @allow4 accept
    # Approved, self-expiring windows (#13).
    ip daddr . tcp dport @grant4 accept
    ip daddr . udp dport @grant4 accept
    # Non-allowlisted egress is REFUSED, not silently dropped. The set is
    # IPv4-only, so IPv6 NEW packets never match the accepts above and are
    # refused here too (#8): no v6 path around the v4 allowlist.
    #
    # Why reject rather than drop. Dropping is for hiding a host from strangers;
    # the process on the other side of this rule is our own sandbox, which we
    # have already TOLD it is contained. Silence buys no secrecy and costs a
    # great deal: a blocked connection hangs until something times out, so the
    # agent burns 60s per attempt, its tool reports a timeout rather than a
    # refusal, and the human sees an empty reply instead of "that host is not
    # allowed". Refusing fails fast and legibly, and the agent can react — by
    # telling you, or by asking for a window. Enforcement is identical either
    # way: the packet still does not leave.
    ct state new limit rate 5/minute log prefix "kagebox egress-deny "
    meta l4proto tcp counter reject with tcp reset
    counter reject with icmpx type admin-prohibited
  }

  # --- guest -> host: only bridge + DNS/DHCP, not every host port (#4) -------
  chain input {
    type filter hook input priority 10; policy accept;
    iifname "$IFACE" jump guest_host
  }
  chain guest_host {
    ct state established,related accept
    # Only the ICMP the guest legitimately needs; NOT router-advert/redirect,
    # which a root guest could use to poison the host's routes/neighbors.
    icmp   type { echo-request, echo-reply, destination-unreachable } accept
    icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big,
                  nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
    udp dport { 53, 67 } accept                 # DNS + DHCP (guest is the client)
    tcp dport 53 accept                          # DNS over TCP
    tcp dport $PORT accept                        # the bridge gateway
    # Refused rather than dropped, for the same reason as guest_egress: a guest
    # probing a host port it may not use should learn that immediately instead
    # of hanging until some timeout fires.
    ct state new limit rate 5/minute log prefix "kagebox host-deny "
    meta l4proto tcp counter reject with tcp reset
    counter reject with icmpx type admin-prohibited
  }
}
EOF
}

# Two units, deliberately: one seals early (before multipassd), one fills the
# allowlist in once DNS works. See kagebox-egress-refresh.service for why.
UNITS="kagebox-egress.service kagebox-egress-refresh.service"

install_unit() {   # boot-time restore, so containment precedes the VM (#12)
  command -v systemctl >/dev/null 2>&1 || return 0
  local unit src dst tmp reloaded=0
  for unit in $UNITS; do
    src="$HERE/bridge/$unit"; dst="/etc/systemd/system/$unit"
    [ -f "$src" ] || continue
    tmp="$(mktemp)"
    sed -e "s|__KAGEBOX_DIR__|$HERE|g" -e "s|__EGRESS_PROFILE__|$PROFILE|g" \
        "$src" > "$tmp"
    if ! cmp -s "$tmp" "$dst" 2>/dev/null; then
      mv "$tmp" "$dst" && chmod 0644 "$dst"
      reloaded=1
    else rm -f "$tmp"; fi
  done
  [ "$reloaded" -eq 1 ] && { systemctl daemon-reload 2>/dev/null || true; }
  for unit in $UNITS; do
    [ -f "/etc/systemd/system/$unit" ] || continue
    systemctl enable "$unit" >/dev/null 2>&1 \
      || echo "host-egress: WARNING: could not enable $unit — containment will NOT be fully restored at boot" >&2
  done
}
remove_unit() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local unit
  for unit in $UNITS; do
    systemctl disable "$unit" >/dev/null 2>&1 || true
  done
}

install_cron() {   # host-side refresh so CDN/rotating allowlist IPs don't go stale
  [ -d /etc/cron.d ] || return 0
  cat > "$CRONFILE" <<EOF
# Kagebox host-side egress — re-resolve allowlisted domains (CDN/rotating IPs).
# Managed by bridge/host-egress.sh; removed on 'egress off'.
# EGRESS_PROFILE must be carried here: without it the refresh would rebuild the
# set from the DEFAULT profile, silently widening a 'sealed' box every 10 min.
# PATH is REQUIRED: cron's default is /usr/bin:/bin, which does not contain
# nft (/usr/sbin/nft), so the job aborted on every tick with its error thrown
# away. Do not remove it, and do not send stderr to /dev/null — a security
# control that fails silently is worse than one that is plainly off.
# Invoke through `bash` rather than as a bare path: this script is tracked
# mode 644, so executing it directly fails with "Permission denied". The
# systemd units already call it as `env bash <path>`; match them, and stay
# correct on a noexec mount or a fresh clone regardless of the exec bit.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/10 * * * * root BRIDGE_IFACE=$IFACE BRIDGE_PORT=$PORT EGRESS_ALLOWFILE='$ALLOWFILE' EGRESS_PROFILE='$PROFILE' EGRESS_PROFILE_DIR='$PROFILE_DIR' bash '$SELF' refresh 2>&1 >/dev/null | logger -t kagebox-egress
EOF
  chmod 644 "$CRONFILE" 2>/dev/null || true
}
remove_cron() { rm -f "$CRONFILE" 2>/dev/null || true; }

case "$ACTION" in
  on)
    ip link show "$IFACE" >/dev/null 2>&1 \
      || die "bridge interface '$IFACE' does not exist — refusing to claim enforcement (set BRIDGE_IFACE correctly). Nothing changed."
    build_table || die "nft failed to load the egress ruleset — the previous state is unchanged (NOT enforcing). Nothing claimed."
    load_set
    flush_conntrack
    install_unit
    install_cron
    echo "host egress ON — iface '$IFACE' may reach: bridge (tcp/$PORT) + DNS/DHCP on the host, and $(set_count) allowlisted destination:port pair(s) from $(basename "$ALLOWFILE"). All other egress DROPPED (host-enforced; the guest cannot remove it)."
    ;;
  grant)
    # grant <seconds> <host[:ports]> [host[:ports]...]   (#13)
    # Open specific destinations for a bounded time instead of taking the whole
    # table down. Called by the warden AFTER a human approved the request.
    #
    # The hostnames originate in the sandbox, so they are treated as hostile
    # input: each is matched against a strict charset before it goes anywhere
    # near a resolver, and we resolve them HERE — the guest never supplies an
    # IP, so it cannot name 10.0.0.5 and call it "github.com".
    secs="${2:-}"; shift 2 2>/dev/null || true
    case "$secs" in ''|*[!0-9]*) die "grant: first argument must be seconds" ;; esac
    [ "$secs" -ge 1 ] && [ "$secs" -le 3600 ] || die "grant: seconds out of range (1-3600)"
    [ $# -gt 0 ] || die "grant: no destinations given"
    nft list table $TABLE >/dev/null 2>&1 || die "grant: egress table not loaded — refusing (run 'egress on' first)"
    elems=""; granted=""
    for spec in "$@"; do
      case "$spec" in
        *[!A-Za-z0-9.:,-]*) echo "host-egress: WARNING: rejecting malformed destination '$spec'" >&2; continue ;;
      esac
      case "$spec" in
        *:*) gh="${spec%%:*}"; gp="${spec#*:}" ;;
        *)   gh="$spec";       gp="$DEFAULT_PORTS" ;;
      esac
      [ -n "$gh" ] || continue
      gips=$(resolve_one "$gh")
      [ -z "$gips" ] && { echo "host-egress: WARNING: grant: '$gh' did not resolve — skipped" >&2; continue; }
      for gip in $gips; do
        for gport in $(echo "$gp" | tr ',' ' '); do
          case "$gport" in ''|*[!0-9]*) continue ;; esac
          [ "$gport" -ge 1 ] 2>/dev/null && [ "$gport" -le 65535 ] 2>/dev/null || continue
          elems="$elems${elems:+, }$gip . $gport timeout ${secs}s"
          granted="$granted $gh:$gport"
        done
      done
    done
    [ -n "$elems" ] || die "grant: nothing resolved to grant — nothing changed"
    nft add element $TABLE grant4 "{ $elems }" || die "grant: could not add elements"
    echo "host egress: GRANTED for ${secs}s ->$granted (kernel-expiring; the table stayed up)"
    ;;
  revoke)
    # Drop every live grant immediately (early close / shutdown). Grants also
    # expire on their own, so this is a courtesy, not the safety mechanism.
    nft list table $TABLE >/dev/null 2>&1 || exit 0
    nft flush set $TABLE grant4 2>/dev/null || true
    echo "host egress: all temporary grants revoked"
    ;;
  grants)
    nft list set $TABLE grant4 2>/dev/null | grep -oE 'elements = \{.*' || echo "no active grants"
    ;;
  boot)
    # Boot-time restore (#12). Runs from kagebox-egress.service, ordered BEFORE
    # multipassd, so containment is in force before the VM can pass a packet.
    #
    # Deliberately does NOT require the bridge interface to exist yet — that is
    # what makes the ordering safe. Every rule matches on `iifname "$IFACE"`, a
    # per-packet NAME comparison (not `iif`, which resolves an interface index
    # at load time), so the table loads fine now and starts biting the moment
    # multipass creates the bridge. Waiting for the interface would mean racing
    # the very thing we are trying to get ahead of.
    #
    # DNS is usually not up this early, so `load_set` may resolve nothing and
    # the allowlist may start EMPTY — i.e. bridge-only, which is stricter, not
    # weaker. The refresh timer fills it in once resolution works. Failing
    # towards "too closed" at boot is the correct direction.
    build_table || die "nft failed to load the egress ruleset at boot — NOT enforcing"
    load_set || true
    echo "host egress: restored at boot (iface '$IFACE', $(set_count) allowlisted destination:port pair(s); the set fills in once DNS is up)"
    ;;
  refresh)
    # Runs on a timer while egress is intended ON. Two jobs:
    #  (1) Re-assert if the table vanished (host reboot / manual flush) — the
    #      cron only exists while ON, so a missing table here means restore it,
    #      not fail open silently.
    #  (2) Re-resolve allowlisted domains (CDN/rotating IPs).
    # It must NOT flush conntrack (that would reset in-flight allowlisted flows
    # every interval); conntrack teardown happens once, on the on-transition.
    if ! nft list table $TABLE >/dev/null 2>&1; then
      ip link show "$IFACE" >/dev/null 2>&1 || exit 0     # iface gone; nothing to enforce
      build_table || exit 0                                # re-assert; retry next tick on failure
    fi
    load_set
    ;;
  off)
    nft list table $TABLE >/dev/null 2>&1 && nft delete table $TABLE
    remove_unit
    remove_cron
    echo "host egress OFF — VM has open internet again."
    ;;
  status)
    if nft list table $TABLE >/dev/null 2>&1; then
      echo "host egress: ON (enforced on the host, iface '$IFACE', $(set_count) allowlisted destination:port pair(s))"
      nft list set $TABLE allow4 2>/dev/null | grep -oE 'elements = \{[^}]*\}' \
        || echo "  allowlisted external destinations: none (bridge + DNS only)"
    else
      echo "host egress: OFF (VM has open internet)"
    fi
    ;;
  *) echo "usage: host-egress.sh {on|off|boot|refresh|status|grant <secs> <host[:ports]>...|revoke|grants}" >&2; exit 1 ;;
esac

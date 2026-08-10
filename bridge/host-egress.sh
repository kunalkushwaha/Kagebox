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

# Emit `IP . PORT` pairs, one per line, for the nft concat set.
resolve_pairs() {
  [ -f "$ALLOWFILE" ] || return 0
  local entry h ports got ip p
  grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$ALLOWFILE" | awk '{print $1}' | while read -r entry; do
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
    # Non-allowlisted egress is dropped. The set is IPv4-only, so IPv6 NEW
    # packets never match the accept above and fall through to drop here (#8) —
    # no v6 path around the v4 allowlist.
    ct state new limit rate 5/minute log prefix "kagebox egress-drop "
    counter drop
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
    ct state new limit rate 5/minute log prefix "kagebox host-drop "
    counter drop
  }
}
EOF
}

UNITFILE="/etc/systemd/system/kagebox-egress.service"

install_unit() {   # boot-time restore, so containment precedes the VM (#12)
  command -v systemctl >/dev/null 2>&1 || return 0
  [ -f "$HERE/bridge/kagebox-egress.service" ] || return 0
  local tmp; tmp="$(mktemp)"
  sed "s|__KAGEBOX_DIR__|$HERE|g" "$HERE/bridge/kagebox-egress.service" > "$tmp"
  if ! cmp -s "$tmp" "$UNITFILE" 2>/dev/null; then
    mv "$tmp" "$UNITFILE" && chmod 0644 "$UNITFILE"
    systemctl daemon-reload 2>/dev/null || true
  else rm -f "$tmp"; fi
  systemctl enable kagebox-egress.service >/dev/null 2>&1 \
    || echo "host-egress: WARNING: could not enable kagebox-egress.service — containment will NOT be restored at boot" >&2
}
remove_unit() {
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl disable kagebox-egress.service >/dev/null 2>&1 || true
}

install_cron() {   # host-side refresh so CDN/rotating allowlist IPs don't go stale
  [ -d /etc/cron.d ] || return 0
  cat > "$CRONFILE" <<EOF
# Kagebox host-side egress — re-resolve allowlisted domains (CDN/rotating IPs).
# Managed by bridge/host-egress.sh; removed on 'egress off'.
*/10 * * * * root BRIDGE_IFACE=$IFACE BRIDGE_PORT=$PORT EGRESS_ALLOWFILE='$ALLOWFILE' '$SELF' refresh >/dev/null 2>&1
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
  *) echo "usage: host-egress.sh {on|off|boot|refresh|status}" >&2; exit 1 ;;
esac

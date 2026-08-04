#!/usr/bin/env bash
# Egress allowlist firewall for the sandbox VM (nftables, OUTPUT default-DROP).
# When ON, the agent can reach only: loopback, established connections, the host
# bridge port, DNS on the gateway, and IPs resolved from egress-allowlist.txt.
#
# SCOPE — read this before trusting it:
#   * This runs INSIDE the VM, where the agent has passwordless sudo. It raises
#     the bar against mistakes and casual injection, but an agent with root here
#     can remove it. `bridge/host-egress.sh` is the authoritative control — it
#     enforces the same allowlist on the HOST, outside the blast radius. This
#     script is defence-in-depth only. See SECURITY.md.
#   * The allowlist is resolved to IP addresses. For CDN-hosted APIs a single
#     address fronts many unrelated names, so an entry is broader than it looks.
#   * DNS is permitted (rate-limited) and remains a low-bandwidth side channel.
#
# Usage (inside the VM):  egress-apply.sh {on|off|refresh|status|render}
#   render = print the ruleset without applying it (used by CI to syntax-check)
#
# Env:
#   BRIDGE_PORT      host bridge port to permit          (default 18080)
#   EGRESS_DNS_RATE  DNS rate limit, nft syntax          (default 120/minute)
set -uo pipefail
ACTION="${1:-status}"
ALLOWFILE="${2:-$HOME/egress-allowlist.txt}"
BRIDGE_PORT="${BRIDGE_PORT:-18080}"
EGRESS_DNS_RATE="${EGRESS_DNS_RATE:-120/minute}"
# GW/GW6 are overridable so `render` can be syntax-checked off-box (see CI).
GW="${GW:-$(ip route | awk '/^default/{print $3; exit}')}"
GW6="${GW6:-$(ip -6 route 2>/dev/null | awk '/^default/{print $3; exit}')}"
TABLE="inet egress"

ensure_nft() { command -v nft >/dev/null 2>&1 || sudo apt-get install -y -qq nftables >/dev/null 2>&1; }

_hosts() { grep -vE '^\s*#|^\s*$' "$ALLOWFILE" 2>/dev/null | awk '{print $1}'; }

resolve_ips() {   # resolve allowlist domains -> unique IPv4s
  [ -f "$ALLOWFILE" ] || return 0
  _hosts | while read -r h; do
    getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}'
  done | sort -u
}

resolve_ips6() {  # resolve allowlist domains -> unique IPv6s
  [ -f "$ALLOWFILE" ] || return 0
  _hosts | while read -r h; do
    getent ahostsv6 "$h" 2>/dev/null | awk '{print $1}' | grep -F ':'
  done | sort -u
}

load_set() {
  local ips ips6
  ips=$(resolve_ips); ips6=$(resolve_ips6)
  sudo nft flush set $TABLE allow4 2>/dev/null || true
  sudo nft flush set $TABLE allow6 2>/dev/null || true
  [ -n "$ips" ]  && sudo nft add element $TABLE allow4 "{ $(echo "$ips"  | paste -sd, -) }" 2>/dev/null || true
  [ -n "$ips6" ] && sudo nft add element $TABLE allow6 "{ $(echo "$ips6" | paste -sd, -) }" 2>/dev/null || true
  echo "$ips" | grep -c .
}

# The single definition of the ruleset. `render` prints it so CI can syntax-check
# exactly what `on` applies, rather than a copy that can drift out of step.
#
# The gateway is permitted ONLY on the bridge port and DNS — not wholesale. A
# bare 'ip daddr $GW accept' exposes every service the host has bound on that
# interface (sshd, dev servers, databases, published container ports).
render_ruleset() {
  cat <<EOF
table $TABLE {
  set allow4 { type ipv4_addr; flags interval; }
  set allow6 { type ipv6_addr; flags interval; }
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept

    # host bridge (LLM/API) — the single intended channel to the host
    ip daddr $GW tcp dport $BRIDGE_PORT accept

    # DNS to the gateway's forwarder, rate-limited. DNS remains a low-bandwidth
    # exfiltration channel, so cap it and log the excess rather than pretend it
    # is closed. Raise EGRESS_DNS_RATE if legitimate resolution gets throttled.
    ip daddr $GW udp dport 53 limit rate $EGRESS_DNS_RATE burst 60 packets accept
    ip daddr $GW tcp dport 53 limit rate $EGRESS_DNS_RATE burst 60 packets accept
    ip daddr $GW udp dport 53 limit rate 5/minute log prefix "egress-dns-throttle "
    ip daddr $GW tcp dport 53 limit rate 5/minute log prefix "egress-dns-throttle "

    # DHCP lease renewal (otherwise the lease lapses and the VM loses its IP)
    udp sport 68 udp dport 67 accept
$( [ -n "$GW6" ] && printf '    ip6 daddr %s udp dport 53 limit rate %s burst 60 packets accept\n' "$GW6" "$EGRESS_DNS_RATE" )
    ip daddr @allow4 accept                                    # allowlisted domains (v4)
    ip6 daddr @allow6 accept                                   # allowlisted domains (v6)
    ct state new limit rate 5/minute log prefix "egress-drop "  # log blocked attempts (auditable)
  }
}
EOF
}

case "$ACTION" in
  render)
    render_ruleset
    ;;
  on)
    ensure_nft
    [ -n "$GW" ] || { echo "!! no default gateway found; refusing to apply (would cut the VM off entirely)" >&2; exit 1; }
    sudo nft list table $TABLE >/dev/null 2>&1 && sudo nft delete table $TABLE
    render_ruleset | sudo nft -f -
    if ! sudo nft list table $TABLE >/dev/null 2>&1; then
      echo "!! egress table failed to load — the sandbox is NOT contained" >&2; exit 1
    fi
    n=$(load_set)
    ( crontab -l 2>/dev/null | grep -v egress-apply.sh; echo "*/15 * * * * BRIDGE_PORT=$BRIDGE_PORT bash \$HOME/egress-apply.sh refresh >/dev/null 2>&1" ) | crontab - 2>/dev/null || true
    echo "egress allowlist ON — reachable: bridge ${GW}:${BRIDGE_PORT}, DNS via ${GW}, + ${n} IP(s) from $(basename "$ALLOWFILE"). All else DROPPED."
    ;;
  refresh)
    sudo nft list table $TABLE >/dev/null 2>&1 || exit 0
    load_set >/dev/null
    ;;
  off)
    sudo nft delete table $TABLE 2>/dev/null || true
    ( crontab -l 2>/dev/null | grep -v egress-apply.sh ) | crontab - 2>/dev/null || true
    echo "egress allowlist OFF — open internet."
    ;;
  status)
    if sudo nft list table $TABLE >/dev/null 2>&1; then
      echo "egress allowlist: ON"
      sudo nft list set $TABLE allow4 2>/dev/null | grep -oE 'elements = \{[^}]*\}' || echo "  external IPs: none (host bridge + DNS only)"
    else echo "egress allowlist: OFF (open internet)"; fi
    ;;
  *) echo "usage: egress-apply.sh {on|off|refresh|status|render}"; exit 1 ;;
esac

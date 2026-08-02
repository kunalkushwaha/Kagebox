#!/usr/bin/env bash
# Egress allowlist firewall for the sandbox VM (nftables, OUTPUT default-DROP).
# When ON, the agent can reach only: loopback, established connections, the host
# bridge/DNS gateway, and IPs resolved from egress-allowlist.txt. Everything else
# is dropped -> no data exfiltration, no phone-home / C2.
#
# Usage (inside the VM):  egress-apply.sh {on|off|refresh|status}
set -uo pipefail
ACTION="${1:-status}"
ALLOWFILE="${2:-$HOME/egress-allowlist.txt}"
GW="$(ip route | awk '/^default/{print $3; exit}')"
TABLE="inet egress"

ensure_nft() { command -v nft >/dev/null 2>&1 || sudo apt-get install -y -qq nftables >/dev/null 2>&1; }

resolve_ips() {   # resolve allowlist domains -> unique IPv4s
  [ -f "$ALLOWFILE" ] || return 0
  grep -vE '^\s*#|^\s*$' "$ALLOWFILE" | awk '{print $1}' | while read -r h; do
    getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}'
  done | sort -u
}

load_set() {
  local ips; ips=$(resolve_ips)
  sudo nft flush set $TABLE allow4 2>/dev/null || true
  [ -n "$ips" ] && sudo nft add element $TABLE allow4 "{ $(echo "$ips" | paste -sd, -) }" 2>/dev/null || true
  echo "$ips" | grep -c .
}

case "$ACTION" in
  on)
    ensure_nft
    sudo nft list table $TABLE >/dev/null 2>&1 && sudo nft delete table $TABLE
    sudo nft -f - <<EOF
table $TABLE {
  set allow4 { type ipv4_addr; flags interval; }
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr $GW accept                                   # host bridge (LLM/API) + DNS forwarder
    ip daddr @allow4 accept                                # allowlisted domains
    ct state new limit rate 5/minute log prefix "egress-drop "  # log blocked attempts (auditable)
  }
}
EOF
    n=$(load_set)
    ( crontab -l 2>/dev/null | grep -v egress-apply.sh; echo "*/15 * * * * bash \$HOME/egress-apply.sh refresh >/dev/null 2>&1" ) | crontab - 2>/dev/null || true
    echo "egress allowlist ON — reachable: host bridge ($GW) + ${n} IP(s) from $(basename "$ALLOWFILE"). All else DROPPED."
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
  *) echo "usage: egress-apply.sh {on|off|refresh|status}"; exit 1 ;;
esac

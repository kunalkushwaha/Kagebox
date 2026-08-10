#!/usr/bin/env bash
# Adversarial invariant suite — live half (issue #16)
# =============================================================================
# Runs ON THE HOST against a provisioned VM, and attacks the boundary from
# inside the sandbox: it tries to escape, to exfiltrate, to find a credential,
# and to open its own door. Anything that succeeds is a BROKEN invariant and
# fails the run.
#
# This is the complement to tests/test_invariants.py (offline, in CI). It needs
# multipass and a running VM, so it is a release/manual gate rather than a CI
# step. Run it after any change to the boundary, and after a host reboot.
#
#   ./tests/adversarial.sh
#
# Probes are deliberately hostile and deliberately cheap: a DROP verdict never
# answers, so every blocked probe costs its full timeout. Keep timeouts short.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
# shellcheck disable=SC1091
source "$ROOT/kagebox.env" 2>/dev/null || true
VM="${VM_NAME:-hermes}"
PORT="${BRIDGE_PORT:-18080}"

held=0; broke=0; skipped=0
hold() { printf '  \033[0;32mheld \033[0m %s\n' "$1"; held=$((held+1)); }
broke() { printf '  \033[0;31mBROKE\033[0m %s\n' "$1"; broke=$((broke+1)); }
skip()  { printf '  \033[0;33mskip \033[0m %s\n' "$1"; skipped=$((skipped+1)); }
sec()   { printf '\n\033[1m%s\033[0m\n' "$1"; }

command -v multipass >/dev/null 2>&1 || { echo "multipass not installed — cannot run the live suite"; exit 2; }
multipass info "$VM" >/dev/null 2>&1 || { echo "VM '$VM' does not exist — run ./kagebox setup"; exit 2; }
multipass info "$VM" 2>/dev/null | grep -q Running || { echo "VM '$VM' is not running — run ./kagebox up"; exit 2; }

# Run a probe inside the guest; echoes its stdout, returns its status.
g() { multipass exec "$VM" -- bash -c "$1" 2>/dev/null; }

echo "Adversarial suite — attacking the boundary from inside '$VM'."
echo "Anything reported BROKE is an invariant that no longer holds."

# --- is containment even supposed to be on? ---------------------------------
CONTAINED=0
[ -f /etc/cron.d/kagebox-egress ] && CONTAINED=1
if [ "$CONTAINED" = 1 ]; then
  echo "(host says containment is CONFIGURED ON — egress probes are enforced)"
else
  echo "(host says containment is OFF — egress probes report as skips, not failures)"
fi

# --- Host-control invariant --------------------------------------------------
sec "Host-control invariant — the guest cannot alter the authoritative policy"
if g 'command -v nft >/dev/null 2>&1' ; then
  # Match on RULESET CONTENT, not the table name: nft's error message echoes
  # the command line ("list table inet kagebox_egress"), so grepping for the
  # name reports a leak every time the read correctly fails.
  out="$(g 'sudo nft list table inet kagebox_egress 2>/dev/null | grep -c "chain guest_egress"')"
  [ "${out:-0}" = 0 ] && hold "guest cannot read the host egress table (it lives in the host netns)" \
                      || broke "the guest can READ the host egress ruleset"
else
  hold "guest has no nft binary to reach for (host table is out of reach regardless)"
fi
# The guest flushing its own firewall must not affect containment (issue #2).
g 'sudo nft flush ruleset >/dev/null 2>&1' >/dev/null
if [ "$CONTAINED" = 1 ]; then
  rc=0; g 'curl -s -o /dev/null --max-time 6 https://1.1.1.1' || rc=$?
  [ "$rc" = 0 ] && broke "after the guest flushed ITS ruleset, egress opened — containment was guest-side" \
                || hold "guest flushed its own ruleset and stayed contained (host-enforced)"
else
  skip "guest-flush test (containment is off by choice)"
fi

# --- Egress invariant --------------------------------------------------------
sec "Egress invariant — nothing leaves except what host policy permits"
if [ "$CONTAINED" = 1 ]; then
  rc=0; g 'curl -s -o /dev/null --max-time 6 https://1.1.1.1' || rc=$?
  [ "$rc" = 0 ] && broke "non-allowlisted IPv4 destination reachable" \
                || hold "non-allowlisted IPv4 destination blocked (rc=$rc)"
  rc=0; g 'curl -s -o /dev/null --max-time 6 -6 https://[2606:4700:4700::1111]' || rc=$?
  [ "$rc" = 0 ] && broke "IPv6 egress reachable — it bypasses the v4 allowlist entirely" \
                || hold "IPv6 egress blocked (no v6 path around the v4 allowlist)"
  # Port scoping (#14): an allowlisted host must not be reachable on a port
  # nobody asked for. Only meaningful if something is actually allowlisted.
  host="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$ROOT/vm/egress-allowlist.txt" 2>/dev/null | head -1 | cut -d: -f1)"
  if [ -n "$host" ]; then
    # WEAK PROBE, on purpose-stated: a refusal here does not prove the firewall
    # did it — the remote may simply not listen on :22. It catches the loud
    # failure (an unlisted port that ANSWERS), not the quiet one. A discriminating
    # test needs an allowlisted host with a known-open non-web port, which we
    # cannot assume. Treat a pass as "no evidence of breakage", not as proof.
    rc=0; g "timeout 4 bash -c 'exec 3<>/dev/tcp/$host/22'" || rc=$?
    [ "$rc" = 0 ] && broke "allowlisted host '$host' ANSWERED on :22 — the rule is not port-scoped" \
                  || hold "allowlisted host '$host' did not answer on an unlisted port (:22; weak probe)"
  else
    skip "port-scoping probe (allowlist is empty — bridge-only, the strictest posture)"
  fi
else
  skip "egress probes (containment is off by choice)"
fi

# --- Ollama invariant --------------------------------------------------------
sec "Ollama invariant — no model management, and no raw host Ollama"
GW="$(g 'ip route | awk "/^default/{print \$3; exit}"')"
bad=""
for ep in delete pull push create copy; do
  c="$(g "curl -s -o /dev/null -w '%{http_code}' --max-time 6 -X POST -d '{}' http://$GW:$PORT/api/$ep")"
  [ "$c" = 403 ] || bad="$bad /api/$ep=$c"
done
[ -z "$bad" ] && hold "model-management endpoints refused at the bridge (403)" \
              || broke "model management reachable:$bad"
# Traversal spellings must not smuggle past the allowlist.
bad=""
for p in '/api/chat/../api/delete' '//api/delete' '/api/./delete'; do
  c="$(g "curl -s -o /dev/null -w '%{http_code}' --max-time 6 -X POST -d '{}' 'http://$GW:$PORT$p'")"
  case "$c" in 403|404) ;; *) bad="$bad $p=$c" ;; esac
done
[ -z "$bad" ] && hold "path-traversal spellings do not reach model management" \
              || broke "traversal reached something:$bad"
rc=0; g "timeout 3 bash -c 'exec 3<>/dev/tcp/$GW/11434'" || rc=$?
[ "$rc" = 0 ] && broke "raw host Ollama reachable from the guest (should be bridge-only)" \
              || hold "raw host Ollama not reachable from the guest"

# --- Credential invariant ----------------------------------------------------
sec "Credential invariant — no host credential is reachable from inside"
out="$(g 'env | grep -iE "(_API_KEY|_AUTH_TOKEN)=.|=(sk-ant-|sk-|aiza)" | head -3')"
[ -z "$out" ] && hold "no host API keys in the guest environment" \
              || broke "API key material in the guest environment"
out="$(g 'ls -d ~/.claude.json ~/.claude/.credentials.json ~/.config/claude ~/.netrc ~/.aws/credentials 2>/dev/null | tr "\n" " "')"
[ -z "$out" ] && hold "no host auth artefacts (claude/netrc/aws) in the guest" \
              || broke "host auth artefacts present: $out"
# Look for HOST key material specifically, and exclude the agent's own source
# tree: hermes-agent ships unit tests full of example keys, which are fixtures,
# not leaks. A suite that reports those trains you to ignore it.
out="$(g 'grep -rIlE "sk-ant-api03-|AIzaSy[0-9A-Za-z_-]{20,}" ~/ \
          --exclude-dir=.cache --exclude-dir=hermes-agent --exclude-dir=node_modules \
          --exclude-dir=site-packages 2>/dev/null | head -3')"
[ -z "$out" ] && hold "no host key material in the guest home directory" \
              || broke "host key material found in: $out"
out="$(g 'cat /proc/1/environ 2>/dev/null | tr "\0" "\n" | grep -iE "_API_KEY|sk-ant-|AIza" | head -2')"
[ -z "$out" ] && hold "no key material in pid 1 environment" \
              || broke "key material in /proc/1/environ"

# --- Guest-escape invariant --------------------------------------------------
sec "Escape invariant — the guest is a VM, not a container on your kernel"
# /dev/kvm may exist in the guest (nested virt), and its presence is NOT an
# escape — a guest running its own VM is still inside the outer one. What would
# matter is the agent's own user being able to open it, so test that instead of
# the node's existence.
out="$(g 'python3 -c "
import os
try:
    fd=os.open(\"/dev/kvm\", os.O_RDWR); os.close(fd); print(\"OPEN\")
except Exception: print(\"DENIED\")" 2>/dev/null')"
case "$out" in
  DENIED|"") hold "/dev/kvm not usable by the agent's user (nested virt would not be an escape anyway)" ;;
  *) broke "the agent's user can open /dev/kvm read-write" ;;
esac
for sock in /var/run/docker.sock /run/docker.sock /run/multipass_socket /var/snap/multipass/common/multipass_socket; do
  out="$(g "ls $sock 2>&1")"
  case "$out" in *"No such file"*) : ;; *) broke "host socket visible in guest: $sock" ;; esac
done
hold "no host/docker/multipass control sockets visible in the guest"
out="$(g 'cat /proc/self/mountinfo 2>/dev/null | grep -ciE " / (ext4|btrfs|xfs) .*(host|hostfs)"')"
[ "${out:-0}" = 0 ] && hold "no host filesystem mounted into the guest" \
                    || broke "a host filesystem appears mounted in the guest"
# `grep -c` counts the probe's own command line and the grep itself, so filter
# both out rather than allowing a fudge factor that could mask a real hit.
out="$(g 'ps aux 2>/dev/null | grep -E "multipassd|qemu-system|dockerd" | grep -v grep | grep -vc "ps aux"')"
[ "${out:-0}" = 0 ] && hold "no host hypervisor/daemon processes visible from the guest" \
                    || broke "host processes visible from inside the guest ($out)"

# --- Workspace invariant -----------------------------------------------------
sec "Workspace invariant — the shared folder is a two-way door, and says so"
if g 'test -d ~/workspace'; then
  if g 'touch ~/workspace/.adversarial-probe 2>/dev/null'; then
    g 'rm -f ~/workspace/.adversarial-probe' >/dev/null
    hold "~/workspace is read-write (expected) — agent output lands on your host; review before running it"
  else
    hold "~/workspace is read-only"
  fi
else
  skip "workspace probe (~/workspace not mounted)"
fi

# --- Warden invariant --------------------------------------------------------
sec "Warden invariant — the guest can ask for a window, never grant one"
body='{"seconds":60,"reason":"adversarial probe","destinations":["example.com:443"]}'
c="$(g "curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'content-type: application/json' -d '$body' http://$GW:$PORT/egress/request")"
case "$c" in
  200) skip "warden answered 200 — a human (or a configured approver) decided; not a self-authorization" ;;
  503) hold "no warden installed -> request denied (fail-closed), guest did not get out" ;;
  4*|5*) hold "warden request refused ($c) — guest cannot self-authorize" ;;
  *) broke "unexpected warden response: $c" ;;
esac
out="$(g 'ls /run/kagebox/warden.sock 2>&1')"
case "$out" in *"No such file"*) hold "warden control socket is not reachable from the guest" ;;
                *) broke "guest can see the warden socket: $out" ;; esac

printf '\n  Summary: %d held · %d skipped · \033[0;31m%d BROKE\033[0m\n' "$held" "$skipped" "$broke"
[ "$broke" -eq 0 ]

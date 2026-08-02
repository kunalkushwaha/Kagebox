#!/usr/bin/env bash
# Runs INSIDE the sandbox VM as `ubuntu` (via `multipass exec`).
# Installs the Claude Code CLI in the sandbox and points it at the host bridge's
# /anthropic route, so `claude -p` works from inside the sandbox while the real
# API key stays on the host (injected by the gateway).
#
# Requires ANTHROPIC_API_KEY in bridge/secrets.env on the host + bridge restarted.
set -euo pipefail

BRIDGE_PORT="${BRIDGE_PORT:-18080}"
GW="$(ip route | awk '/^default/{print $3; exit}')"
ANTHROPIC_BASE="http://${GW}:${BRIDGE_PORT}/anthropic"

# Prefer the Node that the Hermes installer set up; fall back to system/npm.
for n in "$HOME/.hermes/node/bin" "$HOME/.local/bin" /usr/local/bin /usr/bin; do
  [ -x "$n/npm" ] && export PATH="$n:$PATH" && break
done
if ! command -v npm >/dev/null 2>&1; then
  echo "==> Installing Node.js (for the Claude Code CLI)..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - >/dev/null 2>&1 || true
  sudo apt-get install -y nodejs >/dev/null 2>&1 || true
fi
command -v npm >/dev/null 2>&1 || { echo "!! npm unavailable in VM" >&2; exit 1; }

echo "==> Installing @anthropic-ai/claude-code in the sandbox..."
# user-space global if possible; sandbox sudo (passwordless in the VM) as fallback
mkdir -p "$HOME/.npm-global"
npm config set prefix "$HOME/.npm-global" >/dev/null 2>&1 || true
export PATH="$HOME/.npm-global/bin:$PATH"
npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 \
  || sudo npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 \
  || { echo "!! claude-code install failed" >&2; exit 1; }

# Persist the bridge endpoint for interactive + -p use. A dummy key satisfies
# Claude Code's API-key mode; the host bridge overrides it with the real key.
PROFILE="$HOME/.bashrc"
grep -v -E 'hermes-bridge claude|ANTHROPIC_BASE_URL|ANTHROPIC_API_KEY' "$PROFILE" > "$PROFILE.tmp" 2>/dev/null || true
mv "$PROFILE.tmp" "$PROFILE" 2>/dev/null || true
cat >> "$PROFILE" <<EOF
# hermes-bridge claude env
export PATH="\$HOME/.npm-global/bin:\$HOME/.local/bin:\$PATH"
export ANTHROPIC_BASE_URL=${ANTHROPIC_BASE}
export ANTHROPIC_API_KEY=bridge-proxy   # placeholder; real key injected by host bridge
EOF

echo "==> claude wired to bridge: ${ANTHROPIC_BASE}/v1/messages  (host injects the key)"
"$HOME/.npm-global/bin/claude" --version 2>/dev/null \
  || echo "   open a fresh shell, then: claude -p 'hello from the sandbox'"

#!/usr/bin/env bash
# Runs INSIDE the sandbox VM as user `ubuntu` (invoked by `multipass exec`).
# Installs Hermes Agent and points it at host Ollama through the bridge.
#
# Env (passed in by hermesctl):
#   BRIDGE_PORT     port the host gateway listens on            (default 18080)
#   HERMES_MODEL    model name Hermes should use                (default hermes-ctx)
#   HERMES_NUM_CTX  context length to declare to Hermes         (default 65536)
set -euo pipefail

BRIDGE_PORT="${BRIDGE_PORT:-18080}"
HERMES_MODEL="${HERMES_MODEL:-hermes-ctx}"
HERMES_NUM_CTX="${HERMES_NUM_CTX:-65536}"

# The host is the VM's default gateway; the bridge gateway listens there.
GW="$(ip route | awk '/^default/{print $3; exit}')"
BASE="http://${GW}:${BRIDGE_PORT}/v1"
export PATH="$HOME/.local/bin:$PATH"

echo "==> Sandbox sees host bridge at ${GW}:${BRIDGE_PORT}"

echo "==> Waiting for the bridge -> Ollama to answer..."
ok=0
for i in $(seq 1 30); do
  if curl -fsS --max-time 3 "${BASE}/models" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
if [ "$ok" != 1 ]; then
  echo "!! Bridge not reachable at ${BASE}. Start it on the host: ./hermesctl bridge start" >&2
  exit 1
fi
echo "   bridge OK: $(curl -fsS "${BASE}/models" | head -c 120)..."

if ! command -v hermes >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/hermes" ]; then
  echo "==> Installing Hermes Agent (Python 3.11 + Node + browser tools; this takes a few minutes)..."
  curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
else
  echo "==> Hermes Agent already installed, skipping installer."
fi

# Restore prior memory/state from the host backup (if any) before configuring,
# so a rebuilt VM keeps Hermes' memory, sessions, and settings.
[ -f "$HOME/restore-state.sh" ] && bash "$HOME/restore-state.sh" || true

echo "==> Writing Hermes config -> Ollama via bridge (model ${HERMES_MODEL})"
mkdir -p "$HOME/.hermes"
cat > "$HOME/.hermes/config.yaml" <<EOF
# Managed by the hermes-sandbox provisioner.
model:
  provider: custom            # Hermes name for any OpenAI-compatible endpoint
  base_url: "${BASE}"         # host Ollama, reached through the bridge
  default: "${HERMES_MODEL}"
  context_length: ${HERMES_NUM_CTX}
EOF

touch "$HOME/.hermes/.env"
chmod 600 "$HOME/.hermes/.env"
# Refresh the endpoint lines idempotently.
grep -v -E '^(OPENAI_BASE_URL|OPENAI_API_KEY)=' "$HOME/.hermes/.env" > "$HOME/.hermes/.env.tmp" 2>/dev/null || true
mv "$HOME/.hermes/.env.tmp" "$HOME/.hermes/.env"
{
  echo "OPENAI_BASE_URL=${BASE}"
  echo "OPENAI_API_KEY=ollama-local"   # placeholder; Ollama ignores it
} >> "$HOME/.hermes/.env"
chmod 600 "$HOME/.hermes/.env"

# Default all outputs to the shared workspace folder (mirrored to the host).
SOUL="$HOME/.hermes/SOUL.md"; touch "$SOUL"
if ! grep -q "hermes-sandbox:workspace-default" "$SOUL"; then
  cat >> "$SOUL" <<'SOULEOF'

<!-- hermes-sandbox:workspace-default -->
## Working folder & outputs (important)
Your shared folder with the user is `~/workspace/`. It is mirrored to the user's host machine — anything you save there, they can open; anything saved elsewhere stays trapped inside this VM.
- ALWAYS save files, reports, research, generated documents, downloads, and any deliverable to `~/workspace/` (absolute path) unless the user asks for a different location.
- When a task produces files, finish by telling the user the `~/workspace/...` path.
SOULEOF
  echo "==> SOUL.md: default outputs -> ~/workspace"
fi

# Auto-backup Hermes memory/state to the host every 10 minutes (survives VM loss).
if [ -f "$HOME/backup-state.sh" ]; then
  sudo systemctl enable --now cron 2>/dev/null || true
  ( crontab -l 2>/dev/null | grep -v backup-state.sh
    echo "*/10 * * * * bash \$HOME/backup-state.sh >/dev/null 2>&1" ) | crontab - 2>/dev/null \
    && echo "==> auto-backup cron installed (every 10 min -> ~/hermes-state)"
fi

echo "==> Done. Hermes -> ${BASE}  (model ${HERMES_MODEL}, ctx ${HERMES_NUM_CTX})"
command -v hermes >/dev/null 2>&1 && hermes --version 2>/dev/null || echo "   run 'hermes' inside the VM to start."

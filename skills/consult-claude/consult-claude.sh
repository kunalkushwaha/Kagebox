#!/usr/bin/env bash
# consult-claude — ask a STRONGER model (host `claude -p`, via the bridge) a
# knowledge / reasoning / synthesis question and print its answer.
#
# The local Ollama model runs the agent loop + tools; it calls THIS for the
# heavy thinking. Uses the host's Claude auth via the bridge /claude route —
# no API key inside the sandbox.
#
#   consult-claude "Compare these 3 flight options and recommend the best for a family; <details>"
set -euo pipefail
Q="${*:-}"
[ -n "$Q" ] || { echo "usage: consult-claude <question>   (set CONSULT_MODEL=opus|sonnet|haiku)" >&2; exit 2; }
GW="$(ip route | awk '/^default/{print $3; exit}')"
PORT="${BRIDGE_PORT:-18080}"
# opus = deepest reasoning (pricier); sonnet = balanced; haiku = cheapest. Override with CONSULT_MODEL.
MODEL="${CONSULT_MODEL:-opus}"
python3 - "$GW" "$PORT" "$MODEL" "$Q" <<'PY'
import sys, json, urllib.request
gw, port, model, q = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
body = json.dumps({"model": model,
                   "messages": [{"role": "user", "content": q}],
                   "stream": False}).encode()
req = urllib.request.Request(f"http://{gw}:{port}/claude/v1/chat/completions",
                             data=body, headers={"content-type": "application/json"})
try:
    r = json.load(urllib.request.urlopen(req, timeout=300))
    print(r["choices"][0]["message"]["content"])
except Exception as e:
    print(f"consult-claude error: {e}", file=sys.stderr)
    sys.exit(1)
PY

#!/usr/bin/env python3
"""
Kagebox bridge gateway
=============================
Runs on the HOST as your normal user. Binds ONLY to the multipass bridge IP
(the private host<->VM network) so the sandbox VM can reach *allowlisted*
services through it, while your LAN cannot see it at all.

Routing (first match wins); unmatched paths go to the DEFAULT upstream (Ollama):

    /claude/v1/*    ->  LOCAL: runs host `claude -p` (tools disabled), returns
                        an OpenAI-compatible chat completion. Uses your existing
                        Claude auth on the host; no API key enters the sandbox.
    /anthropic/*    ->  https://api.anthropic.com/*   (x-api-key injected here)
    (default)       ->  http://127.0.0.1:11434/*       (local Ollama)

Design intent:
  * Secrets / auth live on the HOST. They never enter the sandbox VM.
  * `claude -p` is invoked with ALL tools disabled, in an empty working dir, so
    the sandbox gets Claude's TEXT but cannot make Claude act on your host.
  * Only allowlisted upstreams are reachable. Add one by editing ROUTES.

Stdlib only. No third-party dependencies.
"""
from __future__ import annotations
import os
import sys
import json
import time
import shutil
import subprocess
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("BRIDGE_PORT", "18080"))
BRIDGE_IFACE = os.environ.get("BRIDGE_IFACE", "mpqemubr0")
DEFAULT_UP = os.environ.get("OLLAMA_UPSTREAM", "http://127.0.0.1:11434").rstrip("/")
# Host-side append-only audit log (JSONL) of every request the sandbox makes.
AUDIT_LOG = os.environ.get("BRIDGE_AUDIT_LOG", "")


def audit(entry):
    if not AUDIT_LOG:
        return
    try:
        d = os.path.dirname(AUDIT_LOG)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

# --- proxied routes ----------------------------------------------------------
# (prefix, upstream_base, strip_prefix, injected_headers)
# injected header values:
#   "env:VARNAME"   -> force header from host env (fail 502 if unset); overrides client
#   "default:VALUE" -> set only if the client did not already send this header
#   "VALUE"         -> force this literal, overriding the client
# Proxy routes are loaded from a runtime-editable registry (providers.json) so
# adding an AI API = edit that file + put its key in secrets.env + restart the
# bridge — no code change. The /claude route (host `claude -p`) is special and
# handled in the Handler below, not here.
PROVIDERS_FILE = os.environ.get(
    "BRIDGE_PROVIDERS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "providers.json"))


def load_routes():
    """Build (prefix, upstream, strip, inject) routes from providers.json."""
    try:
        with open(PROVIDERS_FILE) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        sys.stderr.write(f"[bridge] no providers.json at {PROVIDERS_FILE}; only local Ollama + /claude active\n")
        return []
    except Exception as e:
        sys.stderr.write(f"[bridge] providers.json parse error: {e}\n")
        return []
    routes = []
    for name, p in (cfg.get("providers") or {}).items():
        prefix, upstream = p.get("route_prefix"), p.get("upstream")
        if not prefix or not upstream:
            continue
        inject = {}
        hdr, env = p.get("auth_header"), p.get("auth_env")
        if hdr and env:
            scheme = p.get("auth_scheme", "bearer")
            inject[hdr] = ("bearer-env:" if scheme == "bearer" else "env:") + env
        for hk, hv in (p.get("extra_headers") or {}).items():
            inject[hk] = "default:" + str(hv)  # set only if the client didn't send it
        routes.append((prefix, upstream.rstrip("/"), bool(p.get("strip_prefix", True)), inject))
    return routes


ROUTES = load_routes()

# --- local `claude -p` route -------------------------------------------------
# Exposes the host's authenticated Claude CLI as an OpenAI-compatible endpoint.
# Runs with ALL tools disabled in an empty dir -> the sandbox gets text only and
# cannot make Claude touch the host.
CLAUDE_PREFIX = "/claude/"
CLAUDE_CWD = os.environ.get("CLAUDE_BRIDGE_CWD", "/tmp/hermes-claude-bridge")
CLAUDE_DEFAULT_MODEL = os.environ.get("CLAUDE_BRIDGE_MODEL", "sonnet")
CLAUDE_TIMEOUT = int(os.environ.get("CLAUDE_BRIDGE_TIMEOUT", "600"))
CLAUDE_DISALLOWED = ["Bash", "Edit", "Write", "Read", "MultiEdit", "NotebookEdit",
                     "NotebookRead", "Glob", "Grep", "WebFetch", "WebSearch",
                     "Task", "TodoWrite"]


def claude_bin() -> str:
    """Resolve the claude CLI path (systemd --user PATH omits ~/.local/bin)."""
    b = os.environ.get("CLAUDE_BIN")
    if b and os.path.exists(b):
        return b
    w = shutil.which("claude")
    if w:
        return w
    for c in (os.path.expanduser("~/.local/bin/claude"),
              "/usr/local/bin/claude", "/usr/bin/claude"):
        if os.path.exists(c):
            return c
    return "claude"


CLAUDE_BIN = claude_bin()

HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "accept-encoding",
}


def bind_ip() -> str:
    """The host's IP on the multipass bridge — the only interface we bind to."""
    if os.environ.get("BRIDGE_BIND"):
        return os.environ["BRIDGE_BIND"]
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", BRIDGE_IFACE],
            text=True, stderr=subprocess.DEVNULL)
        for part in out.split():
            if "/" in part and part.count(".") == 3:
                return part.split("/")[0]
    except Exception:
        pass
    return ""


def resolve(path: str):
    for prefix, up, strip, inject in ROUTES:
        if path.startswith(prefix):
            tail = path[len(prefix):] if strip else path
            if not tail.startswith("/"):
                tail = "/" + tail
            return up.rstrip("/") + tail, inject
    return DEFAULT_UP + path, {}


def flatten_messages(messages):
    """Collapse an OpenAI chat message list into a single prompt for `claude -p`."""
    sys_txt, convo = [], []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):  # OpenAI "parts" form
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        content = content or ""
        if role == "system":
            sys_txt.append(content)
        elif role == "assistant":
            convo.append(f"Assistant: {content}")
        elif role == "tool":
            convo.append(f"(tool result) {content}")
        else:
            convo.append(f"User: {content}")
    prompt = ""
    if sys_txt:
        prompt += "\n".join(sys_txt) + "\n\n"
    prompt += "\n".join(convo) + "\n\nAssistant:"
    return prompt


def run_claude(prompt, model, timeout):
    cmd = [CLAUDE_BIN, "-p", prompt, "--output-format", "json",
           "--model", model, "--disallowed-tools", *CLAUDE_DISALLOWED]
    p = subprocess.run(cmd, cwd=CLAUDE_CWD, capture_output=True,
                       text=True, timeout=timeout)
    out = (p.stdout or "").strip()
    try:
        data = json.loads(out)
        return data.get("result", ""), data
    except Exception:
        return out or (p.stderr or "claude: no output"), {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "kagebox-bridge/1.1"

    # -- dispatch -------------------------------------------------------------
    def _dispatch(self):
        if self.path.startswith(CLAUDE_PREFIX):
            return self._claude()
        return self._proxy()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _dispatch

    # -- reverse proxy --------------------------------------------------------
    def _proxy(self):
        url, inject = resolve(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None

        fwd = {k: v for k, v in self.headers.items() if k.lower() not in HOP}

        def force(name, value):
            for k in [k for k in fwd if k.lower() == name.lower()]:
                del fwd[k]
            fwd[name] = value

        for hk, hv in inject.items():
            if hv.startswith("env:"):
                val = os.environ.get(hv[4:], "")
                if not val:
                    return self._fail(502, f"gateway: host env {hv[4:]} not set for {self.path}")
                force(hk, val)
            elif hv.startswith("bearer-env:"):
                var = hv[len("bearer-env:"):]
                val = os.environ.get(var, "")
                if not val:
                    return self._fail(502, f"gateway: host env {var} not set for {self.path}")
                force(hk, "Bearer " + val)
            elif hv.startswith("default:"):
                if not any(k.lower() == hk.lower() for k in fwd):
                    fwd[hk] = hv[len("default:"):]
            else:
                force(hk, hv)

        req = urllib.request.Request(url, data=body, method=self.command, headers=fwd)
        try:
            up = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            up = e  # forward upstream error responses verbatim
        except Exception as e:
            return self._fail(502, f"gateway: upstream error: {e}")
        self._relay(url, up)

    def _relay(self, url, up):
        code = getattr(up, "status", getattr(up, "code", 200))
        self.send_response(code)
        for k, v in up.headers.items():
            if k.lower() in HOP:
                continue
            self.send_header(k, v)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            while True:
                chunk = up.read(65536)
                if not chunk:
                    break
                self.wfile.write(b"%X\r\n" % len(chunk))
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        self._log(url, code)

    # -- local claude -p endpoint --------------------------------------------
    def _claude(self):
        if self.path.rstrip("/").endswith("/models"):
            data = [{"id": m, "object": "model", "owned_by": "anthropic-claude-cli"}
                    for m in ("sonnet", "opus", "haiku")]
            return self._send_json({"object": "list", "data": data})

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            return self._fail(400, "gateway: invalid JSON for /claude")

        model = req.get("model") or CLAUDE_DEFAULT_MODEL
        if model not in ("sonnet", "opus", "haiku"):
            model = CLAUDE_DEFAULT_MODEL  # ignore non-claude model names (e.g. hermes-ctx)
        stream = bool(req.get("stream", False))
        prompt = flatten_messages(req.get("messages", []))

        try:
            text, _meta = run_claude(prompt, model, CLAUDE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return self._fail(504, "gateway: claude -p timed out")
        except FileNotFoundError:
            return self._fail(502, "gateway: 'claude' CLI not found on host")
        except Exception as e:
            return self._fail(502, f"gateway: claude error: {e}")

        created = int(time.time())
        cid = f"chatcmpl-claude-{created}"
        used = f"claude-{model}"
        self._log(f"claude -p (model={model}, {len(prompt)} chars in)", 200)
        if stream:
            return self._claude_sse(cid, created, used, text)
        return self._send_json({
            "id": cid, "object": "chat.completion", "created": created, "model": used,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def _claude_sse(self, cid, created, model, text):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def sse(obj):
            data = ("data: " + json.dumps(obj) + "\n\n").encode()
            self.wfile.write(b"%X\r\n" % len(data) + data + b"\r\n")
            self.wfile.flush()

        base = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model}
        sse({**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]})
        for i in range(0, len(text), 400):
            sse({**base, "choices": [{"index": 0, "delta": {"content": text[i:i + 400]}, "finish_reason": None}]})
        sse({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        done = b"data: [DONE]\n\n"
        self.wfile.write(b"%X\r\n" % len(done) + done + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    # -- helpers --------------------------------------------------------------
    def _send_json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _fail(self, code, msg):
        b = (msg + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
        self._log("-", code)

    def _log(self, url, code):
        sys.stdout.write(f"{self.command} {self.path} -> {url} [{code}]\n")
        sys.stdout.flush()
        audit({"ts": int(time.time()), "method": self.command, "path": self.path,
               "upstream": str(url), "status": code,
               "client": self.client_address[0] if self.client_address else ""})

    def log_message(self, *a):
        pass  # replace noisy default access log with our own


def main():
    ip = bind_ip()
    if not ip:
        sys.stderr.write(
            f"[bridge] no IP found on '{BRIDGE_IFACE}'. Is multipass installed "
            f"and has the VM network come up yet?\n")
        sys.exit(1)
    os.makedirs(CLAUDE_CWD, exist_ok=True)
    srv = ThreadingHTTPServer((ip, PORT), Handler)
    sys.stdout.write(
        f"[bridge] listening on {ip}:{PORT}  default -> {DEFAULT_UP}  "
        f"routes={[r[0] for r in ROUTES] + [CLAUDE_PREFIX + '(claude -p)']}\n")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

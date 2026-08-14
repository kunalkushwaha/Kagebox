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
  * Secrets / auth live on the HOST. They never enter the sandbox VM, and any
    credential header the guest sends is dropped rather than relayed.
  * `claude -p` is invoked with ALL tools disabled, in an empty working dir, so
    the sandbox gets Claude's TEXT but cannot make Claude act on your host. The
    route refuses to serve unless those flags are verified present, and is
    rate-capped so the guest cannot burn your quota.
  * Only allowlisted upstreams are reachable. Add one by editing ROUTES.
  * The default (Ollama) route exposes inference and read-only endpoints only —
    model management stays on the host side of the boundary.

Stdlib only. No third-party dependencies.
"""
from __future__ import annotations
import os
import sys
import json
import time
import shutil
import posixpath
import socket
import subprocess
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("BRIDGE_PORT", "18080"))
BRIDGE_IFACE = os.environ.get("BRIDGE_IFACE", "mpqemubr0")
DEFAULT_UP = os.environ.get("OLLAMA_UPSTREAM", "http://127.0.0.1:11434").rstrip("/")
# Host-side append-only audit log (JSONL) of every request the sandbox makes.
AUDIT_LOG = os.environ.get("BRIDGE_AUDIT_LOG", "")

# Ollama serves model *management* on the same port as inference, so the
# default route is an ALLOWLIST of the endpoints the sandbox legitimately
# needs — inference plus read-only introspection. Anything not named here is
# refused, including endpoints Ollama may add in a future release.
#
# An allowlist rather than a denylist because this check fails closed: a path
# the guest obfuscates (percent-encoding, traversal, duplicate slashes) simply
# fails to match and is refused, so there is no decoding race with however
# Ollama's own router normalises the path.
#
# This is not just model hygiene. `/api/pull` and `/api/create` make the HOST
# fetch from an arbitrary registry, handing the guest an egress path that
# neither the host nor the guest egress allowlist can see. `/api/delete`,
# `/api/copy` and `/api/push` let it destroy or replace the model it is served,
# and `/api/blobs/*` lets it stage arbitrary bytes on the host.
OLLAMA_ALLOWED_EXACT = {
    "/",
    "/api/version", "/api/tags", "/api/ps", "/api/show",
    "/api/chat", "/api/generate", "/api/embed", "/api/embeddings",
    "/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings",
}
OLLAMA_ALLOWED_PREFIX = ("/v1/models/",)


def ollama_path_allowed(path: str) -> bool:
    """True if `path` is an inference/read endpoint we expose to the sandbox."""
    p = path.split("?", 1)[0].split("#", 1)[0]
    # posixpath.normpath preserves a leading '//' (POSIX gives it special
    # meaning), which would make '//api/chat' miss the set and 403 a perfectly
    # good inference call. Collapse it before normalising.
    p = "/" + p.lstrip("/")
    # Normalise so that /api/chat/../api/delete cannot smuggle past the set.
    p = posixpath.normpath(p)
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/")
    if p in OLLAMA_ALLOWED_EXACT:
        return True
    return any(p.startswith(pref) for pref in OLLAMA_ALLOWED_PREFIX)


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


# --- token/cost usage tracking ----------------------------------------------
USAGE_LOG = os.environ.get("BRIDGE_USAGE_LOG", "")


def usage_log(route, model, pt, ct):
    if not USAGE_LOG:
        return
    try:
        d = os.path.dirname(USAGE_LOG)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(USAGE_LOG, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "route": route, "model": model or "",
                                "prompt_tokens": pt or 0, "completion_tokens": ct or 0}) + "\n")
    except Exception:
        pass


def route_name(path):
    for pref in ("/gemini/", "/anthropic/", "/openrouter/", "/openai/", "/claude/"):
        if path.startswith(pref):
            return pref.strip("/")
    return "ollama"


# --- spend budgets (#15) ------------------------------------------------------
# The VM boundary bounds CPU, memory and disk by construction — a runaway agent
# destroys its own sandbox, which is containment working. Money is the one
# resource that escapes the box: the keys are host-held precisely so the guest
# cannot HOLD them, but it can still SPEND them, and a loop or an injected
# instruction will.
#
# So the bridge, which already accounts every call, also enforces a ceiling.
# Requests are checked before the work; tokens and cost are settled after (they
# are only knowable from the response), which means the last call may cross the
# line — the cap bounds the bleeding, it does not predict it.
#
# Counters are seeded from the usage log at startup, so restarting the gateway
# does not hand back a fresh day's budget.
DEFAULT_BUDGET = {"requests_per_hour": 0, "requests_per_day": 0, "usd_per_day": 0.0}
_budget_cfg = {}          # route -> limits
_prices = {}              # route -> (usd per Mtok in, out)
_spend = []               # [ts, route, requests, in_tok, out_tok, usd]
_spend_lock = threading.Lock()


def load_budgets():
    """Read per-route budgets and prices from providers.json (0 = unlimited)."""
    cfg, prices = {}, {"ollama": (0.0, 0.0)}
    try:
        with open(PROVIDERS_FILE) as f:
            data = json.load(f)
    except Exception:
        data = {}
    defaults = (data.get("defaults") or {}).get("budget") or {}
    for name, p in (data.get("providers") or {}).items():
        b = dict(DEFAULT_BUDGET)
        b.update(defaults)
        b.update(p.get("budget") or {})
        cfg[name] = b
        pr = p.get("price_per_mtok") or {}
        prices[name] = (float(pr.get("in", 0) or 0), float(pr.get("out", 0) or 0))
    # /claude is not a providers.json entry; it spends a subscription, not a key.
    cb = dict(DEFAULT_BUDGET); cb.update(defaults)
    cb.update({"requests_per_hour": CLAUDE_MAX_PER_HOUR})
    cfg.setdefault("claude", cb)
    prices.setdefault("claude", (0.0, 0.0))
    cfg.setdefault("ollama", dict(DEFAULT_BUDGET))
    return cfg, prices


def seed_spend_from_log():
    """Replay the last 24h of usage so a restart is not a budget reset."""
    if not USAGE_LOG or not os.path.exists(USAGE_LOG):
        return
    cutoff = time.time() - 86400
    try:
        with open(USAGE_LOG) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                ts = e.get("ts", 0)
                if ts < cutoff:
                    continue
                r = e.get("route", "?")
                pt, ct = e.get("prompt_tokens", 0) or 0, e.get("completion_tokens", 0) or 0
                pin, pout = _prices.get(r, (0.0, 0.0))
                _spend.append([ts, r, 1, pt, ct, pt / 1e6 * pin + ct / 1e6 * pout])
    except Exception:
        pass


def _totals(route, window):
    now = time.time()
    req = tin = tout = 0
    usd = 0.0
    for ts, r, n, i, o, c in _spend:
        if r == route and now - ts < window:
            req += n; tin += i; tout += o; usd += c
    return req, tin, tout, usd


def budget_check(route):
    """(ok, message). False once this route has spent its allowance."""
    lim = _budget_cfg.get(route) or DEFAULT_BUDGET
    with _spend_lock:
        now = time.time()
        _spend[:] = [s for s in _spend if now - s[0] < 86400]
        rh = lim.get("requests_per_hour", 0) or 0
        rd = lim.get("requests_per_day", 0) or 0
        ud = float(lim.get("usd_per_day", 0) or 0)
        if rh:
            n, _, _, _ = _totals(route, 3600)
            if n >= rh:
                return False, f"{route}: hourly request budget spent ({n}/{rh})"
        if rd:
            n, _, _, _ = _totals(route, 86400)
            if n >= rd:
                return False, f"{route}: daily request budget spent ({n}/{rd})"
        if ud:
            _, _, _, usd = _totals(route, 86400)
            if usd >= ud:
                return False, f"{route}: daily cost budget spent (~${usd:.2f}/${ud:.2f})"
        # Reserve the request now so concurrent calls cannot all pass the check.
        _spend.append([now, route, 1, 0, 0, 0.0])
    return True, ""


def budget_settle(route, pt, ct):
    """Attach the actual tokens/cost to this route's most recent reservation."""
    pin, pout = _prices.get(route, (0.0, 0.0))
    cost = (pt or 0) / 1e6 * pin + (ct or 0) / 1e6 * pout
    with _spend_lock:
        for s in reversed(_spend):
            if s[1] == route and s[3] == 0 and s[4] == 0:
                s[3], s[4], s[5] = pt or 0, ct or 0, cost
                return
        _spend.append([time.time(), route, 0, pt or 0, ct or 0, cost])


def extract_usage(tail, ctype):
    """Best-effort (model, prompt_tokens, completion_tokens) from a response tail."""
    s = tail.decode("utf-8", "ignore")
    if "application/json" in (ctype or ""):
        try:
            j = json.loads(s)
            u = j.get("usage") or {}
            return j.get("model"), u.get("prompt_tokens"), u.get("completion_tokens")
        except Exception:
            pass
    model = pt = ct = None  # SSE: scan data: lines for the chunk carrying usage
    for line in s.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload.startswith("{"):
            continue
        try:
            j = json.loads(payload)
        except Exception:
            continue
        if j.get("model"):
            model = j["model"]
        if j.get("usage"):
            pt, ct = j["usage"].get("prompt_tokens"), j["usage"].get("completion_tokens")
    return model, pt, ct

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
    # `services` are host-side helpers the sandbox may use that are NOT model
    # backends — a local search engine, say. Same proxying and same credential
    # injection, but they never appear in `kagebox backend` / `providers`, which
    # would be nonsense for something you cannot run inference against.
    for name, p in (cfg.get("services") or {}).items():
        prefix, upstream = p.get("route_prefix"), p.get("upstream")
        if not prefix or not upstream:
            continue
        inject = {}
        hdr, env = p.get("auth_header"), p.get("auth_env")
        if hdr and env:
            scheme = p.get("auth_scheme", "bearer")
            inject[hdr] = ("bearer-env:" if scheme == "bearer" else "env:") + env
        for hk, hv in (p.get("extra_headers") or {}).items():
            inject[hk] = "default:" + str(hv)
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
# An empty MCP server set. NOTE: `--mcp-config '{}'` is REJECTED by the CLI
# ("mcpServers: expected record, received undefined") — the key is required.
CLAUDE_EMPTY_MCP = '{"mcpServers":{}}'
# Guest-controlled prompts drive a host process authenticated as you, so cap how
# fast the sandbox can spend your quota. 0 disables the cap.
CLAUDE_MAX_PER_HOUR = int(os.environ.get("CLAUDE_BRIDGE_MAX_PER_HOUR", "60"))
# Escape hatch for a CLI whose flags we cannot verify. Default closed.
CLAUDE_ALLOW_UNVERIFIED = os.environ.get("CLAUDE_BRIDGE_ALLOW_UNVERIFIED") == "1"


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

# Sentinel distinguishing "no claude CLI here" from "claude is here but we
# cannot prove it suppresses tools" — the latter is the security-relevant case.
CLAUDE_MISSING = "__claude_not_installed__"


def claude_guard():
    """Resolve the tool/MCP suppression flags this `claude` build understands.

    Returns (flags, error). A non-empty `error` means /claude must refuse to
    serve — the caller turns it into a 503.

    The point is to fail LOUDLY and CLOSED. These flags have been renamed across
    Claude Code releases, and an unrecognised flag does not reliably error — it
    can simply leave tools enabled, which would quietly turn this route into a
    guest-to-host action channel running under the host user's own credentials
    and MCP servers. So we read `claude --help` and assert the flags are really
    there. If we cannot even run --help we still refuse: an unverifiable CLI is
    exactly the case this check exists for. CLAUDE_BRIDGE_ALLOW_UNVERIFIED=1
    overrides, for someone who has read run_claude() and accepts the risk.
    """
    try:
        r = subprocess.run([CLAUDE_BIN, "--help"], capture_output=True,
                           text=True, timeout=30)
        help_txt = (r.stdout or "") + (r.stderr or "")  # some CLIs print help to stderr
    except FileNotFoundError:
        # Not installed at all. That is a plain configuration problem, not a
        # containment failure — keep the actionable 502 rather than telling the
        # user to upgrade a CLI they do not have.
        return [], CLAUDE_MISSING
    except Exception as e:
        return [], f"could not run '{CLAUDE_BIN} --help' to verify tool suppression ({e})"

    def has(flag):
        return flag in help_txt

    flags, missing = [], []
    # MCP suppression is the part that must not silently fail: without it a
    # guest prompt can reach whatever MCP servers the host user has configured.
    if has("--strict-mcp-config") and has("--mcp-config"):
        flags += ["--strict-mcp-config", "--mcp-config", CLAUDE_EMPTY_MCP]
    else:
        missing.append("--strict-mcp-config/--mcp-config")

    # Belt and braces: an explicit empty allowlist *and* the historical denylist.
    # The allowlist is what covers tools added in a future release.
    if has("--allowed-tools"):
        flags += ["--allowed-tools", ""]
    elif has("--allowedTools"):
        flags += ["--allowedTools", ""]
    else:
        missing.append("--allowed-tools")

    if has("--disallowed-tools"):
        flags += ["--disallowed-tools", *CLAUDE_DISALLOWED]
    elif has("--disallowedTools"):
        flags += ["--disallowedTools", *CLAUDE_DISALLOWED]
    else:
        missing.append("--disallowed-tools")

    if missing:
        return flags, (f"this 'claude' build does not expose {', '.join(missing)} "
                       f"— cannot prove tools/MCP are suppressed")
    return flags, ""


CLAUDE_FLAGS, CLAUDE_GUARD_ERR = claude_guard()

HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "accept-encoding",
}

# Upstream credentials are injected here, on the host. Anything the guest sends
# under these names is dropped rather than relayed, so a guest-supplied header
# can never reach an upstream on a route that happens not to inject one of its
# own. (Hermes/Claude Code in the VM send placeholder keys by design.)
CLIENT_AUTH_HDRS = {"authorization", "x-api-key", "api-key", "x-goog-api-key"}


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
    """-> (upstream_url, injected_headers, is_default_route)."""
    for prefix, up, strip, inject in ROUTES:
        if path.startswith(prefix):
            tail = path[len(prefix):] if strip else path
            if not tail.startswith("/"):
                tail = "/" + tail
            return up.rstrip("/") + tail, inject, False
    return DEFAULT_UP + path, {}, True


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


# --- egress-window request route ---------------------------------------------
# The guest's ONLY way to ask for internet access. This route deliberately does
# NOT decide anything: it forwards the ask to the root warden over a unix socket
# and relays the verdict. The gateway runs as the desktop user and cannot open
# nftables either — so a compromised gateway is still not a way through the wall.
# If the warden is not installed or not running, the answer is no.
EGRESS_REQUEST_PATH = "/egress/request"
WARDEN_SOCK = os.environ.get("WARDEN_SOCK", "/run/kagebox/warden.sock")
# Approval needs a human tap and the window itself runs to completion before the
# warden replies, so the guest's HTTP call is a long one by nature.
WARDEN_TIMEOUT = int(os.environ.get("WARDEN_TIMEOUT", "480"))

_claude_calls = []          # unix timestamps of recent /claude invocations
_claude_lock = threading.Lock()


def claude_rate_ok():
    """False once the sandbox has spent its hourly /claude budget.

    The guest writes the prompts but the host pays for them, so an injected
    agent could otherwise burn the host user's quota in a loop.
    """
    if CLAUDE_MAX_PER_HOUR <= 0:
        return True
    now = time.time()
    with _claude_lock:
        _claude_calls[:] = [t for t in _claude_calls if now - t < 3600]
        if len(_claude_calls) >= CLAUDE_MAX_PER_HOUR:
            return False
        _claude_calls.append(now)
        return True


def run_claude(prompt, model, timeout):
    # Tools are suppressed three ways, deliberately redundant so a single CLI
    # change cannot silently re-enable them (CLAUDE_FLAGS is what claude_guard()
    # confirmed this build actually understands):
    #   --allowed-tools ""            an empty allowlist — nothing is permitted,
    #                                 including any tool added in a future release
    #   --disallowed-tools <list>     belt-and-braces denylist of built-ins
    #   --strict-mcp-config + empty --mcp-config
    #                                 ignore the host user's MCP servers entirely
    #                                 (Slack, GitHub, filesystem, …) so a guest
    #                                 prompt can't invoke mcp__* tools host-side.
    # The route returns Claude's TEXT only; it cannot act on the host.
    cmd = [CLAUDE_BIN, "-p", prompt, "--output-format", "json",
           "--model", model, *CLAUDE_FLAGS]
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
        if self.path.rstrip("/") == EGRESS_REQUEST_PATH:
            return self._egress_request()
        return self._proxy()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _dispatch

    # -- reverse proxy --------------------------------------------------------
    def _proxy(self):
        # Read the body first: an early 403 below must not leave unread
        # Content-Length bytes on a kept-alive HTTP/1.1 socket, or they get
        # parsed as the next request and desync the connection.
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None
        url, inject, is_default = resolve(self.path)
        if is_default and not ollama_path_allowed(self.path):
            return self._fail(
                403, f"gateway: {self.path} is not exposed to the sandbox "
                     f"(only inference and read-only endpoints are)")

        # Spend gate (#15). Only the calls that actually cost money: a model
        # listing is free, and the local Ollama route spends electricity, not
        # your card. Checked after the cheap gates so a 403 costs no budget.
        if not is_default and self.path.rstrip("/").endswith(
                ("/chat/completions", "/completions", "/messages", "/generateContent")):
            ok, why = budget_check(route_name(self.path))
            if not ok:
                return self._fail(429, f"gateway: budget exhausted — {why}. The "
                                       f"sandbox writes the prompts; the host pays "
                                       f"for them. Tune it in providers.json.")

        fwd = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        for k in [k for k in fwd if k.lower() in CLIENT_AUTH_HDRS]:
            del fwd[k]

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
        ctype = up.headers.get("Content-Type", "")
        self.send_response(code)
        for k, v in up.headers.items():
            if k.lower() in HOP:
                continue
            self.send_header(k, v)
        if self.command == "HEAD":
            # A HEAD response carries no body; emitting one desyncs a kept-alive
            # connection, letting the next response be read as part of this one.
            self.send_header("Content-Length", "0")
            self.end_headers()
            self._log(url, code)
            return
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        tail = b""
        try:
            while True:
                chunk = up.read(65536)
                if not chunk:
                    break
                self.wfile.write(b"%X\r\n" % len(chunk))
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
                if USAGE_LOG:
                    tail = (tail + chunk)[-16384:]   # keep the end (usage lives there)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        self._log(url, code)
        if USAGE_LOG and self.path.endswith("/chat/completions"):
            model, pt, ct = extract_usage(tail, ctype)
            if pt or ct:
                usage_log(route_name(self.path), model, pt, ct)
                budget_settle(route_name(self.path), pt, ct)

    # -- local claude -p endpoint --------------------------------------------
    def _claude(self):
        # Drain the body before any early return, for the same reason as in
        # _proxy: unread Content-Length bytes left on a kept-alive HTTP/1.1
        # socket get parsed as the next request and desync the connection.
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"

        if CLAUDE_GUARD_ERR == CLAUDE_MISSING:
            return self._fail(502, "gateway: 'claude' CLI not found on host")
        if CLAUDE_GUARD_ERR and not CLAUDE_ALLOW_UNVERIFIED:
            return self._fail(
                503, f"gateway: /claude disabled — {CLAUDE_GUARD_ERR}. Upgrade "
                     f"the claude CLI, or set CLAUDE_BRIDGE_ALLOW_UNVERIFIED=1 "
                     f"to serve it anyway (this may expose host tools and MCP "
                     f"servers to the sandbox).")
        if self.path.rstrip("/").endswith("/models"):
            data = [{"id": m, "object": "model", "owned_by": "anthropic-claude-cli"}
                    for m in ("sonnet", "opus", "haiku")]
            return self._send_json({"object": "list", "data": data})

        # Counted after the cheap gates above so a listing or a disabled-route
        # 503 does not consume budget, but before the work that costs quota.
        ok, why = budget_check("claude")
        if not ok:
            return self._fail(429, f"gateway: budget exhausted — {why}. The "
                                   f"sandbox writes the prompts; the host pays "
                                   f"for them. Tune it in providers.json.")

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
        _u = (_meta or {}).get("usage") or {}
        usage_log("claude", used, _u.get("input_tokens"), _u.get("output_tokens"))
        budget_settle("claude", _u.get("input_tokens"), _u.get("output_tokens"))
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

    # -- egress window request ------------------------------------------------
    def _egress_request(self):
        """Relay a guest 'may I have the internet?' ask to the root warden.

        No decision is made here. We pass the guest's stated reason through to
        the human (clearly labelled as untrusted, warden-side) and return the
        verdict. Every error path is a denial — an unreachable warden means the
        door stays shut, never that it opens by default.
        """
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if self.command != "POST":
            return self._fail(405, "gateway: POST a JSON body to /egress/request")
        try:
            req = json.loads(raw.decode() or "{}")
        except Exception:
            return self._fail(400, "gateway: invalid JSON for /egress/request")
        # Relay only; the warden validates. We pass destinations through so the
        # human sees WHAT is being asked for, not just that something was.
        payload = json.dumps({"reason": str(req.get("reason", ""))[:300],
                              "seconds": req.get("seconds", 60),
                              "destinations": req.get("destinations", []),
                              "scope": req.get("scope", "")}) + "\n"
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(WARDEN_TIMEOUT)
            s.connect(WARDEN_SOCK)
        except FileNotFoundError:
            return self._fail(503, "gateway: egress warden is not installed "
                                   "(host: ./kagebox warden setup) — denied")
        except Exception as e:
            return self._fail(503, f"gateway: cannot reach the egress warden ({e}) — denied")
        try:
            s.sendall(payload.encode())
            buf = b""
            while b"\n" not in buf and len(buf) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            resp = json.loads(buf.decode(errors="replace").strip() or "{}")
        except socket.timeout:
            return self._fail(504, "gateway: warden did not answer in time — denied")
        except Exception as e:
            return self._fail(502, f"gateway: warden error ({e}) — denied")
        finally:
            s.close()
        self._log("warden", 200)
        return self._send_json(resp)

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
    global _budget_cfg, _prices
    _budget_cfg, _prices = load_budgets()
    seed_spend_from_log()
    caps = ", ".join(
        f"{r}:{v.get('requests_per_hour') or '-'}/h,{v.get('requests_per_day') or '-'}/d,"
        f"${v.get('usd_per_day') or 0:g}/d"
        for r, v in sorted(_budget_cfg.items())
        if any((v.get('requests_per_hour'), v.get('requests_per_day'), v.get('usd_per_day'))))
    sys.stdout.write(f"[bridge] spend budgets: {caps or 'none configured (unlimited)'}\n")
    ip = bind_ip()
    if not ip:
        sys.stderr.write(
            f"[bridge] no IP found on '{BRIDGE_IFACE}'. Is multipass installed "
            f"and has the VM network come up yet?\n")
        sys.exit(1)
    os.makedirs(CLAUDE_CWD, exist_ok=True)
    if CLAUDE_GUARD_ERR == CLAUDE_MISSING:
        sys.stderr.write("[bridge] note: no 'claude' CLI on host — /claude will 502 "
                         "(the other routes are unaffected)\n")
        sys.stderr.flush()
    elif CLAUDE_GUARD_ERR:
        state = ("SERVING ANYWAY (CLAUDE_BRIDGE_ALLOW_UNVERIFIED=1)"
                 if CLAUDE_ALLOW_UNVERIFIED else "route DISABLED (fail closed)")
        sys.stderr.write(f"[bridge] !! /claude: {CLAUDE_GUARD_ERR} — {state}\n")
        sys.stderr.flush()
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

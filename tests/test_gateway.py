#!/usr/bin/env python3
"""Regression tests for the bridge gateway's containment behaviour.

These run the REAL gateway against a stub upstream. They exist because every
control in this project fails open: if the Ollama path filter or the header
stripping silently regresses, nothing else would notice.

    python3 tests/test_gateway.py

Stdlib only, no network, no VM required.
"""
import http.client
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UP_PORT, GW_PORT = 21434, 21808
seen = []
fails = []


class Upstream(BaseHTTPRequestHandler):
    """Stand-in for Ollama: records what actually reached it."""

    def _handle(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n:
            self.rfile.read(n)
        seen.append((self.command, self.path, dict(self.headers)))
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_DELETE = do_HEAD = _handle

    def log_message(self, *a):
        pass


def check(label, got, want):
    if got == want:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
        fails.append(label)


def call(method, path, body=None, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{GW_PORT}{path}",
                                 data=body, method=method, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def main():
    threading.Thread(
        target=lambda: ThreadingHTTPServer(("127.0.0.1", UP_PORT), Upstream).serve_forever(),
        daemon=True).start()

    env = dict(os.environ,
               BRIDGE_BIND="127.0.0.1", BRIDGE_PORT=str(GW_PORT),
               OLLAMA_UPSTREAM=f"http://127.0.0.1:{UP_PORT}",
               BRIDGE_PROVIDERS=os.path.join(REPO, "bridge", "providers.json"),
               CLAUDE_BRIDGE_MAX_PER_HOUR="2",
               BRIDGE_AUDIT_LOG="", BRIDGE_USAGE_LOG="")
    proc = subprocess.Popen([sys.executable, os.path.join(REPO, "bridge", "gateway.py")],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(80):
            if call("GET", "/api/version"):
                break
            time.sleep(0.1)
        else:
            print("FAIL: gateway did not come up")
            return 1

        # Model management must never be reachable from the sandbox. /api/pull
        # and /api/create in particular make the HOST fetch from an arbitrary
        # registry, which would sidestep the guest egress allowlist entirely.
        print("Ollama model-management endpoints are refused:")
        for p in ("/api/delete", "/api/pull", "/api/push", "/api/create",
                  "/api/copy", "/api/blobs/sha256:aa",
                  "/api/chat/../api/delete", "/api/delete/", "//api/delete"):
            check(p, call("POST", p, b"{}"), 403)

        print("Inference and read-only endpoints still pass through:")
        for p in ("/api/chat", "/api/generate", "/api/tags", "/api/version",
                  "/api/show", "/v1/models", "/v1/models/hermes-ctx",
                  "/v1/chat/completions", "/v1/embeddings",
                  "/api/chat?stream=true", "/api//chat",
                  # posixpath.normpath keeps a leading '//', which previously
                  # 403'd these perfectly legitimate calls.
                  "//api/chat", "//v1/chat/completions"):
            check(p, call("POST", p, b"{}"), 200)

        print("Guest-supplied credentials never reach the upstream:")
        seen.clear()
        call("POST", "/api/chat", b"{}",
             {"Authorization": "Bearer LEAKED", "x-api-key": "LEAKED2",
              "Content-Type": "application/json"})
        got = {k.lower() for k in (seen[-1][2] if seen else {})}
        check("auth headers stripped", sorted(got & {"authorization", "x-api-key"}), [])

        print("HEAD returns no body (keep-alive stays in sync):")
        conn = http.client.HTTPConnection("127.0.0.1", GW_PORT, timeout=10)
        conn.request("HEAD", "/api/version")
        resp = conn.getresponse()
        check("HEAD body length", len(resp.read()), 0)
        check("HEAD status", resp.status, 200)

        print("/claude is rate-capped (cap set to 2 for this run):")
        payload = json.dumps({"model": "haiku",
                              "messages": [{"role": "user", "content": "x"}]}).encode()
        codes = [call("POST", "/claude/v1/chat/completions", payload,
                      {"Content-Type": "application/json"}) for _ in range(3)]
        check("third call refused", codes[2], 429)
        check("model listing is not rate-capped", call("GET", "/claude/v1/models"), 200)
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=10)
        except Exception:
            proc.kill()

    print(f"\n{len(fails)} failure(s)" + (": " + ", ".join(fails) if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

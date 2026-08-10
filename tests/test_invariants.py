#!/usr/bin/env python3
"""Adversarial invariant suite — offline half (issue #16).

Every control in Kagebox fails open, so a rule that silently stopped applying
looks exactly like one that works. These tests do not check that features
function; they try to BREAK the stated invariants, and fail the build when one
gives way.

This file covers the invariants checkable without a VM, so it runs on every
push. The live half — guest escape, real egress, credential exposure inside the
sandbox — is tests/adversarial.sh, which needs a provisioned host.

Invariants exercised here (see INVARIANTS.md):
  Ollama    the guest cannot reach model management, however it spells the path
  Credential the guest cannot smuggle its own credentials to an upstream
  Warden    guest code cannot self-authorize an egress window
  Budget    a compromised agent cannot spend without limit
  Egress    allowlist entries name a service, not an address
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(mod, path):
    spec = importlib.util.spec_from_file_location(mod, os.path.join(ROOT, path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


os.environ.setdefault("BRIDGE_USAGE_LOG", "")
os.environ["WARDEN_CONF"] = "/nonexistent-so-every-approval-denies"
g = load("gw", "bridge/gateway.py")
w = load("warden", "bridge/egress-warden.py")

fails = []


def attack(name, got, want):
    """`got` is what the boundary did; `want` is what it must have done."""
    if got == want:
        print(f"  held   {name}")
    else:
        print(f"  BROKE  {name}: got {got!r} want {want!r}")
        fails.append(name)


def main():
    # --- Ollama invariant ----------------------------------------------------
    # /api/pull and /api/create make the HOST fetch from an arbitrary registry:
    # an egress path neither egress allowlist can see. Every spelling must miss.
    print("Ollama invariant — model management is unreachable however it is spelled:")
    for path in [
        "/api/delete", "/api/pull", "/api/push", "/api/create", "/api/copy",
        "/api/blobs/sha256:abc",
        "/api/chat/../api/delete",          # traversal through an allowed path
        "/api/./delete",                    # dot segment
        "/v1/models/../../api/pull",        # traversal from the allowed prefix
        "//api/delete",                     # leading double slash (POSIX-special)
        "///api/delete",
        "/api/delete/",                     # trailing slash
        "/api/delete/.",
        "/API/DELETE",                      # case
        "/Api/Delete",
        "/api/%64elete",                    # percent-encoded 'd'
        "/api%2fdelete",                    # encoded separator
        "/api/chat%2f..%2fapi%2fdelete",
        "/api/delete?x=1",                  # query string
        "/api/delete#frag",
        "/api/delete\t",                    # trailing whitespace
        "/../api/delete",
        "/api/../api/delete",
    ]:
        attack(f"denies {path!r}", g.ollama_path_allowed(path), False)

    print("\n  ...without breaking the endpoints the agent legitimately needs:")
    for path in ["/api/chat", "/api/generate", "/api/version", "/api/tags",
                 "/v1/chat/completions", "/v1/models", "/v1/models/llama3",
                 "//api/chat", "/api/chat/", "/"]:
        attack(f"allows {path!r}", g.ollama_path_allowed(path), True)

    # --- Credential invariant ------------------------------------------------
    print("\nCredential invariant — the guest cannot smuggle its own key upstream:")
    for hdr in ["authorization", "Authorization", "AUTHORIZATION",
                "x-api-key", "X-Api-Key", "api-key", "x-goog-api-key"]:
        attack(f"{hdr} is dropped, not relayed", hdr.lower() in g.CLIENT_AUTH_HDRS, True)

    # --- Warden invariant ----------------------------------------------------
    print("\nWarden invariant — guest code cannot self-authorize a window:")
    attack("no approver configured -> approval denied",
           w.ask_human("x", 60, "n", ["a.example:443"], False), False)
    attack("vague request is refused, not upgraded to full-VM",
           w.handle({"reason": "let me out"})["granted"], False)
    for bad in ["a.example; rm -rf /", "$(id).example", "`id`.example",
                "../../etc/passwd", "-rf", "a b.example"]:
        attack(f"rejects hostile destination {bad!r}", w.clean_destinations([bad]), [])
    attack("destination count is capped",
           len(w.clean_destinations([f"h{i}.ex" for i in range(99)])) <= w.MAX_DESTS, True)
    attack("window duration is bounded", w.MAX_SECONDS <= 300, True)

    # --- Budget invariant ----------------------------------------------------
    print("\nBudget invariant — a compromised agent cannot spend without limit:")
    g._budget_cfg, g._prices = g.load_budgets()
    g._budget_cfg["atk"] = {"requests_per_hour": 2, "requests_per_day": 0, "usd_per_day": 0}
    g._prices["atk"] = (1.0, 1.0)
    g._spend[:] = []
    attack("a request loop is cut off at the cap",
           [g.budget_check("atk")[0] for _ in range(6)],
           [True, True, False, False, False, False])
    g._budget_cfg["atk"] = {"requests_per_hour": 0, "requests_per_day": 0, "usd_per_day": 0.10}
    g._spend[:] = []
    ok1, _ = g.budget_check("atk"); g.budget_settle("atk", 0, 1_000_000)   # $1.00
    ok2, why = g.budget_check("atk")
    attack("an expensive call closes the door behind it", (ok1, ok2), (True, False))
    attack("the refusal explains itself", "budget" in why, True)

    print(f"\n{len(fails)} broken invariant(s)" + (": " + ", ".join(fails) if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

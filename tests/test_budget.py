#!/usr/bin/env python3
"""Spend-budget invariant (issue #15).

A compromised or looping agent cannot spend host-held credentials without
limit. The VM bounds CPU/memory/disk by construction — a runaway agent wrecks
its own sandbox, which is containment working — but money is the one resource
that escapes the box: the guest cannot HOLD the keys, yet it can still SPEND
them.

Exercises the real budget layer in bridge/gateway.py. No network, no VM.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
os.environ.setdefault("BRIDGE_USAGE_LOG", "")

spec = importlib.util.spec_from_file_location("gw", os.path.join(ROOT, "bridge", "gateway.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

fails = []


def check(name, got, want):
    if got == want:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}: got {got!r} want {want!r}")
        fails.append(name)


def reset(cfg):
    g._spend[:] = []
    g._budget_cfg = dict(g._budget_cfg)
    g._budget_cfg["testroute"] = cfg
    g._prices["testroute"] = (1.0, 10.0)      # USD per Mtok in/out


def main():
    g._budget_cfg, g._prices = g.load_budgets()

    print("providers.json carries budgets and prices:")
    check("every configured provider has a budget",
          all("requests_per_hour" in (g._budget_cfg.get(p) or {})
              for p in ("gemini", "anthropic", "openrouter")), True)
    check("a price is known for gemini", g._prices.get("gemini") is not None, True)
    check("local ollama is free", g._prices.get("ollama"), (0.0, 0.0))

    print("\nrequest caps stop the loop:")
    reset({"requests_per_hour": 3, "requests_per_day": 0, "usd_per_day": 0})
    got = [g.budget_check("testroute")[0] for _ in range(5)]
    check("hourly cap admits exactly N then refuses", got, [True, True, True, False, False])
    reset({"requests_per_hour": 0, "requests_per_day": 2, "usd_per_day": 0})
    got = [g.budget_check("testroute")[0] for _ in range(4)]
    check("daily cap admits exactly N then refuses", got, [True, True, False, False])

    print("\ncost caps stop the spend:")
    reset({"requests_per_hour": 0, "requests_per_day": 0, "usd_per_day": 0.50})
    seq = []
    for _ in range(4):
        ok, _why = g.budget_check("testroute")
        seq.append(ok)
        if ok:
            g.budget_settle("testroute", 0, 30_000)   # 30k out tokens = $0.30
    check("stops once accumulated cost crosses the cap", seq, [True, True, False, False])
    check("the refusal names the cost", "cost budget" in g.budget_check("testroute")[1], True)

    print("\nunlimited is opt-in, and free routes stay free:")
    reset({"requests_per_hour": 0, "requests_per_day": 0, "usd_per_day": 0})
    check("all-zero config means unlimited",
          all(g.budget_check("testroute")[0] for _ in range(50)), True)

    print("\na gateway restart is not a fresh budget:")
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        now = int(time.time())
        for _ in range(5):
            f.write(json.dumps({"ts": now, "route": "gemini", "model": "x",
                                "prompt_tokens": 1000, "completion_tokens": 1000}) + "\n")
        # A day-old line must NOT count against today.
        f.write(json.dumps({"ts": now - 90000, "route": "gemini", "model": "x",
                            "prompt_tokens": 10 ** 9, "completion_tokens": 10 ** 9}) + "\n")
        path = f.name
    try:
        g.USAGE_LOG = path
        g._spend[:] = []
        g.seed_spend_from_log()
        n, _i, _o, _usd = g._totals("gemini", 3600)
        check("recent usage is replayed at startup", n, 5)
        n24, _, _, _ = g._totals("gemini", 86400)
        check("usage older than 24h is dropped", n24, 5)
    finally:
        os.unlink(path)

    print(f"\n{len(fails)} failure(s)" + (": " + ", ".join(fails) if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

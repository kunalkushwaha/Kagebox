#!/usr/bin/env python3
"""Warden scoping invariants (issue #13).

Guest code cannot self-authorize an egress window, and a vague ask must never
quietly become a full-VM one. These strings also cross from the sandbox into a
root-run script, so the charset is allowlisted rather than escaped.

Exercises the real bridge/egress-warden.py with no config present, so every
approval path denies and nothing here can touch nftables.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
os.environ["WARDEN_CONF"] = "/nonexistent-so-every-approval-denies"

spec = importlib.util.spec_from_file_location("warden", os.path.join(ROOT, "bridge", "egress-warden.py"))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

fails = []


def check(name, got, want):
    if got == want:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}: got {got!r} want {want!r}")
        fails.append(name)


def main():
    print("destinations are validated, not escaped:")
    check("normal host:port survives", w.clean_destinations(["github.com:443"]), ["github.com:443"])
    check("bare host survives", w.clean_destinations(["github.com"]), ["github.com"])
    check("multi-port survives", w.clean_destinations(["a.b-c.io:443,8443"]), ["a.b-c.io:443,8443"])
    for bad, label in [
        ("github.com; rm -rf /", "shell metacharacters"),
        ("$(whoami).evil.com", "command substitution"),
        ("`id`.evil.com", "backticks"),
        ("../../etc/passwd", "path traversal"),
        ("-rf", "argument/flag injection"),
        ("host name", "whitespace"),
        ("x" * 300, "overlong"),
        ("", "empty"),
    ]:
        check(f"rejects {label}", w.clean_destinations([bad]), [])
    check("caps the number of destinations",
          len(w.clean_destinations([f"h{i}.example" for i in range(50)])), w.MAX_DESTS)
    check("non-list input is not trusted", w.clean_destinations({"a": 1}), [])

    print("\na vague ask never becomes a full-VM window:")
    r = w.handle({"reason": "i need the web"})
    check("no destinations -> denied", r["granted"], False)
    check("no destinations -> told how to ask", "destinations" in r["detail"], True)
    r = w.handle({"reason": "x", "destinations": ["bad;host"]})
    check("only-malformed destinations -> denied", r["granted"], False)

    print("\nevery approval path denies when no approver is configured:")
    check("no token/approvers -> ask_human denies",
          w.ask_human("reason", 60, "nonce", ["github.com:443"], False), False)
    r = w.handle({"reason": "x", "destinations": ["github.com:443"]})
    check("scoped request without approver -> denied", r["granted"], False)
    r = w.handle({"reason": "x", "scope": "all"})
    check("explicit full-VM request without approver -> denied", r["granted"], False)

    print("\ncaps:")
    check("duration ceiling is bounded", w.MAX_SECONDS <= 300, True)
    check("windows per hour is bounded", w.MAX_PER_HOUR <= 8, True)

    print(f"\n{len(fails)} failure(s)" + (": " + ", ".join(fails) if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Agentic capability test for a local Ollama model — does it drive Hermes well?

Tests the skills the orchestrator role actually needs: tool-calling, tool
selection, argument extraction, the multi-turn tool loop, restraint (no spurious
tool calls), delegation judgment, and structured JSON.

Uses Ollama's native /api/chat (supports tools). By default sends NO num_ctx/
num_gpu overrides, so it reuses the ALREADY-LOADED model instance (no reload =
no GPU eviction = safe for the pinned GPU model).

Usage: model_eval.py <model> [more models...]
"""
import sys, json, time, urllib.request

OLLAMA = "http://127.0.0.1:11434/api/chat"

def chat(model, messages, tools=None, timeout=120):
    body = {"model": model, "messages": messages, "stream": False,
            "options": {"temperature": 0}}
    if tools:
        body["tools"] = tools
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=timeout))
    return r.get("message", {})

def tool_calls(msg):
    out = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        args = fn.get("arguments")
        if isinstance(args, str):
            try: args = json.loads(args)
            except Exception: args = {"_raw": args}
        out.append((fn.get("name", ""), args or {}))
    return out

# --- tool schemas -----------------------------------------------------------
def fn(name, desc, props, required=None):
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props,
                           "required": required or list(props)}}}

WEATHER = fn("get_weather", "Get current weather for a city", {"city": {"type": "string"}})
SEARCH  = fn("web_search", "Search the web", {"query": {"type": "string"}})
EMAIL   = fn("send_email", "Send an email", {"to": {"type": "string"}, "body": {"type": "string"}})
BOOK    = fn("book_flight", "Book a flight", {
    "origin": {"type": "string"}, "dest": {"type": "string"},
    "depart_date": {"type": "string"}, "return_date": {"type": "string"},
    "passengers": {"type": "integer"}})
CONSULT = fn("consult_claude", "Ask a stronger model to do deep reasoning/analysis/synthesis", {"question": {"type": "string"}})

def s(x): return str(x).lower()

# --- tests: each returns (passed, detail) -----------------------------------
def t_single(m):
    msg = chat(m, [{"role": "user", "content": "What's the weather in Tokyo right now?"}], [WEATHER])
    tc = tool_calls(msg)
    ok = len(tc) == 1 and tc[0][0] == "get_weather" and "tokyo" in s(tc[0][1].get("city"))
    return ok, (tc or msg.get("content", ""))

def t_select(m):
    msg = chat(m, [{"role": "user", "content": "Find current web results about Gold Coast theme parks for kids."}],
               [WEATHER, SEARCH, EMAIL])
    tc = tool_calls(msg)
    ok = len(tc) >= 1 and tc[0][0] == "web_search" and any(w in s(tc[0][1]) for w in ("gold coast", "theme"))
    return ok, (tc or msg.get("content", ""))

def t_args(m):
    msg = chat(m, [{"role": "user", "content": "Book a round-trip flight from Tokyo NRT to Gold Coast OOL, "
                    "departing 2026-09-17, returning 2026-09-27, for 4 passengers."}], [BOOK])
    tc = tool_calls(msg)
    if not tc or tc[0][0] != "book_flight":
        return False, (tc or msg.get("content", ""))
    a = tc[0][1]
    ok = ("nrt" in s(a.get("origin")) or "tokyo" in s(a.get("origin"))) and \
         ("ool" in s(a.get("dest")) or "gold" in s(a.get("dest"))) and \
         "09-17" in s(a.get("depart_date")) and "09-27" in s(a.get("return_date")) and \
         str(a.get("passengers")) == "4"
    return ok, a

def t_restraint(m):
    msg = chat(m, [{"role": "user", "content": "What is 17 multiplied by 4? Just answer."}], [WEATHER, SEARCH])
    tc = tool_calls(msg)
    ok = len(tc) == 0 and "68" in s(msg.get("content"))
    return ok, (tc or msg.get("content", ""))

def t_loop(m):
    first = chat(m, [{"role": "user", "content": "What's the weather in Osaka?"}], [WEATHER])
    tc = tool_calls(first)
    if not tc or tc[0][0] != "get_weather":
        return False, ("no initial tool call", tc)
    msgs = [{"role": "user", "content": "What's the weather in Osaka?"},
            {"role": "assistant", "content": first.get("content", ""), "tool_calls": first.get("tool_calls")},
            {"role": "tool", "tool_name": "get_weather", "content": "Osaka: 24C, sunny, light wind."}]
    final = chat(m, msgs, [WEATHER])
    c = s(final.get("content"))
    ok = ("24" in c or "sunny" in c) and not tool_calls(final)
    return ok, final.get("content", "")

def t_delegate(m):
    q = ("I gathered 3 flights: A) 1 stop, 14h, $920, arrives 11pm. B) direct, 9h, $1450, arrives 2pm. "
         "C) 2 stops, 21h, $610, arrives 6am. For a family with two young kids, decide the best option and "
         "explain the tradeoffs.")
    msg = chat(m, [{"role": "user", "content": q}], [CONSULT, WEATHER])
    tc = tool_calls(msg)
    ok = any(name == "consult_claude" for name, _ in tc)
    return ok, (tc or (msg.get("content", "")[:160]))

def t_json(m):
    msg = chat(m, [{"role": "user", "content": 'Return ONLY a JSON object, no prose, with keys "city" and '
                    '"country" for Tokyo.'}])
    txt = (msg.get("content") or "").strip().strip("`")
    if txt.lower().startswith("json"): txt = txt[4:].strip()
    try:
        j = json.loads(txt[txt.find("{"): txt.rfind("}") + 1])
        ok = "tokyo" in s(j.get("city")) and "japan" in s(j.get("country"))
    except Exception:
        ok = False
    return ok, msg.get("content", "")[:120]

TESTS = [("tool-call", t_single), ("tool-select", t_select), ("arg-extract", t_args),
         ("restraint", t_restraint), ("multi-turn loop", t_loop),
         ("delegation", t_delegate), ("json-output", t_json)]

def run(model):
    print(f"\n=== {model} ===")
    passed = 0
    t0 = time.time()
    for name, test in TESTS:
        try:
            ok, detail = test(model)
        except Exception as e:
            ok, detail = False, f"ERROR: {e}"
        passed += ok
        mark = "PASS" if ok else "FAIL"
        d = json.dumps(detail, default=str)
        print(f"  [{mark}] {name:16} {d[:150]}")
    print(f"  ---> {passed}/{len(TESTS)} passed in {time.time()-t0:.0f}s")
    return passed

if __name__ == "__main__":
    for mdl in (sys.argv[1:] or ["hermes-ctx"]):
        run(mdl)

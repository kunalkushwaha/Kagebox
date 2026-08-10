#!/usr/bin/env python3
"""Kagebox egress warden — time-boxed, human-approved internet windows.

The sandbox can *ask* for the internet. Only the human can *grant* it. This
daemon is where that asymmetry lives.

Why this exists
---------------
`./kagebox research` opens egress from the host CLI, which means it needs a
terminal and your sudo. That is fine at a keyboard and useless from a phone:
the messaging bot runs *inside* the VM, and the VM cannot open its own door —
by design (see bridge/host-egress.sh). So the bot could never search.

The warden closes that gap without giving the guest the latch:

    guest ──ask──> bridge gateway ──unix socket──> warden (root, host)
                                                      │
                                              Telegram (host-held token)
                                                      │
                                                    YOU tap approve
                                                      │
                                          egress OFF (open) for N seconds
                                                      │
                                            egress ON again, always

Three properties this is built to keep
--------------------------------------
1. **The guest can ask, never grant.** The request arrives over a unix socket
   the VM cannot reach; the decision is made here, on the host, as root.
2. **Approval cannot be forged by a compromised VM.** The approval bot's token
   lives ONLY on the host (/etc/kagebox/warden.env, root-owned 0600). It is a
   DIFFERENT bot from the one in the VM. If the sandbox is fully compromised it
   still cannot see, consume, or answer the approval conversation — it holds
   the wrong credential entirely.
3. **The window always closes.** The deadline is enforced here on a monotonic
   clock, in a `finally`, backed by signal handlers, an on-disk marker checked
   at startup, and systemd's ExecStopPost. A warden that crashes mid-window
   re-seals on restart; a machine that reboots comes up sealed.

What this is NOT
----------------
While a window is open the WHOLE VM has open internet — the agent, the gateway,
every process in it. This is a bounded window, not a narrow channel. It shrinks
the exposure from "always open" to "60 seconds, with your thumbprint on it"; it
does not make the open period selective. Per-destination filtering (SNI/proxy)
is the version that would, and it is not this.

The `reason` string is written by the guest. It is shown to you so you can
judge the request — but it is UNTRUSTED text from a process that may be
prompt-injected, and it is rendered as plain text, never as markup. A
convincing reason is not evidence of a benign request.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EGRESS_SH = os.path.join(HERE, "host-egress.sh")

CONF_FILE = os.environ.get("WARDEN_CONF", "/etc/kagebox/warden.env")
RUN_DIR = os.environ.get("WARDEN_RUN_DIR", "/run/kagebox")
SOCK_PATH = os.path.join(RUN_DIR, "warden.sock")
# Presence of this file means "we opened the door and have not confirmed it shut".
# Checked at startup and by ExecStopPost so a crash cannot leave the VM open.
MARKER = os.path.join(RUN_DIR, "window-open")

# --- caps (deliberately small; a window is a hole in the wall) ---------------
DEFAULT_SECONDS = 60
MAX_SECONDS = 300           # hard ceiling; the guest cannot ask past this
MIN_SECONDS = 10
MAX_PER_HOUR = 8            # approval fatigue is an attack; keep prompts rare
APPROVAL_TIMEOUT = 120      # how long we wait for a human tap before denying
REASON_MAX = 300            # truncate guest text before it reaches your screen

TG_API = "https://api.telegram.org/bot{token}/{method}"

_lock = threading.Lock()    # one window at a time, period
_grants = []                # monotonic timestamps of granted windows
_window_until = 0.0         # monotonic deadline of the currently-open window


def log(msg):
    sys.stdout.write(f"[warden] {msg}\n")
    sys.stdout.flush()


def load_conf():
    """Read the root-only config. Fails closed: no token -> no approvals."""
    conf = {}
    try:
        with open(CONF_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        return {}
    except Exception as e:
        log(f"cannot read {CONF_FILE}: {e}")
        return {}
    return conf


CONF = load_conf()
TOKEN = CONF.get("WARDEN_BOT_TOKEN", "")
ALLOWED = {u.strip() for u in CONF.get("WARDEN_ALLOWED_USERS", "").split(",") if u.strip()}


# --- Telegram (host-held credential; the VM never sees this token) -----------

def tg(method, params=None, timeout=30):
    if not TOKEN:
        return None
    url = TG_API.format(token=TOKEN, method=method)
    data = urllib.parse.urlencode(params or {}).encode()
    try:
        with urllib.request.urlopen(url, data=data, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        log(f"telegram {method} HTTP {e.code}")
    except Exception as e:
        log(f"telegram {method} failed: {e}")
    return None


def drain_updates():
    """Skip anything queued before we started, so old taps can't be replayed."""
    r = tg("getUpdates", {"timeout": 0, "offset": -1})
    if r and r.get("ok") and r.get("result"):
        return r["result"][-1]["update_id"] + 1
    return 0


_offset = 0


def ask_human(reason, seconds, nonce):
    """Post the request and block until someone with authority answers.

    Returns True only on an explicit approve, from an allowed user id, matching
    this request's single-use nonce. Everything else — deny, timeout, unknown
    sender, malformed callback — is a denial. There is no default-yes path.
    """
    global _offset
    if not TOKEN or not ALLOWED:
        log("no warden bot token / allowed users configured — denying")
        return False

    # Guest-authored text, shown to a human. Strip control chars, truncate, and
    # send WITHOUT parse_mode so markup in it cannot dress the message up.
    clean = re.sub(r"[\x00-\x1f\x7f]", " ", reason)[:REASON_MAX].strip() or "(no reason given)"
    text = (
        "🔓 Sandbox is asking for the internet\n\n"
        f"Duration: {seconds}s\n"
        f"Reason (written by the AGENT — untrusted):\n{clean}\n\n"
        "While open, the WHOLE VM can reach the web. Approve only if you "
        "expected this."
    )
    kb = {"inline_keyboard": [[
        {"text": f"✅ Open {seconds}s", "callback_data": f"ok:{nonce}"},
        {"text": "❌ Deny", "callback_data": f"no:{nonce}"},
    ]]}

    sent = None
    for uid in ALLOWED:
        r = tg("sendMessage", {"chat_id": uid, "text": text,
                               "reply_markup": json.dumps(kb)})
        if r and r.get("ok"):
            sent = (uid, r["result"]["message_id"])
    if not sent:
        log("could not deliver the approval prompt — denying")
        return False

    deadline = time.monotonic() + APPROVAL_TIMEOUT
    while time.monotonic() < deadline:
        left = max(1, int(deadline - time.monotonic()))
        r = tg("getUpdates", {"timeout": min(20, left), "offset": _offset},
               timeout=min(25, left) + 10)
        if not r or not r.get("ok"):
            time.sleep(1)
            continue
        for upd in r.get("result", []):
            _offset = max(_offset, upd["update_id"] + 1)
            cq = upd.get("callback_query")
            if not cq:
                continue
            data = cq.get("data", "")
            frm = str((cq.get("from") or {}).get("id", ""))
            if frm not in ALLOWED:
                log(f"callback from non-allowed user {frm} — ignored")
                tg("answerCallbackQuery", {"callback_query_id": cq["id"],
                                           "text": "Not authorised."})
                continue
            if data == f"ok:{nonce}":
                tg("answerCallbackQuery", {"callback_query_id": cq["id"],
                                           "text": "Opening…"})
                _edit(sent, f"✅ Approved by {frm} — open for {seconds}s.")
                return True
            if data == f"no:{nonce}":
                tg("answerCallbackQuery", {"callback_query_id": cq["id"],
                                           "text": "Denied."})
                _edit(sent, "❌ Denied.")
                return False
            # A stale nonce is a tap on an expired prompt — tell them, don't act.
            if data.startswith(("ok:", "no:")):
                tg("answerCallbackQuery", {"callback_query_id": cq["id"],
                                           "text": "That request already expired."})
    _edit(sent, "⌛ Expired with no answer — denied.")
    return False


def _edit(sent, text):
    if not sent:
        return
    uid, mid = sent
    tg("editMessageText", {"chat_id": uid, "message_id": mid, "text": text})


# --- the door ----------------------------------------------------------------

def egress(action):
    """Drive the authoritative host-side control. Returns True on success."""
    try:
        p = subprocess.run(["bash", EGRESS_SH, action],
                           capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            log(f"host-egress.sh {action} failed rc={p.returncode}: "
                f"{(p.stderr or '').strip()[:200]}")
            return False
        return True
    except Exception as e:
        log(f"host-egress.sh {action} error: {e}")
        return False


def seal(why=""):
    """Re-close the door and clear the marker. Safe to call any number of times."""
    ok = egress("on")
    if ok:
        try:
            os.unlink(MARKER)
        except FileNotFoundError:
            pass
        log(f"re-sealed{(' (' + why + ')') if why else ''}")
    else:
        # Loud, and the marker STAYS so startup/ExecStopPost try again.
        log("!! FAILED TO RE-SEAL — the VM may still have open internet. "
            "Run: sudo bridge/host-egress.sh on")
    return ok


def open_window(seconds, reason):
    """Open egress for `seconds`, then close it no matter how we leave."""
    global _window_until
    with open(MARKER, "w") as fh:
        fh.write(json.dumps({"reason": reason[:REASON_MAX], "seconds": seconds,
                             "opened_at": time.time()}))
    if not egress("off"):
        try:
            os.unlink(MARKER)
        except FileNotFoundError:
            pass
        return False, "could not open egress (nft failed) — nothing changed"
    _window_until = time.monotonic() + seconds
    log(f"window OPEN for {seconds}s — reason: {reason[:120]!r}")
    try:
        while True:
            left = _window_until - time.monotonic()
            if left <= 0:
                break
            time.sleep(min(left, 1.0))
    finally:
        _window_until = 0.0
        seal("window expired")
    return True, "window closed"


# --- request handling --------------------------------------------------------

def rate_ok():
    now = time.monotonic()
    _grants[:] = [t for t in _grants if now - t < 3600]
    return len(_grants) < MAX_PER_HOUR


def handle(req):
    """One request, start to finish. Every failure path denies."""
    reason = str(req.get("reason", ""))[:REASON_MAX]
    try:
        seconds = int(req.get("seconds", DEFAULT_SECONDS))
    except Exception:
        seconds = DEFAULT_SECONDS
    seconds = max(MIN_SECONDS, min(MAX_SECONDS, seconds))

    if not _lock.acquire(blocking=False):
        return {"granted": False, "detail": "a window is already open or pending"}
    try:
        if not rate_ok():
            log("rate limit hit — denying without prompting")
            return {"granted": False,
                    "detail": f"rate limit: max {MAX_PER_HOUR} windows/hour"}
        log(f"request: {seconds}s — {reason[:120]!r}")
        if not ask_human(reason, seconds, nonce=f"{int(time.time())}-{os.urandom(4).hex()}"):
            return {"granted": False, "detail": "denied (or no answer in time)"}
        _grants.append(time.monotonic())
        ok, detail = open_window(seconds, reason)
        return {"granted": ok, "detail": detail, "seconds": seconds}
    finally:
        _lock.release()


def serve():
    os.makedirs(RUN_DIR, exist_ok=True)
    # Startup self-heal: a marker here means a previous warden died mid-window.
    if os.path.exists(MARKER):
        log("found a stale open-window marker — re-sealing before serving")
        seal("stale marker at startup")

    try:
        os.unlink(SOCK_PATH)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    # The bridge gateway runs as the desktop user and must be able to submit
    # requests; nothing else needs access, and the VM has no path to a unix
    # socket at all. Group is set by the installer.
    os.chmod(SOCK_PATH, 0o660)
    grp = CONF.get("WARDEN_SOCK_GROUP", "")
    if grp:
        try:
            import grp as grpmod
            os.chown(SOCK_PATH, 0, grpmod.getgrnam(grp).gr_gid)
        except Exception as e:
            log(f"could not set socket group to {grp!r}: {e}")
    srv.listen(8)
    log(f"listening on {SOCK_PATH} (max {MAX_SECONDS}s, {MAX_PER_HOUR}/hour, "
        f"{len(ALLOWED)} approver(s))")
    if not TOKEN or not ALLOWED:
        log("WARNING: no bot token / approvers configured — every request will "
            "be DENIED. Run: ./kagebox warden setup")

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=_serve_one, args=(conn,), daemon=True).start()


def _serve_one(conn):
    try:
        conn.settimeout(APPROVAL_TIMEOUT + MAX_SECONDS + 60)
        buf = b""
        while b"\n" not in buf and len(buf) < 8192:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        req = json.loads(buf.decode(errors="replace").strip() or "{}")
        resp = handle(req)
    except Exception as e:
        log(f"request error: {e}")
        resp = {"granted": False, "detail": f"warden error: {e}"}
    try:
        conn.sendall((json.dumps(resp) + "\n").encode())
    except Exception:
        pass
    finally:
        conn.close()


def _bye(signum, _frame):
    log(f"signal {signum} — sealing before exit")
    if os.path.exists(MARKER) or _window_until:
        seal("shutting down")
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seal-if-open":
        # Used by systemd ExecStopPost: re-seal ONLY if a window was open, so
        # stopping the warden never overrides a deliberate `egress off`.
        sys.exit(0 if not os.path.exists(MARKER) else (0 if seal("ExecStopPost") else 1))
    if os.geteuid() != 0:
        sys.stderr.write("egress-warden must run as root (it drives nftables)\n")
        sys.exit(1)
    signal.signal(signal.SIGTERM, _bye)
    signal.signal(signal.SIGINT, _bye)
    _offset = drain_updates()
    serve()

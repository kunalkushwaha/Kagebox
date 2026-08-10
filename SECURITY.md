# Security & Threat Model

This project runs an **autonomous agent** (Hermes) — software that executes
arbitrary shell commands, edits files, installs packages, and drives a browser
— inside a sandbox so that a *misbehaving or prompt-injected* agent cannot harm
your host. This document states plainly **what the sandbox protects against and
what it does not.** Read it before trusting it with anything sensitive.

## What the agent is

An LLM-driven agent that acts on your behalf. It can be steered by:
- the model making mistakes, and
- **prompt injection** — malicious instructions hidden in a web page, file, or
  message the agent reads, causing it to act against your interest.

Assume the agent may attempt anything its tools allow. The sandbox's job is to
bound the blast radius.

## Isolation boundaries (what IS protected)

| Boundary | Mechanism | Result |
|---|---|---|
| **Host filesystem** | Runs in a KVM microVM (own kernel) with only `workspace/` mounted | The agent cannot read or write your host files, except the one shared folder. |
| **Host kernel / processes** | Hardware-virtualized VM, not a shared-kernel container | An escape needs a hypervisor breakout, not a container escape. |
| **Credentials / API keys** | Kept on the **host**, injected by the bridge gateway; credential headers sent *by the guest* are dropped, not relayed | LLM/API keys (Gemini, Claude, …) never enter the sandbox; a compromised VM can't read them, and can't smuggle its own key to an upstream either. |
| **Host model store** | The bridge's default (Ollama) route is an **allowlist**: inference and read-only endpoints only | The sandbox cannot `pull`, `create`, `delete`, `copy` or `push` host models — closing both a tampering path and an egress path (`pull`/`create` make the *host* fetch from an arbitrary registry). |
| **Host `claude` CLI** (`/claude` route) | Runs `claude -p` with tools and MCP suppressed, in an empty dir; the route **refuses to serve** unless those flags are verified present, and is rate-capped | The sandbox gets Claude's text, not the ability to act on your host through your own credentials — and a CLI change that dropped the flags takes the route offline instead of silently enabling tools. |
| **Your LAN** | Bridge binds the VM-only network IP; Ollama stays on loopback | Neither the bridge nor Ollama is exposed to other machines. |
| **Network egress** *(optional)* | **Host-side** nftables allowlist keyed on the VM bridge interface (`./kagebox egress on`) | Enforced on the *host*, so a root agent in the VM cannot switch it off. With it on, the agent reaches only the bridge + allowlisted IPs; **bulk exfiltration and direct C2 are blocked.** Low-bandwidth residual channels remain (DNS, CDN-fronted entries) — see below. **Enabled by `./kagebox setup`; `./kagebox egress off` to open it.** |
| **Auditability** | Bridge logs every API call; agent activity is recorded | You can review what the agent did. |

## What is NOT protected (know these)

- **Network egress is CONTAINED by default** (since `./kagebox setup` enables
  the allowlist). The allowlist starts empty — bridge-only — which is the
  tightest posture; add domains you trust to `vm/egress-allowlist.txt`. It is
  **enforced on the host** (nftables on the bridge interface), so the agent —
  even with root in the VM — cannot remove it, and IPv6 egress is dropped so it
  can't slip around the (IPv4) allowlist. Run `./kagebox egress off` to open the
  VM's internet, and `./kagebox verify` to confirm the posture from inside the
  VM. **Across a host reboot**, containment is restored by a root systemd unit
  (`kagebox-egress.service`, installed by `egress on`) that is ordered *before*
  `multipassd` — so the allowlist is in force before the VM can pass a packet,
  rather than arriving up to 10 minutes later on the refresh timer. The unit can
  load the table before the bridge interface exists because every rule matches
  on `iifname` (a per-packet name comparison) rather than `iif` (which resolves
  an interface index at load time). At that point DNS is usually not up, so the
  allowlist may start **empty** — bridge-only, i.e. stricter — and the refresh
  timer fills it in. The timer remains as a backstop; it is no longer the
  mechanism that restores containment. `./kagebox doctor` shows the posture.
  **`./kagebox setup` fails closed about this.** It reports the posture it
  actually observed — never the one it intended — and exits **non-zero** with a
  loud `SECURITY CONTAINMENT IS NOT ENABLED` banner if containment could not be
  applied (sudo declined, nftables missing) or if `verify` found a broken
  invariant. It will not print "Sandbox ready" in either case.
  `KAGEBOX_ALLOW_UNCONTAINED=1` proceeds anyway, and still warns. Likewise
  `verify` treats "egress open while containment is configured on" as a
  **[FAIL]**, not a note — a rule that silently did not load is the exact
  failure this command exists to catch.
- **The allowlist is scoped to destination *and port*.** An entry is
  `hostname[:port[,port…]]`, defaulting to 443 and 80 — allowlisting a name does
  not open every port on the addresses it resolves to. This closes the non-web
  surface (SSH, databases, mail, admin panels) that an address-only rule
  silently permitted; it does **not** help with CDN fronting, where the
  neighbours share :443 anyway.
- **The egress allowlist is IP-based, and two residual channels survive it.**
  (1) *DNS:* the guest resolves through the host, so an agent can encode data into
  subdomain lookups (`<data>.attacker.example`) — low bandwidth, but enough for a
  key. (2) *CDN fronting:* an allowlisted hostname resolves to shared CDN IPs that
  also serve unrelated sites, so allowlisting `api.anthropic.com` effectively
  permits anything else on those front-end IPs. The allowlist stops bulk
  exfiltration and direct C2, not these; name-based (SNI/proxy) filtering is the
  roadmap.
- **`./kagebox task` refuses to run uncontained.** The throwaway-clone mode is
  the one most likely to be pointed at untrusted input, so if the host egress
  table cannot be loaded (sudo declined, for instance) the clone is destroyed
  and the task is not run. Set `KAGEBOX_TASK_UNCONTAINED=1` to override — only
  when you trust the prompt and everything it will read.
- **`./kagebox skills` opens egress for the fetch, then re-seals.** Skills install
  from open-ended, CDN-fronted registries (skills.sh, GitHub, ClawHub, PyPI/npm
  for their deps) that an IP allowlist cannot reliably pin, so the command opens
  egress for the duration of the fetch and re-seals afterward (even on Ctrl-C).
  It is a deliberate, user-initiated window — and installing a skill runs that
  skill's code inside the VM, so only install skills you trust. Read-only
  operations (`list`, `config`, `uninstall`) never open the door.
- **`./kagebox research "<q>"` opens the VM's full internet for one run, then
  re-seals.** Web research that reads arbitrary pages *is* broad egress — you
  cannot allowlist "the web" by IP — so this opens the door for the duration of
  the run and re-seals afterward (even on Ctrl-C). While the window is open the
  **whole VM** (the agent and any gateway) can reach the internet, so run it only
  on prompts you trust; for untrusted input prefer `./kagebox task` (throwaway
  clone). A best-effort content filter (a family DNS resolver that blocks
  adult/malware, tunable via `KAGEBOX_FILTER_DNS`) applies during the window —
  but that is **hygiene, not containment**: a DNS denylist fails *open* and
  cannot stop a determined exfil, which is exactly why the door still closes
  again when the run ends.
- **`./kagebox warden` lets the sandbox *request* internet windows you approve
  from your phone.** The guest POSTs to `/egress/request` on the bridge; the
  bridge relays it over a root-only unix socket to the warden, which asks you on
  Telegram and opens egress only on your tap — for a bounded number of seconds
  (default 60, hard max 300, 8/hour), after which it re-seals. **The guest can
  ask; it can never grant:** it has no path to nftables, no path to the unix
  socket, and — critically — the **approval bot must be a different bot from the
  one running in the VM**, with its token in root-only `/etc/kagebox/warden.env`.
  The in-VM bot's token lives inside the sandbox, so a compromised sandbox holds
  it; it must not also be the credential guarding the door. Every failure path
  denies (no warden, no token, no approver, timeout, malformed request). The
  window closes on a monotonic deadline in a `finally`, backed by signal
  handlers, an on-disk marker re-checked at startup, and systemd
  `ExecStopPost` — a warden killed mid-window re-seals on restart.
  **Windows are scoped to named destinations.** A request names hosts
  (`github.com:443`), the **host** resolves them — the guest never supplies an
  address, so it cannot point a trusted name at an internal one — and only
  those `(ip, port)` pairs are granted, into a *separate* nft set so the refresh
  timer cannot wipe a live window and a grant is never mistaken for permanent
  policy. The egress table stays **up** throughout: containment is narrowed for
  the window, not suspended. Grants carry a **kernel-side timeout**, so the
  window closes even if the warden is killed `-9`. Destination strings cross
  into a root-run script, so they are matched against an allowlisted charset
  (never escaped) and passed as separate argv elements. A vague or malformed
  request is **refused**, never silently upgraded — a whole-VM window requires
  an explicit `scope: "all"`, and is labelled as such where you approve it.
  **Residual:** an explicit full-VM window still opens everything for its
  duration. Scoped windows are still IP-based once resolved, so CDN fronting
  applies exactly as it does to the standing allowlist. And the `reason` shown
  to you is written by the guest, so a prompt-injected agent can word it
  persuasively; it is displayed as untrusted plain text, never markup, but
  *approve on whether you expected the request, not on how good the reason
  sounds.* Approval fatigue is the attack the rate cap exists to blunt.
- **The shared `workspace/` folder is a two-way door.** Anything you put there is
  readable by the agent; anything it writes there lands on your host. Don't put
  secrets in `workspace/`.
- **`workspace/` is also a code-execution path onto your host — through you.** The
  agent writes deliverables there and you open them. Agent-authored files can carry
  code that runs on the *host* the moment you act on them: a `Makefile` or script
  you run to "check the output", `.git/hooks/*` if it's a git repo,
  `.vscode/tasks.json` / `.envrc` / devcontainer files an editor auto-runs, or a
  poisoned `package.json` / `requirements.txt` / lockfile you install. The VM
  boundary holds; you are the transport. **Review diffs before running, installing,
  or opening `workspace/` contents in an auto-executing editor.**
- **The guest can't hold your keys, but it can still spend them — so the bridge
  caps that.** The VM bounds CPU, memory and disk by construction (a runaway
  agent wrecks its own sandbox, which is containment working); money is the one
  resource that escapes the box. Every paid route is capped per hour, per day,
  and by estimated daily cost, configured per provider in
  `bridge/providers.json` (`budget` and `price_per_mtok`; `0` = unlimited).
  Exhaustion returns **429**. Counters are seeded from the usage log at startup,
  so restarting the bridge does not hand back a fresh day's budget. **Residual:**
  token counts are only knowable *after* a response, so the call that crosses
  the line still completes — the cap bounds the bleeding, it does not predict
  it. Costs are estimates from a local price table; the provider's bill is
  authoritative.
- **The `/claude` route spends your quota, on the guest's instructions.** The
  prompts come from the sandbox; the host pays for them. Tools and MCP servers
  are suppressed, so this is a cost and a prompt-privacy exposure rather than an
  action channel. It is capped at 60 calls/hour — tune with
  `CLAUDE_BRIDGE_MAX_PER_HOUR` (`0` disables the cap). If the bridge cannot
  confirm your `claude` build still accepts the tool/MCP-suppression flags it
  disables the route rather than guess; `CLAUDE_BRIDGE_ALLOW_UNVERIFIED=1`
  overrides that, and should only be set after reading `run_claude()`.
- **Bot tokens live in the VM.** A messaging bot (Telegram/Discord) token must sit
  where the bot runs — inside the VM. It's a *scoped* bot credential (not your
  account), and the VM is isolated, but a VM compromise exposes that token.
- **Shared host GPU.** When the local model runs on the host iGPU, the VM sends
  inference requests to it; this is a compute channel, not a filesystem/host one.
- **What the sandbox contains is recorded, and optionally pinned.**
  Provisioning downloads the Hermes installer, prints its sha256 and runs it
  from a file rather than piping it into a shell; set `HERMES_INSTALLER_SHA256`
  in `kagebox.env` to pin it, and a mismatch aborts instead of installing
  something other than what you reviewed. Each provision records
  `hermes-state/provenance.txt` — agent version, installer hash, OS, kernel,
  Python, the requested image alias *and the actual image build*, multipass
  version, and the Kagebox commit — shown by `./kagebox status`. Note the
  installer runs **inside the contained VM**, and a hostile agent is what the
  whole design already assumes, so the security gain here is modest; the real
  value is being able to answer "which build was that?" for reproducibility,
  rollback and incident response.
- **Hypervisor / kernel 0-days.** VM isolation is strong but not absolute — a
  QEMU/KVM breakout would defeat it. Keep your host patched.
- **The model provider sees your prompts.** When using a cloud backend (Gemini,
  Claude), your task text is sent to that provider. Use the local backend for
  private data.

## Hardening checklist

- [ ] `./kagebox egress on` for any untrusted / web-facing task.
- [ ] `./kagebox verify` afterwards — assert the boundary from inside the VM
      rather than assuming a control loaded. Every control here fails open, so
      one that silently did not apply looks exactly like one that is working.
- [ ] Keep secrets in `bridge/secrets.env` (host, git-ignored) — never in the VM or `workspace/`.
- [ ] Set a messaging **allowlist** (`TELEGRAM_ALLOWED_USERS`) so only you can drive the bot.
- [ ] Review the audit log (`./kagebox audit`) after unattended runs.
- [ ] Keep host + `multipass` + `ollama` patched.

## Reporting a vulnerability

Please report security issues privately to the maintainer (see the repo's
contact) rather than opening a public issue. Include reproduction steps and the
impact. We aim to acknowledge within a few days.

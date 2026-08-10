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
  VM. **After a host reboot** the runtime table is gone until the 10-minute
  refresh cron re-asserts it (or you run `./kagebox egress on`); `./kagebox
  doctor` shows the current posture.
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

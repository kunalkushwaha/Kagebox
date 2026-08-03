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
| **Credentials / API keys** | Kept on the **host**, injected by the bridge gateway | LLM/API keys (Gemini, Claude, …) never enter the sandbox; a compromised VM can't read them. |
| **Your LAN** | Bridge binds the VM-only network IP; Ollama stays on loopback | Neither the bridge nor Ollama is exposed to other machines. |
| **Network egress** *(optional)* | **Host-side** nftables allowlist keyed on the VM bridge interface (`./kagebox egress on`) | Enforced on the *host*, so a root agent in the VM cannot switch it off. With it on, the agent reaches only the bridge + allowlisted IPs; **bulk exfiltration and direct C2 are blocked.** Low-bandwidth residual channels remain (DNS, CDN-fronted entries) — see below. **Off by default.** |
| **Auditability** | Bridge logs every API call; agent activity is recorded | You can review what the agent did. |

## What is NOT protected (know these)

- **Network egress is OPEN by default.** Until you run `./kagebox egress on`,
  the VM has normal internet access, so a prompt-injected agent could exfiltrate
  the contents of `workspace/` or contact an external server. Enable the egress
  allowlist for untrusted workloads. When on, it is **enforced on the host**
  (nftables on the bridge interface), so the agent — even with root in the VM —
  cannot remove it, and IPv6 egress is dropped so it can't slip around the
  (IPv4) allowlist.
- **The egress allowlist is IP-based, and two residual channels survive it.**
  (1) *DNS:* the guest resolves through the host, so an agent can encode data into
  subdomain lookups (`<data>.attacker.example`) — low bandwidth, but enough for a
  key. (2) *CDN fronting:* an allowlisted hostname resolves to shared CDN IPs that
  also serve unrelated sites, so allowlisting `api.anthropic.com` effectively
  permits anything else on those front-end IPs. The allowlist stops bulk
  exfiltration and direct C2, not these; name-based (SNI/proxy) filtering is the
  roadmap.
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
- [ ] Keep secrets in `bridge/secrets.env` (host, git-ignored) — never in the VM or `workspace/`.
- [ ] Set a messaging **allowlist** (`TELEGRAM_ALLOWED_USERS`) so only you can drive the bot.
- [ ] Review the audit log (`./kagebox audit`) after unattended runs.
- [ ] Keep host + `multipass` + `ollama` patched.

## Reporting a vulnerability

Please report security issues privately to the maintainer (see the repo's
contact) rather than opening a public issue. Include reproduction steps and the
impact. We aim to acknowledge within a few days.

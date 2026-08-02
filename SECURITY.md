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
| **Network egress** *(optional)* | nftables allowlist in the VM (`./kagebox egress on`) | With it enabled, the agent can only reach the bridge + allowlisted domains — no data exfiltration or C2. **Off by default.** |
| **Auditability** | Bridge logs every API call; agent activity is recorded | You can review what the agent did. |

## What is NOT protected (know these)

- **Network egress is OPEN by default.** Until you run `./kagebox egress on`,
  the VM has normal internet access, so a prompt-injected agent could exfiltrate
  the contents of `workspace/` or contact an external server. Enable the egress
  allowlist for untrusted workloads.
- **The shared `workspace/` folder is a two-way door.** Anything you put there is
  readable by the agent; anything it writes there lands on your host. Don't put
  secrets in `workspace/`.
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

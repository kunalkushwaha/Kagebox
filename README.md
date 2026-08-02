# Kagebox

> **Run autonomous AI agents safely** — isolated microVM, host-side credentials, controllable egress, auditable.

[Hermes Agent](https://github.com/NousResearch/hermes-agent) executes arbitrary shell,
edits files, and drives a browser — so **Kagebox** runs it inside a **KVM microVM**
(its own kernel) that can't touch your host, reaching LLMs through a **bridge that keeps
your API keys on the host**. Local models (Ollama) or cloud brains (Gemini, Claude, …)
are one command to switch, and the agent's memory survives a VM crash.

> ⚠️ It runs an autonomous, promptable agent. Read **[SECURITY.md](SECURITY.md)** —
> especially "network egress is open by default" — before trusting it with sensitive work.

## Architecture

```
  YOUR HOST                                        SANDBOX  (KVM microVM, own kernel)
  ┌───────────────────────────────┐               ┌──────────────────────────────┐
  │ Ollama :11434 (local models)  │               │ Hermes Agent + headless      │
  │                               │               │ Chromium                     │
  │ bridge gateway (your user)    │◀──────────────│ base_url -> bridge routes     │
  │  binds VM-only IP :18080      │   bridge      │                              │
  │  /v1        -> Ollama         │  (NAT, or     │ tools · files · browser      │
  │  /claude    -> host claude -p │   egress-     │                              │
  │  /gemini /anthropic /...      │   allowlisted)│ ~/.hermes  memory (backed up │
  │  keys injected here, host-side│               │            to host)           │
  └───────────────────────────────┘               │ only workspace/ shared       │
     keys never enter the VM                       └──────────────────────────────┘
```

The **bridge** is the only channel from sandbox to host. Keys live in
`bridge/secrets.env` (host, git-ignored) and are injected into requests — they never
enter the VM. Providers are a runtime registry (`bridge/providers.json`).

## Requirements

- Linux host with **KVM** (`/dev/kvm`), **[multipass](https://multipass.run)**, and
  **[Ollama](https://ollama.com)** (for local models).
- Run `./kagebox doctor` to check everything at once.

## Quickstart

```bash
git clone https://github.com/kunalkushwaha/Kagebox.git && cd Kagebox
./kagebox doctor          # verify host prerequisites
./kagebox setup           # build the VM, bridge, and install Hermes (~10 min)
./kagebox shell           # enter the sandbox, then run:  hermes
```

Use a cloud brain for heavy research (key stays host-side):

```bash
cp bridge/secrets.env.example bridge/secrets.env
echo 'GEMINI_API_KEY=...' >> bridge/secrets.env      # free key: aistudio.google.com
./kagebox bridge start
./kagebox backend gemini
```

## Commands

| Command | What it does |
|---|---|
| `./kagebox doctor` | preflight-check the host |
| `./kagebox setup` / `destroy` | build / tear down the sandbox |
| `./kagebox up` / `down` / `status` | start / stop / inspect |
| `./kagebox shell` | shell into the VM (then run `hermes`) |
| `./kagebox backend <name>` | switch model: `ollama` · `claude` · `gemini` · … |
| `./kagebox providers` | list backends + cloud providers |
| `./kagebox telegram` | set up a Telegram bot to chat with Hermes |
| `./kagebox egress on` / `off` | network egress allowlist (containment) |
| `./kagebox audit` | review the agent's API-call log |
| `./kagebox backup` / `restore` | snapshot / restore Hermes memory to the host |

## Backends

- **`ollama`** — local models on your GPU/CPU. Free, private, offline. Best for quick
  tool-driven tasks. (Small models are fine as *tool drivers*; see `evals/model_eval.py`.)
- **`gemini` / `anthropic` / `openrouter`** — cloud brains via the bridge (key host-side).
  Best for real multi-step research. Add any OpenAI-compatible API to `bridge/providers.json`.
- **`claude`** — the host's `claude -p` (uses your existing Claude auth, no API key),
  invoked tools-disabled; also available to the agent as a "consult a stronger model" skill.

## Memory & files

- **`workspace/`** — two-way shared folder; the agent saves deliverables here and they
  appear on your host. It's told to default outputs here.
- **`hermes-state/`** — the agent's memory (SQLite + sessions) is snapshotted here every
  10 min and on `down`, and restored on rebuild. Blow away the VM; your memory survives.

## Security

This is a containment tool for untrusted agent behavior. **[SECURITY.md](SECURITY.md)**
documents the full threat model — what's isolated (host FS, kernel, credentials) and
what isn't (egress is open until you enable the allowlist). For untrusted work:
`./kagebox egress on`.

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)**. No build step — it's shell + stdlib Python.

## License

[MIT](LICENSE)

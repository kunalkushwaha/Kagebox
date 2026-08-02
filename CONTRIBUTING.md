# Contributing

Thanks for your interest! This project is a small, hackable set of shell + Python
scripts around multipass, Ollama, and the Hermes agent. No build step.

## Ground rules

- **Never commit secrets.** `bridge/secrets.env` and `hermes-state/` are
  git-ignored — keep it that way. Double-check `git status` before pushing.
- **Keep the isolation model intact.** New host capabilities should be exposed to
  the sandbox only as allowlisted *network/API* routes through the bridge — never
  as host command execution from the VM. See [SECURITY.md](SECURITY.md).
- Match the existing style: small POSIX-ish bash, stdlib-only Python (the bridge
  has no third-party deps), clear comments explaining *why*.

## Dev workflow

```bash
./hermesctl doctor      # check your host prerequisites
./hermesctl setup       # build the sandbox
# ...make changes...
bash -n hermesctl vm/*.sh                 # shell syntax
python3 -m py_compile bridge/gateway.py   # python syntax
shellcheck hermesctl vm/*.sh              # if you have shellcheck
python3 evals/model_eval.py <model>       # agentic capability tests
```

## What's welcome

- New provider entries in `bridge/providers.json` (any OpenAI-compatible API).
- Portability: alternative VM backends (Lima, libvirt, WSL2), non-AMD GPU paths.
- Hardening: egress rules, audit coverage, seccomp/resource limits.
- Docs, examples, and `doctor` checks.

## PRs

Keep them focused; describe the change and how you tested it. For anything that
touches the isolation boundary, explain the security implications.

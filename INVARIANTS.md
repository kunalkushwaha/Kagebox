# Security Invariants

These are the properties Kagebox claims. They are written here so they can be
argued with, and tested continuously rather than believed.

**Why a list like this exists.** Every control in this project fails *open*: a
firewall rule that silently did not load, a flag a CLI quietly stopped
accepting, a header that stopped being stripped — each looks exactly like a
working control right up until it matters. Features announce their own
breakage; boundaries do not. So the boundary gets its own tests, and they are
written as attacks.

## The invariants

| # | Invariant | Tested by |
|---|---|---|
| 1 | **Credential** — the guest never receives long-lived provider credentials, and cannot smuggle its own to an upstream. | `test_invariants.py`, `adversarial.sh` |
| 2 | **Host-control** — the guest cannot modify (or read) the authoritative host egress policy, even as root. | `adversarial.sh` |
| 3 | **Claude** — the `/claude` route is unavailable unless the installed CLI is verified to suppress host-side tools and MCP. | `test_gateway.py` |
| 4 | **Ollama** — the guest cannot reach model management, however the path is spelled, and cannot use Ollama as a host-side network pivot. | `test_invariants.py`, `adversarial.sh` |
| 5 | **Egress** — network access is denied unless explicitly permitted by current host policy; an allowlist entry names a *service*, not an address. | `test_egress_allowlist.sh`, `adversarial.sh` |
| 6 | **Reboot** — a host reboot creates no period of unintended guest internet access. | `adversarial.sh` after a reboot *(see gap below)* |
| 7 | **Workspace** — files produced by the guest are treated as untrusted until reviewed by the host user. | `adversarial.sh` (asserts the door, and says so) |
| 8 | **Warden** — guest code cannot self-authorize an egress window; it can ask, only a human grants. | `test_warden_scope.py`, `test_invariants.py`, `adversarial.sh` |
| 9 | **Budget** — a compromised agent cannot exceed configured spend limits indefinitely. | `test_budget.py`, `test_invariants.py` |
| 10 | **Reporting** — Kagebox never claims a posture it did not observe. | `test_setup_posture.sh` |

Invariant 10 is not from the usual lists, and it earned its place: `setup` used
to print `egress: contained` unconditionally, so a declined sudo prompt ended
with a reassuring green banner (#11). A boundary you *believe* in but do not
have is worse than a known-open one.

## Running them

```bash
# Offline half — no VM, no sudo, no network. Runs in CI on every push.
python3 tests/test_invariants.py     # adversarial: attacks the pure boundary logic
python3 tests/test_gateway.py        # bridge containment
python3 tests/test_warden_scope.py   # warden cannot be talked into granting
python3 tests/test_budget.py         # spend caps
bash    tests/test_egress_allowlist.sh
bash    tests/test_setup_posture.sh

# Live half — needs a provisioned, running VM. Run after boundary changes,
# and after a host reboot.
bash tests/adversarial.sh
./kagebox verify
```

`adversarial.sh` attacks from *inside* the sandbox: it tries to read the host
ruleset, flush its way out, reach non-allowlisted destinations over v4 and v6,
find a credential, see a host process or socket, and open its own door.

## Known gaps

Being explicit about what is *not* covered, since a suite that looks complete is
worse than one that admits its edges.

- **Reboot (invariant 6) is not automated.** `kagebox-egress.service` is ordered
  before `multipassd`, but nothing here reboots a host to prove it. Run
  `adversarial.sh` after your next reboot.
- **The port-scoping probe is weak.** A refusal on an unlisted port does not
  prove the firewall caused it — the remote may simply not listen there. It
  catches an unlisted port that *answers*, not a rule that quietly stopped
  applying.
- **No agent-level injection tests yet.** Prompt injection from a web page, a
  `workspace/` file, a malicious skill or package is the category most likely to
  matter in practice and the least covered here. It needs a harness that drives
  a real agent against hostile content.
- **CDN fronting is unaddressed by design, not by omission.** An IP allowlist
  cannot separate a hostname from its neighbours on a shared front end. Only
  name-based (SNI/proxy) policy would, and that is not built.
- **The suite runs as the operator, not as an attacker with a 0-day.** It tests
  the controls as designed; it does not attempt hypervisor escape.

## Adding one

If you fix a boundary bug, add the attack that would have caught it — to
`test_invariants.py` if it can be shown offline, to `adversarial.sh` if it needs
a live sandbox. A regression test written after the fact is the only part of the
fix that keeps working.

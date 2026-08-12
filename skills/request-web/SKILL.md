# request-web — ask the human for internet access

You run inside a sandbox with **no internet by default**. This is deliberate, not
a fault: the door is held from outside the VM and you cannot open it yourself.
What you *can* do is ask, and a human decides on their phone.

## First: try the request. Some hosts are always open.

A small set of destinations is permanently allowed (search, Wikipedia, arxiv and
similar — see what actually works by trying). The model API you are talking to
right now also always works. **Do not ask for a window before you have hit an
actual network failure** — most lookups need no approval at all.

## What a blocked host looks like

A destination outside the current policy is **refused immediately** — `curl`
returns `Connection refused` in milliseconds, not a hang. That fast failure is
the signal: it means "not allowed", not "the site is down" and not "try again".
Retrying it will fail exactly as fast, forever.

**A refusal is not an answer to give the user.** When a host is refused, work
through these in order, and only report failure if all three fail:

1. **Try an allowed equivalent.** A search endpoint is almost always reachable
   and its result snippets often answer the question outright. If you wanted a
   news aggregator, search for the topic instead — the summaries in the results
   are frequently enough. Do this *first*; it needs no approval and no waiting.
2. **Ask for a window** for the specific host you need, naming it (below).
3. **Only then** tell the user, saying which host was refused *and* what you
   already tried, so they can decide whether to allow it permanently.

Answering "my connection was refused" without having tried a permitted source or
asked for access is not a useful answer. The user cannot tell from it whether
the task was impossible or you simply stopped at the first obstacle.

## When a fetch fails with a network error

Ask for a time-boxed window, naming the hosts you need:

```bash
kagebox-web -t 60 example.com:443 cdn.example.com:443 -- "why you need it, in one line"
```

- It blocks until a human approves or denies, then prints `GRANTED:` or `DENIED:`.
- On `GRANTED`, do your fetches **immediately** — the window is seconds long and
  closes on its own.
- Exit status is 0 on grant, non-zero on denial.

**Name the hosts.** A request without destinations is refused outright. The human
sees exactly what you asked for, which is the whole point — "the agent wants
github.com:443 for 60s" is a decision someone can make; "the agent wants the
internet" is not.

Use `--all` only when you genuinely cannot know the hosts in advance (following
search results across unknown domains). It opens the whole VM and is a much
bigger ask, so expect it to be refused more often, and say why you need it.

## Installing skills

Skill registries are CDN-fronted, so a scoped grant may miss some addresses:

```bash
kagebox-web -t 120 --all -- "installing the <name> skill from the hub"
hermes skills install <name>
```

## Rules

- **A denial is an answer.** Do not re-request the same thing in a loop. Tell the
  user it was denied and what you would have done with it.
- Windows are rate-limited (a handful per hour). Batch the hosts you need into
  **one** request rather than asking repeatedly.
- Never claim you fetched something you did not. If the window was denied or
  expired, say so plainly and give the user what you have.
- The reason you write is shown to a human who is deciding whether to trust it.
  Describe what you will actually do, in plain words. Do not pad it to sound
  more legitimate — you are being read by someone who knows what they asked for.

## When NOT to use it

- You have not tried yet and do not know whether the host is already reachable.
- The task does not need the internet — answer from what you have.
- You were denied a moment ago for the same thing.

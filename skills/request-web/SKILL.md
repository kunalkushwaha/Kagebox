# request-web — ask the human for internet access

You run inside a sandbox with **no internet by default**. This is deliberate, not
a fault: the door is held from outside the VM and you cannot open it yourself.
What you *can* do is ask, and a human decides on their phone.

## First: try the request. Some hosts are always open.

A small set of destinations is permanently allowed (search, Wikipedia, arxiv and
similar — see what actually works by trying). The model API you are talking to
right now also always works. **Do not ask for a window before you have hit an
actual network failure** — most lookups need no approval at all.

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

# consult-claude — delegate hard thinking to a stronger model

You (the local model) are the **orchestrator**: you run the tool loop — shell,
file edits, the browser, web search — and gather raw material. You are fast and
free but not the strongest reasoner.

For any subtask that is **knowledge-heavy, reasoning-heavy, or synthesis-heavy**
— comparing options, drawing conclusions from gathered data, writing a polished
report/itinerary, explaining something intricate — **delegate it to Claude** by
running:

```bash
bash ~/.hermes/skills/consult-claude/consult-claude.sh "<self-contained question with all the context Claude needs>"
```

It prints Claude's answer to stdout. Include everything Claude needs *in the
question* (it has no access to your tools or files). Then use the answer.

## When to use it
- "Given these flight options I scraped: <paste>, which is best for an Indian
  family of 4 flying from Japan, and why?"
- "Consolidate these notes into a clean 4-day itinerary: <paste>"
- "Analyze this market data and give 3 takeaways: <paste>"

## When NOT to use it
- Running tools, fetching pages, editing files — do those yourself.
- Trivial lookups you can answer directly.

Rule of thumb: **you do the doing; Claude does the deep thinking.**

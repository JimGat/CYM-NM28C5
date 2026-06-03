# CYM-NM28C5 development cost discipline

## When the user asks for a development task (without using /dev)

Apply the same scoped workflow automatically:

1. **Classify first.** State the task size (Tiny/Small/Medium/Large) and the plan before touching code.
2. **Use Haiku subagents** for any grep/locate/explore work. Never read large sections of main.c speculatively. State what you expect to find, spawn Haiku to confirm, then read only the exact lines needed.
3. **One task per response chain.** If multiple tasks are requested, implement the first and ask which to do next rather than doing all at once.
4. **Stop at 3 build-fix cycles.** If a fix requires more than 3 iterations, declare it a dedicated-session task and stop.
5. **No unsolicited cleanup.** A bug fix does not justify surrounding refactors, renames, or style changes.

## Model selection guidance

- **Haiku** → file search, grep, log analysis, "where is X in the code"
- **Sonnet (current)** → writing code, reasoning about architecture, commit messages
- Do NOT use Sonnet to do what a Haiku grep agent can do in seconds.

## Session hygiene

- Commit and push after every working change. Never accumulate uncommitted work.
- If a session has been running > 90 minutes, suggest a clean break: commit what works, note what's next in memory, close.
- HERMES.md and memory files should be trimmed when stale entries outnumber active ones.

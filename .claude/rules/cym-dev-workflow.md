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

## Version bump — MANDATORY before every build

Before every build that produces a changed binary:
1. Increment the PATCH digit in the SoC's CMakeLists.txt:
   - ESP32C5 boards: `ESP32C5/CMakeLists.txt` → `set(PROJECT_VER "vX.Y.Z+1")`
   - ESP32 boards: `ESP32/CMakeLists.txt` → `set(PROJECT_VER "vX.Y.Z+1")`
2. Update the board-specific manifest:
   - NM-CYD-C5: `ESP32C5/docs/manifest.json` → `"version"` and `"build"`
   - WS-C5-28: `ESP32C5/docs/manifest.ws-c5-28.json` → `"version"` and `"build"`
   - CYD-2432S028: `ESP32/docs/manifest.cyd-2432s028.json` → `"version"` and `"build"`
3. After build, verify the correct binary in the correct directory:
   - NM-CYD-C5: `strings ESP32C5/binaries-esp32c5/CYM-NM28C5.bin | grep vX.Y.Z+1`
   - WS-C5-28: `strings ESP32C5/binaries-ws-c5-28/CYM-WS-C5-28.bin | grep vX.Y.Z+1`
   - CYD-2432S028: `strings ESP32/binaries-cyd-2432s028/CYM-CYD-2432S028.bin | grep vX.Y.Z+1`

**No two different binaries may share a version number.**
When building multiple boards in one session, each board gets its own version bump.
See `cym-release-workflow.md` for the full multi-board build commands and staging lists.

## Session hygiene

- Commit and push after every working change. Never accumulate uncommitted work.
- Do NOT merge to main unless user explicitly says "merge to main" or "next release".
- If a session has been running > 90 minutes, suggest a clean break: commit what works, note what's next in memory, close.
- HERMES.md and memory files should be trimmed when stale entries outnumber active ones.

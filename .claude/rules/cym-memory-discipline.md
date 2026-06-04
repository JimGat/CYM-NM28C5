# CYM-NM28C5 Claude memory discipline

Use durable memory deliberately. Prefer these layers:

1. `CLAUDE.md` / `.claude/rules/*.md` for stable project rules, workflows, commands, safety constraints, and architecture invariants.
2. `/home/dev/.claude/projects/-home-dev-projects-CYM-NM28C5/memory/` for compact learned facts that are still useful weeks later.
3. Session notes only for temporary debugging state; do not promote temporary crash logs, commit SHAs, or one-off observations to long-term memory.

Keep memory small and searchable:
- Update existing memory files instead of creating many overlapping ones.
- Maintain `memory/MEMORY.md` as an index of what exists and where to look.
- Prefer concise bullets with exact file paths and commands.
- Remove stale implementation status after it becomes misleading.
- If memory exceeds ~25 KB total, consolidate old feature-specific files into the index or current project-status file.

Before editing firmware, read the relevant rules and current memory index. For runtime bugs, capture root cause, fix pattern, and verification method only after the fix is proven.

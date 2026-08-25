# 90-second demo video script

**Purpose:** The single video that ships with the launch. Goal: make a viewer who has never heard of VANTAGE understand in 90 seconds that this tool finds AND fixes bugs, and that it plugs into Claude Code as infrastructure.

**Format:** Screen recording, no talking head. Voiceover optional but not required — the actions on screen carry the narrative. If VO: calm, matter-of-fact, no hype.

**Resolution:** 1920×1080. Record in OBS or QuickTime. Output MP4 and GIF (first 30s) for Twitter.

---

## Shot list

### 0:00–0:05 — Title card
Static frame. Black background. White text:

> **VANTAGE**
> Autonomous code review for AI coding agents.
> ›  `benchmark.vantage.dev`

Hold 3 seconds. Fade out.

### 0:05–0:15 — "The problem"
Cursor / Claude Code window open. Agent is about to commit a change to a real-looking file (`src/api/handler.ts`). The code contains:

```typescript
export function handleRequest(req: any) {
  const config = JSON.parse(req.body);
  return doSomething(config);
}
```

Agent runs `git commit -m "Add request handler"`. Hook intercepts. Show the block output on screen (already structured nicely from our hook code):

```
VANTAGE REJECTED this commit (score: 67.2%).

AURORA found issues that must be addressed:
  [HIGH] handler.ts: JSON.parse() without try/catch
  [MED]  handler.ts: Deep property access without null check

Auto-fix available. If you have the vantage MCP server wired up, you can:
  • generate_fix(finding_id='pulsar_a813b1ac26e9') — JSON.parse() without try/catch
  • generate_fix(finding_id='pulsar_b4ce12f9d8a1') — Deep property access without null check

Fix the HIGH severity issues above, then retry.
```

VO (optional): "VANTAGE reviews the change before it lands."

### 0:15–0:40 — "The fix"
Agent sees the hint, calls `generate_fix` via the MCP tool. Show the tool call in the agent UI. Animated json output slides in:

```json
{
  "success": true,
  "templateId": "error-boundary-jsonparse-trycatch",
  "rationale": "Hoisted config declaration and wrapped JSON.parse in a try/catch that re-throws with context.",
  "patch": "--- a/src/api/handler.ts\n+++ b/src/api/handler.ts\n@@ -1,4 +1,10 @@\n...",
  "verification": {
    "verdict": "APPROVED",
    "resolvedFindings": ["pulsar_a813b1ac26e9"],
    "newFindings": []
  }
}
```

Cut to a split screen: before / after diff of the file. The try/catch wrap is visible. Highlight the `resolvedFindings` and `verdict: APPROVED` in the JSON.

VO: "Every patch passes the same analysis gate before it reaches you. If it doesn't resolve the finding, you never see it."

### 0:40–0:55 — "It lands"
Agent applies the patch, re-commits. Hook passes:

```
{"decision":"approve","reason":"VANTAGE APPROVED (95.8%)"}
```

Cut to a GitHub PR view. Show the commit that just landed:

> **VANTAGE auto-fix: error-boundary-jsonparse-trycatch**
>
> Finding: pulsar_a813b1ac26e9
> File: src/api/handler.ts:2
> Hoisted config declaration and wrapped JSON.parse in a try/catch that re-throws with context.
>
> Post-fix verification:
>   Verdict: APPROVED (95.8%)
>   Resolved: 1
>   New: 0

VO: "Found it, fixed it, verified it, committed it. No human in the loop for the class of bug that doesn't need one."

### 0:55–1:15 — "How to add it"
Cut to terminal. Show two commands:

```bash
npm install -g vantage vantage-mcp
```

(1.5s pause showing install output)

Show `~/.claude/settings.json` being edited in VS Code with:

```json
{
  "mcpServers": {
    "vantage": { "command": "vantage-mcp" }
  }
}
```

Run `vantage-mcp install-hook` in the terminal. See:

```
✓ Installed VANTAGE PreToolUse hook in .claude/settings.json
```

VO: "Two commands. Works with Claude Code, Cursor, Aider — any MCP client."

### 1:15–1:30 — "Open benchmark"
Cut to `benchmark.vantage.dev` in a browser. Show the leaderboard table with VANTAGE at the top, Semgrep and SonarQube below. Scroll once slowly.

VO: "Methodology, ground-truth catalogs, and configurations are all public. Every tool's number is reproducible from a commit SHA. Updated weekly."

### 1:30 — End card
Fade to black.

> **VANTAGE**
> `npm install -g vantage vantage-mcp`
> `benchmark.vantage.dev`
> Built by JourdanLabs · MIT

Hold 2 seconds. Cut.

---

## Recording checklist

- [ ] Fresh Claude Code session with no prior VANTAGE state (clean `.claude/`)
- [ ] Target repo cloned locally with the sample bug already present
- [ ] Terminal cleared, large font (16pt+)
- [ ] Agent UI at full window, no sidebars
- [ ] No personal info visible in paths, git config, or git hooks
- [ ] Rehearse once — the cuts between tool call → JSON output → diff need to feel inevitable, not laggy

## Captions & title copy

For Twitter / LinkedIn: "VANTAGE — find, fix, gate. 90-second demo."
For YouTube: "VANTAGE: finding and fixing bugs in Claude Code, in 90 seconds"
For HN: Lead with the demo link; headline is the blog post headline.

## Notes on voice

If you're going to do VO: flat affect, no upspeak, minimal adjectives. Nobody trusts a fast-talking pitch. The tool is doing the work; your voice is just identifying what's happening on screen. 45 seconds of total VO at most; let the silence speak.

If no VO: make sure the on-screen text (block messages, JSON output, commit messages) is legible at 1080p with good timing. Captions on YouTube are fine.

## Alternate "receipts" version (3-minute cut)

Same opening, same install section. Swap the "it lands" segment for: "Here are five bugs VANTAGE found in [OSS repos]. Each one with a working generate_fix call." Then cut to the leaderboard. Use this version for developer audiences who want empirical proof; use the 90-second version for general software-engineering audiences.

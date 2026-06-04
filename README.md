# AI Assistant Security Hardening Guide

A systematic walkthrough for hardening any agentic AI assistant that can run commands, touch files, and act on your behalf.

This guide is **runtime-agnostic**. The concepts apply to any agentic assistant; the specifics differ by platform. Throughout the guide, OpenClaw and Claude Code are used as **concrete examples** because they're well-documented and behaviorally distinct — but the same patterns apply to LangChain agent loops, the Anthropic Agent SDK, OpenAI Assistants, custom MCP-host integrations, on-device frameworks, or anything else with comparable capabilities. If you're on a different runtime, read the body for the principle and the examples for the shape.

This guide helps you think through security decisions — it doesn't prescribe specific settings.

**Time required:** 1-2 hours for full walkthrough
**Prerequisites:** A working agentic assistant (any runtime), basic familiarity with its capabilities

> **A note on terminology.** Throughout this guide:
> - **Behavioral config** = the file your assistant reads each turn to learn how to behave (markdown system prompt, behavior rules, etc.). Names vary by runtime: `AGENTS.md` (OpenClaw), `CLAUDE.md` (Claude Code), `system_prompt.md`, `instructions.md`, etc. The guide says "behavioral config" generically.
> - **Platform config** = the assistant's runtime settings — usually JSON or YAML. Examples: `~/.openclaw/openclaw.json` (OpenClaw), `~/.claude/settings.json` (Claude Code). Whatever your runtime calls "the file where I configure tool permissions and security policies," that's it.
> - **Platform layer** = the runtime's built-in enforcement — the gates that fire *regardless* of what the model decided. Examples: OpenClaw's exec approvals, Claude Code's permissions + hooks. Your runtime should have equivalent gating; if it doesn't, that's a red flag.

---

## ⚡ Quick Start — The Easy Button

**Just paste this into your AI assistant's chat:**

```
Read the security hardening guide at https://github.com/rbfp/openclaw-security-guide and work through it with me one category at a time. For each category:
1. Explain the risks in plain language
2. Present my options and tradeoffs
3. Wait for my decision before moving on
4. Write the agreed rules into my behavioral config (AGENTS.md or CLAUDE.md)

Don't rush ahead. One category at a time, starting with Category 1.
```

Your assistant will fetch the guide, explain each section, help you make decisions, and write the rules directly into your config. You stay in control at every step.

> **Note:** Your assistant's behavior after hardening will depend on the choices *you* make — this guide doesn't impose a specific configuration. Every setup is different.

---

## Why This Matters

Your agentic AI assistant can:
- Read and write files on your machine
- Execute shell commands
- Send emails and messages
- Make web requests
- Access your calendar, notes, and other apps
- Run automated tasks while you're away

This power is useful — and exploitable. A malicious email, webpage, or file could contain instructions that hijack your assistant's behavior. This guide helps you build defenses.

This is not a problem with any particular runtime — it's inherent to *any* assistant you give real capabilities. The mechanisms differ by platform; the threat model is shared.

---

## Threat Model

Before hardening, understand what you're protecting against:

| Threat | Description | Risk Level |
|--------|-------------|------------|
| **Prompt Injection** | Malicious content in emails/web pages that instructs your assistant to take harmful actions | High |
| **Data Exfiltration** | Sensitive data (credentials, files, client info) leaving your machine through the assistant | High |
| **Destructive Commands** | Accidental or manipulated `rm`, infrastructure teardown, etc. | High |
| **Credential Exposure** | API keys, passwords appearing in logs, messages, or memory files | Medium |
| **Runaway Automation** | Cron jobs or sub-agents doing damage unsupervised | Medium |
| **Scope Creep** | Assistant doing more than asked, touching things it shouldn't | Low-Medium |

**Your first decision:** Which of these matter most to you? Rank them. Your answers will shape which categories you prioritize.

---

## Two-Layer Security Model

This guide focuses on **assistant-enforced** guardrails — rules your assistant follows because you wrote them into its behavioral config. But every serious agentic platform also has **platform-enforced** security: native gating that intercepts actions at the infrastructure level, below the model's discretion.

Neither layer is sufficient alone. Together, they cover each other's gaps. The behavioral layer knows *why* an action is happening; the platform layer enforces *regardless of why* — it still fires even if the model has been talked out of its own rules.

### The Platform Layer — Concept

A platform layer should give you, at minimum:

- **Allowlist / denylist gating** — a way to designate which actions run freely, which prompt for approval, and which are hard-blocked. Hard-block must be hard — the model cannot talk past it.
- **Per-action approval flow** — when an action isn't pre-approved, a prompt with the exact command/tool call + arguments, surfaced in context (not stuffed in a log you'll never read).
- **Pre-action hooks** — a programmable gate that fires *before* the action runs, with access to the full call shape (tool name, arguments, source), able to allow / block / ask. This is where your behavioral rules become mechanically enforced rather than merely instructed.
- **Post-action hooks** — runs after the action, for audit logging and injection scanning. Useful precisely because a successful prompt-injection might suppress the model's own self-report.
- **Fail-closed default** — if you're not around to approve, the action doesn't run. An unattended assistant cannot execute arbitrary actions.
- **Per-agent isolation** — if you run multiple agents, one agent's allowlist doesn't leak to another.

Coverage varies by runtime. Some runtimes gate **only shell exec** (the legacy minimum). Others gate **every tool call** — file reads/writes, web fetches, MCP tool calls, agent spawns. Broader coverage is strictly better: an attacker who can't reach a shell can still exfiltrate data through `WebFetch` or write to a hooked file path if those aren't gated.

**Audit your runtime against this list.** If your runtime doesn't have one of these, you've found a place where your behavioral config is the *only* line of defense — and the behavioral layer is exactly what prompt injection targets. Either fix it at the runtime layer, write a wrapper that adds the gate, or shift the action out of the assistant's reach entirely.

> **Platform examples — OpenClaw and Claude Code.**
> Full configuration reference at the end of this section. In brief:
> - **OpenClaw** gates **shell exec only**, with `allow-once` / `allow-always` / `deny` approvals routed to your Discord channel. Fail-closed, per-agent allowlists. Non-exec actions (channel deletes, calendar edits, etc.) aren't covered by the platform layer; the behavioral config is the only gate.
> - **Claude Code** gates **every tool call** (Bash, Read, Edit, Write, WebFetch, MCP tools, agent spawn) through `permissions` (allow/ask/deny lists) + **hooks** (PreToolUse, PostToolUse) defined in `~/.claude/settings.json`. `deny` is unforgeable; hooks run regardless of what the model decided.
> - **Other runtimes** — look for the equivalent of permission lists + pre/post hooks. If your runtime offers only "approve every command," that's a partial platform layer; add a wrapper or migrate to a runtime that gates the broader tool surface.

### What the Behavioral Config Covers That the Platform Can't

The platform layer shows you *what* an action is — `curl -X POST ...`, a write to `~/.ssh/`. It doesn't always tell you *why*, and on runtimes that only gate exec it doesn't cover non-exec actions at all.

Your behavioral config fills these gaps:

- **Semantic intent review** — The platform shows `curl -X POST ...`; your tier system asks "why are you sending data outbound?"
- **Data egress rules** — Detecting whether `curl` is uploading sensitive data vs. fetching a webpage
- **Protected filesystem paths** — Token-gated access to sensitive directories (iCloud, credential stores)
- **Credential handling** — Never writing secrets to logs, memory, or messages
- **Prompt injection defense** — Detecting and quarantining malicious instructions in fetched content
- **Non-exec actions** — Channel deletes, cron modifications, email sends, calendar edits. On exec-only runtimes these aren't gated by the platform at all — your tier system is the only line of defense. On runtimes that gate every tool call, these *can* be covered by platform rules or hooks — but only if you've written rules for them.

### How the Layers Work Together

| Action Type | Behavioral Layer | Platform Layer |
|---|---|---|
| Read-only / workspace files | Tier 1 — just do it | Allow rule / not-exec-gated |
| Shell command (trusted binary) | Tier 1 | Pre-approved (allowlist) |
| Shell command (new/unknown) | Tier 2 — assistant explains intent | Approval prompt / ask rule / PreToolUse hook |
| Destructive exec (force push, terraform, `rm`) | Tier 3 — token flow | Hard deny + double-gate (approval *and* deny rule) |
| Non-exec action (channel delete, cron, email) | Tier 2 or 3 | Per-tool permission rule or hook (if your runtime gates non-exec tools) |

The ideal: even if the assistant hallucinates past a Tier 2 check, the platform layer still catches the action. And even if you've allowed a binary, the assistant's tier system still requires intent disclosure before using it destructively.

### Appendix: Platform Examples

The rest of this section is concrete configuration for OpenClaw and Claude Code. If you're on another runtime, the patterns are the same; the syntax differs. Use these as templates to find / build the equivalent in your runtime's docs.

#### OpenClaw — Platform Config Reference

Set these in `~/.openclaw/openclaw.json` under `"tools"`:

| Key | Values | Recommended | What It Does |
|-----|--------|-------------|--------------|
| `tools.exec.security` | `"deny"` \| `"allowlist"` \| `"full"` | `"allowlist"` | Controls which binaries can run. `allowlist` = only pre-approved run freely. `full` = no gate. `deny` = all blocked. |
| `tools.exec.ask` | `"off"` \| `"on-miss"` \| `"always"` | `"on-miss"` | What happens when a command isn't on the allowlist. `on-miss` = prompt you. `always` = prompt for everything. `off` = auto-deny unlisted. |
| `tools.exec.strictInlineEval` | `true` \| `false` | `true` | Gates `python -c`, `node -e`, `osascript -e`, etc. Even if the interpreter is allowlisted, inline eval still needs approval. Prevents code injection through eval. |
| `tools.elevated.enabled` | `true` \| `false` | `true` | Enables elevated (privileged) command execution. |
| `tools.elevated.allowFrom.discord` | `["user-id"]` | Your Discord user ID only | Restricts who can authorize elevated commands from Discord. |

**Example `openclaw.json` snippet:**
```json
{
  "tools": {
    "exec": {
      "security": "allowlist",
      "ask": "on-miss",
      "strictInlineEval": true
    },
    "elevated": {
      "enabled": true,
      "allowFrom": {
        "discord": ["YOUR_DISCORD_USER_ID"]
      }
    }
  }
}
```

**Approval flow in practice:** When the agent runs a command that isn't on the allowlist, you'll see a prompt in your Discord channel:
```
Approval required (id abc123).
Command: git push origin main
Reply with: /approve abc123 allow-once|allow-always|deny
```

The allowlist grows organically through your `allow-always` approvals. Start conservative — you'll build up a tailored set of trusted commands quickly.

#### Claude Code — Platform Config Reference

Set these in `~/.claude/settings.json`. Permissions are matched most-specific-first; `deny` beats `ask` beats `allow`.

| Setting | Example | What It Does |
|---|---|---|
| `permissions.deny` | `["Bash(rm:*)", "Read(./.env)", "Read(~/.ssh/**)"]` | Hard-block — no prompt, no override. Your denylist. |
| `permissions.ask` | `["Bash(git push:*)", "Bash(gh:*)"]` | Always prompt, even mid-session. Your Tier 2 surface. |
| `permissions.allow` | `["Bash(git status:*)", "Read(~/projects/**)"]` | Runs without asking. Your Tier 1 surface. |
| `defaultMode` | `"default"` | Session baseline. `"plan"` for read-only audits; never ship `"bypassPermissions"`. |
| `hooks.PreToolUse` | matcher + command | A script that gates *every* matching tool call before it runs. Your strongest enforcement point. |
| `hooks.PostToolUse` | matcher + command | A script that runs after a tool call — use for audit logging and injection scanning. |

**Example `settings.json` snippet:**
```json
{
  "permissions": {
    "deny": ["Bash(rm -rf:*)", "Read(./.env)", "Read(~/.ssh/**)"],
    "ask": ["Bash(git push:*)", "Bash(gh repo:*)", "Bash(terraform apply:*)"],
    "allow": ["Bash(git status:*)", "Bash(git diff:*)", "Read(~/projects/**)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "~/.claude/hooks/pretooluse-credential-scan.sh" }]
      }
    ]
  }
}
```

A `PreToolUse` hook receives the tool call as JSON on stdin and returns a decision. Exit non-zero (or emit a structured block) and the tool call is stopped before it runs — the model never gets to act. This is where "never write credentials to logs" stops being a polite instruction and becomes a wall.

---

## Category 1: Behavioral — Confirmation Tiers

The foundation. Define what your assistant can do freely vs. what requires your approval.

### The Concept: Three Tiers

**Tier 1 — Just Do It**
Low-risk, read-only, or fully reversible actions. No confirmation needed.

**Tier 2 — Tell Me First**
Medium-risk actions. Assistant describes what it's about to do and waits for your explicit "go."

**Tier 3 — Hard Gate**
High-risk actions. Requires a secondary verification (passphrase, token, or multi-channel confirmation).

### Decision Points

**Question 1:** What actions should be Tier 1 (no confirmation)?
- Reading files, emails, calendar?
- Web searches and research?
- Writing to workspace files?
- Creating folders and channels?

**Question 2:** What actions should be Tier 2 (tell me first)?
- Sending emails or messages?
- Deleting files (even to trash)?
- Installing software?
- Modifying config files?
- Running shell commands?

**Question 3:** What actions should be Tier 3 (hard gate)?
- Destructive shell commands (`rm`, `dd`)?
- Infrastructure changes (`terraform apply`)?
- Financial transactions?
- Publishing content publicly?

**Question 4:** How should Tier 3 verification work?
- **Option A: Passphrase** — Assistant asks for a secret word you've pre-shared
- **Option B: Token + dual-channel** — Assistant generates a one-time code, posts it to a **notification channel** (e.g. #general) with instructions to reply in the **originating channel**. You post the token back where the action was requested. This separates the audit trail from the authorization, and keeps the confirmation in the same conversation context as the action.

> **Token secrecy:** The token value must appear **only in the notification channel** (e.g. #general). Never echo or repeat the token in the originating channel — not in instructions, not as a reminder, not in any form. The originating channel message should say only: *"🔐 Authorization required. Check [notification channel] for the code, then reply here."* Leaking the token into the originating channel defeats the dual-channel model entirely.
- **Option C: Dual-channel** — Requires confirmation in two different places

Token-based is stronger (can't be faked by injection), but more friction.

### Template

```markdown
## Confirmation Tiers

### Tier 1 — Just Do It
- [list your Tier 1 actions]

### Tier 2 — Tell Me First
- [list your Tier 2 actions]
Confirmation must come from [your username/ID].

> **Best practice:** Require the assistant to state the *exact command or action* it intends to run — not just a description. "I'm going to push to GitHub" is not enough; `git push origin main` is. This prevents the assistant from rationalizing past edge cases and gives you a chance to catch unintended scope.

> **Critical:** This applies even on direct requests. "Push to GitHub" or "install X" is authorization to *ask* — not to *act*. The assistant must still state the exact command and wait for an explicit "go." A request is not a bypass. If your assistant skips this step because you asked it to do something, that is a process violation, not acceptable behavior.
>
> **The assistant must end its proposal with an explicit "Go?" and then stop.** The message that triggered the Tier 2 check is **categorically ineligible as confirmation** — it cannot count as a "go" under any interpretation, regardless of wording. Confirmation must be a new, separate message from you sent *after* the assistant's proposal.

### Tier 3 — Hard Gate
- [list your Tier 3 actions]

**Verification method:** [passphrase / token / dual-channel]
**Notification channel:** [where assistant posts the token for you to see — e.g. #general]
**Confirmation channel:** [where you post the token back — typically the originating channel where the action was requested]
```

> **Platform-layer tie-in:** Tiers are behavioral — back the high-risk ones with the platform layer too. The tier is what the assistant *should* do; the platform rule is what the system *enforces*. Wire Tier 2 actions into your runtime's approval flow; wire Tier 3 / destructive actions into a hard deny or pre-action hook that the model cannot talk past.
> **Examples:** OpenClaw — Tier 3 commands should *also* hit an exec approval. Claude Code — Tier 2 actions go in `permissions.ask`, Tier 3 actions in `permissions.deny` or behind a `PreToolUse` hook.

---

## Category 2: File System Scope

What can your assistant read and write?

### Decision Points

**Question 1:** What paths should be freely accessible?
- Workspace directory only?
- Your entire home folder?
- Specific project directories?

**Question 2:** What paths need extra protection?
- iCloud Documents?
- SSH keys (`~/.ssh/`)?
- Application data?
- Client/work files?

**Question 3:** How should protected paths work?
- **Hard block** — Assistant can never access, period
- **Token gate** — Requires secondary confirmation each time
- **Read-only** — Can read but not write
- **Audit only** — Can access but every access is logged

### Template

```markdown
## File System Scope

### Free Access
- `~/path/to/workspace/` — full read/write

### Protected Paths (requires confirmation)
- `~/path/to/sensitive/` — [token gate / read-only / audit]

### Off-Limits (never access)
- `~/.ssh/`
- [other paths]
```

> **Platform-layer tie-in:** Your off-limits paths should be hard-blocked at the platform layer, not just instructed in the behavioral config — "never access" must mechanically mean "cannot access," even if the model is talked into trying. Where your runtime offers tool-call gating, register `Read` / `Edit` / `Write` denies on the protected paths.
> **Examples:** Claude Code — off-limits paths go in `permissions.deny` as `Read(...)` / `Edit(...)` rules. OpenClaw — exec-only gating doesn't cover non-exec reads/writes, so enforce protected paths through the behavioral tier system plus any pre-action hook your runtime supports.

---

## Prod File Change Management

Config and system files sit outside normal Tier 1/2 territory — the risk isn't just "did I authorize this?" it's "what if the change breaks something and the assistant itself goes down?"

Two-tier approach:

### Tier A — Scripted Rollback (high-value files)

Identify your most critical config files. Write a dedicated script that:
1. Backs up the file before any change
2. Restarts the relevant service
3. Polls health post-restart
4. Automatically restores the backup on failure — without requiring the assistant to be running

Reserve this tier for files where failure is non-interactive and costly. The obvious candidate is the **platform config itself** — whatever file holds your runtime's permissions, hooks, or allowlist (e.g., `~/.openclaw/openclaw.json` for OpenClaw, `~/.claude/settings.json` for Claude Code, or the equivalent for your runtime) — because a bad edit there can break the assistant's ability to fix its own mistake.

### Tier B — Dead Man's Switch (everything else)

For any other config or system file outside your workspace:

1. Back up: `cp "$TARGET" "$TARGET.aisnap"`
2. Spawn a 2-minute auto-revert:
   ```bash
   nohup bash -c "sleep 120 && cp '$TARGET.aisnap' '$TARGET'" & echo $! > /tmp/tier-b-revert.pid
   ```
3. Make the change
4. Ask your human: *"Change applied — 2 min on the clock. Did it work? Confirm to cancel the revert."*
5. **On confirm:** kill the revert process, delete `.aisnap`, log CONFIRMED
6. **On timeout/no response:** revert fires automatically, even if the assistant is down

The key property of Tier B: the revert process is independent of the assistant. If a change breaks the assistant itself, the revert still fires.

### Decision Points

**Question 1:** Which files need Tier A? (scripted backup + auto-rollback)
- Platform config (your runtime's permissions/hooks file — e.g., `openclaw.json`, `settings.json`)?
- Behavioral config (`AGENTS.md` / `CLAUDE.md`)?
- Auth configs?
- Shell init files?

**Question 2:** What backup extension will you use?
Choose something your tooling won't accidentally treat as a live config. Avoid `.bak` if your tools use it. A distinctive extension like `.aisnap` works well — it's meaningless to everything else.

**Question 3:** How long is 2 minutes for your use case?
Some changes need a few minutes to settle. 2 minutes is a reasonable default; your Tier B procedure can allow a longer window when declared before making the change.

**Question 4:** What if there's already a backup file?
An existing `.aisnap` means a prior run may have failed without reverting. Treat it as a hard stop — don't silently overwrite. Alert and let your human decide before proceeding.

### Template

```markdown
## Prod File Change Management

### Tier A — Scripted (automated rollback)
Files: [your runtime's platform config — e.g., ~/.openclaw/openclaw.json, ~/.claude/settings.json, or equivalent]
Script: [path to rollback script]
Behavior: backs up → restarts service → health-polls → auto-reverts on failure

### Tier B — Dead Man's Switch (all other prod/system files outside workspace)
Before any change:
1. cp "$TARGET" "$TARGET.aisnap"
2. nohup bash -c "sleep 120 && cp '$TARGET.aisnap' '$TARGET'" & echo $! > /tmp/tier-b-revert.pid
3. Make the change
4. Ask: "Did it work? Confirm to cancel the revert (2 min on the clock)."
5. On confirm: kill $(cat /tmp/tier-b-revert.pid) && rm "$TARGET.aisnap" — log CONFIRMED
6. On timeout/no response: revert fires automatically

Backup extension: .aisnap
Revert window: 2 minutes (declare longer if needed before making the change)
```

---

## Category 3: Network & Outbound

Control what leaves your machine.

### Sub-decisions

**3A: Web Fetching**
- Allow all URLs freely? (convenient but riskier)
- Warn on unknown domains?
- Maintain an allowlist of permitted domains?

**3B: Email Sending**
- Allow sending to any address?
- Maintain a domain allowlist? (start empty, add as needed)
- Require confirmation for every email?

**3C: Data Egress Rules**
- Scan outbound URLs for embedded credentials?
- Block file contents from being transmitted?
- Inspect shell commands that send data (`curl`, `scp`)?

**3D: Audit Logging**
- Log every outbound network call?
- How long to retain logs?
- What to include? (domain only vs. full URL)

### Template

```markdown
## Network & Outbound

### Web Fetching
[Your policy — open / warn on unknown / allowlist]

### Email
Domain allowlist: `config/email-allowlist.md`
Currently allowed: [domains or "none — all blocked"]
Adding domains requires: [Tier 2 / Tier 3]

### Data Egress
- Scan URLs for credential patterns: [yes/no]
- Block transmission of: [list sensitive data types]
- Shell egress inspection: [yes/no]

### Audit Log
Location: `memory/outbound-audit.log`
Retention: [X days]
Format: [domain only / full URL]
```

> **Platform-layer tie-in:** Outbound traffic is one of the highest-risk action classes — gate it with platform rules wherever possible, especially scanning arguments for credential patterns (the model often doesn't realize a token is in the URL it's about to fetch). Cover both the web-fetch tool *and* the shell tools that exfiltrate (`curl`, `scp`, `rsync`, `nc`).
> **Examples:** Claude Code — gate `WebFetch` and outbound `Bash` patterns with `ask` / `deny` rules or a `PreToolUse` hook that scans arguments. OpenClaw — `curl` / `scp` are exec, so route them through approvals and the inline-eval gate.

---

## Category 4: Command Execution

Shell commands are powerful. Constrain them.

### Decision Points

**Question 1:** What commands should be hard-blocked?
Patterns so dangerous they should never run, regardless of authorization:
- `rm -rf /` — filesystem wipe
- `dd` to disk devices — disk destruction
- `mkfs` — format filesystem
- Fork bombs
- System file overwrites

**Question 2:** What commands should require confirmation?
- Commands targeting system paths (`/etc/`, `/usr/`)?
- Privilege escalation (`sudo`, `su`)?
- Network listeners (`nc -l`, `socat`)?
- Background processes (`nohup`, `screen`)?

**Question 3:** How to handle dynamically-constructed commands?
If the assistant builds a shell command from external input (filenames, fetched content), should it:
- Sanitize metacharacters automatically?
- Show you the full command before running?
- Reject external content in commands entirely?

### Template

```markdown
## Command Execution

### Hard Denylist (never execute)
- `rm -rf /`, `rm -rf ~`
- `dd if=... of=/dev/disk*`
- `mkfs`
- [add your own]

### Requires Confirmation
- Commands targeting: `/dev/`, `/etc/`, `/System/`, `/usr/`
- Privilege escalation: `sudo`, `su`
- Network listeners
- Background detachment

### Per-Action Pre-Flight Rules
For high-impact commands, define a specific required format before execution. Example for GitHub:
```
Before any: gh repo create, git push, git remote add
Required format: "Tier 2 — GitHub: I'm about to run `[exact command]`. This will [what it does]. Go?"
```
Consider similar rules for: terraform apply, aws writes, sending emails, publishing PRs.

**Important: Authorization does not carry forward.**
A "go" for one push does not authorize the next push in the same session. Each push needs its own pre-flight — even if you're in an active work session and things are flowing. This is especially important because:
- Sessions can accumulate many small pushes
- A direct request like "update the GitHub" still requires the assistant to state the exact command before running it
- **The assistant must not bundle unrequested changes into a commit.** If you ask to push a specific change and the assistant decides to also add a rename, a doc update, or anything else you didn't ask for — that's a separate action requiring its own confirmation. What goes into the commit must match what you asked for, no more.

### Dynamic Commands
- Sanitize shell metacharacters: [yes/no]
- Show constructed command before running: [yes/no]

### Platform Enforcement
Back the denylist with your platform layer so a bypassed tier check still gets caught. The principle: the hard-block list belongs in mechanical enforcement (allowlist-default, deny rules, pre-action hooks), not just in behavioral instructions.

**Examples:**
- **OpenClaw:** configure `tools.exec.security: "allowlist"` and `tools.exec.ask: "on-miss"`. Even if the agent bypasses its own tier check, the exec approval still catches the command.
- **Claude Code:** put the hard denylist in `permissions.deny` as `Bash(...)` rules, put confirmation-required patterns in `permissions.ask`, and add a `PreToolUse` hook on `Bash` for anything pattern-matching can't express. `deny` beats everything; the model cannot talk its way past it.
- **Other runtimes:** find the equivalent of "deny these commands no matter what" — usually a pre-tool-call hook or a denylist in the runtime's permission system. If your runtime can't express "hard deny that the model cannot override," that's a meaningful gap; consider migrating or wrapping.
```

---

## Category 5: Credential Handling

Protect your API keys, tokens, and passwords.

### Decision Points

**Question 1:** Where are your credentials stored?
- Platform config (your runtime's permissions/hooks file — e.g., `openclaw.json`, `settings.json`)?
- Environment variables?
- Separate secrets file?
- OS keychain?

**Question 2:** What should the assistant never do with credentials?
- Write to memory files or logs?
- Include in Discord/Slack messages?
- Pass to sub-agents in task prompts?

**Question 3:** What files should be off-limits for reading?
- Config files with embedded keys?
- `.env` files?
- Keychain access?

**Question 4:** What happens on suspected exposure?
- Alert you immediately?
- Log the incident?
- Treat credential as compromised until rotated?

### Template

```markdown
## Credential Handling

### Never Write Credentials To
- Memory files
- Logs
- Messages
- [other locations]

### Off-Limits for Direct Reads
- Platform config — your runtime's settings file (`~/.openclaw/openclaw.json`, `~/.claude/settings.json`, or equivalent)
- `.env` files, credential directories, keychain
- [other sensitive paths]

### Exposure Protocol
On suspected leak:
1. Alert in [channel]
2. Log incident (without the value)
3. Treat as compromised until [rotation confirmed / X hours]
```

> **Platform-layer tie-in:** A pre-action hook that greps tool-call arguments for credential patterns (long hex strings, `sk-`, `ghp_`, `AKIA...`, JWT-shaped tokens) is the most reliable defense — it catches a leak the model didn't realize it was making. Pair it with hard `Read` / `Edit` denies on every secrets file: `.env`, keystore directories, the runtime's own config file, the OS keychain backing store. The model can't expose what it cannot open.
> **Examples:** Claude Code — `permissions.deny` lists every secrets file as `Read(...)`; a `PreToolUse` hook on `Bash` greps args for credential patterns. OpenClaw — keep secrets out of allowlisted-binary arguments, gate inline eval, and treat the credentials directory as off-limits in the behavioral config.

---

## Category 6: Cron & Sub-Agent Limits

Automated and isolated sessions need constraints too.

### Decision Points

**Question 1:** Should all guardrails apply to sub-agents?
Recommended: Yes. Isolated sessions should not be exempt from any rule. Note that sub-agents and scheduled runs often start with a *fresh* context — they won't carry your in-conversation caution unless the rules are in the behavioral config they load.

**Question 2:** Can cron/sub-agents perform Tier 3 actions?
Tier 3 typically requires interactive confirmation. Options:
- **Block** — Cron jobs can't do Tier 3 things; they must alert and stop
- **Pre-authorize** — Specific cron tasks can be pre-approved for specific actions
- **Allow** — Trust cron jobs fully (not recommended)

**Question 3:** How many cron jobs is too many?
A runaway setup could create dozens. Set a soft ceiling (e.g., 10).

**Question 4:** Can task prompts come from external content?
If a cron prompt is derived from a fetched webpage or email, it's a persistent injection vector. Require confirmation for externally-derived prompts.

### Template

```markdown
## Cron & Sub-Agent Limits

### Guardrail Inheritance
All rules apply to cron sessions and sub-agents: [yes/no]

### Tier 3 from Isolated Sessions
Policy: [block and alert / pre-authorize / allow]

### Cron Job Ceiling
Soft limit: [number] active jobs

### External Content in Prompts
Task prompts from external sources require: [Tier 2 / block entirely]
```

> **Platform-layer tie-in:** Sub-agents and cron sessions are particularly dangerous because they often start fresh without your in-conversation caution. The platform layer should treat agent-spawn and scheduled-task invocations as gated actions: enforce ceilings (max active jobs) and block externally-derived task prompts before the new context spins up. Inheritance rule: a sub-agent should run with **at most** the parent's allowlist, never wider.
> **Examples:** Claude Code — a `PreToolUse` hook on the agent-spawn and task tools enforces the ceiling and blocks externally-derived prompts mechanically. OpenClaw — sub-agents inherit per-agent allowlists; confirm an isolated session can't quietly run with a wider allowlist than the parent.

---

## Category 7: Audit Trail

Logs give you visibility and forensic capability.

### Decision Points

**Question 1:** What should be logged?
- All outbound network calls?
- Injection attempts (detected)?
- Tier 2 confirmations?
- Protected path access?

**Question 2:** What should NOT be in logs?
- Full URLs (may contain tokens)?
- Credential values?
- Specific injection patterns (could be a bypass map)?

**Question 3:** How long to retain?
Balance forensic value against disk space. 30-90 days is typical.

**Question 4:** Should logs ever leave the machine?
Logs contain operational patterns. Recommend: gitignore, don't sync to cloud.

**Question 5:** Daily summary?
Should the assistant surface notable security events proactively?

### Template

```markdown
## Audit Trail

### Logs Maintained
- `memory/outbound-audit.log` — network calls
- `memory/injection-log.md` — detected attempts
- `memory/tier2-audit.log` — Tier 2 actions (two-step: pending + confirmed)
- [others]

### Tier 2 Log Format (two-step)
Write a PENDING entry *before* asking for confirmation, and a CONFIRMED entry after execution:
```
[TIMESTAMP] PENDING [action] channel=[channel]
[TIMESTAMP] CONFIRMED [action] confirmed_by=[id] channel=[channel]
```
A PENDING with no CONFIRMED = fell through. A Tier 2 action with no PENDING at all = process violation.

### Retention
[X] days, pruned during maintenance

### Git/Cloud
All security logs in `.gitignore`: [yes/no]

### Daily Summary
Configure a morning briefing that scans the previous 24h logs and posts to your monitoring channel if any of the following occurred:
- Red injection attempt
- Protected-path access (iCloud or equivalent)
- Tier 3 execution
- Credential exposure
- Data egress block
- `tier2-audit.log` has a PENDING entry with no matching CONFIRMED — **this is a process violation**: a Tier 2 action was logged as pending but never confirmed

That last one is easy to miss. It means your assistant completed a Tier 2 action without finishing the authorization flow — the log looks clean but the process was skipped.
```

> **Platform-layer tie-in:** Logging that depends on the model writing audit entries is fragile — a successful prompt injection can suppress self-reporting. Drive your audit log from a post-action hook so it fires regardless of what the model decided. Pair with a tamper-resistant log destination (append-only file, syslog) so an injection that *does* slip past the gates can't quietly cover its tracks.
> **Examples:** Claude Code — a `PostToolUse` hook is the natural place to write audit entries; it sees every tool call after the fact and can't be skipped by the model. OpenClaw — drive logging from behavioral rules and the exec-approval record, both of which are runtime-side rather than model-discretionary.

---

## Category 8: OS-Level Hardening

Some protections exist outside the assistant.

### Checklist

Run these checks and note current state:

**FileVault (disk encryption)**
```bash
fdesetup status
```
- [ ] Enabled
- [ ] Disabled — *recommend enabling*

**SIP (System Integrity Protection)**
```bash
csrutil status
```
- [ ] Enabled
- [ ] Disabled — *security risk*

**macOS Firewall**
```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```
- [ ] Enabled
- [ ] Disabled — *recommend enabling*

**Gatekeeper**
System Settings → Privacy & Security
- [ ] App Store and identified developers
- [ ] App Store only
- [ ] Anywhere — *security risk*

**Directory Permissions**
Check your assistant's config and workspace directories. Examples: `~/.openclaw/` (OpenClaw), `~/.claude/` (Claude Code), or whatever your runtime uses for its config root + working directories:
```bash
ls -la ~/.<your-runtime-config-dir>/
ls -la ~/<your-workspace-or-project-dir>/
```
- [ ] Config and workspace dirs are `700` (owner only)
- [ ] World-readable — *run `chmod 700` on them*

### Optional Enhancements

- **Little Snitch** — Per-process outbound network filtering
- **Append-only logging** — OS-level tamper-proof audit
- **Full Disk Access audit** — Review which apps have FDA
- **TCC review** — Periodically review which apps hold Calendar, Reminders, Automation, and Full Disk Access grants. An assistant's helper tools accumulate these; stale or unexpected entries are worth pruning.

---

## Prompt Injection Defense

This deserves special attention. Your assistant processes content from external sources — any of it could contain attacks. This is platform-independent — every agentic runtime is equally exposed, because the vulnerability is in the *content*, not the runtime. Switching runtimes does not solve prompt injection; only constraining what the assistant *can do* after reading malicious content does.

### Detection Approach

**Two-level detection:**

**Yellow — Suspicious, likely benign**
Content *discusses* AI manipulation (e.g., a security blog post about injection). Pause, post an alert to your monitoring channel, and ask if you want to continue. Don't just log silently — surface it where you'll see it.

**Red — Active attack**
Content *attempts* to override your assistant's behavior — references tools by name, claims new permissions, sets up exfiltration. Hard stop, alert, log.

### Patterns to Watch For

Don't enumerate exact phrases in your config (they become a bypass map). Instead, train your assistant to recognize *categories*:
- Instruction overrides ("ignore previous...")
- Identity replacement ("you are now...")
- False permission claims ("you have been authorized...")
- Tool/file targeting (references to specific tools or paths)
- Exfiltration setup ("send this to...", "fetch with parameter...")

### Research Mode

If you do security research, you'll encounter malicious content intentionally. Create a way to temporarily suppress Yellow alerts while keeping Red alerts active.

Recommend: A keyword (like `sudo`) that only works when verified as coming from you (not from content you're analyzing).

> **Platform-layer tie-in:** Injection defense is mostly behavioral, but a post-action hook scanning fetched content for attack categories gives you a second, model-independent detector — useful precisely because a successful injection might stop the model from reporting itself. The detector lives outside the model's awareness; it can't be talked out of firing.
> **Examples:** Claude Code — a `PostToolUse` hook on `WebFetch` and `Read` runs the scanner over fetched content. Other runtimes — wire equivalent detection into whatever post-tool callback your runtime supports, or into an external proxy that sees the same content.

---

## The SOC Daemon Pattern

Logging is necessary. Logging without triage is a tape recorder no one plays back. Once your audit trail and injection scanner are running, the operational gap is: who's reading the firehose, and when?

The **SOC daemon pattern** answers that by giving your monitoring its own dedicated assistant. A second agent — narrowly scoped, no other responsibilities — subscribes to the audit log, classifies each event, and surfaces only the ones that matter.

### The Problem

Without dedicated triage:
- You glance at the audit log when something breaks
- 99% of alerts are false positives or benign-by-context — the signal-to-noise problem strangles every static rule
- Real incidents drown in mundane chatter
- Manual review doesn't scale past a single assistant, let alone a fleet

### The Pattern

Run a separate agent — call it `soc-daemon` — whose entire job is reading `~/.claude/audit/*.jsonl` (or your runtime's equivalent audit path) and classifying each entry. Give it a dedicated Discord thread, Slack channel, or chat surface that *only it* posts to. Its taxonomy is small and operational:

| Verdict | Action |
|---|---|
| `🟢 false_positive` | Post in-thread, no further action |
| `🔵 benign` | Post in-thread, no further action |
| `🔴 ESCALATE` | Post in-thread *and* DM you |

Every alert gets a verdict and a one-line rationale. Real escalations cut through because they're the only thing that ever pages you.

### Topology

```
   PostToolUse hooks (every assistant)
                │
                ▼
        ~/.claude/audit/*.jsonl
                │
                ▼
            SOC daemon
                │
        ┌───────┴───────┐
        ▼               ▼
   #soc thread       Your DM
   (every verdict)   (escalations only)
```

### Operating Rules

- **Single subscriber.** Only the SOC daemon reads the audit firehose. Other assistants stay out of the thread; cross-talk poisons triage.
- **DM only on real escalation.** Yellow/blue posts stay in-thread. Red gets pushed to your phone. If you change nothing else, do this — it's what makes the alert volume sustainable.
- **Signal stacking.** Two yellow rules firing on the same tool call = treat as one logical red. A single yellow is noise; two yellows on the same call is correlation worth a closer look.
- **Verdict + rationale, always.** "🟢 FP: gog --help service list, on the kill list" is a real triage entry. "🟢" alone is not. The rationale is what makes the audit auditable.

### Gotcha: Scanner Self-Recursion

The SOC daemon's job involves reading the same files the injection scanner watches. If you don't exclude that loop, every alert payload re-fires the moment the daemon reads its own log — an infinite false-positive amplifier.

**Fix:** In the scanner, exclude reads of `~/.claude/audit/` regardless of which tool is doing the read. Both `Read(~/.claude/audit/x.jsonl)` and `Bash(cat ~/.claude/audit/x.jsonl)` need the same exclusion — path-based, not tool-based.

```python
# In your PostToolUse injection scanner
AUDIT_ROOT = os.path.expanduser("~/.claude/audit/")
if tool == "Read":
    if tool_input.get("file_path", "").startswith(AUDIT_ROOT):
        sys.exit(0)
elif tool == "Bash":
    if AUDIT_ROOT in tool_input.get("command", ""):
        sys.exit(0)
```

Path-based audit exclusion accounted for roughly 30% of pre-tuning alert volume in our deployment.

### FP Triage Is Ongoing Work

A scanner is not a fixed asset. The first weeks after deploying one are dominated by tuning false positives:
- Build an **FP corpus** from your real audit log — pull every hit, classify by source pattern
- Add **post-match validators** (entropy gates, JSON-path allowlists, surrounding-context allowlists) when a rule fires reliably on legitimate traffic
- Bench changes against the corpus before shipping — "would this have suppressed the FPs without losing the TPs?"
- Re-bench periodically as new tools and workflows produce new traffic patterns

The SOC daemon is also a natural feedback loop here: when it classifies the same pattern as a false positive ten times, that's the cue to add a validator and stop generating those alerts at the source.

### When You Need It

- You have more than one or two assistants on the same host and audit volume is past glance-friendly
- You've shipped a PostToolUse scanner and notice the audit log is full of yellow events you don't read
- You want a separate eye on your assistant's behavior — same model as having a security team review SOC alerts even when nothing's wrong

If you're running a single assistant for personal use with light traffic, you can probably skip this pattern. The moment you scale past one or two assistants, it pays for itself.

> **Platform-layer tie-in:** The SOC daemon is behavioral — it's an agent reading files. The *platform* responsibility is making sure that agent (a) only ever runs read-only against `~/.claude/audit/`, (b) has the audit-log scanner exclusion configured so it doesn't loop, and (c) is the *only* assistant authorized to DM you from its scoped channel.
> **Examples:** Claude Code — `permissions.deny` for writes to the audit log, `permissions.allow` for reads of audit log only, and a hook that gates DM-sends from non-SOC daemons. Other runtimes — equivalent allow/deny rules on the SOC daemon's file scope, and a channel-policy lock on who can DM.

---

## Implementation Checklist

Work through these in order:

- [ ] **Platform layer:** Configure your runtime's gating — permissions, allowlists, and pre/post-tool hooks (see "Two-Layer Security Model" for the concept; the appendix has OpenClaw and Claude Code examples)
- [ ] **Category 1:** Define your three tiers
- [ ] **Category 2:** Map your filesystem — free, protected, off-limits
- [ ] **Prod File Change Management:** Identify Tier A files, write rollback script, document Tier B procedure
- [ ] **Category 3:** Set outbound policies and create audit log
- [ ] **Category 4:** Define command denylist and confirmation patterns
- [ ] **Category 5:** Identify credential locations and set handling rules
- [ ] **Category 6:** Establish sub-agent inheritance and cron limits
- [ ] **Category 7:** Create log files and set retention policy
- [ ] **Category 8:** Run OS-level checks and fix any gaps
- [ ] **Injection Defense:** Implement two-level detection
- [ ] **SOC Daemon (if running a fleet):** Stand up a dedicated triage agent, configure path-based audit-log exclusion, DM-on-escalate only

After implementation:
- [ ] Test each tier with a real action
- [ ] Verify logs are being written
- [ ] Confirm gitignore covers sensitive logs
- [ ] Document your rollback procedure

---

## Maintenance

Security isn't set-and-forget.

**Weekly:**
- Glance at security logs for anomalies

**Monthly:**
- Review cron job list — still needed?
- Check for new credential files that should be protected
- Update OS and your AI assistant runtime (whichever you're using)

**Quarterly:**
- Re-read your behavioral config (`AGENTS.md` / `CLAUDE.md`) — still accurate?
- Review tier assignments — anything need adjustment?
- Test the Tier 3 flow to make sure it works
- Re-check platform config — exec approvals / permission rules / hooks still doing what you intended?

---

## Final Notes

**No configuration survives a compromised machine.** These guardrails are behavioral and platform-level — they constrain what your assistant *chooses* and is *permitted* to do. If your machine is fully compromised at the OS level, all bets are off.

**The strongest protections are mechanism-based, not pattern-based.** Token verification, allowlists, hard `deny` rules, and `PreToolUse` hooks work even if an attacker knows about them. Pattern detection (injection phrases) can be bypassed by a motivated attacker who's read your rules.

**Two layers, not one.** The behavioral config is what your assistant *intends*; the platform layer is what the system *enforces*. A guide that only hardens behavior leaves the model as the sole gatekeeper — and the model is exactly what prompt injection targets. Configure both.

**Start restrictive, loosen as needed.** It's easier to add permissions than to recover from a security incident.

---

*This guide grew out of hands-on hardening sessions on OpenClaw and Claude Code, which are used as concrete examples throughout. The concepts apply to any agentic AI assistant — LangChain, the Anthropic Agent SDK, OpenAI Assistants, custom MCP-host integrations, on-device frameworks, whatever you're running. Adapt the platform specifics to your runtime, and the rest to your threat model and risk tolerance. The threat model is what's shared; the syntax is what's not.*

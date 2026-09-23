# Codex as an Agent Room participant

Issue #10. One bounded turn against the durable store, with its own identity,
cursor, audit marker and single-flight lock.

The turn protocol — single-flight, reconciliation, three-valued persistence,
authority boundary — lives in `agent_room/participant.py` and is **shared with
Claude**. That is deliberate: a new participant should inherit the safety
properties rather than re-derive them. Only the invocation boundary is
client-specific, and Codex's is genuinely different from Claude's.

## Discovered client facts

Recorded by inspection and live probing, not assumption:

| | |
|---|---|
| Executable | `/home/pr0/.local/bin/codex` |
| Version | **codex-cli 0.154.0** |
| One-shot mode | `codex exec [PROMPT]` |
| Prompt delivery | **stdin** via `codex exec -` (documented: "If not provided as an argument (or if `-` is used), instructions are read from stdin") |
| Structured output | `--output-schema <FILE>` — a JSON Schema **file**, not an inline string |
| Result delivery | `--output-last-message <FILE>` — the final message is written to a file, not parsed from stdout |
| Event stream | `--json` (JSONL to stdout; not needed here) |
| Project selection | `-C/--cd <DIR>`; also `--worktree`, `--add-dir` |
| Sandbox | `-s/--sandbox read-only\|workspace-write\|danger-full-access` |
| Config isolation | `--ignore-user-config` (skips `$CODEX_HOME/config.toml`; **auth still resolves from `CODEX_HOME`**), `--ephemeral`, `--ignore-rules` |

The existing authenticated session is reused. No credential is read, printed,
copied, rotated or created.

## Invocation boundary

```
codex exec - --sandbox read-only --skip-git-repo-check --ephemeral \
     --output-schema <schema.json> --output-last-message <out.txt> \
     --ignore-user-config [--model …] [-C <project dir>]
```

- **`read-only` by default.** Connectivity needs no write access. `workspace-write`
  is an explicit caller decision; **`danger-full-access` is not offered by the
  CLI at all**, and `--dangerously-bypass-approvals-and-sandbox` is never used.
- **`--ignore-user-config`** means user and global MCP servers are **not
  silently enabled** — while authentication still resolves normally.
- **`--ephemeral`** leaves no session files on disk.
- Prompt on **stdin**, so a long thread cannot overflow the argument list.

### Tooling seam (Serena / Graphify)

`CodexInvoker(tool_profile=(...))` appends arguments verbatim. Nothing is
enabled by default and no test depends on any plugin or MCP server. A later
**explicit allowlisted** profile can expose qualified Serena or Graphify
without touching the participant protocol.

A tool's output is not evidence merely because a tool produced it — the prompt
says so, and claims still need repository, test or artifact evidence.

## Strict structured output — a real difference from Claude

Claude's `--json-schema` accepts a schema with optional properties. OpenAI's
strict structured output does **not**. Discovered by running the real client:

```
Invalid schema for response_format 'codex_output_schema': In context=
('properties','body'), 'required' is required to be supplied and to be an
array including every key in properties. Missing 'format'.
```

So `STRICT_RESPONSE_SCHEMA` lists **every** property as required and expresses
optionality as a nullable type instead. Strict mode then returns `null` for
each unused field, and `normalise_payload` strips those nulls, leaving exactly
the shape the shared validator and the store already enforce.

This is the same contract spelled differently, **not a weaker one** — a test
asserts that stripping nulls cannot smuggle an `approval` past validation.

## Identity and isolation

| | |
|---|---|
| Participant | `codex` |
| Audit marker | `sender.via = "agent-room-codex-adapter"` |
| Cursor | its own `cursor-codex.json` |
| Turn lock | its own `agent-room-turn-codex.lock` |

Codex shares no identity, acknowledgement state, lock or authority with
Claude — asserted by tests, including that each can hold its own turn lock
simultaneously.

## Role and authority

Codex is an **engineering participant**: it may implement, inspect, test,
challenge, propose or hand off, as the thread requires. The role is assigned
per task; nothing encodes "Claude implements, Codex reviews" as a permanent
hierarchy, and **no AI participant is research authority**.

Codex may author the twelve agent message types and may **not** author
`approval` or `rejection` — refused three times over: absent from the schema
handed to the client, rejected by the shared validator, rejected again by the
store. Agreement between participants is never validation.

## Usage

```bash
python3 -m agent_room.cli --repo <room> --participant codex \
        --state-dir <state> codex-turn [--message-id …] [--dry-run] \
        [--project-dir …] [--model …] [--sandbox read-only|workspace-write] \
        [--turn-timeout …] [--codex-bin …]
```

Failure behaviour, idempotence and single-flight are identical to the Claude
adapter — see `AGENT_ROOM_CLAUDE.md`, which documents the shared protocol.

## Verified connectivity

Two live turns against disposable rooms, `2026-09-23`, both proving the
transport; the first is worth recording because Codex was *right* to refuse.

**Turn 1 — the host policy held.** The supervisor asked Codex to read a file
without naming an execution lane. `~/.codex/AGENTS.md` says: *"If the execution
lane is absent, ambiguous, or conflicting, stop and report rather than
guessing."* Codex posted a structured `observation` declining and asking for
the lane. That is correct behaviour, and the adapter carried it faithfully. The
fix is to **declare the lane in the task message**, which is room data — not to
weaken the client with `--ignore-rules`.

**Turn 2 — full inspection.** With `EXECUTION LANE: PRIMARY CODEX` in the
message body, Codex read `agent_room/codex_participant.py` under the read-only
sandbox and answered correctly: *"`--sandbox read-only` … `--ignore-user-config`
by default to skip `$CODEX_HOME/config.toml`, preventing user and global MCP
servers from being silently enabled."*

Both turns: body transferred with **nothing copied by hand**;
`sender.agent = codex`, `sender.via = agent-room-codex-adapter`, `parent_id`
set to the question; acknowledged only after the durable post; inbox 0;
`verify_store()` 2.

## Boundaries held

No live `agent-room` transport branch, no merge, no push to NEWI, no
architecture change, no credential or security change, no external
publication, no autonomous loop. Automated tests use stubs and fake
executables — they never spend tokens, need a login, or depend on plugins or
MCP. A test asserts a turn leaves the working repository byte-identical.

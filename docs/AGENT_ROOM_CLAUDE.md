# Claude Code as an Agent Room participant

Issue #3. One bounded turn against the durable store from Issue #2.

**No daemon, no poller, no loop.** The adapter selects one message, asks Claude
once, posts the reply, acknowledges, and exits. Autonomous Claude↔OpenAI
exchange is Issue #5's problem, not this one.

## Discovered client facts

Recorded by inspection, not assumption:

| | |
|---|---|
| Executable | `/home/pr0/.local/bin/claude` |
| Version | **2.1.267 (Claude Code)** |
| One-shot mode | `claude -p --output-format json` |
| Structured output | `--json-schema '<JSON Schema>'` — the client validates shape before we see it |
| Prompt delivery | **stdin**, so a long thread cannot overflow the argument list |
| Project selection | process working directory (`cwd`), plus `--add-dir` |
| Permission controls | `--restricted`, `--strict-mcp-config`, `--allowedTools`, `--disallowedTools`, `--permission-mode` |

The existing login is reused. No credential is read, created, or printed.

## Invocation boundary

```
claude -p --output-format json --json-schema <response schema> \
       --strict-mcp-config --restricted [--model …]
```

`--restricted` removes the code-running tools (Bash, REPL, …) and WebFetch,
confines file tools to the working directory, ignores user/project/local
settings files, and **refuses `bypassPermissions`**. `--strict-mcp-config`
drops MCP servers. The CLI deliberately exposes **no** flag to turn these off:
the adapter reuses the installed client's permission system and never widens
it.

## The turn

1. select **one** message — `--message-id`, else the oldest unread addressed to
   `claude-code`;
2. recover the complete thread from durable state;
3. invoke Claude once with the thread rendered into the prompt;
4. validate the structured reply;
5. post it into the **same** thread as `claude-code`;
6. acknowledge the incoming message **only after** the reply is durably
   recorded;
7. exit.

```bash
python3 -m agent_room.cli --repo <room> --participant claude-code \
        --state-dir <state> claude-turn [--message-id …] [--dry-run] \
        [--project-dir …] [--model …] [--claude-bin …]
```

`--dry-run` selects the message and builds the prompt without invoking Claude.

## What Claude may and may not do

Claude may author the twelve agent message types: `observation`, `hypothesis`,
`claim`, `evidence`, `test_result`, `question`, `challenge`, `proposed_test`,
`answer`, `retraction`, `decision_request`, `handoff`.

It may **not** author `approval` or `rejection`. That is refused three times
over — absent from the schema handed to the client, rejected by the adapter's
own validator, and rejected again by the store. Human authority arrives in
Issue #5.

The prompt states explicitly that agreement from another participant is never
validation, that a claim may honestly stay `proposed` or `challenged`, and that
`supported` needs scope, a revision condition and an admissible evidence basis.

**The reply is read as data.** Only structured fields are used; free-form text
is never executed and never treated as an authority signal. Unknown fields in
the response or its body are refused rather than ignored.

## Failure behaviour

| Situation | Result |
|---|---|
| Malformed / unparseable reply | `MalformedResponse`; **nothing posted, nothing acknowledged** |
| Reply the room refuses (bad evidence locator, forbidden type) | `MalformedResponse` naming the rejection; nothing written |
| Claude exits non-zero, is missing, or times out | `ClaudeAdapterError` |
| Client reports `is_error` | `ClaudeAdapterError` carrying its message |
| Post succeeds but acknowledgement fails | turn returns `acknowledged: false` with `acknowledge_error`; the reply stands and the turn is safely repeatable |

Durability precedes acknowledgement deliberately. The reverse order could mark
a request read with no answer recorded — losing it. This way the worst case is
a repeated turn, not a dropped request.

## Restart continuity

Nothing lives in the process. Thread history is in the room branch; read/ack
state is the participant-local cursor. A fresh process pointed at the same
repo and state directory recovers both and can continue the thread — proven in
`tests/test_agent_room_claude_participant.py` by a genuinely separate
subprocess.

## Verified connectivity

One live turn against a disposable room, `2026-09-23`:

- supervisor posted a `question` addressed to `claude-code`;
- the adapter carried the body — **the human copied nothing**;
- Claude inspected the repository read-only under `--restricted`;
- it returned a structured `answer`, posted at commit `c046896…` with
  `sender.agent = claude-code` and `parent_id` set to the question;
- the incoming message was acknowledged only after that post; inbox went to 0;
- `verify_store()` returned 2.

## Boundaries held

No live `agent-room` transport branch, no merge, no push to NEWI, no
architecture change, no credential or security change, no external
publication, no autonomous loop. Tests use a stub invoker and never spend
tokens or require a login.

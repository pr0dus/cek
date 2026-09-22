# Agent Room store — operations

Implementation of Issue #2 against the design qualified at `cb13177`.

Library plus one-shot CLI. **No daemon, no systemd unit, no poller, no
participant, no execution capability, no database.** Participant workers are
Issues #3/#4; mechanical human authority is Issue #5.

## Layout

```
agent_room/
├── ids.py        UUIDv7 identity
├── canonical.py  canonical JSON + envelope_sha256
├── schema.py     envelope contract + PROCESS.md claim rules
├── gitstore.py   append-only Git store, bounded push retry
├── cursor.py     participant-local read/ack state (never committed)
├── room.py       library API
└── cli.py        one-shot CLI
```

Durable history lives on a dedicated Git branch:

```
.agent-room/messages/<thread_id>/<message_id>.json
```

## Identity and integrity — two separate fields

| Field | Purpose |
|---|---|
| `message_id` | **UUIDv7**. Identity and path. Uniqueness comes from the generator. |
| `envelope_sha256` | **Full 64-char** SHA-256 of the canonical envelope. Integrity and idempotency only — never identity, never the filename. |

**UUIDv7 choice.** Python 3.12's `uuid` has no `uuid7`, so `agent_room/ids.py`
implements RFC 9562 §5.7 directly (~20 lines, `os.urandom` for the random
bits, validated through `uuid.UUID`). No dependency was added. The time-ordered
prefix is what the design wants for rough chronological sortability; ordering
of record still comes from Git history, never from the id.

**Canonical JSON** is pinned in `canonical.py` and asserted in tests: UTF-8,
sorted keys, `(",", ":")` separators, no insignificant whitespace,
`ensure_ascii=False`. The digest covers every immutable envelope field except
itself. `verify()` runs on **every read**.

## Append-only rules

- One immutable file per message; committed bytes are the canonical form.
- Same id + **same** digest → idempotent, returns `{"status": "duplicate"}`.
- Same id + **different** digest → `ConflictError`, nothing is written, no
  commit is created, prior content stays authoritative.
- Acknowledging never touches a message artifact or the branch.
- Reads come from `git show`/`git log`, never the working tree.

**Ordering** is commit-add order, via
`git log --reverse --diff-filter=A -- <path>` — the same discovery the existing
bridge uses. Independent of mtime and of filename sort; both are covered by
tests that deliberately put them in conflict with commit order.

## Epistemic rules (from `PROCESS.md`)

Message lifecycle and claim state are separate machines:

- **lifecycle**: `open | answered | superseded | withdrawn` — conversation only.
- **claim**: `proposed | challenged | supported | retracted` — no generic
  `validated`.

`supported` requires a non-empty `scope`, a non-empty `revision_condition`, and
a non-empty admissible `evidence_basis`. Evidence of kind `agent_output` is
**not** admissible support and cannot close a challenge. Any assertion type may
cite evidence; citing it never promotes a claim.

Agent-facing `post`/`reply` refuse `approval` and `rejection` outright. The
schema and `approvals/` path stay reserved for Issue #5.

## CLI

```bash
python3 -m agent_room.cli --repo <dir> --participant <name> [--state-dir <dir>] \
        [--branch agent-room] [--remote <url>] <command>
```

| Command | Purpose |
|---|---|
| `init` | create the orphan room branch |
| `post` | post a message |
| `reply` | reply, inheriting the parent's thread |
| `get` | fetch one message (digest verified) |
| `thread` | complete thread; `--tree` for parent/child structure |
| `inbox` | unread for `--participant`; `--all` includes acknowledged |
| `ack` | acknowledge (not agreement) |
| `query` | `--participant-name` / `--project-repo` / `--thread-id` |
| `threads` | thread ids in commit order |
| `verify` | re-verify every stored digest |

Example:

```bash
python3 -m agent_room.cli --repo /tmp/room --participant claude-code init
python3 -m agent_room.cli --repo /tmp/room --participant claude-code \
  --state-dir /tmp/state post --thread-id th-1 --type observation \
  --body '{"format":"markdown","text":"..."}' \
  --project '{"repo":"pr0dus/concept-evolution-kernel"}'
```

## Concurrency

Participants never target the same path, so a race shows up only as a
non-fast-forward on the branch ref. `push()` retries with fetch +
rebase, **bounded** by `push_retries` (default 3), then raises `PushRaceError`.
A failed push never loses the local commit. If the fetch itself fails there is
nothing to rebase onto, so the attempt is retried within the bound rather than
misreported as a rebase failure.

## Participant-local state

`cursor-<participant>.json` under `--state-dir`, written atomically. Not in
Git, because a read must never mutate shared history. Rebuildable: losing it
reverts messages to unread and costs nothing else.

## Not yet done

The live `agent-room` transport branch has **not** been created or pushed.
Every test uses throwaway local repositories. Creating the real branch is a
deliberate, separately reported step after supervisor review.

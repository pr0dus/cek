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

## Append-only rules — enforced, not assumed

A digest alone cannot catch a rewrite: whoever edits a message can recompute
it. Only history shows that a message is not what was committed, so **history
is the authority**.

- Every message blob is read from **the commit that added it**, never from the
  branch tip.
- The whole message tree is scanned for later `M`/`D`/`R` events. A path must
  appear exactly once as `A` and never mutate again. Any later modification,
  deletion or rename raises `AppendOnlyViolation` and **fails the read closed**
  — a deleted message is never silently skipped.
- One immutable file per message; committed bytes are the canonical form.
- Same id + **same** digest → idempotent, `{"status": "duplicate"}`.
- Same id + **different** digest → `ConflictError`; nothing written, no commit.
- Acknowledging never touches a message artifact or the branch.

`verify_append_only()` is the cheap primitive: it re-scans history for M/D/R
and duplicate ids and returns the message count.

`verify_store()` is the **full gate**. It walks every committed message and
checks append-only history, path/envelope identity, structural schema, digest,
global id uniqueness, parent/thread validity, historical reference causality
and evidence admissibility. It runs **before the first push attempt and again
after every successful fetch/rebase**, so a writer never extends or delivers
history that is append-only yet semantically corrupt. The CLI `verify` command
uses the same gate and reports the verified count.

**Message ids are globally unique**, not merely unique within a thread path.
The same id under two threads would make `resolve_message()` ambiguous, so it
is refused on append and detected on read.

**Path and envelope identity are bound.** On every read the committed path
must agree with the sealed body: `.agent-room/messages/<thread>/<id>.json`
requires `envelope.thread_id == <thread>` and `envelope.message_id == <id>`.
A valid digest is not enough — history indexes the path while consumers read
the body, so a mismatch would let `resolve_message()` return an envelope
claiming an identity it is not filed under. Checked before the artifact can
participate in any reference resolution.

**Local history overrides are refused.** A checkout carrying `refs/replace/*`
or a non-empty legacy `.git/info/grafts` shows a history that is not the
committed one, so verification refuses to run from it at all. Every Git call
additionally uses `--no-replace-objects` and a **sanitised environment** —
`GIT_DIR`, `GIT_REPLACE_REF_BASE`, `GIT_OBJECT_DIRECTORY`, `GIT_CONFIG*` and
friends are stripped — so a caller's environment cannot change what
verification sees. This is local-checkout integrity, distinct from the remote
force-push boundary below, which Git cannot settle at all.

**Complete history is a precondition.** A shallow repository is refused for
verification, append and push (`git rev-parse --is-shallow-repository`): a
truncated clone cannot prove append-only semantics, because the commits that
would show a rewrite may simply be absent. Every required history query fails
closed — a missing configured branch, a failed `git log`, a failed merge scan
or malformed output raises `HistoryUnavailable`. **An empty room and an
unreadable history are different answers**, and only `verified: 0` on a real,
readable branch means the former.

> **Operational trust anchor.** Code can reject a shallow or unreadable local
> history, but Git alone cannot prove a remote branch was never force-rewritten
> before this clone existed. When the live transport branch is created it must
> carry **branch protection with force-push disabled**. That is an operational
> control; Issue #2 deliberately implements no remote administration.

**The branch is linear.** Merge commits are refused anywhere in the room
branch. Concurrency is resolved by rebase, so a merge adds no capability — but
it does add a hiding place, since a merge commit's own A/M/D changes are not
reported by default log traversal. Linear history is what makes the scan
complete.

**History parsing is NUL-safe and fail-closed.** The scan uses `-z`: without
it Git quotes paths containing spaces or non-ASCII, and a quoted path would
silently vanish from verification. Any path under `.agent-room/messages/` that
is not a canonical `<thread_id>/<uuid7>.json` fails verification rather than
being skipped — including a tracked file at exactly `.agent-room/messages`,
the namespace root itself, which has no trailing slash to match on.

**References obey historical causality.** A parent or cross-message
`evidence_basis` entry must resolve to a message whose add commit is a **strict
ancestor** of the referencing message's add commit — Git ancestry, not log
order, because log order is a traversal artifact that would call two sibling
commits ordered when neither can see the other. Self-reference, same-commit,
sibling and forward references are all refused — a message may only rely on state
that existed when it was committed, otherwise a claim could become
retrospectively supported by evidence added later. In-message evidence ids are
unaffected: they live inside the same envelope.

**Phase one defers graph traversal, never artifact validation.** A raw load
still validates every evidence locator and every locally-decidable artifact
fact; only resolution of *other messages* is deferred to bound recursion. A
`supported` claim therefore cannot become admissible by citing an out-of-band
evidence message whose own locator is invalid — the cited message must pass
its own intrinsic validation first.

**Reads are two-phase**, which is what bounds reference validation: phase one
loads a message and validates it structurally with no resolution; phase two
resolves its parent and evidence basis using *phase-one* loads of the
referenced messages. Validating A therefore resolves B and stops — it never
walks B's own references, so a cycle cannot recurse without bound. A valid
cross-message `supported` claim reads back through `get`, `thread`,
`iter_messages`, and a fresh store instance.

**Ordering** is commit-add order — the same discovery the existing bridge uses.
Independent of mtime and of filename sort; both are covered by tests that
deliberately put them in conflict with commit order.

## Branch pinning

`assert_room_branch()` runs before **every** write, commit and rebase. A store
configured for `agent-room` cannot commit onto `main`, onto another branch, or
onto a detached HEAD — it raises `WrongBranchError` and changes nothing.

`initialise()` never repurposes someone's checkout. It refuses whenever `.git`
already existed and the room branch is not already checked out — including an
**unborn** repo with no commits and untracked files, which an earlier version
would have switched to the orphan branch. It also refuses a pre-existing
non-empty directory. Only a directory Agent Room creates may become a room
branch.

## Single-writer lock

Two processes sharing one checkout share one Git index, so one could commit the
other's staged message. `writer_lock()` takes an exclusive `fcntl` lock on
`<git-dir>/agent-room-writer.lock`, held across the clean check, write, commit
and any push/rebase. The wait is **bounded** by `lock_timeout` (default 10 s)
and then raises `LockTimeout` — a stuck holder can never hang a caller. This is
a lock, not a poller: nothing runs in the background.

`ParticipantCursor` takes the same kind of lock on its own file and **re-reads
under the lock before writing**, so two processes acknowledging different
messages cannot lose each other's acknowledgements.

## Clean checkout

`append()` also runs the **full-store gate on existing history before
extending it**, with or without a remote: a local-only store must not build on
a correctly hashed but semantically invalid artifact either.

`append()` refuses to start unless `git status --porcelain` is empty
(`DirtyCheckoutError`). Otherwise a rewrite of an already-committed message
that someone had staged would be swept into the next message commit and then
pushed as legitimate history. The commit is additionally restricted to the new
message's pathspec, so nothing can ride along even if the index changes between
the check and the commit.

## Trust boundary

`append()` and every read validate **both** the digest and the structural
schema. A correctly resealed but malformed envelope is refused — a valid digest
is not a valid message. Reads validate with `agent_facing=False`, so the
reserved Issue #5 `approval`/`rejection` types stay structurally readable while
remaining un-authorable by an agent.

## Epistemic rules (from `PROCESS.md`)

Message lifecycle and claim state are separate machines:

- **lifecycle**: `open | answered | superseded | withdrawn` — conversation only.
- **claim**: `proposed | challenged | supported | retracted` — no generic
  `validated`.

`supported` requires a non-empty `scope`, a non-empty `revision_condition`, and
an `evidence_basis` in which **every entry resolves**. Any assertion type may
cite evidence; citing it never promotes a claim.

**Admissibility rule.** A basis entry resolves one of two ways:

1. **In-message** — it names an `id` in this message's own `evidence[]`. That
   entry must exist and its `kind` must not be `agent_output`.
2. **Cross-message** — it names a `message_id` in the store. That message must
   exist and must itself carry at least one evidence entry of an admissible
   kind (`repo`, `run`, `external`). A message whose evidence is exclusively
   `agent_output`, or which carries none, is **never** support.

Anything that resolves to neither fails closed. This is what stops two agents
citing each other into `supported` — `LLM_OUTPUT != EVIDENCE`, made mechanical.

`repo`/`run` evidence must pin a **full** Git object ID (40 hex for SHA-1, 64
for SHA-256). Abbreviations and branch-like strings are refused: an
abbreviation is not an immutable identity.

Identifier shapes are checked before they are used as lookup keys, so
malformed input fails as `SchemaError`/`ClaimStateError` and never escapes as a
raw Python `TypeError`: an `evidence[].id`, if present, must be a non-empty
string, and every `evidence_basis` entry must be a non-empty string.
Duplicates are refused on both — duplicate evidence ids would collapse during
resolution and make admissibility depend on list order, and a duplicated basis
entry is a redundant citation.

## Safe identifiers

**Defaults apply only to `None`.** `build_envelope` never uses `x or default`,
so `recipient=[]` cannot silently become a broadcast, `message_id=""` cannot be
replaced by a fresh UUID, and a malformed `sender` cannot become a valid empty
metadata object. Anything explicitly passed is preserved so validation can
refuse it.

**Stored roots must be JSON objects.** `null`, arrays, booleans, numbers and
bare strings fail as `SchemaError` before any `.get()` is attempted.

Every field is type-checked before it is used: `schema_version` must be a real
`int` equal to 1 (`True` is not 1 here), `timestamp` must parse as canonical
UTC `%Y-%m-%dT%H:%M:%SZ`, `claim.scope` and `claim.revision_condition` must be
non-empty strings with no `str()` coercion, enum-like fields are type-checked
before membership so a list or dict cannot escape as a raw `TypeError`, and
boolean flags are **not** coerced with `bool(...)` — `"false"`, `0`, `[]` and
`{}` are rejected rather than silently accepted.

**References are the store's own authority.** `GitMessageStore.append()` takes
no caller-supplied resolver: an exported write API that accepted one would let
a caller assert that a parent or evidence message exists when it does not.

`thread_id` becomes a Git path segment and is parsed back out of
`git log --name-status` line by line, so it is restricted to
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}` — ASCII only, first character alphanumeric,
at most 64 characters. Whitespace, tabs, newlines, control characters,
separators, leading dots and non-ASCII are refused, since Git would quote or
escape them and could break the parse or hide a committed message.
`message_id` is a UUIDv7 and is path-safe by construction.

`decision_request` mechanically requires `human_approval_required: true`.
`challenge` and `retraction` must reference the message they contest or
withdraw. Every `parent_id` must resolve, and parent and child must share a
thread; `reply()` refuses a conflicting explicit `thread_id`.

Agent-facing `post`/`reply` refuse `approval` and `rejection` outright. The
schema and `approvals/` path stay reserved for Issue #5.

## Evidence locator schemas

An admissible reference must identify something inspectable. The store still
does not decide whether evidence is *true*.

| kind | required |
|---|---|
| `repo` | non-empty `repo`, full non-null Git object id `commit`, non-empty repository-relative `path`; optional `lines` as `[start, end]` with `start >= 1` and `end >= start` |
| `run` | full non-null `commit`, plus **at least one** stable locator: `run_id` (non-empty string) or a repository-relative artifact `path` |
| `external` | non-empty `url` |
| `agent_output` | free-form; never admissible as support |

Paths must be repository-relative — no leading `/`, no `..` segment. The
all-zero object id is refused: it is syntactically a full oid but names
nothing.

### What the store can and cannot establish

This boundary is deliberate, and future validators should hold it:

| Situation | The store does |
|---|---|
| Pinned object **is** in this machine's object database | require it to be a commit, **and** require the cited repo-relative path to exist in it (`repo` and `run` alike) |
| Object lookup itself **fails** (unreadable object DB, permissions, transport) | raise an Agent Room error — **never** downgrade to "foreign evidence" |
| Pinned object is **not** local (foreign repository) | keep the full immutable locator; make **no** claim that it exists; **never** fetch |
| `external.url` | validate URL **syntax** only — absolute `http`/`https` with a host; **never** make an HTTP request |

Absence is distinguished from failure by `git cat-file --batch-check`, which
reports a missing object as *data* with a zero exit status — so a non-zero
status means a real operational failure and is raised instead of being misread
as "this object does not exist".

`run_id`-only locators imply no filesystem lookup. Artifact paths are rejected
for NUL/control characters, absolute form and `..` traversal **before** they
reach a Git argument, and external URLs must be absolute `http`/`https` with a
valid authority, host and port — whitespace, control characters, malformed IPv6
and out-of-range ports are refused, with parser `ValueError` converted to
`SchemaError`.

The store preserves evidence references; it does not decide scientific truth
or external availability. A `supported` claim citing an unavailable foreign
locator remains **the participant's evidence-scoped assertion**, not a
store-generated attestation that the artifact exists.

The same verification applies to in-message evidence, to cross-message evidence
returned by the internal resolver, to low-level `append`, and to read/verify.

## Provenance

`sender.agent` is fixed to the `AgentRoom`'s participant. A room opened as
`claude-code` cannot post as `human` or `openai-research` — a mismatch raises
`ForbiddenOperation`. Optional `model`/`operator` metadata stays configurable.
Git authorship is deliberately not authority, which is exactly why `sender`
must be reliable.

`sender` metadata beyond the identity must be scalar. `recipient` must name a
non-empty `agent` or set `broadcast: true` as a real boolean — a truthy string
would otherwise silently widen a directed message. `project.repo` and
`project.commit` are typed the same way as evidence locators.

**Reserved types are not writable.** Every write API in this package —
including the exported `GitMessageStore.append()` — refuses `approval` and
`rejection` for Issues #2–#4, so there is no privileged bypass around
`AgentRoom.post()`. Reads keep `agent_facing=False`, so Issue #5 records stay
parseable once that authority-bearing path exists.

**Stored JSON is decoded strictly.** Duplicate object keys are refused rather
than silently resolved to the last value — at an audited boundary that
ambiguity is a defect. CLI JSON arguments are parsed the same way.

`acknowledge()` requires the message to exist and, for directed messages, to be
addressed to (or broadcast to) the acknowledging participant.

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
| `push` | retry delivery of already-committed messages (one shot, bounded) |
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

## Delivery and partial failure

`append()` commits locally and then pushes. If the commit succeeds but delivery
fails, the message is **already durable locally**, so a naive retry of `post()`
would mint a second UUID and duplicate the logical message in permanent
history. That state is therefore explicit:

- success returns `locally_committed: true, pushed: true`;
- a local-only store returns `locally_committed: true, pushed: false`;
- delivery failure raises **`DeliveryError`**, carrying `message_id`, `commit`,
  `path`, the underlying `cause`, and `locally_committed=True` / `pushed=False`
  (`as_result()` renders the same facts as a dict).

The correct recovery is to retry `push()`, never to repost.

**Git timeouts stay inside the contract.** A `subprocess.TimeoutExpired` from
any Git call becomes `GitTimeout` (an `AgentRoomError`) carrying the command;
on the post-commit push path it becomes a `DeliveryError` like any other
delivery failure. If the *commit* itself returns ambiguously, the store looks
up whether the message actually landed and reports that identity rather than
letting a caller assume nothing happened.

**The reported commit does not depend on store-wide validity, and never
lies.** `recover_add_commit()` uses an exact per-path `git log --diff-filter=A`
lookup and returns `(commit, known, error)`:

- commit proven → `commit: "<sha>"`, `commit_known: true`;
- lookup failed or timed out → `commit: null`, `commit_known: false`, plus a
  `recovery_error`, while `message_id`, `path` and the local/delivery state are
  preserved. A known-stale pre-rebase SHA is **never** reported as current.

If the push itself succeeded and only the receipt lookup failed, `pushed`
stays **true** — a successful delivery is not converted into an apparent
pre-commit failure.

### Truth, falsehood and "unknown"

Every outcome field is paired with an explicit knowledge flag, because the
damaging failure mode is not an error — it is a confident wrong answer that
invites a repost and duplicates a message permanently.

| Field | `true` | `false` | `null` + `*_known: false` |
|---|---|---|---|
| `locally_committed` | commit proven in history | never reached staging | commit sequence failed **and** reconciliation failed |
| `pushed` | push returned success, or remote ref proven to match | remote **responded** with a rejection | result lost (timeout/transport) and reconciliation could not prove inclusion |
| `commit` | add commit proven | — | lookup failed or timed out |

A lost push acknowledgement is **not** `pushed: false`: the remote may already
hold the ref. One bounded `ls-remote` reconciliation is attempted — no fetch —
and delivery is reported `true` only if the remote ref matches what was pushed,
`false` only if the branch is absent entirely, and `null` otherwise.

**The safe recovery is always `push()` for the same committed message**, never
a repost. While `locally_committed_known` is `false` the error says so
explicitly and tells the operator to inspect the path rather than repost.

**The reported `commit` is always current.** A non-fast-forward rebase rewrites
local commit SHAs, so both the success result and `DeliveryError.commit` report
the message's add commit *as it exists in room history after* any push/rebase
processing — never the pre-rebase SHA.

**From the CLI**, a partial delivery prints the same facts as JSON on stdout
and exits **3** (`EXIT_PARTIAL_DELIVERY`), distinct from `2` for ordinary
errors:

```bash
$ agent-room ... post --thread-id t1 --type observation --body '{"text":"..."}'
{ "locally_committed": true, "pushed": false,
  "message_id": "...", "commit": "...", "path": "...", "error": "..." }
# exit 3 — then, once the remote accepts again:
$ agent-room ... push
{ "pushed": true, "attempts": 1 }
```

`push` is one shot: it calls the same bounded `store.push()` and exits. It does
not wait, loop, or run anything in the background.

## Participant-local state

`cursor-<participant>.json` under `--state-dir`, written atomically. Not in
Git, because a read must never mutate shared history. Rebuildable: losing it
reverts messages to unread and costs nothing else.

## Not yet done

The live `agent-room` transport branch has **not** been created or pushed.
Every test uses throwaway local repositories. Creating the real branch is a
deliberate, separately reported step after supervisor review.

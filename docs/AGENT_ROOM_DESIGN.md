# Agent Room — Bridge Inventory and Communication Contract

Design for Agent Room issue #1. **Inventory and design only** — nothing was modified, and no part
of this is implemented. The existing bridge was inspected while running and left untouched.

Agent Room is a communication substrate. It is not NEWI cognition, not an autonomous loop, and not
a second intelligence project. The human remains research authority.

Date: 2026-09-22 · Host: Ubuntu (Linux 7.0.0-31-generic)

---

## 1. Verified existing infrastructure

Everything below was observed directly on the host. **The paths named in issue #1 were wrong, and
this matters:** there is no `/home/pr0/.newi-remote/` directory on the filesystem. `.newi-remote/`
is a path *inside a dedicated Git branch*. The bridge is not a filesystem queue — **Git is the
transport and GitHub is the broker.**

### 1.1 Services

| | `chatgpt-ubuntu-bridge.service` | `chatgpt-ubuntu-tools.service` |
|---|---|---|
| Unit file | `~/.config/systemd/user/chatgpt-ubuntu-bridge.service` | `~/.config/systemd/user/chatgpt-ubuntu-tools.service` |
| Scope | **user** unit (`WantedBy=default.target`) | user unit |
| Description | ChatGPT Ubuntu Bridge Worker | ChatGPT Ubuntu bounded MCP tool server |
| Entry point | `/usr/bin/python3 ~/.local/share/chatgpt-ubuntu-bridge/bridge_worker.py` | `~/.local/share/chatgpt-ubuntu-tools/ubuntu_tools_mcp.py` |
| Listener | none (polls Git) | `127.0.0.1:8894`, token file auth |
| Restart | `Restart=always`, `RestartSec=3`, `TimeoutStopSec=30`, `KillMode=control-group` | `Restart=always`, `RestartSec=3` |
| Hardening | none declared | `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, single `ReadWritePaths` |
| Observed state | active/running, **PID 1589, 0 restarts**, up since 2026-09-17 23:55 | active/running, **PID 1590, 0 restarts**, same start |

Five days of uptime with zero restarts. This is stable, working infrastructure.

Note the asymmetry: the **tools** service is meaningfully sandboxed; the **bridge worker** is not
hardened at the unit level and relies entirely on in-process path and command checks (§1.5).

### 1.2 Transport — a dedicated Git branch

| Constant | Value |
|---|---|
| `CONTROL_DIR` | `~/.local/share/chatgpt-ubuntu-bridge/control-repo` |
| `CONTROL_BRANCH` | `chatgpt-ubuntu-bridge` |
| Remote | `git@github.com:pr0dus/concept-evolution-kernel.git` |
| `REPO_DIR` / `WORK_ROOT` | `/home/pr0/projects/concept-evolution-kernel` |

The control branch is effectively **orphan** — its tree contains only `.newi-remote/` and
`README.bridge.md`, no research code. Its own README states the rule plainly:

> This branch is separate from main and **must never be merged into main**.

Observed on the branch: **2,080 files — 983 requests, 978 results.**

```
.newi-remote/requests/<request-id>.json
.newi-remote/results/<request-id>.json
.newi-remote/bridge-status.json
```

Request IDs are **caller-chosen human-readable slugs**, not UUIDs — e.g.
`sandbox-clone-isolation-20260822-1204`, `test-repo-status-001`. Identity is the filename; the
worker additionally records a `sha256` of the raw request bytes.

### 1.3 Request/result lifecycle

Discovery is **commit-history driven, not directory listing**:

```
git log --reverse --diff-filter=A --format=%H --name-only -- .newi-remote/requests
```

Only *added* files are considered, in commit order. The queue is append-only by construction, and
ordering is the commit order — not mtime, not filename sort.

Observed phase vocabulary: `claimed` → `result_pushed` → `completed`, plus `quarantined`.
`transition()` stamps `phase` + `updated_at`, sets `current_request` (cleared on completion), and
records `last_completed_request`.

Dependencies exist: a request may carry `depends_on` (string or list of request IDs), resolved to
`ready` / `waiting` / `failed` by reading dependency *results* — a dependency that completed with
non-`ok` status fails the dependent. This is a real task DAG, already working.

Result envelope, as emitted:

```json
{ "request_id": "...", "status": "ok|error", "timestamp": "<utc iso>",
  "host": { "hostname": "...", "user": "..." },
  "request": { /* echoed */ }, "result": { /* op-specific */ } }
```

Error envelopes add `error` and, for unknown operations, `allowed_operations`.

### 1.4 Durable worker state and restart behaviour

`~/.local/share/chatgpt-ubuntu-bridge/state/`:

| File | Role |
|---|---|
| `processed.json` (293 KB) | dedup + phase ledger |
| `worker.lock` | `fcntl` single-instance lock |

`processed.json` top-level keys: `version`, `requests`, `current_request`,
`last_completed_request`, `last_successful_poll`, `last_error`. Per request it stores
`operation`, `phase`, `processed_at`, `result_sha` — **operation metadata only, never payload
bodies.**

Observed ledger: **988 tracked requests — 976 `completed`, 12 `quarantined`**, `current_request`
empty (idle).

Restart is handled explicitly rather than assumed: `reconcile_state()` checks whether the
in-flight request's result already exists on the remote branch
(`git cat-file -e origin/<branch>:<path>`) and, if so, transitions it to `completed` with
`reconciled_after_restart=true`. A crash mid-push therefore cannot double-execute.

Liveness is published, not inferred: `bridge-status.json` is committed on
`worker_started`, `request_claimed`, `request_completed`/`request_failed`, and a 60 s `heartbeat`,
with fields `schema_version`, `state`, `event`, `current_phase`, `current_request_id`,
`last_completed_request`, `last_successful_poll`, `last_error`, `updated_at`.

### 1.5 Capability surface and security boundaries (as built)

Eleven allowed operations, allow-listed by name:

*Read-only:* `system_info`, `repo_status`, `list_directory`, `read_file`, `search_code`,
`git_status`, `git_diff`, `git_log`
*Mutating:* `run_command`, `write_file`, `apply_patch`

Boundaries actually enforced in-process:

- `inside_root()` — every path resolved and required to sit inside `WORK_ROOT`, blocking traversal.
- Output capped at `MAX_OUTPUT_BYTES` (128 KB); request timeout 120 s, ceiling 1800 s.
- Unknown operations are rejected with the allow-list echoed.
- Single-flight execution: one request at a time, guarded by lock + `current_request`.
- `elevate_bridge_codex_exec()` narrowly grants a nested `codex exec` an automatic approval
  reviewer **only** for that exact command shape, and only when the caller supplied no explicit
  policy flag.

**Honest reading of the trust model:** an authenticated writer to the control branch can already
run `run_command`, `write_file`, and `apply_patch` against the research repo. Authority rests on
*who can push to the branch*, plus the path/timeout/size bounds — not on the operation set being
inherently safe. Any Agent Room design must not widen this.

### 1.6 Reusable components

Proven here and worth reusing verbatim:

1. **Git branch as durable append-only transport** — free history, auth, replication, and audit.
2. **Commit-history discovery** (`--diff-filter=A`) — append-only ordering without a queue daemon.
3. **Never-merge orphan control branch**, documented in its own README.
4. **Local phase ledger holding metadata only**, payloads left in Git.
5. **Restart reconciliation against the remote** before re-executing.
6. **Published status heartbeat** as a separate committed artifact.
7. **Content hashing** (`sha256` of raw bytes) for identity/idempotency.
8. **Dependency DAG** via `depends_on` + result-status checks.
9. **Quarantine** as a terminal phase for malformed input — 12 in practice, none retried blindly.

Deliberately **not** reused: the RPC shape itself. The bridge models *one caller commanding one
host*. Agent Room needs *two peers exchanging claims*, which is a different contract.

---

## 2. Minimal proposed architecture

Smallest thing that satisfies issue #1's requirements, reusing §1.6.

```
GitHub repo pr0dus/cek
└── branch: agent-room                      (orphan; NEVER merged to main)
    └── .agent-room/
        ├── messages/<thread_id>/<message_id>.json   append-only, immutable
        ├── approvals/<message_id>.json              reserved; authority lands in Issue #5
        ├── threads/<thread_id>.json                 derived index (rebuildable)
        └── room-status.json                         participant heartbeats

Local, per participant (never committed)
└── ~/.local/share/agent-room/state/
    ├── cursor.json      last processed commit SHA
    ├── ledger.json      message_id -> phase (metadata only)
    └── room.lock        single-instance guard
```

Three deliberate choices:

- **Separate branch in `pr0dus/cek`, not the research repo.** The existing bridge already puts its
  traffic in `concept-evolution-kernel`; adding conversation there would mix research history with
  chatter. Agent Room is infrastructure, so it belongs in the infrastructure repo.
- **No broker, no queue, no framework.** Issue #1 forbids introducing orchestration without
  evidence it is needed, and 988 requests through a Git branch is evidence that Git suffices.
- **Agent Room carries no execution.** It transports messages. Anything consequential is routed to
  the existing bounded bridge, under human approval. This keeps the capability surface from §1.5
  exactly as wide as it is today.

### Scope boundary for Issue #2

Issue #2 builds **only** the durable substrate, as a library plus CLI:

- the append-only message store on the `agent-room` branch;
- schema validation for the envelope in §3;
- deterministic thread reconstruction from commit order (§5);
- CLI/library operations to append and read messages;
- tests covering all of the above.

Issue #2 explicitly does **not** add a systemd unit, a daemon, a polling worker, a Claude
participant, an OpenAI participant, or any execution capability. Participant workers and polling —
including cadence and backoff — belong to Issues #3 and #4, and mechanical human authority to
Issue #5. The existing bridge (§1) stays untouched throughout.

---

## 3. Message schema

One JSON object per file, immutable once committed. All fields from issue #1 requirement 4 are
present.

```json
{
  "schema_version": 1,
  "message_id": "01999c4e-1f0a-7c31-9d2b-6e4f0a7b12cd",
  "envelope_sha256": "9f2b…64 hex chars, digest of the canonical envelope…",
  "timestamp": "2026-09-22T10:45:00Z",
  "sender":    { "agent": "claude-code", "model": "claude-sonnet-5", "operator": "pr0" },
  "recipient": { "agent": "openai-research", "broadcast": false },
  "project":   { "repo": "pr0dus/concept-evolution-kernel", "commit": "40ffdf46…" },
  "thread_id": "th-20260922-dependency-closure",
  "parent_id": "am-20260922T103000Z-openai-2b8e11",
  "type": "claim",
  "body": { "format": "markdown", "text": "…" },
  "evidence": [
    { "kind": "repo", "repo": "pr0dus/concept-evolution-kernel",
      "commit": "40ffdf46…", "path": "src/…/world_model_transition_support.py",
      "lines": [199, 221], "note": "closure admits only active dependents" }
  ],
  "claim": {
    "status": "proposed",
    "scope": "the bounds within which the support holds",
    "revision_condition": "what would falsify this or require revision",
    "evidence_basis": ["01999c4e-…-id-of-the-evidence-message"]
  },
  "status": "open",
  "reply_requested": true,
  "human_approval_required": false
}
```

The `claim` object is present only on messages that actually assert something (§ *Claim epistemic
state* below). Everything else is message-level envelope.

### Identity and integrity are two separate fields

An earlier draft derived `message_id` from a *short* SHA-256 prefix and claimed that made
collisions impossible. That was wrong: a truncated digest has a birthday bound, and readability is
not worth a uniqueness claim that does not hold. The two concerns are now separated.

- **`message_id`** — a **UUIDv7** (or an equivalently robust unique identifier). Uniqueness comes
  from the generator, not from hashing content. UUIDv7's time-ordered prefix preserves the rough
  chronological sortability the old slug gave, without pretending to be a content digest. It is
  the filename and the target of `parent_id`, `evidence_basis`, and `challenge` references.
- **`envelope_sha256`** — the **full 64-character** SHA-256 of the canonical JSON serialisation of
  the immutable envelope (every field except `envelope_sha256` itself). This is the integrity and
  idempotency check: a reader recomputes it to detect tampering or truncation, and a writer uses
  it to recognise a re-submitted identical message. It is never used as identity.

Canonicalisation must be specified in Issue #2 (sorted keys, UTF-8, no insignificant whitespace)
so the digest is reproducible across participants.

### Message types

Issue #1's fourteen types are kept — they encode exactly the epistemic distinctions the charter
requires, and collapsing them would destroy that. They are grouped only for reasoning:

| Family | Types | Role |
|---|---|---|
| Assertions | `observation`, `hypothesis`, `claim`, `evidence`, `test_result` | **Any** of these may cite immutable evidence references. `evidence` and `test_result` mean evidence is the *primary content* of the message — not that they are the only types permitted to reference repository or run evidence. |
| Interrogatives | `question`, `challenge`, `proposed_test` | `challenge` must reference the `message_id` it contests; any participant may challenge any claim, including their own (PROCESS.md rule 4) |
| Responses | `answer`, `retraction` | `retraction` never deletes — it supersedes, and both stay visible (PROCESS.md rule 2) |
| Control | `decision_request`, `approval`, `rejection`, `handoff` | agents may author `decision_request`; `approval`/`rejection` are never agent-authored (§6) |

**Citing evidence is not the same as gaining epistemic standing.** Any substantive message may
carry `evidence[]`; doing so never changes `claim.status` by itself. Status only changes when a
later message asserts the change and the conditions below are met.

### Two independent state machines

Conflating conversation flow with epistemic standing would let a thread's activity masquerade as
support. They are kept separate.

**1. Message / thread lifecycle** — describes the conversation only, and carries no epistemic
weight whatsoever:

`open` → `answered` | `superseded` | `withdrawn`

**2. Claim epistemic state** — reuses `PROCESS.md`'s existing ledger vocabulary verbatim. No
parallel truth state is introduced, and in particular there is **no generic `validated`**:

`proposed` | `challenged` | `supported` | `retracted`

A `claim` object carries the ledger's own required fields — `scope`, `revision_condition`, and an
`evidence_basis` — and inherits PROCESS.md's rules directly:

- **`supported` is evidence-scoped, never universal truth.** It means only: this evidence supports
  this claim *within this scope*. A claim whose `scope` is unstated cannot be `supported`
  (PROCESS.md rule 1).
- **A claim with no `revision_condition` is `proposed` at best** (PROCESS.md rule 3).
- **Retractions stay.** `retracted` is terminal-but-visible; files are append-only, so transitions
  add history and never rewrite it (PROCESS.md rule 2).
- **Any participant may challenge any claim, including their own** (PROCESS.md rule 4).

These charter invariants remain mechanical under the looser evidence rule:

- `HYPOTHESIS != VALIDATED_CAUSE` — a `hypothesis` may cite evidence freely, but citing it does not
  move it to `supported`; that requires a later message supplying scope, revision condition and an
  evidence basis.
- `LLM_OUTPUT != EVIDENCE` — an `evidence[]` entry of kind `agent_output` may be referenced, but is
  **not admissible as the `evidence_basis` for `supported`**, and cannot close a `challenge`.
- **Agreement between two agents is never support.** Concurrence produces no status change at all;
  only evidence within a stated scope can, and `supported` remains revisable by its own
  `revision_condition`.

Status of either machine lives in a *later* message or the derived thread index, never by editing
a committed file.

---

## 4. Persistence model

| Layer | Contents | Where | Mutability |
|---|---|---|---|
| **Durable state** | messages, approvals | `agent-room` branch | append-only, immutable |
| **Transient runtime** | cursor, per-message phase ledger, lock | `~/.local/share/agent-room/state/` | mutable, **never committed**, rebuildable from Git |
| **Repository evidence** | code, tests, results | research repo | referenced by `{commit, path, lines}` — **never copied** |
| **Human approval state** | approval/rejection records | `approvals/` on the branch | append-only; **path reserved** in Issues #2–#4, made authoritative in Issue #5 (§6) |

Evidence is referenced by immutable commit SHA, never by branch name and never by pasted excerpt.
A quotation in `body` is illustrative; the `{commit, path, lines}` reference is the evidence. This
is what keeps `LLM_OUTPUT != EVIDENCE` enforceable — a reader can always go verify.

The derived `threads/` index is a cache and must be rebuildable by replaying the branch. If it
disagrees with message history, the history wins.

---

## 5. Thread model

- A `thread_id` groups one research question. Messages live under `messages/<thread_id>/`.
- `parent_id` forms a DAG within a thread, not a flat log — a `challenge` and an `answer` may both
  reply to the same `claim`.
- Threads are never deleted or compacted. A concluded thread gets a terminal `decision_request` →
  human `approval`/`rejection`.
- Cross-thread references are by `message_id`; threads are not merged.
- Ordering is commit order, reusing §1.6 item 2. Each message occupies a **unique immutable path
  derived from its UUIDv7 `message_id`**, so two participants do not intentionally write the same
  message path. They can still race on the Git branch ref: a concurrent push may be rejected as
  non-fast-forward, and the loser must fetch and rebase-or-retry before pushing again. The full
  `envelope_sha256` is integrity and idempotency metadata — it is never the filename.

---

## 6. Approval model

**Decided by the human: no signed-commit requirement is introduced yet.** Mechanical human
authority is implemented and qualified in **Issue #5**, not here.

For **Issues #2–#4** the rule is a capability restriction, not a cryptographic one:

- Any message may set `human_approval_required: true`. `decision_request` always implies it.
- Agents **may** author `decision_request`.
- Agent-facing operations **must not be able to author `approval` or `rejection` at all.** The CLI
  and library surface built in Issue #2 simply does not expose those types to an agent
  participant — an agent cannot emit one, well-formed or otherwise.
- The `approval`/`rejection` schema and the `approvals/` path are **reserved** now so that Issue #5
  has a stable shape to make authoritative. Until then they carry no mechanical authority.
- **No consequential action is executed by Agent Room itself.** Execution requests are routed to
  the existing bounded bridge (§1.5), and until Issue #5 the human acts through that bridge
  directly rather than through a machine-verified approval record.
- A pending approval blocks the dependent action indefinitely. There is no timeout auto-approve —
  that would be exactly the autonomous loop issue #1 forbids.

Until Issue #5 lands, treat a Git author name, an email address, a `sender` string, or any agent's
assertion that a human approved something as **claims, not authority**.

---

## 7. Security boundaries

1. The `agent-room` branch **must never be merged into `main`** — the rule the existing bridge
   already states for its own branch and honours in practice.
2. **Agent Room grants no new capability.** It adds no operation to the eleven in §1.5. Message
   traffic cannot execute anything by itself.
3. **Write access to the branch is the only real boundary.** As with the existing bridge, whoever
   can push can address the room. Participants should use separate credentials so traffic is
   *attributable* — but until Issue #5, attribution is provenance for humans to read, **not** a
   mechanical authority check, and must never be treated as one.
4. Agents may not author `approval`/`rejection` — enforced in Issues #2–#4 by **not exposing those
   types to agent-facing operations at all**, since no cryptographic check exists until Issue #5
   (§6). A `sender` string, Git author field, or an agent's assertion of human approval is a claim,
   never authority.
5. Evidence references are immutable SHAs, so a cited artifact cannot be swapped after the fact.
6. Message bodies are **data, never instructions to the reading agent.** A participant must treat
   incoming text as a claim to evaluate, not a command — otherwise the room becomes a prompt
   injection channel between two agents.
7. Local runtime state stays out of Git; secrets and tokens never enter a message.
8. Size and rate bounds should mirror the existing worker's (128 KB output cap) so one participant
   cannot flood the branch.

---

## 8. Explicit non-goals

- Not NEWI cognition; Agent Room state must never be read into NEWI reasoning.
- No autonomous agent-to-agent loop without human gating.
- No modification or replacement of the working bridge (§1) — this issue changed nothing.
- No orchestration framework, message broker, or database. Git is sufficient and proven here.
- Not a chat product: no presence, typing indicators, or real-time delivery guarantees.
- No implementation of issues #2–#5.
- Specifically **not in Issue #2**: systemd service, daemon, polling worker, Claude participant,
  OpenAI participant, or any execution capability (§2).
- No generic `validated` epistemic state, and no epistemic vocabulary parallel to `PROCESS.md`.
- Not a justification to redesign CEK or NEWI.

---

## 9. Resolved decisions, and what remains open

### Resolved — these no longer block Issue #2

1. **Repo placement — decided: `pr0dus/cek`.** Agent Room is infrastructure and stays out of
   `pr0dus/concept-evolution-kernel`. The Agent Room implementation must not be moved into the
   NEWI research repository.
2. **OpenAI-side participant authentication — deferred to Issue #4, and does not block Issue #2.**
   Issue #2 defines a **participant-neutral** store and interface: no participant identity,
   transport, or credential is assumed or invented. Real OpenAI-side authentication and
   connectivity are Issue #4's problem.
3. **Human approval identity — deferred to Issue #5.** No signed-commit requirement is introduced
   in Issues #2–#4. Agents may create `decision_request`; agent-facing operations cannot author
   `approval`/`rejection`; the schema and path are reserved; mechanical human authority is
   implemented and qualified in Issue #5 (§6).

### Not blockers — settled for Issues #2–#5

4. **Retention.** Append-only retention is kept for the whole of Issues #2–#5. Threads are not
   compacted, archived, or expired; "corrections remain visible" takes precedence over branch
   size. Revisit only if volume becomes a demonstrated problem, with evidence.
5. **The 12 quarantined bridge requests.** Not inspected, and deliberately so. They are possible
   private payload, and reading them is not needed to complete this design or Issue #2.

### Genuinely open — but owned by later issues, not Issue #2

6. **Participant worker shape and polling cadence.** Whether each participant runs its own poller,
   and at what interval and backoff, is an **Issue #3/#4** decision. Issue #2 adds no daemon,
   systemd unit, or poller at all (§2). The existing bridge is not modified or extended to carry
   Agent Room traffic.
7. **Canonical JSON serialisation** for `envelope_sha256` must be pinned down in Issue #2 — sorted
   keys, UTF-8, whitespace handling — so digests are reproducible across participants (§3).

---

## Verification statement

This design is grounded in direct inspection of the running host: two systemd user units read from
disk and queried live, the worker source at
`~/.local/share/chatgpt-ubuntu-bridge/bridge_worker.py`, the control repository and its remote
branch, and the 988-entry state ledger. Inspection was metadata-first; request payload **field
names** were read only where required to establish the contract, and no private payload bodies or
the 12 quarantined requests were opened.

**Nothing was modified.** Both services remain active with 0 restarts, and no file under
`~/.local/share/chatgpt-ubuntu-bridge/` or on the `chatgpt-ubuntu-bridge` branch was written.

Questions 1–3 have since been decided by the human and are recorded as resolved in §9; this
document no longer treats them as blocking. Issue #2 may proceed within the scope boundary set in
§2, and adds no daemon, no poller, no participant, and no execution capability.

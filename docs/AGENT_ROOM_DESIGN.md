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
        ├── approvals/<message_id>.json              human-authored commits only
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

---

## 3. Message schema

One JSON object per file, immutable once committed. All fields from issue #1 requirement 4 are
present.

```json
{
  "schema_version": 1,
  "message_id": "am-20260922T104500Z-claude-7f3a9c",
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
  "status": "open",
  "reply_requested": true,
  "human_approval_required": false
}
```

**`message_id`** = `am-<UTC timestamp>-<sender>-<short sha256 of canonical body>`. This keeps the
existing bridge's readable-slug property while making collisions impossible and identity
content-derived.

### Message types

Issue #1's fourteen types are kept — they encode exactly the epistemic distinctions the charter
requires, and collapsing them would destroy that. They are grouped only for reasoning:

| Family | Types | Epistemic weight |
|---|---|---|
| Assertions | `observation`, `hypothesis`, `claim`, `evidence`, `test_result` | `observation`/`evidence`/`test_result` may cite repo evidence; `hypothesis` and `claim` **may not** be treated as validated |
| Interrogatives | `question`, `challenge`, `proposed_test` | `challenge` must reference the `message_id` it contests |
| Responses | `answer`, `retraction` | `retraction` never deletes — it supersedes, and both stay visible |
| Control | `decision_request`, `approval`, `rejection`, `handoff` | `approval`/`rejection` are **human-only** (§6) |

Rules that make the charter's invariants mechanical rather than aspirational:

- `HYPOTHESIS != VALIDATED_CAUSE` — only `evidence` and `test_result` may carry `evidence[]`
  entries of kind `repo`/`run`. A `hypothesis` with no evidence cannot be promoted to `claim`
  except by a new message citing evidence.
- `LLM_OUTPUT != EVIDENCE` — `evidence[]` entries of kind `agent_output` are permitted but are
  **explicitly not** valid support for closing a `challenge`.
- Agreement is not validation — a `claim` reaches `status: "validated"` only via a `test_result`
  citing a reproducible artifact, never by two agents concurring.
- Corrections stay visible — files are append-only; `retraction` and `status` transitions add
  history, never rewrite it.

### Status vocabulary

`open` → `answered` | `challenged` | `validated` | `retracted` | `superseded` | `withdrawn`.
Status lives in a *later* message or the derived thread index, never by editing the original file.

---

## 4. Persistence model

| Layer | Contents | Where | Mutability |
|---|---|---|---|
| **Durable state** | messages, approvals | `agent-room` branch | append-only, immutable |
| **Transient runtime** | cursor, per-message phase ledger, lock | `~/.local/share/agent-room/state/` | mutable, **never committed**, rebuildable from Git |
| **Repository evidence** | code, tests, results | research repo | referenced by `{commit, path, lines}` — **never copied** |
| **Human approval state** | approval/rejection records | `approvals/` on the branch | append-only, human-authored commits only |

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
- Ordering is commit order, reusing §1.6 item 2. Concurrent pushes from two participants are
  resolved by Git; because every file is write-once with a content-derived name, **there are no
  content conflicts** — only occasional non-fast-forward retries.

---

## 6. Approval model

- Any message may set `human_approval_required: true`. `decision_request` always implies it.
- `approval` and `rejection` messages are valid **only** when authored by a human-controlled
  identity. No agent participant may author them.
- **No consequential action is executed by Agent Room itself.** Execution requests are routed to
  the existing bounded bridge (§1.5) and only after an `approval` exists for the specific
  `message_id`.
- Enforcement is by commit authorship/signature on the approvals path, not by an honour-system
  field inside a JSON file an agent could write.
- A pending approval blocks the dependent action indefinitely. There is no timeout auto-approve —
  that would be exactly the autonomous loop issue #1 forbids.

---

## 7. Security boundaries

1. The `agent-room` branch **must never be merged into `main`** — the rule the existing bridge
   already states for its own branch and honours in practice.
2. **Agent Room grants no new capability.** It adds no operation to the eleven in §1.5. Message
   traffic cannot execute anything by itself.
3. **Authority is push access to the branch.** As with the existing bridge, whoever can write the
   branch can address the room; participants should use separate credentials so authorship is
   meaningful.
4. Agents may not author `approval`/`rejection` (§6).
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
- Not a justification to redesign CEK or NEWI.

---

## 9. Open questions and blockers

Decisions that need the human before issue #2:

1. **Repo placement.** This design puts `agent-room` in `pr0dus/cek`. The alternative is reusing
   `concept-evolution-kernel` where the bridge already lives. Recommendation: `cek`, to keep
   research history clean — needs confirmation.
2. **OpenAI-side participant.** How the OpenAI agent authenticates and pushes is **unverified**.
   The current bridge is driven by something that can already commit to the control branch, but I
   did not inspect the ChatGPT-side configuration, and issue #1 does not cover it. This is the
   largest unknown and directly gates issue #4.
3. **Identity for approvals.** §6 requires enforceable human authorship. Signed commits (GPG/SSH)
   are the obvious mechanism; whether the workflow already has signing keys is unconfirmed.
4. **Reuse vs parallel worker.** Should Agent Room poll via a second systemd user unit modelled on
   the bridge worker, or extend the existing worker? A separate unit is safer (issue #1 forbids
   modifying the bridge) but doubles polling. Recommendation: separate unit, decided in issue #2.
5. **Polling cadence and cost.** The bridge polls at 2 s when active. For conversation this is
   probably wasteful; an idle backoff needs choosing.
6. **The 12 quarantined requests.** Not inspected — their contents may reveal malformed-input
   modes worth designing against. Deliberately left alone as possible private payload.
7. **Retention.** Threads accumulate forever by design. At what volume does the branch need
   archival, and does archival violate "corrections remain visible"?

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

Issue #2 should begin only after questions 1–3 above are answered.

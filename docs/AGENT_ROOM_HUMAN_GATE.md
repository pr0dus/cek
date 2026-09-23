# Agent Room — the human decision gate

Issue #5. The final infrastructure gate: mechanical human authority, deterministic
snapshot binding, bounded coordination, and independently observed proof.

Everything here is additive. No existing message, adapter or store behaviour changes,
and nothing in this issue executes a consequential action — the gate's whole job is to
stop before one.

---

## 1. Why capability separation rather than signatures

The design deferred signed commits deliberately (§6), and this issue does not reintroduce
them. So this code never claims to *prove* a human acted. It guarantees something
narrower and mechanically checkable:

- `approval` and `rejection` are refused by **every** agent surface — `AgentRoom.post`,
  `GitMessageStore.append`, both participant adapters, and the supervisor import
  boundary. Not "discouraged": the validation path rejects them.
- The one write path that accepts them, `GitMessageStore.append_decision`, is called by
  exactly one caller, `decision.HumanDecisionAuthority`.
- No participant or orchestrator module references either symbol, and a test reads the
  sources to keep it that way.
- The identity `human` is reserved: `AgentRoom.__init__` refuses to post under it.

A model cannot author an approval by being clever about JSON, because there is no agent
path to the write at all.

What this does **not** establish: that the person at the keyboard is who they say they
are. `sender.agent` remains provenance, not authentication — the same caveat the design
states, unchanged.

---

## 2. The decision record

A human decision is an ordinary append-only message of type `approval` or `rejection`,
carrying a top-level `decision` object and replying to the `decision_request` it decides.

```json
{
  "decision_schema_version": 1,
  "decision_id": "hd-…",
  "decision": "approve",
  "decided_at": "2026-09-23T18:04:11Z",
  "request_message_id": "01a0cfb2-…",
  "request_envelope_sha256": "…64 hex…",
  "action_id": "activate-agent-room-transport",
  "action_scope": "create the production agent-room branch in pr0dus/cek",
  "binding": {
    "snapshot_sha256": "…64 hex…",
    "supervisor_context_sha256": "…64 hex…",
    "project": {"repo": "pr0dus/cek", "commit": "…full oid…"}
  },
  "decision_binding_sha256": "…64 hex…"
}
```

`decision_binding_sha256` covers the request id and digest, the action id and scope, the
binding, and the verdict — and deliberately **not** `decision_id` or `decided_at`. The
digest answers "what was decided", not "which keystroke recorded it".

Every binding is re-derived from the stored request by `HumanDecisionAuthority.record`;
none is taken from the caller. The optional `expect_*` arguments let a person state what
they believe they are approving and be refused if that belief is wrong.

The matching request carries a top-level `action`:

```json
{"action_id": "…", "scope": "…", "consequential": true,
 "binding": {"snapshot_sha256": "…", "supervisor_context_sha256": "…"}}
```

`action` is optional. A `decision_request` may legitimately ask an open question, and one
without a bound action can never release anything — `evaluate_gate` reports
`blocked_unbound`.

---

## 3. The gate

`decision.evaluate_gate(store, request_id, snapshot_sha256=…, supervisor_context_sha256=…)`
returns one state:

| state | meaning |
|---|---|
| `blocked_unbound` | no bound action, or a malformed one |
| `blocked_no_decision` | nobody has decided; blocks indefinitely |
| `blocked_rejected` | the human said no |
| `blocked_stale` | the decision no longer matches what is bound or observed |
| `released` | exact match, and only for this action |

The observed digests are what a caller measured **now**. Supplying them is what makes an
approval stop releasing once the code or the reviewed conversation moves; omitting them
checks only the record's internal consistency, and the report says so in `reasons`
rather than quietly checking less.

Last decision wins, so a human may reject what they earlier approved. There is no
timeout and no auto-approval.

---

## 4. Snapshot binding

`snapshot.snapshot_manifest(workdir, base_commit)` measures the inspected state. It takes
no file list — a builder's account of what it changed is a report, not a measurement — and
records four independent comparisons per path (base↔worktree, base↔index, index↔worktree,
untracked), plus kind, mode, size and a content digest. A symlink is hashed over its
*target* and never followed.

`manifest_sha256` covers all of it plus the exact bytes of the tracked diff, so a mode
change with identical content still moves the digest. Measuring the same state twice gives
the same digest; measuring it after any edit does not. That is the whole staleness
mechanism.

---

## 5. Bounded coordination

`orchestrator.Coordinator` routes durable messages and invokes bounded turns through
already-qualified surfaces. It is not a model, it writes no code, and it holds no state:
every count is derived from the thread, which is what lets a restarted process land on the
same numbers.

Ceilings for one work item, all enforced *before* a model is invoked:

| kind | default |
|---|---|
| `implementation_attempts` | 2 |
| `inspection_rounds` | 2 |
| `supervisor_corrections` | 2 |

Reaching one raises `BoundExhausted` carrying the reconstructed state, which is the report
of what is still unresolved. It is not an error to route around, and nothing retries.

A round is always a reply — the opening task assignment is routing, not a round. An
inspection round additionally requires that the inspector be replying to the *builder* or
to the coordinator's routing: an inspector questioning the task before any work exists is
taking part in the review conversation, and charging that against the inspection budget
would spend the ceiling before there was anything to inspect. That rule came out of the
live qualification run, where exactly that happened.

Independence is mechanical. `authorship()` is every coding participant that produced an
implementation attempt, and `assert_independent_inspector` refuses an inspector in that
set. If both providers edit, neither can claim independent review.

`NoWorkAvailable` is ordinary idle at this layer, and idle consumes no round.

---

## 6. Independently observed proof

`proof.run_proof` runs the agreed command itself and records argv, exit status, digests
over the full output, a bounded tail, and the repository/snapshot identity, writing an
immutable artifact **outside** the inspected checkout — writing it inside would change the
state the proof is about.

A non-zero exit is a result, not a harness failure. A denied command is recorded as the
outcome and never retried with different flags. `proof_evidence` turns a record into a
`run` locator whose `run_id` is the proof digest, so the reference names the observation
rather than a mutable path.

---

## 7. Operating it

```
agent-room --repo <room> --participant coordinator snapshot \
    --target <checkout> --base-commit <full oid>

agent-room --repo <room> --participant coordinator gate-status \
    --request-id <id> --snapshot-sha256 <…> --context-sha256 <…>

agent-room --repo <room> --participant human human-decide \
    --request-id <id> --show            # read what would be decided

agent-room --repo <room> --participant human human-decide \
    --request-id <id> --decision approve --confirm-human
```

`--confirm-human` is required, and `human-decide` is never invoked by participant or
orchestrator code. That is the point at which the machine stops and waits for a person.

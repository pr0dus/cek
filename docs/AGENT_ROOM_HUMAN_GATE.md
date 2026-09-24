# Agent Room — the human decision gate

Issue #5. The final infrastructure gate: mechanical human authority, deterministic
snapshot binding, bounded coordination, and independently observed proof.

Everything here is additive. No existing message, adapter or store behaviour changes,
and nothing in this issue executes a consequential action — the gate's whole job is to
stop before one.

---

## 1. Capability separation, and — since S2 — signatures behind it

Issue #5 deferred signed human identity deliberately (design §6) and this document once
said so. **That is no longer true.** Issue #13 Stage S2 made the human decision
cryptographic: an `approval` or `rejection` carries authority only when it is signed by
the credential pinned for the `human` role in the trust policy, and that credential lives
in a personal device's keystore, unlocked per approval by a fingerprint. Nothing on this
host can produce a human signature. See `docs/AGENT_ROOM_AUTH.md`.

Capability separation did not go away; it sits one layer in front of the signature, and
it is what stops an agent *surface* reaching the write path at all:

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

What this does **not** establish, stated plainly because the wording above could be read
as stronger than it is:

- **`--confirm-human` is an operator assertion, not authentication.** It is a flag. It
  proves that whoever ran the command meant to run it, and nothing more. There is no
  signature, no hardware token, no challenge, and no check of who is at the keyboard.
- **The isolation is within Agent Room, not on this host.** The guarantee is that the
  qualified participant and orchestrator surfaces cannot reach
  `HumanDecisionAuthority` — not that no process on the machine can. Any process with
  shell execution in this repository can invoke the CLI. The existing ChatGPT-Ubuntu
  bridge is one such process: its bounded `run_command` can target
  `/home/pr0/projects/cek`, so the human surface is reachable from it by construction.
- `sender.agent` is a claim. Since S2 the signature is what corroborates it, and
  `release.authorise` independently re-checks that the effective decision is signed by
  the key pinned for the human role.

What is still **not** claimed: hardware backing of the device credential is not attested,
and none of this survives an attacker with arbitrary root on this host — see
`docs/AGENT_ROOM_SECURITY.md` §3, and the S3 audit finding about passwordless root in
`docs/AGENT_ROOM_TRANSPORT.md`.

The procedural rule still stands alongside the cryptography: the supervisor does not ask
for a decision until the user has explicitly approved or rejected in ChatGPT, and the
device is what turns that into authority.

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
| `blocked_unmeasured` | approved, but current state was not measured |
| `blocked_rejected` | the human said no |
| `blocked_stale` | the decision no longer matches what is bound or observed |
| `released` | exact match on **both** measurements, and only for this action |

The observed digests are what a caller measured **now**, and **both are required**. An
approval says "this state, as I reviewed it, may go ahead"; a gate that has not looked at
current state has established nothing about whether that state still exists, so it
reports `blocked_unmeasured` rather than releasing on the record's internal consistency
alone. `assert_releasable` names both parameters explicitly, so a misspelled one is a
`TypeError` at the call site instead of a silently unmeasured check.

A measured mismatch outranks a missing measurement: if one digest was checked and had
moved, the state is `blocked_stale`, because "we looked and it moved" is the more
actionable answer. Either way the `unmeasured` field lists what was not checked.

`Coordinator.reconstruct()` measures nothing — it reads durable state. Every gate it
reports therefore comes back blocked, it says so with `gates_measured: false`, and it
raises rather than ever emitting a releasable gate. Finding an approval in history is not
the same as a live release.

Last decision wins, so a human may reject what they earlier approved. There is no timeout
and no auto-approval.

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

# both measurements, or the answer is blocked_unmeasured
agent-room --repo <room> --participant coordinator gate-status \
    --request-id <id> --snapshot-sha256 <…> --context-sha256 <…>

agent-room --repo <room> --participant human --trust-policy <policy> \
    human-decide --request-id <id> --show      # read what would be decided

# Recording one is the device ceremony (S2). There is no host-signed route.
agent-room --repo <room> --participant human --trust-policy <policy> \
    human-prepare --request-id <id> --decision approve --out <file>
#   … the trusted device shows the summary, takes the fingerprint, and signs
#     payload_b64 …
agent-room --repo <room> --participant human --trust-policy <policy> \
    human-submit --prepared <file> --signature <base64>
```

`human-decide --show` is read-only. In an authenticated room `human-decide` will **not**
record a decision, even with `--confirm-human` and a `--signing-key`: signing a human
decision with a key on this host would contradict the model that put the credential on a
separate device, and leaving the route available is an invitation to put a real
credential here. It refuses and points at `human-prepare` / `human-submit`.

The gate is still never invoked by participant or orchestrator code. Since S2 that
capability separation has a signature behind it: `--confirm-human` gates the surface so
nothing is recorded by accident, and the device's assertion is what carries authority.

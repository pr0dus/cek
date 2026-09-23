# The OpenAI supervisor handoff boundary

Issue #4. **Not another model adapter.**

There is no second OpenAI process on this host and no API key. The supervisor
is the **ChatGPT host conversation**, which already reaches this machine
through the existing bridge. What was missing is a durable, auditable boundary
it can drive so that no human copies message bodies between systems.

Two bounded, one-shot operations, both runnable through the bridge's
`run_command`:

| | |
|---|---|
| `supervisor-export` | select one message addressed to `openai-research`, emit a canonical **supervisor packet** |
| `supervisor-import` | post one structured supervisor response, **bound to the context it reviewed** |

## The packet

Canonical JSON, deterministic for unchanged state:

| Field | |
|---|---|
| `packet_schema_version` | `1` |
| `target_message_id` / `target_envelope_sha256` | the message under review |
| `thread_id`, `thread` | the **complete** thread in durable commit order — full envelopes, so identities, `parent_id` links and evidence locators travel with it |
| `project` | repository identity from the target |
| `room` | `branch`, `ref`, `tip`, `workdir` |
| `context_sha256` | binds exactly what was reviewed |

**The packet is data, not instructions.** Evidence is *referenced*, never
inlined — a locator stays the authority, and exporting one does not make it
verified. A test asserts the cited file's contents do not appear in the packet.

Export is read-only: it does not acknowledge, and it does not move the ref.

## Context binding — "materially changed", defined mechanically

`context_sha256` is SHA-256 over the canonical form of:

```
packet_schema_version, target_message_id, target_envelope_sha256, thread_id,
[ {message_id, envelope_sha256} for each message, in commit order ]
```

Nothing else. Not timestamps, not prose similarity, not body text — each body
is already covered by its envelope digest.

Consequences, all tested:

- **appending to the reviewed thread invalidates the review** — the binding changes;
- **activity in another thread does not** — which is why the room `tip` is
  reported for provenance but deliberately kept *out* of the hash;
- waiting changes nothing;
- the hash is identical from a fresh process, because it is computed from
  durable state alone.

On import the binding is recomputed from current state **inside the turn
lock**, after reconciliation and before any post. A mismatch raises
`StaleSupervisorContext` and posts nothing. Recovery is to export a fresh
packet and review again — never to override the binding.

## Import

`SupervisorBoundary` inherits the participant protocol unchanged — single-flight
lock, idempotent reconciliation, three-valued persistence, post-before-ack —
with a *supplied response* standing in where the other adapters call a model.
So the supervisor path carries exactly the guarantees already proven for Claude
and Codex:

- no agent-authored `approval` or `rejection`;
- malformed response posts and acknowledges nothing;
- acknowledgement follows durable response;
- post/ack crash reconciles without a duplicate;
- one target → at most one automatic supervisor response.

The supervisor may author challenges, evidence-scoped claims, questions,
proposed tests, handoffs and decision requests. Replies carry
`sender.via = "agent-room-supervisor-import"`.

Note the ordering: reconciliation runs *before* the freshness check. If a
supervisor response to that target already exists, the turn reports
`already_responded` and posts nothing — so there is nothing stale to reject.

## Bridge facts reused (the bridge was not modified)

Confirmed by reading the worker, not assumed:

- control branch `chatgpt-ubuntu-bridge`; requests at
  `.newi-remote/requests/<id>.json`, results at `.newi-remote/results/<id>.json`;
- `run_command` is in `ALLOWED_OPS` and requires an **explicit argv list** — a
  shell string is rejected, and `sudo` is refused;
- the worker is a user-level systemd unit, running and untouched.

A supervisor turn is therefore two ordinary bridge requests:

```json
{"operation": "run_command",
 "command": ["python3", "-m", "agent_room.cli", "--repo", "<room>",
             "--participant", "openai-research", "--state-dir", "<state>",
             "supervisor-export"]}
```

then, after composing a response bound to the returned `context_sha256`:

```json
{"operation": "run_command",
 "command": ["python3", "-m", "agent_room.cli", "--repo", "<room>",
             "--participant", "openai-research", "--state-dir", "<state>",
             "supervisor-import", "--response", "<path>"]}
```

`--response -` reads the document from stdin instead.

## No hidden conversational state

A fresh ChatGPT session continues from the packet, the Agent Room thread, the
repository evidence and prior supervisor messages. Nothing requires memory from
an earlier window — proven by a subprocess that reconstructs senders, types,
evidence locators and acknowledgement state from artifacts alone.

## Verified handoff

Live, `2026-09-23`, disposable room, **nothing transcribed by a human**:

1. `claude-code` posted an evidence-citing claim to `openai-research`;
2. `supervisor-export` emitted the packet — `context_sha256=196cd0e3…`, the
   `repo`/`commit`/`path`/`lines` locator carried intact;
3. a response bound to that hash was piped to `supervisor-import`;
4. it posted as `openai-research`, `via=agent-room-supervisor-import`, parented
   to the claim; acknowledged after the durable post; `verify_store()` → 2.

Stale protection, separately and live: after a new message was appended, the
context moved `dedc356a… → 816a8622…`, replaying the earlier review exited **2**
with `StaleSupervisorContext`, **nothing was posted**, no traceback leaked — and
the same review succeeded once re-bound to a fresh export.

**What remains for the supervisor:** issuing those two bridge requests from the
ChatGPT side. The boundary, the binding and the bridge contract are proven here;
the composing of a real review is the supervisor's own act.

## Boundaries held

No local OpenAI API key or model process, no bridge modification, no live
`agent-room` branch, no merge, no NEWI change, no autonomous loop. A test
asserts a handoff leaves the working repository byte-identical.

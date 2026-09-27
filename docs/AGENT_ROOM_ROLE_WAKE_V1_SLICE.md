# Issue 16 source prerequisite slice — BLOCKED

Historical pre-Issue-17 status, retained to explain the inherited uncommitted
work. Issue 17 supersedes the source-only/no-deployment scope and coding-worker
home denial; current implementation/operation is documented in
`AGENT_ROOM_TASK_DISPATCH.md` and `AGENT_ROOM_OWNER_HOME.md`. Statements below
describe the earlier slice, not the current qualification state.

This change is not Role Wake V1 activation. The signed webhook still accepts
only `refs/heads/agent-room-control`; an `agent-room` push remains refused.
TransportWorker's operation allowlist, trust policy, release path, human
authority, service units and timers are unchanged. No scheduler, broker,
polling loop or GitHub Actions workflow is added.

The implementation contract available locally was the execution prompt at
base `88d33d5992224da86ded5b802d1e13e453693999`. Issue #16's authoritative
comments and the frozen #265 external registry were not available in this
checkout; the source-only task forbids retrieving them from the web.

## Implemented boundaries

* Webhook ingress handles one request per connection. The existing serial
  server bounds active handlers to one, with an accept backlog of eight.
  Reads share a ten-second absolute deadline and an 80 KiB total byte budget;
  the body remains capped at 64 KiB. Duplicate framing or authentication
  headers, transfer encoding, short bodies and `100-continue` are refused.
  A slow peer cannot reset the request deadline by sending individual bytes.
  Control pushes and signed pings keep their existing wake behavior.
* Production coding-role configuration requires `enabled` to be a JSON
  boolean. Codex also requires the exact `model` value `gpt-6-astra`. Unknown
  fields and alternate refs/remotes fail closed. Configuration is loaded
  from the existing fixed root-owned path after custody verification.
  Both example configurations are disabled. Old configurations lacking the
  new fields fail closed; there is no implicit enablement or model fallback.
* A disabled role returns without constructing a signer, room, or client.
  Existing UID/key/workspace custody remains in force. The fixed Codex
  invocation supplies Astra explicitly, keeps the read-only sandbox and
  ignores user configuration. No message or environment field chooses argv.
* The coding worker takes its existing role lock without waiting, then
  fetches the fixed room ref into the existing bounded verification
  quarantine. It verifies signatures and the role-local pinned checkpoint
  before installing the candidate, rechecks the remote tip, and accepts the
  verified checkpoint before selecting work. A wrong checkout, dirty clone,
  missing/corrupt checkpoint, rollback, or local unpublished divergence is
  refused. This path never resets away unpublished output. NoWorkAvailable
  returns clean idle. Coordinator behavior is unchanged.

Tests use deterministic HTTP peers, fake clients, and disposable Git/key
material. Mocked custody tests are not proof of deployed cross-UID isolation.

## Remaining Medium+ blockers

* There is no room-ref dirty/reconcile scheduler or fixed role-to-unit
  dispatcher. Disabled-role admission is implemented in the worker only;
  scheduling admission and concurrent/queued/multiple-work handling remain.
* Automatic eligibility needs an explicit recipient, broadcast/self
  rejection, closed sender/type allowlists, enabled-role checks, reservation
  and settled-state checks, and bounded scheduling. Existing manual adapter
  selection is not qualified for automatic invocation.
* There is no content-derived verified work identity or durable
  queued/launch/settled/uncertain ledger. Invocation intent and validated
  output are not atomically journaled. At-most-one automatic invocation
  across crashes is therefore not established. Automatic scheduling must
  remain disconnected.
* Publication, acknowledgement and terminal-notification recovery must use
  persisted output without calling the model again. Local unpublished
  divergence currently stops admission; it is not recovered automatically.
* Explicit initial backlog enrollment is unimplemented. Existing unread
  traffic must not be enrolled by simply enabling webhook room routing.
* Full Issue #16 adversarial tests remain, including invocation/launch crash
  ambiguity, ledger corruption, persisted-output republication, notification
  recovery, closed eligibility and fixed dispatcher mapping. Registry/issue
  contract reconciliation and actual cross-UID custody qualification remain
  prerequisites for a complete candidate.

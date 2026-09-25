# S4-C2 — remote-head-bound manual reservation

Authority: Issue #13 comment 5826554760. Base:
`fac06a60937ecb067249b0ce7881e6f833b571ab`.
Implementation correction only, **not S4 qualification or activation**.

## Production invariant

`verified remote H -> full authorise(H) -> signed R directly on H -> CAS H→R`

The existing guarded, model-free `release_worker` supplies its fixed role-local
`checkpoint.json` and `state/release-reservation.json`. Requests cannot choose
these paths. Bootstrap the checkpoint using the existing out-of-band genesis,
tip and policy ceremony; a missing checkpoint is not auto-bootstrapped.

`release_delivery.RemoteReservation` reuses `RoomRemote` fetch/lease and
`TrustCheckpoint` signed-room/monotonic verification under the room writer lock.
It verifies a candidate before installation and confirms the exact remote ref.
Rollback, replacement, missing refs and unavailable state grant no permission.

Every fresh attempt runs the complete existing `release.authorise()` gate:
latest effective human decision/provenance, request/action/binding, measured
snapshot/context, project identity, unreviewed messages, nonce/receipt state
and key validity. A moved remote requires proof of absence and full
reauthorization, not rebase. At most three fresh attempts run per invocation.

`append_receipt` cannot auto-publish a remote `uncertain` receipt. The release
transaction appends locally and uses an exact lease. Generic push/rebase also
rejects provisional reservations. Ordinary participant delivery is unchanged.
No generic privileged push, command, executor or signer endpoint is added.

## Durable recovery

The role-local journal binds room/ref/remote/checkout/target/checkpoint. It
fsyncs the exact signed intent, authorization and parent H BEFORE commit/push,
then records the actual commit R. Atomic replacement and directory fsync
precede publication/permission. It is bookkeeping, not a second trust root.

| Verified observation | Behavior |
|---|---|
| Exact artifact/commit present with original direct parent H | Persist nonce consumption before returning permission. |
| Absent on verified remote-confirmed history | Discard only the exact provisional local child; install verified state; fully reauthorize before constructing another receipt. |
| Unavailable/invalid state or mismatched artifact/ancestry | `action_permitted=false`; retain pending identity; no second reservation. |

The next invocation first reconciles the exact pending transaction, even if
the root-authored ticket changed. Recovered presence reports reserved/uncertain
and requires manual reconciliation: it never grants a second permission to
act. This covers a caller losing the result after permission was issued. A
crash after durable consumption but before return also leaves the nonce
consumed. A reconcile ticket cannot bypass unknown publication.

## Withdrawal semantics

Before successful reservation, the latest signed human decision controls
release. Rejection before reserve, or between authorization and CAS, blocks
publication. A newer approval must be evaluated anew and named by the new
reservation on its actual authorized parent.

After R is committed, the nonce is already `uncertain`: a manual side effect
may have begun. Later rejection does not erase R or prove that nothing
happened. Explicit `reconcile()` records `executed` or `failed`; it executes
nothing. No cancellation guarantee is invented. The separate manual action
still needs its own preconditions.

## Scope, tests and residuals

`tests/test_agent_room_release_c2.py` covers A–J with real disposable remotes
and signatures. Fault hooks alter scheduling/acknowledgements only, not gates
or verification. It includes fresh-process recovery and crash boundaries.
Local-only `remote=None` library tests retain explicitly local semantics and
are not production release evidence. Remote calls without checkpoint/recovery
paths fail closed; the fixed worker is the production manual entrypoint, not
the generic development CLI.

Journal/checkpoint integrity depends on C1 custody. Arbitrary release-UID/root
compromise is not solved here. Operational no-force-push protection remains
necessary: unseen rewritten history cannot be reconstructed from Git alone.

Real cross-UID denial, installed unit/drop-in/ACL behavior and credentials are
**NOT TESTABLE UNTIL DEPLOYMENT**. The `pr0 -> NOPASSWD: ALL` activation blocker
is unchanged. No users, production credentials, services or policies are
installed by C2. S4 remains NOT QUALIFIED pending a separate review.

# C3: transport lifecycle serialization and durable provenance

Implementation correction to the failures reproduced at
`c42c0945dd485a5f3c243c80d9f08c01c61bf638`, Issue #13 comment 5827617038.
This is not deployment or independent certification.

## One worker, one mutable lifecycle

`TransportWorker.run()` first acquires `transport-worker.lock` under its
service-owned `state_dir`, before reading any ledger, checkpoint, queue or
working checkout. Production custody pins that directory to
`/var/lib/agent-room/state`. The root must be owned by the running role and
0700; locks are regular owner-owned 0600 files with one link. Every directory
component is opened without following symlinks. Lock names are fixed, not
request arguments. No bypass/config flag exists.

Linux `flock` covers all recovery, sync, processing and delivery in that run,
including exceptional exits. Another process waits at most five seconds and
then returns a structured failed/busy lifecycle with zero requests performed.
Normal exit, exception and death release the kernel lock. The lock file is
never deleted or replaced on release. Systemd single-unit serialization is
additional protection, not the correctness argument.

The service root is an authority boundary: a process allowed to replace its
own arbitrary state files is not contained by advisory locks. C1 must establish
real cross-UID custody before deployment. Separate configs pointing multiple
state roots at the same writable checkout are not a supported production
layout; custody pins the unique layout.

## Stale objects do not overwrite newer durable state

A separate fixed `transport-state.lock` serializes short state transactions.
Processed/pending ledgers compare exact bytes read at construction against
the current file while holding this lock. A stale object fails closed: callers
must reload and reconcile, never overwrite or silently merge a stale removal.
Monotonic revisions distinguish later writes, including identical-looking
content. Completed request entries cannot be removed or changed. Pending
results/imports may be cleared by the existing proof-driven worker paths; an
unrelated newer addition invalidates the stale snapshot before any write.

Control anchors cannot be written through generic `set()`/`save()`. The narrow
`advance_control()` re-reads disk under the state lock, verifies control
history, the pinned genesis and the exact advertised remote head, and checks
the proposed tip against the *current durable* tip using actual Git ancestry.
Equal-tip idempotence is allowed; regression, unrelated ancestry, repinning
and local-only advancement in remote mode are refused. This occurs before
installing the control candidate. `None` remote is the existing explicit
local test mode, not an absent/refused production remote.

State writes use exclusive owner-only temporary files in a no-symlink pinned
directory, fsync the file, replace atomically and fsync the directory. Crash
recovery sees old-valid or new-valid state. An interrupted temporary file is
not consulted as authority.

## Linear control history

Before interpreting path changes, the control store requires exactly one
zero-parent genesis and one parent for every later commit. All merge commits
are rejected, including apparently harmless additions. Existing closed
namespace, modes and add-once/no-modify/no-delete rules remain unchanged.

## Reservation provenance

The first `uncertain` receipt binds the decision which authorized reservation.
Every terminal receipt retains that decision ID even after a later rejection.
Full room verification rejects a terminal artifact that substitutes a different
decision ID. This does not erase an uncertain side effect or grant a second
reservation. C2 exact-head authorization/CAS and its recovery path are unchanged.

## Regression and verification boundary

`tests/test_agent_room_transport_c3.py` covers real overlapping processes,
bounded busy refusal before state reads, crash before/after anchor replace,
stale protected objects, pending/processed preservation, path substitution,
merge-only request/result changes and provenance under later rejection.
Existing C1/C2/S1–S3 checks remain applicable.

After source freeze, verification must use a fresh detached checkout and
separate read-only probes. Same-provider verification is not independent
provider certification. Real cross-UID canary/ACL/system-service/credential
evidence remains **NOT TESTABLE UNTIL DEPLOYMENT**. `pr0 -> NOPASSWD: ALL`
remains an independent activation blocker. No deployment, user/key creation,
policy change, production service start, merge or activation is authorized.

The prior audit also reported that `RuntimeMaxSec` is ignored for the supplied
oneshot transport template; `TimeoutStartSec=600` remains the configured
startup limit. That Low template/documentation observation is not silently
claimed fixed by these four C3 corrections.

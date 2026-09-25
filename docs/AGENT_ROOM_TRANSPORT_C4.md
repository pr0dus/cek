# C4 — protected state and bounded Git ingestion

Scope: the two C3-V Medium findings only. No deployment, activation, custody
policy change, credential provisioning or Low-finding correction. S4 deployment
evidence remains separate. The C3 lifecycle lock and C2 reservation CAS remain.

## Protected state is not a hint

`protected_state.py` validates existing transport state by kind, on load **and
before atomic write**. Revision is a non-negative integer (not bool); timestamps
have the canonical UTC spelling. Control genesis/tip are full OIDs. Processed
ledgers require all three maps, UUIDv7 keys, typed completion/result/uncertain
delivery records and their cross-bindings. A release journal requires its exact
identity and pending-intent shape/bindings; C2 still checks signed content and
actual history before any permission.

Only ENOENT creates initial state. Null, truncated JSON, missing fields, wrong
containers or half-initialized objects are errors, not migrations. Protected
state reads are capped at 16 MiB. There is no deployed legacy schema migration
in this patch. Existing incomplete records require explicit operator recovery,
not deleting continuity state to get past validation.

Checkpoints also require generation, policy digest and canonical timestamps;
missing generation can no longer disable rollback comparison. Cursors require
an acknowledgement map and timestamp-bearing entries; null/missing maps and
symlinks fail instead of resetting read state. Participant adapters derive turn
recovery from committed room history plus these cursors; no additional turn
database was introduced.

## Ingestion sequence

All room/control candidate fetches, release reconciliation, and the generic
library's delivery/rebase fetches use `git_ingestion.fetch_verified`:

1. Inventory the existing authoritative ODB, including unreachable and partial
   objects. Refuse shallow/alternate/promisor/replaced/grafted history. Do not
   prune trusted history to fit a budget.
2. Acquire the fixed private quarantine lock in the common Git directory.
   Remove only its previous disposable `attempt` directory. The private-root
   checks reject symlinks and unsafe ownership/modes. No request selects a path.
3. Initialize a fresh, empty, same-object-format repository, with no templates,
   alternates or local-object hard links. Fetch **one exact branch ref** there.
4. Enumerate its complete reachable object graph, enforce count and expansion
   budgets, run strict Git fsck, and verify the full protocol there. Control
   verifies linear/add-only closed namespace, pinned genesis/accepted ancestry
   and payload limits. Authenticated room consumers verify their pinned trust
   and checkpoint. Generic legacy unauthenticated library mode remains explicitly
   unauthenticated; it still verifies its complete room/schema/history contract
   and genesis. It cannot be used by an authority-bearing release path.
5. Check evidence locators both against the quarantine and objects already in
   the original ODB: isolation must not turn a known bad local artifact into an
   allegedly unavailable foreign locator. No external evidence is fetched.
6. Export **only the verified reachable graph** as one pack; index it strictly.
   Budget the cumulative persistent store before promotion. Atomically rename
   pack/index, fsync, then update only the candidate ref. Existing working-branch,
   checkpoint, anchor and remote-CAS checks still happen before installation.
7. Remove quarantine on success and every handled failure. A crash leaves at
   most one bounded attempt. The next locked attempt removes it before fetching.

## Fixed limits and enforcement

These are source constants, not control-request fields or environment overrides:

| Boundary | Limit |
| --- | ---: |
| Each Git-written file, enforced by inherited kernel RLIMIT_FSIZE | 16 MiB |
| Each ingestion Git process virtual address space, RLIMIT_AS | 512 MiB |
| Each ingestion command stdout/stderr | 16 MiB each |
| Each ingestion command wall time | 120 s; process-group teardown |
| Reachable object count | 20,000 |
| Single uncompressed object | 1 MiB |
| Aggregate reachable uncompressed objects | 32 MiB |
| Persistent ODB accounted bytes at promotion | 128 MiB |
| Persistent ODB filesystem entries at inventory | 40,000 |
| Control request/result object | 256 KiB (unchanged) |

`/usr/bin/prlimit` is mandatory; missing/failed enforcement fails closed. Core
dumps are disabled for those children. File bounds are **live**, not a post-fetch
`du` test. Fetch forces `--keep`, `fetch.unpackLimit=0`, `transfer.unpackLimit=0`;
Git receives one pack plus its index instead of unpacking into an unbounded
number of loose files. No automatic tags, FETCH_HEAD, reflogs, submodules,
commit-graph writing, auto-GC or maintenance are enabled in quarantine. Refmap
is explicit and empty apart from the one destination ref.

The byte bound relies on this fixed trusted Git command mode, not on an
arbitrary program writing arbitrary files. Fetch creates a pack/index (and
small fixed lock/keep/ref files); reachable-only export creates a second
pack/index. With single-attempt locking and per-file bounds, a conservative
256 MiB regular-file payload allowance covers the fixed quarantine working set.
There is no attacker-selected checkout/file fanout. Filesystem block/metadata
overhead and whole-unit aggregate process memory are distinct from byte and
per-process address-space limits; real installed service/cgroup/quota enforcement
remains **NOT TESTABLE UNTIL DEPLOYMENT**. This patch does not change host policy.

Inventory counts `max(st_size, st_blocks*512)` and includes rejected old/orphan
objects already present before C4. No silent maintenance occurs. Budgets may
refuse a legitimate sufficiently large room; explicit archival/maintenance
policy is required then. Local messages still use the existing write/payload
bounds; this limit specifically controls remote ingestion/promotion, not every
other application or operator writing to the same filesystem.

## Crash and rejection semantics

A protocol-invalid or over-budget candidate is never promoted. Repeated unique
rejects leave the authoritative ODB byte-identical. A crash after verification
may leave an already-verified pack without its index, but no trusted ref/state
advances. Recovery revalidates and completes the same bounded promotion. Missing
or conflicting pack bytes fail closed. No protected-state reset is performed.

Tests use disposable remotes, real kernel file limits, a bounded 17 MiB random
pack test, aggregate many-small-object expansion, repeated unique rejects,
normal signed-room/control traffic, process death at fetch/verification/promotion,
and a sparse pre-existing over-budget file. Reduced trusted-code constants in
two boundary tests are explicitly test-only, not request configuration.

## Still outside this correction

- The retained Low: RuntimeMaxSec with Type=oneshot. Not edited under the latest
  owner's narrower C4 instruction.
- Actual cross-UID custody, SSH credentials, installed-unit policy and cgroups:
  NOT TESTABLE UNTIL DEPLOYMENT, not PASS.
- Existing passwordless-sudo activation blocker unchanged.
- No production identities/credentials, deployment, activation or merge.

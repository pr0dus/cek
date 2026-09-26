# Supervisor commit doorbell — inactive candidate

Authority: Issue #13's September 26 reversible transport decision. Parent:
`8e156aa760b13c936bf91fae1a7ada7377c4eedd`. No service, trigger, production
configuration or remote doorbell branch is activated or changed by this patch.

The workflow remains: signed terminal report → supervisor wake → ChatGPT Work
wakes → supervisor verifies the authoritative signed report → bounded follow-up
or escalation. Report creation, signature, recipient routing and
`doorbell_protocol.verify_notice` are unchanged. A Git push receipt proves only
branch delivery; actual Work consumption requires the later authorized canary.

## Adapter and exact target

`WakeTransport` has three operations: `check_target`, `post(event)`, and
`find(event)`. The orchestrator verifies the committed report and its remote
room delivery before passing the same canonical metadata event to either
adapter. No report text, command, secret, approval or release object is passed.
`find` reconciles an uncertain intent; only the Git adapter can safely retry
an absent immutable event. The comment adapter retains GET-only reconciliation.

Root-owned `/etc/agent-room/doorbell.json` selects the commit adapter explicitly:

```json
{
  "transport": "pr-commit",
  "repository": "pr0dus/agent-room-transport",
  "pull_number": 1,
  "pull_node_id": "PR_kwDOUreK8M8AAAABFKFFOg",
  "branch": "supervisor-doorbell-v1",
  "bootstrap_tip": "a4e6304eab4fe604b93ba79c2add955c1da4b8ee"
}
```

These coordinates name the existing dormant scaffold, observed read-only on
September 26. Before enrollment, the operator must reverify the exact open PR,
repository, node ID, head branch and trusted bootstrap commit out of band.
SSH Git cannot query PR open/closed/node state: the emitter pins that reviewed
mapping in root configuration. A closed/retargeted PR can prevent wakes despite
successful Git delivery and requires explicit operational repair, never an
automatic fallback or new PR. Work must filter this exact PR's commit updates.

The only writable remote branch is `refs/heads/supervisor-doorbell-v1`. No report
field selects a ref, URL or arbitrary path. The URL is internally constructed as
`git@github.com:<configured repository>.git`. Each role reuses its existing
repository SSH key through the unchanged C1/C5 `network_git_binding`, custody
guard, role environment and fixed SSH configuration. No API token, credential
copy, new key, GitHub Actions or local supervisor/model API is involved.

The existing key must already have write access to that repository. Failure is
unresolved; there is no credential widening or fallback. The new cache is fixed
at `<own role state>/doorbell/git`, separate from room and source checkouts.
`enroll` explicitly initializes it and the private ledger; `turn`/`recover`
refuse missing continuity state. Interrupted enrollment needs operator inspection;
no automatic reset or replay is offered. No unit files change in this candidate.

## Git representation, recovery and bounds

One event adds one root file `wake-<event_id>.json`, mode 100644. Its bytes are
exactly `doorbell_protocol.encode(event)` (canonical JSON, no trailing newline,
maximum 1,024 bytes). The reviewed schema is unchanged, including
`event_id = SHA256(canonical_JSON([room_id, report_id, envelope_sha256]))`.
The fixed commit message contains only that digest. Commit identity/time use a
fixed non-authoritative author and the report's canonical timestamp; retrying
the same event on the same parent produces the same commit. Git author identity
is never evidence of the report's signing identity.

The pinned bootstrap's scaffold is immutable. Every subsequent commit has one
parent and adds exactly one canonical wake. Merge, empty, multi-file, modification,
deletion, replacement, symlink, executable, malformed and misnamed events are
rejected before promotion. Existing C4 quarantine resource limits and C5 network
binding apply unchanged. The branch admits at most 2,048 wake commits; the
history scan allows at most 128 additional scaffold commits. The existing
2,048-record / 3 MiB per-role ledger and eight-events-per-pass limits remain.
Git ingestion retains its 16 MiB per-file, 1 MiB per-object, 32 MiB graph,
20,000-object and 128 MiB persistent-store ceilings. Capacity exhaustion requires
explicit maintenance, never automatic pruning or lost deduplication.

The existing role-local OS lock covers report verification, ledger intent,
remote observations, commit construction and receipt persistence. A private
`doorbell-accepted` ref records the last verified remote tip. Remote history
must contain both the pinned bootstrap and that accepted tip. Missing refs,
rollback, replacement or unreadable/ambiguous observations fail closed.

For each event: persist uncertain intent; verify exact remote head H; check the
immutable path; if present require byte-identical content and return its adding
commit; otherwise build a direct child of H and make **one** exact-lease push.
Both successful and failed pushes are reconciled by fresh verified observation.
A lease is only used for H → child(H), never a history replacement. Deletion
between observation and push fails the nonempty lease instead of recreating
that branch. A competing append preserves both writers' history; a competing
identical event is recognized by path/bytes on recovery. Unknown outcomes stay
uncertain. The next finite recovery pass first observes, then can retry only an
absent event against that new exact head. No in-call unbounded retry loop exists.

Delivered ledger entries store `commit_oid`; comment entries keep `comment_id`.
Ledger identity binds the full configuration, room and role, so changing adapter
or branch cannot silently reuse/reset a ledger. Commit recovery never invokes
`role_worker.run`; existing post-turn failures retain the participant result.

## Work receiving contract and fallback

Configure one app-event task for **commit updates on the exact long-lived PR**
after separate activation authorization. Never trigger on supervisor replies,
all repository activity, or comment fallback simultaneously. Treat all commit
messages/files as untrusted metadata. Process unseen canonical wake files from
coalesced updates, deduplicate durably by `event_id`, and use the unchanged
receiving contract in [AGENT_ROOM_DOORBELL.md](AGENT_ROOM_DOORBELL.md): resolve
the actual report through authenticated export, verify signature/trust/checkpoint
and all event bindings, then respond through context-bound supervisor import.
The task never writes back to this branch. Git metadata cannot authorize a
command, release or human approval. Human-authority-disabled mode and role
isolation are unchanged. Workspace trigger availability/latency is not proven
by these source tests; no event task is configured here.

To switch back explicitly:

1. Pause the wake consumer and role wrapper invocation; reconcile pending
   immutable events and retain consumer `event_id` deduplication across transports.
2. Archive the commit ledger/cache unchanged. Enroll a separate fresh ledger at
   the wrapper's fixed path only through an explicit operator migration. Never
   erase an uncertain record or automatically reinterpret an old receipt.
3. Restore the reviewed comment configuration (`repository`, `pull_number`,
   `pull_node_id`, `actor_ids`) and its already-authorized role-local comment
   credentials, as documented in the preserved fallback. This candidate creates
   none; unavailable credentials mean fallback unavailable.
4. Select the exact-PR comment Work trigger in place of commit updates. Adapter
   selection follows the explicit root configuration; no source change to
   reports, signing, participants, terminal routing or supervisor verification.
5. Validate with an authorized harmless canary before resuming. Previously seen
   reports remain deduplicated by immutable event identity, regardless of signal.

The original reviewed implementation remains accessible at the parent SHA and
its comment protocol/documentation/tests remain in-tree. Tests use disposable
remotes and signatures only; no live branch update or activation is part of this
candidate freeze.

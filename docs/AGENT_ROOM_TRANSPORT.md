# Agent Room — narrow supervisor transport (Stage S3)

Issue #13, Stage S3. S1 and S2 made the *artifacts* trustworthy. This stage is
about the *operating path*: making the unattended route narrow enough that a
write to a control repository cannot become a shell, and that the trust state
is not owned by the principal a broad bridge already controls.

**Nothing here is deployed.** No system user, no service, no timer, no
repository, no credentials. The templates and procedures are versioned for
review; installing them is a later human-gated step.

---

## 1. What the existing bridge actually is — measured, read-only

Re-audited on 2026-09-24. The service was not modified.

| Property | Observed |
|---|---|
| unit | `~/.config/systemd/user/chatgpt-ubuntu-bridge.service` |
| runs as | `pr0` (no `User=`; it is a user unit) |
| `systemd-analyze --user security` | **9.8 UNSAFE** |
| `UMask=` | `0002` — group-writable by default |
| `CapabilityBoundingSet=` | full default set (40 capabilities) |
| `NoNewPrivileges` / `ProtectSystem` / `ProtectHome` / `PrivateTmp` / `PrivateDevices` | all off |
| `SystemCallFilter` / `RestrictAddressFamilies` | none |
| worker | `/home/pr0/.local/share/chatgpt-ubuntu-bridge/bridge_worker.py`, `pr0:pr0` `755`, in a `775` directory |
| control repo | `~/.local/share/chatgpt-ubuntu-bridge/control-repo`, `pr0:pr0` `775` |
| `run_command` | still accepts an arbitrary argv, still `subprocess.run` |
| `elevate_bridge_codex_exec()` | still present; still injects `--approve-for-me` |
| service environment | `USER`, `HOME`, `PATH` only — no credential names, no values |
| MainPID / restarts | 1589 / 0, active |

### The finding that governs everything else

```
$ sudo -n true      →  succeeds
$ sudo -n -l        →  (ALL : ALL) NOPASSWD: ALL
```

**`pr0` has non-interactive root.** So a shell as `pr0` — which a write to the
bridge's control repository already yields — is a shell as root, one `sudo`
away. Unix-user separation therefore **cannot** protect Agent Room state from
the existing bridge on this host as it stands.

That is not something S3 fixes. Changing sudo policy is a server security
change and is human-gated. It is recorded here as an **activation blocker**:
the dedicated-user boundary in §7 is real and correct, and it is worth
nothing on this machine until passwordless root for `pr0` is resolved. The
permission-boundary script refuses to report success while it holds, rather
than reporting a boundary that does not exist.

The existing bridge stays running for deliberate manual maintenance. It must
not be the unattended Agent Room path, and no Agent Room timer or service may
call through it.

---

## 2. The transport protocol

Three operations. The request schema has no field in which anything else can
be expressed — that is the design, not a filter in front of a larger surface.

```json
{ "control_schema_version": 1,
  "request_id": "<uuid7>",
  "created_at": "2026-09-24T12:00:00Z",
  "operation": "supervisor_export" | "supervisor_import" | "status",
  "params": { … } }
```

Any other top-level field is **refused**, not ignored: an ignored field is a
field somebody is trying.

| Operation | Params | Effect |
|---|---|---|
| `supervisor_export` | `{"message_id": <uuid7>\|null}` | one deterministic supervisor packet, read-only |
| `supervisor_import` | `{"response": <context-bound response document>}` | one reviewer message, signed by the service key |
| `status` | `{}` | room id, tip, verified count, trust generation, checkpoint tip |

### What cannot be said

There is no field for: command, argv, shell, interpreter, cwd, filesystem
path, repository, remote, branch, refspec, signer, key id, key path, room id,
message id, thread, parent, recipient, sender, decision, receipt, action,
trust-policy update, checkpoint path, release operation, proof, model
invocation, tool profile, or permission widening. Unknown operation and
unknown field both fail closed.

`agent_room/transport.py` and `control_store.py` contain no `subprocess`,
`exec`, `eval` or shell reference at all. The whole transport has **one**
subprocess surface — `remote_sync.run_git` — whose argv is built from
constants, configured names it validated, and object ids it read from Git
itself. Static tests enforce this, scanning code with comments and docstrings
stripped, because scanning raw text finds the modules' own prose about not
having one.

### It is not a signing oracle

The service will hold the `openai-research` ingress key. The only way untrusted
input produces a signature is a successful, context-bound
`SupervisorBoundary.import_response`. Everything about the resulting envelope
except its reviewer content comes from service configuration and room state:
identity, key id, method, room id, message id, thread, parent, recipient.

The response type is further restricted to an explicit reviewer allowlist —
`observation, hypothesis, claim, evidence, test_result, question, challenge,
proposed_test, answer, retraction`. Refused with reasons: `approval` and
`rejection` (human authority is not the transport's to exercise),
`execution_receipt` (a receipt consumes a human approval), `decision_request`
(it puts a consequential action in front of a human), `handoff` (routing is
orchestration, not review). A response may not carry an `action` or set
`human_approval_required`.

### Residual risk, stated rather than softened

A compromised control-repository credential **can** inject a bounded reviewer
response into a thread genuinely awaiting supervisor input. It cannot obtain
shell, filesystem, human, release, trust-policy, receipt, model-execution or
generic-signing authority, and human approval still gates every consequential
action.

What this transport authenticates is the channel's *effects*, not its author.
The repository credential is **not** an independent cryptographic identity for
ChatGPT, and nothing here pretends it is. If reviewer-content injection is
judged too strong a residual, the answer is a supervisor-side signing identity
— a separate design, not a tightening of this one.

---

## 3. The untrusted control branch

A closed namespace, on its own branch, in the dedicated private repository:

```
README.agent-room-control.md                  immutable genesis
.agent-room-control/requests/<uuid7>.json     append-only, immutable
.agent-room-control/results/<uuid7>.json      one per request, immutable
```

Regular non-executable files only. Symlinks, gitlinks, executable bits,
`.gitattributes`, `.gitmodules` and hooks are all refused. Strict JSON with
duplicate-key rejection, exact schema version, uuid7 request ids.

Append-only: a request that is modified, deleted or re-added fails the history
scan. A duplicate identical request is idempotent; the same id with different
content is a conflict and is never overwritten.

### Bounds

| Limit | Value |
|---|---|
| request artifact | 256 KiB |
| result artifact | 256 KiB |
| pending backlog | 256 (beyond this the worker refuses to scan) |
| requests per invocation | 8 |
| tracked control paths | 4096 |
| Git command | 60 s, 8 MiB output |
| worker deadline | `worker_timeout_seconds`, enforced across the run |
| service runtime | `RuntimeMaxSec=900` — the cgroup-level hard stop |

Oversize input fails before anything durable or expensive happens.

---

## 4. Synchronisation, verification and delivery

The worker owns the whole lifecycle. Nothing outside it runs Git for Agent
Room — the previous version operated on local checkouts, which is either a
service that never sees new work or an unspecified broad synchronisation path,
and both are what S3 exists to remove. Measured against that version:

```
REMOTE_ONLY_REQUEST_SEEN        processed 0   — the worker never saw it
LOCAL_RESULT_REACHES_REMOTE     on_remote false
REMOTE_CONTEXT_RACE_SAME_THREAD posted        — a review of a head that had moved
```

### The run, in order

1. **Recover.** A crash can leave a room commit that was never pushed. If the
   remote already has it, it stays; otherwise it is discarded back to the last
   accepted checkpoint. Nobody has seen an undelivered commit, so discarding
   it loses nothing durable — and keeping it would mean either delivering a
   review of a head that has since moved, or carrying an unauditable local
   divergence forward.
2. **Synchronise the room.** Fetch the fixed remote ref onto a **separate
   local candidate ref**; verify it *there* — genesis, descent from the
   accepted checkpoint, policy generation and digest, and the full S2
   verification of that exact candidate; install with `merge --ff-only` only
   after it passes; then persist the checkpoint for the state now installed. A
   candidate that fails leaves the local room exactly where it was. This is
   deliberately not `git pull` or fetch-then-reset, both of which install
   first and check afterwards.
3. **Synchronise the control queue.** Fetch, verify closed namespace and
   append-only history on the candidate, require descent from the service's
   own anchor, install.
4. **Deliver.** Results this service produced but has not confirmed on the
   remote go out before any new work is taken on.
5. **Process.** Bounded new requests, each against verified state.

If any of 1–4 fails, the run reports a lifecycle failure and processes
nothing: no export, no import, no status, no result claiming success for work
that was never attempted, and no checkpoint movement.

### Delivery is a compare-and-swap

A supervisor response reviewed against head H must not be rebased onto H+1 and
delivered as though it still applied. The generic `GitMessageStore.push()`
rebases on a non-fast-forward, so the transport's room store is constructed
with **no remote** and delivery is done here instead:

1. synchronise and verify remote head H;
2. the import boundary checks `context_sha256` against H;
3. sign and commit the response locally on top of H;
4. push with `--force-with-lease=refs/heads/<room>:H` — it lands only while
   the remote is still H. The push is a fast-forward from H, so the lease is
   an atomic comparison and never discards valid history;
5. if the ref moved: discard the local commit, re-synchronise, recompute the
   reviewed thread's context against the new head. **Changed context fails
   stale and is not delivered.** Identical context — an unrelated thread
   moved — may be reconstructed and retried, at most 3 times;
6. after delivery, re-observe the settled head and advance the checkpoint.

No request field supplies or overrides any ref, remote, repository, path,
checkpoint or policy.

### Control egress

Push the exact ref; never forced. On a non-fast-forward, fetch and verify the
remote candidate first, then re-apply the pending results on top — request and
result paths are unique per id, so nothing of the other writer's is discarded
and nothing of ours is overwritten. An identical result already present is
idempotent; a *different* result at the same id is a conflict and fails
closed. Bounded at 3 attempts.

## 5. Result authenticity: what a forged result can and cannot do

The control-repository writer is in the threat model and can write a
syntactically valid `results/<request_id>.json`. So: **how does anyone know a
result came from the worker rather than from that writer?**

The answer taken here is option B — control results are **untrusted
telemetry, never authority** — with one thing made explicit that was
previously an unexamined trust decision.

The worker does **not** decide what to run by looking for result files. It
keeps a service-owned ledger in its own owner-only state directory and selects
requests that are not in it. A forged result therefore cannot make the service
skip an operation. The earlier version filtered by "has a result", which handed
that decision to the attacker; a regression now covers it.

For success claims, every result carries `room_tip` — the room head at
completion — which the far side can check against the signed, checkpointed
room rather than trusting the artifact's provenance.

What a forged result *can* do, stated as the documented limit: because
artifacts are immutable, a pre-written result at a request id means the real
result can never be stored there, and the worker records a `conflict`. That is
a denial of service by a party that could equally stop sending requests. It
cannot cause or suppress a consequential Agent Room side effect: selection is
ledger-driven, and the room mutation is idempotent through the participant
turn protocol.

---

## 6. Replay, crashes and races

- Each immutable request id is processed at most once, decided by the
  service's ledger — not by the presence of a result in the untrusted queue.
- A crash after the room mutation but before the result write reconciles on
  restart rather than importing twice: the participant turn protocol finds the
  durable response and returns `already_responded`. There is a regression for
  exactly this window.
- A stale supervisor context is never "retried with force" — it is recorded as
  a failed result and the reviewer re-exports.
- Ambiguous push outcomes use the existing three-valued delivery rules.
- A malformed or forbidden request produces a bounded failure result and no
  side effect.

---

## 7. Filesystem, Unix identity and key separation

### Root-owned, immutable

```
/opt/agent-room/<frozen-sha>/        root:root, 0755 — the reviewed code
/opt/agent-room/current -> <sha>     root:root symlink
/etc/agent-room/transport.json       root:root, 0644 — paths and bounds, no secrets
/etc/agent-room/trust-policy.json    root:root, 0644 — public verification material
```

The unit executes `/opt/agent-room/current`, **never** `/home/pr0/projects/cek`.
The worker has no trust-update operation, so it does not need to write the
policy.

### Service-owned, owner-only

```
/var/lib/agent-room/                 agentroom:agentroom, 0700
  room/                              signed room checkout
  control/                           untrusted control checkout
  checkpoint.json                    0600
  state/                             participant cursor
  keys/openai-research.ed25519.pem   0600
  keys/transport_deploy_key          0600 (if file-based)
```

`UMask=0077`, `StateDirectoryMode=0700`, `InaccessiblePaths=/home/pr0`.

### Keys the service holds, and does not

| Holds | Does not hold |
|---|---|
| `openai-research` ingress signing key | human credential (device only) |
| repository transport credential | Claude signing key |
| | Codex signing key |
| | release-recorder key — the transport writes no receipts |
| | general GitHub/source credentials |

**No production key is generated by this stage.**

---

## 8. Least-privilege repository and credential design

A **dedicated private repository**, used only for Agent Room transport and
control, separate from public `pr0dus/cek`, from the authoritative NEWI/CEK
source repositories, and from the existing generic bridge's control repository.
It is **not created here**.

For the Ubuntu side, a repository-scoped **write-enabled SSH deploy key**:

```
Host agent-room-transport
  HostName github.com
  User git
  IdentityFile /var/lib/agent-room/keys/transport_deploy_key
  IdentitiesOnly yes
  IdentityAgent none
  StrictHostKeyChecking yes
  UserKnownHostsFile /etc/agent-room/known_hosts
  BatchMode yes
```

`IdentitiesOnly=yes` and `IdentityAgent=none` matter: without them the service
could fall back to `pr0`'s agent or a global credential helper, which would
hand it far more than one repository. `known_hosts` is pinned from GitHub's
published keys at deployment, not learned on first connect. No secret value
appears in the unit environment or in argv.

Required permission: write to that one repository, nothing else.

For the ChatGPT/GitHub side, the narrowest installation scope actually
available must be measured at activation time — not assumed. Branch
protections and rulesets are defence in depth only; S2 signatures and the
checkpoint remain mandatory regardless of what the account plan offers.

---

## 9. The unit, and what it scores

A **one-shot service plus a timer**, not a daemon: the lifecycle and the
cgroup belong to systemd, each run is bounded, and a failure is a failed unit
rather than a wedged loop nobody is watching.

`deploy/agent-room-transport.service` — `systemd-analyze security --offline`:

```
→ Overall exposure level for agent-room-transport.service: 1.2 OK 🙂
   (the existing bridge, for comparison: 9.8 UNSAFE)
```

Every remaining exposure is inherent to a service that must reach a private
Git remote:

| Exposure | Why it stays |
|---|---|
| `PrivateNetwork=` (0.5) | the transport's whole job is a Git remote |
| `RestrictAddressFamilies=~AF_INET/INET6` (0.3) | same |
| `RestrictAddressFamilies=~AF_UNIX` (0.1) | local sockets for DNS/ssh |
| `IPAddressDeny=` (0.2) | a GitHub IP allowlist is brittle and would fail closed at the wrong moment |
| `PrivateUsers=` (0.2) | complicates `StateDirectory` ownership; re-test at deployment |
| `RootDirectory=` (0.1) | no image isolation attempted in S3 |
| `DeviceAllow=` char-rtc:r (0.1) | default under `PrivateDevices=yes` |

`SystemCallFilter=@system-service ~@privileged ~@resources`,
`MemoryDenyWriteExecute=yes`, `LockPersonality=yes` and `NoNewPrivileges=yes`
were each **measured** against the real workload — `python3`, `git
init/clone/ls-tree`, `openssl` Ed25519 sign and verify — under transient units
on systemd 255 before being written into the template. The score is evidence,
not the goal.

---

## 10. The detached-`setsid()` escape, closed in production

S1 documented, and still asserts, that `run_bounded()` cannot kill a
descendant which calls `setsid()`: `killpg` signals a process *group*, and the
child has left it. That test has not been weakened and must not be.

S3 closes the **production** escape with the cgroup, measured on this host:

```
unit          agent-room-cgroup-probe.service (transient, --user)
cgroup        /user.slice/user-1000.slice/user@1000.service/app.slice/…
parent        pid 355051  pgid 355051  sid 355051
child         pid 355053  pgid 355053  sid 355053   ← its own group and session
both in       the same cgroup
after `systemctl stop`   parent alive=no   child alive=no
```

The child escaped the process group and did not escape the cgroup.
`KillMode=control-group` with `SendSIGKILL=yes` reaches it; `Delegate=no` stops
the service moving itself out.

**Scope of this measurement, honestly:** it was taken with a transient unit
under the *user* manager, which reproduces the cgroup semantics but not the
dedicated system identity. The production configuration must be re-measured
after deployment (step 13 below) before S3 is considered qualified on the real
service.

---

## 11. Deployment, migration and rollback — *not executed*

1. Host precheck: pending security updates and reboot state (§13); resolve the
   passwordless-root blocker in §1 with the human.
2. `groupadd --system agentroom && useradd --system --gid agentroom
   --home-dir /var/lib/agent-room --shell /usr/sbin/nologin agentroom`.
   Confirm `pr0` is **not** in `agentroom` and `agentroom` is in no group `pr0`
   can write.
3. Install the reviewed frozen SHA to `/opt/agent-room/<sha>`, root-owned, and
   point `/opt/agent-room/current` at it.
4. Create the dedicated **private** repository (§7).
5. Configure the repository-scoped deploy key and pinned `known_hosts`;
   `0600`, owned by `agentroom`.
6. Create the room and control branches; record the room genesis and the trust
   policy digest **out of band** for the checkpoint pins.
7. Generate production participant/service keys at the human-gated step, on the
   host, owner-only.
8. Enroll the real human device credential through the reviewed device flow
   (`docs/AGENT_ROOM_AUTH.md`) — public key only leaves the device.
9. Write `/etc/agent-room/trust-policy.json`, public material only, every key
   with an explicit effective commit.
10. `checkpoint-bootstrap` with **both** out-of-band roots.
11. Install the unit and timer; `daemon-reload`; do **not** enable yet.
12. Run `deploy/verify-permissions.sh` as `pr0`. It must print
    `RESULT: boundary holds`.
13. Re-run the cgroup detached-child probe against the real unit.
14. `systemd-analyze security agent-room-transport.service`.
15. Send a harmless `status` canary, then an export/import canary.
16. Confirm the generic bridge was not involved: its journal shows no
    corresponding `run_command`.
17. Only then `systemctl enable --now agent-room-transport.timer`.

### Rollback

`systemctl disable --now agent-room-transport.timer` and stop the service. The
room branch, control branch, checkpoint and results are all append-only
evidence and are **kept**, not cleaned up. Re-anchoring after a rollback uses
the same two out-of-band roots.

**There is no automatic fallback to the generic bridge.** If the narrow
transport fails, the correct state is "not running", not "running through the
thing S3 exists to stop using". Any fallback would restore exactly the path
this stage removed.

---

## 12. What the transport cannot reach

It does not open project files, check out source repositories, run tests or
proofs, apply patches, or browse `/home/pr0/projects` — `InaccessiblePaths`
and `ProtectHome=yes` make the last one structural. A supervisor packet
carries immutable evidence *locators* that are already in the room; resolving
one to content would be a separate, separately designed capability, and it is
not smuggled in here.

---

## 13. Host patch state (read-only, 2026-09-24)

- 10 pending upgrades, **none from the security pocket**: `krb5` and
  `netplan` from `noble-updates`, plus `google-chrome-stable` from Google's own
  repository.
- The `sudo` update noted earlier in Issue #13 is **no longer pending**.
- `/var/run/reboot-required`: **absent** — no reboot required.
- systemd 255 (255.4-1ubuntu8.17).

Nothing was installed and nothing was rebooted. Re-check immediately before
activation; a clean result today is not a clean result then.

# Agent Room — security model

Issue #13. Written against `426089ce…` and covering **Stage S1 only**: local
fail-closed hardening. Identity authentication (S2) and the narrow transport
service (S3) are not implemented, and this document says so everywhere it
matters rather than in a footnote.

The honest summary: S1 closes every local integrity, filesystem and release
defect the red team reproduced. It does **not** make identity authentic. A
writer to the Git remote can still forge a human approval, and that is the
expected S2 blocker — there is a test asserting the attack still works, so the
gap cannot quietly disappear from view.

---

## 1. Threat model

Protected against, after S1:

| # | Adversary | S1 status |
|---|---|---|
| 5 | malicious committed room artifacts / history | closed — closed namespace, append-only, per-read digest |
| 6 | replay of a human approval | closed — one-shot nonce and execution receipts |
| 7 | crashes and races | closed since Issues #2–#5 |
| 8 | malicious paths / identifiers / output sizes | closed — proof-id grammar, resolved containment, hard limits |

Not protected against by S1:

| # | Adversary | Stage |
|---|---|---|
| 1 | write access to the Agent Room Git remote | **S2** — participant and human signatures |
| 2 | injected requests on the existing bridge control branch | **S3** — narrow transport |
| 3 | a compromised Claude or Codex process | **S2** (partially; capability limits already apply) |
| 4 | a compromised ChatGPT/GitHub connector credential | **S2 + S3** |
| 9 | remote branch rollback or force replacement | **S2** — trust anchor and last-seen checkpoint |

**Explicit non-goal.** Nothing here survives an attacker with arbitrary root or
kernel control on this host. Every guarantee below is stated for an
unprivileged attacker, and none of them is a claim about a rooted machine.

---

## 2. What S1 guarantees

### The branch namespace is closed

`verify_store()` authenticates every tracked path on the branch, not only
`.agent-room/messages/**`. The protocol defines exactly two things:

- `README.agent-room.md` — one immutable genesis marker;
- `.agent-room/messages/<thread_id>/<uuid7>.json`.

Anything else fails closed: root files, `.gitattributes`, `.gitmodules`,
`.gitignore`, nested directories, and — checked at the tree rather than the
path — symlinks, executables and gitlinks. `.gitattributes` is the reason this
is not pedantry: a filter or `text` attribute changes what the bytes of a
checked-out file are, so a committed artifact and its verified digest could be
made to disagree by design.

### Proof artifacts are contained and write-once

A proof id is validated against `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` — one
filename component, no separators, no traversal — and the resolved artifact
path is asserted to be inside the *resolved* run directory, so a symlinked run
directory cannot smuggle a write out either. Artifacts are content-addressed by
their own digest, created with `O_EXCL`, and left mode `0400`. Re-running an id
produces a second artifact; it never rewrites the first. `verify_artifact`
rehashes the stored bytes and checks them against both the record's digest and
the one in its filename.

### Timeouts kill the family

Proof and model invocations start their own session, and a timeout or an
interrupt tears down the whole process group: SIGTERM, a bounded grace period,
then SIGKILL. The previous `subprocess.run(timeout=…)` boundary reaped only the
direct child; a `sleep` it had spawned survived. Regressions prove no
descendant outlives a timeout for proof, Claude and Codex.

### A bound proof does not depend on unmeasured state

A snapshot manifest binds **tracked content only**, and now says so inside its
own hashed payload (`binds: "tracked-content-only"`). Ignored paths are *named*
in the manifest — their names digested, their contents deliberately not — so an
ignored `sitecustomize.py` appearing beside the source moves the binding
instead of leaving it identical. Hashing a virtualenv would be theatre.

The actual mechanism is isolation: `run_isolated_proof` reconstructs the exact
bound commit with `git archive` into a directory outside the source, and runs
there with a minimal environment (`PYTHONNOUSERSITE=1`, no `PYTHON*`, `LD_*` or
`GIT_*` inherited). The ignored file is not in the checkout at all. If the
measured state has anything uncommitted, an isolated proof refuses rather than
running against a state nobody measured.

### The release path measures for itself

`decision.evaluate_gate` accepts caller-supplied digests and is therefore
**advisory** — every report it returns says `advisory: true`. It is a
diagnostic, never an authorisation.

`release.authorise` is the release-capable API. Its whole signature is
`(store, request_message_id, *, workdir)`: there is nowhere to put a digest. It
derives the current snapshot from the binding's recipe and the current
supervisor context from the thread, then evaluates the gate against what it
measured.

The circularity — a review bound to a thread that the decision request itself
extends — is resolved explicitly, not with timestamps. The context recipe names
a **cutoff message**; the derived digest covers the thread up to it; anything
appended afterwards other than the request, its decisions and its receipts
blocks the release as `blocked_unreviewed`.

### A consequential action names its target, and happens once

For a consequential action the binding must carry `project.repo` and
`project.commit`, a measurement recipe, a one-shot `action_nonce`, and
**structured parameters** from a fixed allowlist of action kinds. Prose scope is
for the human; the parameters are what a later check compares, and they are
inside the decision's binding digest. `authorise` verifies that the checkout's
head is the approved commit, so an approval for one state cannot release
another.

One-shot is enforced by receipts. `reserve` consumes the nonce as `uncertain`
*before* a person acts; `reconcile` records `executed` or `failed` afterwards.
Any receipt consumes the nonce permanently — a retry needs a new human
decision, not a second use of the old one — and an unresolved `uncertain`
receipt blocks until a human reconciles it, because the alternative is doing it
twice.

### There is no executor

Nothing in `release.py` performs a side effect. It imports no subprocess
machinery, and a test asserts that by reading the source. The consequential
action is carried out **manually** after `authorise` — the exact final recheck —
and then recorded. Building a generic privileged executor is what the audit
asked us not to do.

### Git and process environment

Every store and snapshot Git command runs with `core.hooksPath=/dev/null`
(a hook in a room checkout is attacker-supplied code inside verification),
`protocol.ext.allow=never`, `--no-replace-objects`, and an environment stripped
of `GIT_*`, `PYTHON*`, `LD_*` and the shell/interpreter injection variables.
Replacement refs, grafts and alternate object directories are refused outright:
each one makes Git answer a question about objects that are not the ones
committed here.

### Bounds and modes

Hard limits on canonical envelope size, `body.text`, evidence count, thread
length, supervisor packet size and proof output, each enforced before the Git
commit or before the model invocation. Participant state is `0700`/`0600`, run
directories `0700`, proof artifacts `0400` — set explicitly, because the host
umask is `0002` and would otherwise leave them group-writable.

---

## 3. What S1 does not guarantee

**Identity is not authenticated.** `sender.agent` is a string in a file. A
writer to the Git remote can commit a structurally valid `approval` with
`sender.agent: "human"`, and `release.authorise` will accept it. This is
CRITICAL A, it remains open, and
`test_KNOWN_S2_GAP_raw_git_can_still_forge_human_authority` asserts that it
still works so the gap stays visible. S2 must invert that test.

The same applies to `claude-code`, `codex` and `openai-research`: capability
separation stops an agent *surface* from authoring a decision or a receipt; it
says nothing about a raw Git writer.

**The existing bridge is still a broad remote shell.** `run_command` accepts
arbitrary argv, the service is unsandboxed, and a repository-write credential
on the control branch is shell-as-`pr0`. S1 changed nothing about it, by
instruction. The human CLI surface is reachable from it.

**`--confirm-human` is an operator assertion, not authentication.** Unchanged
from Issue #5 and repeated here: no signature, no token, no check of who is at
the keyboard. The isolation is within Agent Room, not on this host.

**Rollback is not detected.** Local checks authenticate the object graph they
can see. A structurally valid history substituted before a fresh clone would
pass. The monotonic trust anchor is S2.

**The transport repository is still public.** `pr0dus/cek` is public; the
production room must live in a dedicated private repository. Not created, not
activated.

**Ignored-file *contents* are not measured.** Names are. An edit to an ignored
file already present does not move the manifest. Isolation is what makes that
acceptable for a bound proof, and a proof run in-place (`run_proof` without
isolation) records `binds_execution_state: false` rather than implying
otherwise.

---

## 4. Keys and trust anchors

None exist yet. S1 introduces no key material, generates nothing, and stores no
secret. The pinned human verification identity, participant verification
identities, key rotation policy and the transport genesis checkpoint are all
S2.

Recorded here so S2 inherits the decision: the human private credential must
never be generated, copied or imported on this host, in the repository, in
bridge state, in Claude/Codex config, or in the ChatGPT connector. The host
stores only public verification material.

---

## 5. Incident recovery

Until S2, recovery is manual and depends on the human, which is itself a
limitation worth stating:

- **Unexpected tracked content on the branch** — `verify_store()` fails closed;
  nothing reads through it. Recover by identifying the injecting commit from
  `git log --name-status` and rebuilding the branch from the last good tip.
- **A forged decision record** — S1 cannot detect one. The mitigation today is
  that no consequential action is executed automatically: a human performs it
  after reading `release.authorise`'s output, which names the decision id.
- **An unresolved `uncertain` receipt** — the action stays blocked. A human
  establishes what actually happened and calls `release.reconcile`.
- **A suspect remote** — until the S2 trust anchor exists, compare a fresh
  clone's tip against a tip recorded out of band before trusting it.

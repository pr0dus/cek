# Agent Room — security model

Issue #13, through **Stage S2**. S1 was local fail-closed hardening; S2 made
cryptographic provenance the authority boundary and added a monotonic trust
anchor for the transport. The narrow transport service (S3) is not
implemented, and this document says so everywhere it matters rather than in a
footnote.

The honest summary: S1 closed every local integrity, filesystem and release
defect the red team reproduced. S2 closed identity — a writer to the Git remote
can no longer forge a human approval, a participant message or an execution
receipt, and the test that used to assert the forgery worked now asserts it
fails. What remains open is the host itself: participant keys live here, so an
attacker who holds those files can sign as those participants. The human
credential deliberately does not live here.

The identity design in full: `docs/AGENT_ROOM_AUTH.md`.

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
| 1 | write access to the Agent Room Git remote | closed — every trusted artifact is signed by a pinned key |
| 9 | remote branch rollback or force replacement | closed — monotonic checkpoint, descendant-only |
| 2 | injected requests on the existing bridge control branch | **S3** — narrow transport |
| — | a descendant that detaches from the process group | **S3** — cgroup/PID namespace |
| 3 | a compromised Claude or Codex process | partly — capability limits apply; a stolen host key still signs |
| 4 | a compromised ChatGPT/GitHub connector credential | impersonation closed; **S3** for the shell it still grants |

**Explicit non-goal.** Nothing here survives an attacker with arbitrary root or
kernel control on this host. Every guarantee below is stated for an
unprivileged attacker, and none of them is a claim about a rooted machine.

---

## 2. What S1 guarantees

### Identity is cryptographic

`sender.agent` is a claim; a signature over the whole envelope is what
corroborates it. Every trusted artifact carries a versioned auth record, and
`verify_store()` fails closed on one that is missing, malformed, signed by an
unpinned key, signed by a key pinned for a different role, or signed over
different bytes. The trust policy holds public material only and does not live
on the room branch, so the branch cannot rewrite its own trust roots.

The human credential lives in a personal device's keystore and is unlocked per
approval by a fingerprint. Nothing on this host can produce a human signature —
the ceremony is `human-prepare` here, biometric confirmation there,
`human-submit` here. `release.authorise` independently re-checks that the
effective decision is signed by the key pinned for the *human role*, rather
than assuming the read path did it.

Rotation and revocation are human-signed updates with monotonic generations,
and key validity is decided by Git ancestry rather than by a clock, so history
signed by a since-rotated key stays verifiable while the revoked key signs
nothing new.

### The transport has a monotonic anchor

A local checkpoint records the anchored genesis and the last tip that passed
full verification. A candidate head is accepted only if it descends from that
tip, and only after everything else verifies; a failure leaves the anchor
exactly where it was. Bootstrapping requires a genesis identity obtained out of
band — there is no trust on first use.

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

### Timeouts kill the process group — and only the process group

Proof and model invocations start their own session, and a timeout or an
interrupt tears down the whole process **group**: SIGTERM, a bounded grace
period, then SIGKILL. The previous `subprocess.run(timeout=…)` boundary reaped
only the direct child; a `sleep` it had spawned survived. Regressions prove no
ordinary descendant outlives a timeout, for proof, Claude and Codex.

**The guarantee stops at the group, and that was measured rather than assumed.**
A descendant that calls `setsid()` has left the group by definition and survives
`killpg`. `test_DETACHED_CHILD_TIMEOUT` asserts that it survives — observed pgid
equal to its own pid — so the limit stays visible instead of being papered over.
Closing it needs a cgroup or a PID namespace, which belongs to the S3 systemd
transport boundary and is recorded there as a blocker. Do not read "the whole
process tree is killed" into this section: what is enforced is every descendant
that remains in the group.

### Output is bounded while it is produced

An earlier version set `MAX_PROOF_STREAM_BYTES` and then applied it to what got
*stored*, after `communicate()` had already buffered the entire stream in
memory. That is not a resource bound. Output is now read incrementally against a
hard cap on each stream, and crossing it tears down the process group rather
than continuing to read — for proofs, for Claude and for Codex. Codex's
structured result arrives as a file, which the stream cap never sees, so its
size is checked before it is read.

When a cap is reached the result says so: a proof records
`status: "output_limited"` and `digest_covers: "captured-prefix"`, because the
process was killed mid-stream and the digest covers the bytes that were
accepted, not bytes that were never read. A limited run is never retried with a
looser bound.

### A bound proof binds the commit it claims

`run_isolated_proof` verifies a supplied manifest's digest before believing
anything it says, requires the manifest to describe exactly the commit being
archived, and rejects **staged**, unstaged and untracked state. Staged mattered
and was missed: `git archive` builds from the commit, so a staged change is
silently absent from the proof while the manifest suggests it was measured.
Telling "staged but uncommitted" apart from "committed since the baseline" needs
a HEAD↔index comparison, which the manifest now records as `staged_vs_head`.

The commit must be a full object id naming a commit object — `HEAD`, `main~2`
and a blob id are all refused, because a proof bound to a revision expression is
bound to whatever it resolved to at the time. The snapshot binding is derived
from the verified manifest, and a caller-supplied digest that contradicts it is
refused rather than preferred.

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
head is the approved commit **and that the checkout is the approved
repository**. Only checking the commit was a hole: a commit can be fetched into
any number of repositories, so an approval for `pr0dus/cek` would have released
against any clone or fork holding it. The observed identity is derived from the
checkout's own remote configuration and normalised — `https://`, `ssh://` and
`git@host:` spellings all reduce to `host/owner/name`, and a local path becomes
`path:<realpath>`, which can never match a hosted identity. Missing, ambiguous
and mismatched identities all fail closed.

**Threat boundary for that identity.** It is read from the target checkout's
`.git/config`. Anyone who can write there can make it claim anything, so this
is not an authenticated binding — S2's signatures are. What it establishes is
that a release is running against the repository the approval named, rather
than a different checkout that merely contains the same commit.

One-shot is enforced by receipts, and the check is atomic with the write. The
earlier flow read "unconsumed" and then appended, holding the writer lock only
during the append, so two callers could both pass the check. `reserve` and
`reconcile` now hold the store's writer lock across the recheck *and* the
receipt.

The lock is re-entrant **for the thread that holds it**, and that distinction
was itself a defect once: counting nesting depth on the store alone meant a
second thread sharing one store saw a non-zero depth, concluded it was a nested
call, and entered the critical section somebody else was holding. Depth and
owner are now keyed to the owning thread id, so a different thread always takes
the ordinary bounded path. That path blocks correctly inside one process as
well as between processes: `flock` treats two descriptors for the same file
independently, so the second thread's `LOCK_EX` is denied by the lock this
store already holds on another descriptor.

The lifecycle is `unused → uncertain → executed|failed`: no second reservation,
no second terminal receipt, no transition out of a terminal state. An
unresolved `uncertain` receipt blocks until a human reconciles it, because the
alternative is doing the action twice, and any terminal receipt consumes the
nonce permanently — a retry needs a new human decision, not a second use of the
old one. `verify_store()` enforces the same lifecycle against history, so a
branch containing two reservations for one nonce fails closed rather than being
read past: it is evidence the action was released twice.

### There is no executor, and the operator sequence has one order

Nothing in `release.py` performs a side effect. It imports no subprocess
machinery, and a test asserts that by reading the source. Building a generic
privileged executor is what the audit asked us not to do.

The sequence is exactly:

1. `release-reserve` — rechecks everything and consumes the one-shot nonce as
   `uncertain`, atomically;
2. the human performs the action by hand;
3. `release-reconcile` — records `executed` or `failed`.

`release-authorise` is a **diagnostic**. An earlier version's output told the
operator to carry the action out and then record it, which would have performed
the real side effect while the nonce was still unconsumed — the exact window
`reserve` exists to close. Its result now carries `action_permitted: false` and
says plainly that nothing may be performed from it; its CLI help says the same.
Both are asserted by tests, so the wording cannot quietly regress.

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

**Host compromise is not addressed.** Participant keys — Claude, Codex, the
supervisor boundary, the release recorder, the coordinator — are owner-only
files on this machine. Anyone who can read them can sign as those participants.
Read the guarantee as "a repository writer cannot impersonate a participant",
never as "a host attacker cannot". The human credential is the exception: it is
not here at all.

**The human credential's hardware backing is not attested.** Whether an Android
Keystore key lands in a TEE or StrongBox depends on the handset, and nothing
verifies it. Treat it as software held on a separate device.

**Local policy and checkpoint files are not tamper-proof.** Both belong to the
service user. Someone who already controls that user's state can edit the pins
or rewind the anchor. S3.

**The existing bridge is still a broad remote shell.** `run_command` accepts
arbitrary argv, the service is unsandboxed, and a repository-write credential
on the control branch is shell-as-`pr0`. S1 changed nothing about it, by
instruction. The human CLI surface is reachable from it.

**`--confirm-human` is an operator assertion, not authentication** — and since
S2 it is no longer what carries authority. The flag still gates the CLI surface
so a decision is never recorded by accident; the signature is what makes it
count, and `--confirm-human` with no valid human assertion records nothing.

**The transport repository is still public.** `pr0dus/cek` is public; the
production room must live in a dedicated private repository. Not created, not
activated.

**Ignored-file *contents* are not measured.** Names are. An edit to an ignored
file already present does not move the manifest. Isolation is what makes that
acceptable for a bound proof, and a proof run in-place (`run_proof` without
isolation) records `binds_execution_state: false` rather than implying
otherwise.

**A detached descendant survives a timeout.** `killpg` cannot reach a process
that left the group, and one that calls `setsid()` has. Measured, asserted by a
test, and recorded as an S3 blocker rather than mitigated by something weaker
that would read like a guarantee.

**Repository identity is configuration, not authentication.** See the threat
boundary above: it defends against acting on the wrong checkout, not against
someone who already controls that checkout's config.

---

## 4. Keys and trust anchors

Ed25519 throughout, via the installed `openssl`. Full detail in
`docs/AGENT_ROOM_AUTH.md`; the custody summary:

| Identity | Where the private key lives | Custody recorded as |
|---|---|---|
| `human` | a personal device's keystore, unlocked per approval by a fingerprint | `android-keystore-device-bound` |
| `claude-code`, `codex`, `openai-research`, `release-recorder`, `coordinator` | owner-only file on this host | `host-file` |

**No human private credential exists on this host**, in the repository, in
bridge state, in Claude/Codex config, or in the ChatGPT connector — and none
was created by this stage. The trust policy stores public keys only, and
refuses to hold anything containing `PRIVATE KEY`.

The transport anchor is the room branch's root commit, confirmed out of band at
bootstrap.

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
- **An impossible receipt history** — `verify_store()` fails closed with
  `ReceiptStateError`, naming the nonce and the offending receipt. Establish out
  of band whether the action happened, then rebuild the branch from the last
  good tip; do not append a third receipt to "settle" it.

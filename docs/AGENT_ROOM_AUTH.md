# Agent Room — authenticated identity (Stage S2)

Issue #13, Stage S2. Before this, `sender.agent` was a string in a file: anyone
who could write the Git remote could be the human, and a passing test said so.
This document is the design that closes it, and the limits it does not close.

---

## 1. What is signed

One function defines the signed bytes — `auth.signed_payload()` — and both
signing and verification call it. It is canonical JSON over:

```
{ "domain": "agent-room.v1.envelope",
  "auth":   { auth_schema_version: 2, domain, room_id, method, signer, key_id },
  "envelope": <the whole envelope, minus envelope_sha256 and auth.signature> }
```

**`room_id` is the branch's root commit**, and it is in the signed bytes.
Schema 1 bound the protocol but not the instance: a domain of
"agent-room.v1" says what kind of thing was signed, not which room, and
participant keys are expected to be reused across rooms and projects. A
byte-identical envelope signed in room A therefore verified perfectly when
copied into room B. Verification now requires

```
signed room_id == trust_policy.room_id == store.room_id()
```

and the first of those three is inside the signature, so the check cannot be
removed by editing an unsigned field. Trust-policy updates carry the room id
in both the signed body and the signed auth header.

The genesis commit contains a random nonce for this reason. Two rooms created
in the same second from the same template otherwise produce byte-identical
root commits — same tree, same author, same message, same timestamp — and
therefore the same identity, which would make the room binding bind nothing.
The nonce is committed and not secret; its only job is to be different.

So the signature covers `message_id`, `thread_id`, `type`, `sender`,
`recipient`, `project`, `parent_id`, `body`, `evidence`, `status`,
`reply_requested`, `human_approval_required`, and the `action`, `decision` and
`receipt` records that carry authority. Two fields are excluded, for one reason
each: `envelope_sha256` is computed *after* the signature is attached and would
otherwise be circular, and `auth.signature` cannot cover itself.

The auth header is inside the signed payload, which is what makes downgrade
attacks fail: an artifact cannot claim a weaker `method`, a different `key_id`
or an older `auth_schema_version` than the one that was actually signed.

The domain string is inside it too, so a signature produced here is not a
signature anywhere else — and a trust-policy update, which has its own domain
(`agent-room.v1.trust-update`), can never be replayed as a message.

**Order of operations, which is also the order of trust:**

1. build the unsigned immutable envelope;
2. sign the domain-separated canonical payload;
3. attach the auth record;
4. seal — the envelope digest then covers the signature as well.

**Verification order**, all fail-closed, in `gitstore._load` → `trust.verify_envelope`:

1. strict JSON parse, duplicate keys rejected;
2. envelope integrity digest;
3. schema and references;
4. auth record structure — version, domain, method, signer, key id, signature;
5. `auth.signer` must equal `sender.agent`;
6. key id looked up in the pinned policy; role and method must match the pin;
7. validity at this message's commit in history;
8. cryptographic verification.

A correctly hashed message whose `sender.agent` names an allowed participant is
**not** trusted by that fact. It fails at step 4 if unsigned, and the failure
takes the whole read with it rather than returning the message with a warning.

Verification runs on the bytes that were committed: the envelope is parsed from
the blob at its own add commit and its digest checked, not handed in by the
caller who wants it trusted.

---

## 2. The primitive

Ed25519 through the installed `openssl` (3.0.13 here). No custom signature
construction, no new Python dependency, no shell: fixed executable, internally
constructed argv, sanitised environment, bounded time and output. Private keys
reach `openssl` as `-inkey <path>` to an owner-only file — never as an
argument, never through the environment.

Signatures are base64, bounded at 512 characters; an Ed25519 signature is 88.

---

## 3. Human authority: the design decision

The contract asked for a comparison of two real options before choosing.

### Option 1 — passkey / WebAuthn assertion

**Rejected, for two reasons that are about this system rather than about
WebAuthn.**

WebAuthn's security rests on an RP ID and an allowed origin, and those are
properties of a *web* ceremony: to pin them meaningfully there has to be a page
served from an origin, in a browser, talking to a verifier. Agent Room's
approval ceremony is a CLI on a headless host. Making a passkey fit would mean
standing up a web service whose only purpose is to make the passkey work —
precisely what the contract said to avoid.

Second, verifying an assertion means parsing CBOR/COSE, extracting the
credential public key, reconstructing `authData || SHA-256(clientDataJSON)`,
and checking flags. That is a real parser in a package that is otherwise
standard library plus `openssl`, and a parser sitting in front of a signature
check is the wrong place for new surface.

There is also a property mismatch. A synced passkey may be usable from *any*
device in the same provider account. That is a fine property for logging into
a website and the wrong one here, where the human's stated preference is that
one enrolled device approves. Calling a synced credential device-bound would be
inaccurate, and the policy would have to say "unknown".

### Option 2 — device-bound Android Keystore signer — **chosen**

- **Key algorithm:** Ed25519 (`KeyProperties.KEY_ALGORITHM_ED25519`), generated
  *in* the Android Keystore, `setUserAuthenticationRequired(true)` with
  `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` — authentication
  per operation, not a time window. Non-exportable where the platform supports
  it.
- **Availability must be probed, not assumed.** Android exposes Curve25519 in
  the hardware keystore as a *feature level capability*, not a guarantee on
  every handset, and the same is true of strong-biometric-per-operation. Before
  any real enrollment the client must query the device's actual support for the
  chosen algorithm **and** the per-operation authentication policy, and either
  fail closed or fall back to an explicitly reviewed alternative — not silently
  to a weaker one. Nothing in this document should be read as a claim that
  Ed25519 in the Android Keystore is universally available.
- **Exact bytes signed:** the output of `auth.signed_payload()` for the
  decision envelope, raw, with no further hashing or wrapping. `human-prepare`
  prints them as `payload_b64` together with `payload_sha256`; the device signs
  the bytes, not the digest.
- **There is no host-signed alternative.** `human-decide` records nothing in an
  authenticated room, even with `--confirm-human` and a host `--signing-key`:
  that route would sign a human decision with a key on this machine, which is
  exactly what the credential living on a separate device is meant to prevent,
  and leaving it available invites someone to put a real credential here. It
  refuses and names the ceremony instead. `human-decide --show` stays
  read-only.
- **Ceremony:** `agent-room human-prepare` shows the action summary — verdict,
  action id, scope, structured parameters, project, snapshot and supervisor
  context digests — the device displays it, the person confirms with a
  fingerprint, the device returns a base64 signature, and `agent-room
  human-submit` attaches it. The biometric is a local unlock gesture: it never
  leaves the device, and no biometric data is sent to Ubuntu or stored in Agent
  Room.
- **Credential type:** device-bound. The policy records
  `custody: "android-keystore-device-bound"`, and only the enrolled device can
  approve.
- **Verifier:** `openssl pkeyutl -verify -pubin -rawin`, the same path as every
  other signature here.
- **Hardware backing:** **not claimed.** Whether the key lands in a TEE or
  StrongBox depends on the handset, and nothing here attests to it. Treat it as
  software-held-on-a-separate-device unless and until key attestation is
  verified — which is not part of S2.
- **Enrollment format:** PEM SPKI public key, pinned in the trust policy by key
  id.
- **Replay:** the assertion covers the entire decision, message id included.
  Yesterday's signature does not approve today's action because the payload is
  different. No sign-count is used, and none is needed.

### The deployment rule S2 followed

No real human credential was created. The tests use disposable Ed25519 keys on
disk because a test cannot present a fingerprint; the format and the verifier
are identical either way. **No human private key exists on this host.**

No phone client was built. Writing an Android app is a build surface this stage
was told not to open silently, and the format above is precise enough to
implement against — which is the point of writing it down rather than shipping
it.

---

## 4. Participant signatures

Claude, Codex, the supervisor boundary, the release recorder and the
coordinator each have a pinned key id and an Ed25519 key held in an owner-only
file on this host. Outbound messages are signed before append; inbound messages
are verified before they can reach an inbox, a claim, a gate or an audit path.

**The guarantee is bounded, and the boundary is the interesting part.** These
keys are on the host. An attacker with arbitrary access to them can sign as
that participant, and nothing here changes that. What this closes is
impersonation by a *repository writer* — someone with push access, a
compromised connector credential, or write access to the branch — who holds no
key. That was the demonstrated attack, and it is now refused.

A key pinned for one participant cannot authenticate another: the role is in
the policy, the signer is in the signed payload, and `sender.agent` has to
agree with both.

---

## 5. Trust policy format

Public material only, versioned by a monotonically increasing generation:

```json
{
  "trust_schema_version": 1,
  "room_id": "<root commit of the room branch>",
  "generation": 7,
  "keys": {
    "<key_id>": {
      "key_id": "...", "role": "codex", "method": "ed25519",
      "public_key": "-----BEGIN PUBLIC KEY-----…",
      "custody": "host-file" | "android-keystore-device-bound",
      "added_generation": 3, "effective_commit": "<full oid>",
      "revoked_generation": null, "revoked_effective_commit": null,
      "replaces": null
    }
  },
  "history": [ <every signed update, in order> ]
}
```

It refuses to hold anything containing `PRIVATE KEY`, and a test asserts that.

**It is not on the room branch.** If the keys that authenticate the branch's
messages lived on the branch, whoever could write the branch could install
their own. The room identity is the branch's root commit, which cannot change
without rewriting all of history.

**It is a local file owned by the service user.** Someone who already controls
that user's local state can edit it. That is not solved here; it is what S3's
service isolation is for. Do not read this file as tamper-proof.

There is no `--trust-any` and no `--no-auth`. A release-capable command with no
policy fails closed, and a test asserts that no such flag exists in the CLI.

---

## 6. Rotation and revocation

Every change is a signed update in its own domain:

```json
{ "trust_update_schema_version": 1, "domain": "agent-room.v1.trust-update",
  "room_id": "…", "generation": <exactly current + 1>,
  "action": "add" | "rotate" | "revoke", "participant": "codex",
  "old_key_id": "codex-1", "new_key_id": "codex-2",
  "public_key": "…", "method": "ed25519", "custody": "host-file",
  "effective_commit": "<full oid, mandatory>",
  "new_key_proof": "<counter-signature, human rotations only>",
  "auth": { …, "signer": "human", "signature": "…" } }
```

- **Authority is the human credential.** A participant cannot rotate itself;
  an update signed by anyone else is refused, and an unsigned one installs
  nothing.
- **Generations are monotonic and exact** (`current + 1`), so an old update
  cannot be replayed.
- **Validity is history, not wall clock, and the boundaries are mandatory.**
  Every key has an `effective_commit`; every revocation has a
  `revoked_effective_commit`. Both are full object ids, both must name a commit
  that exists in this room's history at the time of the update, and neither may
  be null or a revision expression. A null lower bound used to mean "valid for
  all of history", including commits that predate the key — which is precisely
  how a newly installed key could authenticate a forged artifact from before it
  existed. A null revocation bound only blocked the write path, leaving raw-Git
  artifacts at any commit verifiable.
- **The interval is inclusive at both ends.** A key is valid *at* its effective
  commit and every descendant; a revoked key is invalid *at* its revocation
  commit and every descendant. A rotation whose boundary is the current tip
  therefore does not retroactively invalidate the outgoing key's earlier
  messages — but it does invalidate anything it signed *in* that boundary
  commit. An operator rotating a key that signed the tip should first land a
  neutral marker commit from another valid identity and use that as the
  boundary.
- **The write path uses the same interval.** A message being written is checked
  against the tip it will descend from. There is no boundary-free mode: a key
  that is not yet effective cannot sign early, and a revoked one cannot sign
  late.
- **Key ids are never reused.** A reused id makes history ambiguous.
- **Human rotation needs proof of possession**: the incoming credential
  counter-signs the same payload, so a credential nobody holds cannot be
  pinned — including by accident, which would lock the human out.

### Emergency human recovery is a ceremony, not an API

If the human credential is lost or compromised there is deliberately **no**
in-band command to replace it — an unsigned recovery path is just the forgery
this stage closed, wearing a helpful name.

Recovery is an out-of-band trust-anchor replacement, and it re-anchors **both**
roots:

1. enroll a new credential on a trusted device; export only its public key;
2. construct a fresh trust policy file out of band, pinning the new human
   credential and re-pinning the participant keys that are still trusted, each
   with an explicit effective commit in the room's history;
3. compute the new policy digest and confirm it through a channel that is not
   the compromised one;
4. re-anchor the checkpoint against **both** the room's genesis and that policy
   digest, each confirmed from a source that is not the remote;
5. review the interval since the compromise: every decision signed by the old
   credential after that point is suspect and must be re-taken.

Step 4 is the part that is work rather than typing, and it is why losing the
credential is a real incident rather than a reset.

---

## 7. Transport trust anchor

`checkpoint.py`. A local durable record of the genesis this room was anchored
to, the trust-policy root it was anchored under, and the last remote tip that
passed full verification. A new tip is accepted only if it **descends** from
the last accepted one; rollback to an ancestor, replacement by an unrelated
history and rewritten history are all "not a descendant", and all refused. A
trust-policy generation that went backwards is refused too, since an older
policy may pin keys that have since been revoked.

**The candidate is observed, never supplied, at bootstrap as well as on every
acceptance.** The checkpoint must name exactly the history that passed
verification. Bootstrap observes the head, verifies, re-observes, and refuses —
writing no anchor at all — if the branch moved meanwhile; a ceremony anchors one
explicit object rather than silently taking whichever head arrived last. That
matters most at bootstrap, because the first anchor is what every later
acceptance is measured against. An earlier version checked a
caller-supplied candidate for descent, verified the *branch*, and then recorded
the *candidate* — so any reachable descendant object could become the accepted
anchor while a different history was the one actually checked. The candidate is
now read from the configured ref; a supplied one is an assertion that must
equal it, and the tip is re-read after verification so a branch that moved
underneath fails rather than advancing.

Everything else verifies first — namespace, append-only history, digests,
references, receipt lifecycle, signatures — and only then does the checkpoint
advance. A failed verification leaves the anchor exactly where it was, so a bad
fetch can never become the new baseline.

### Bootstrap: no trust on first use, and there are two roots

A fresh device with no checkpoint does not believe whatever tip the remote
offers — and a genesis commit alone is not enough. Because the trust policy
deliberately does not live on the room branch, it is a **second root**: an
attacker who supplies both a plausible history and a policy pinning their own
human key produces a branch that verifies perfectly under it. A genesis pin
says which history; it does not say which keys may authenticate the history
descending from it.

So bootstrapping requires both, out of band, and neither may be defaulted from
the artefact being checked:

```
agent-room --repo <room> --participant coordinator --trust-policy <policy> \
    checkpoint-bootstrap --state <checkpoint> \
        --expected-genesis <root oid> \
        --expected-trust-policy-sha256 <policy digest>

agent-room --repo <room> --participant coordinator --trust-policy <policy> \
    checkpoint-accept --state <checkpoint>
```

The accepted policy digest is recorded in the checkpoint. On a later
acceptance, a changed digest at an **unchanged generation** fails closed: the
only legitimate way for the pins to move is a signed update, and a signed
update advances the generation.

Local checkpoint tampering by an attacker who already controls the service
user's state is **not** solved here. S3.

---

## 8. What S2 does not establish

- **Host compromise.** Participant keys are on this host. Read the guarantee as
  "a repository writer cannot impersonate a participant", never as "a host
  attacker cannot".
- **Hardware backing of the human credential.** Not attested, not claimed.
- **Local policy and checkpoint integrity.** Both are files owned by the
  service user.
- **The detached `setsid()` descendant**, which survives process-group
  teardown. Still S3, untouched, still asserted by a passing test.

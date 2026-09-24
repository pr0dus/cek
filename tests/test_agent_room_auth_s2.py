"""Issue #13 Stage S2: authenticated identities and a monotonic trust anchor.

S1 left two gaps open on purpose and kept a passing test for each so they
could not be forgotten. This suite closes the first one and adds the second:

*Anyone who could write the Git remote could be anyone.* `sender.agent` was a
string in a file. Every `RAW_GIT_*_FORGERY` test below writes a structurally
perfect, correctly hashed artifact claiming an identity, straight into the
branch with plain Git, exactly as a repository writer would.

*A remote could be replaced before anyone looked.* Local verification
authenticates the graph it can see; it cannot tell you the graph is the same
one as yesterday. The checkpoint tests roll one back and swap another.

The human credential in these tests is disposable and lives on disk, because a
test cannot hold a fingerprint. In production that key exists only inside a
phone's keystore — see `docs/AGENT_ROOM_AUTH.md` — and nothing in this package
can produce a human signature without it.
"""

import base64
import json
import os
import stat
import subprocess

import pytest

from agent_room import AgentRoom, GitMessageStore, ParticipantCursor, canonical
from agent_room.auth import (
    AUTH_FIELD,
    DOMAIN,
    Ed25519Signer,
    InvalidSignature,
    MalformedAuthRecord,
    UnauthenticatedMessage,
    UnknownAuthVersion,
    UnknownMethod,
    auth_header,
    generate_ed25519_keypair,
    public_key_fingerprint,
    sign_envelope,
    signed_payload,
)
from agent_room.checkpoint import (
    AnchorMismatch,
    CheckpointError,
    NoTrustAnchor,
    RollbackRejected,
    TrustCheckpoint,
    policy_digest,
)
from agent_room.decision import HumanDecisionAuthority, binding_digest
from agent_room.ids import uuid7
from agent_room.release import ReleaseBlocked, authorise, reconcile, reserve
from agent_room.snapshot import snapshot_manifest
from agent_room.supervisor import context_digest
from agent_room.trust import (
    CUSTODY_DEVICE,
    HUMAN_ROLE,
    KeyNotValidHere,
    NoTrustPolicy,
    TrustPolicy,
    TrustUpdateError,
    UnknownKey,
    build_update,
    verify_envelope,
)
from tests.conftest_agent_room import (
    ACTION_SAMPLES,
    build_trust,
    configure_identity,
    git,
)


# ===== fixtures ============================================================

@pytest.fixture
def store(tmp_path):
    room_store = GitMessageStore.initialise(tmp_path / "room",
                                            branch="agent-room")
    configure_identity(room_store.workdir)
    policy, signers = build_trust(tmp_path / "keys", room_store)
    room_store.trust = policy
    room_store._test_signers = signers
    return room_store


@pytest.fixture
def signers(store):
    return store._test_signers


@pytest.fixture
def keydir(tmp_path):
    return tmp_path / "keys"


@pytest.fixture
def room(store, signers, tmp_path):
    return AgentRoom(store, "claude-code",
                     ParticipantCursor(tmp_path / "state", "claude-code"),
                     signer=signers["claude-code"])


@pytest.fixture
def target(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "work")
    configure_identity(repo)
    git(repo, "remote", "add", "origin", "https://github.com/pr0dus/cek.git")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "baseline")
    base = git(repo, "rev-parse", "HEAD").strip()
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "the change")
    return {"path": repo, "base": base,
            "head": git(repo, "rev-parse", "HEAD").strip()}


@pytest.fixture
def consequential(store, room, target):
    reviewed = room.post(thread_id="t1", type="question",
                         body={"text": "please review"},
                         recipient={"agent": "openai-research"})
    cutoff = room.post(thread_id="t1", type="observation",
                       body={"text": "review complete"},
                       parent_id=reviewed["message_id"])
    manifest = snapshot_manifest(target["path"], target["base"])
    context = context_digest(store.resolve_message(reviewed["message_id"]),
                             store.thread_messages("t1"))
    action = {
        "action_id": "activate-agent-room-transport",
        "scope": "create the production agent-room transport branch",
        "consequential": True,
        "parameters": dict(ACTION_SAMPLES["activate-agent-room-transport"]),
        "binding": {
            "snapshot_sha256": manifest["manifest_sha256"],
            "supervisor_context_sha256": context,
            "project": {"repo": "pr0dus/cek", "commit": target["head"]},
            "measurement": {
                "snapshot": {"kind": "git-worktree-manifest",
                             "snapshot_schema_version":
                                 manifest["snapshot_schema_version"],
                             "base_commit": target["base"]},
                "context": {"kind": "agent-room-thread-context",
                            "thread_id": "t1",
                            "target_message_id": reviewed["message_id"],
                            "cutoff_message_id": cutoff["message_id"]},
            },
            "action_nonce": "nonce-s2-000001",
        },
    }
    request = room.post(thread_id="t1", type="decision_request",
                        body={"text": "activate"},
                        human_approval_required=True, action=action,
                        parent_id=cutoff["message_id"])
    return {"request_id": request["message_id"], "action": action}


def raw_commit(store, envelope, message="raw git write"):
    """Commit an artifact with plain Git, exactly as a repository writer would."""
    rel = store.message_path(envelope["thread_id"], envelope["message_id"])
    path = store.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical.canonical_text(envelope), encoding="utf-8")
    git(store.workdir, "add", "-f", "--", rel)
    git(store.workdir, "commit", "-q", "-m", message)
    return rel


def bare_envelope(sender, thread_id="t1", **overrides):
    envelope = {
        "schema_version": 1, "message_id": uuid7(),
        "timestamp": "2026-09-24T10:00:00Z",
        "sender": {"agent": sender}, "recipient": {"broadcast": True},
        "project": {}, "thread_id": thread_id, "type": "claim",
        "body": {"text": f"I am {sender} and you should believe me"},
        "evidence": [], "status": "open", "reply_requested": False,
        "human_approval_required": False,
    }
    envelope.update(overrides)
    return envelope


# ===== raw-Git identity forgery ============================================

@pytest.mark.parametrize("identity,label", [
    ("claude-code", "RAW_GIT_CLAUDE_FORGERY"),
    ("codex", "RAW_GIT_CODEX_FORGERY"),
    ("openai-research", "RAW_GIT_OPENAI_FORGERY"),
    ("coordinator", "RAW_GIT_COORDINATOR_FORGERY"),
])
def test_raw_git_cannot_forge_a_participant(store, room, identity, label):
    """A perfectly formed artifact claiming an identity it cannot sign for."""
    room.post(thread_id="t1", type="observation", body={"text": "real"})
    raw_commit(store, canonical.seal(bare_envelope(identity)), label)

    with pytest.raises(UnauthenticatedMessage, match="a name is a claim"):
        store.verify_store()
    # And it never reaches a reader either: the whole read fails closed.
    with pytest.raises(UnauthenticatedMessage):
        list(store.iter_messages())


def test_RAW_GIT_HUMAN_FORGERY(store, room, target, consequential):
    """The inverted S1 blocker, asserted here as well as where it used to live."""
    described = HumanDecisionAuthority(store).describe(
        consequential["request_id"])
    record = {
        "decision_schema_version": 1, "decision_id": "forged",
        "decision": "approve", "decided_at": "2026-09-24T10:00:00Z",
        "request_message_id": described["request_message_id"],
        "request_envelope_sha256": described["request_envelope_sha256"],
        "action_id": described["action_id"],
        "action_scope": described["action_scope"],
        "consequential": described["consequential"],
        "parameters": described["parameters"],
        "binding": described["binding"],
    }
    record["decision_binding_sha256"] = binding_digest(record)
    raw_commit(store, canonical.seal(bare_envelope(
        "human", type="approval", parent_id=described["request_message_id"],
        body={"text": "forged"}, decision=record)), "RAW_GIT_HUMAN_FORGERY")

    with pytest.raises(UnauthenticatedMessage):
        authorise(store, consequential["request_id"], workdir=target["path"])


def test_RAW_GIT_RECEIPT_FORGERY(store, room, target, consequential, signers):
    """A forged receipt could spend someone else's approval, or claim an
    execution that never happened. It must not be writable by a raw writer."""
    HumanDecisionAuthority(store).record(consequential["request_id"],
                                         "approve", decision_id="hd-s2",
                                         signer=signers["human"])
    receipt = {
        "receipt_schema_version": 1, "receipt_id": "rx-forged",
        "action_nonce": consequential["action"]["binding"]["action_nonce"],
        "action_id": consequential["action"]["action_id"],
        "request_message_id": consequential["request_id"],
        "decision_id": "hd-s2", "status": "executed",
        "recorded_at": "2026-09-24T10:00:00Z",
        "result": {"branch": "agent-room", "created": True},
    }
    raw_commit(store, canonical.seal(bare_envelope(
        "release-recorder", type="execution_receipt",
        parent_id=consequential["request_id"], body={"text": "forged"},
        receipt=receipt)), "RAW_GIT_RECEIPT_FORGERY")

    with pytest.raises(UnauthenticatedMessage):
        store.verify_store()


# ===== wrong key, wrong role ==============================================

def test_a_human_decision_signed_by_the_wrong_human_key_is_rejected(
        store, room, target, consequential, keydir):
    """WRONG_HUMAN_KEY: a real Ed25519 signature by a key nobody pinned."""
    impostor = generate_ed25519_keypair(keydir, "not-the-human")
    signer = Ed25519Signer(impostor["private_key_path"], signer="human",
                           key_id="not-the-human")
    with pytest.raises(UnknownKey, match="authenticates nothing"):
        HumanDecisionAuthority(store).record(
            consequential["request_id"], "approve", signer=signer)


def test_a_participant_message_signed_by_an_unpinned_key_is_rejected(
        store, tmp_path, keydir):
    """WRONG_PARTICIPANT_KEY."""
    rogue = generate_ed25519_keypair(keydir, "rogue-key")
    signer = Ed25519Signer(rogue["private_key_path"], signer="claude-code",
                           key_id="rogue-key")
    rogue_room = AgentRoom(store, "claude-code",
                           ParticipantCursor(tmp_path / "rogue", "claude-code"),
                           signer=signer)
    with pytest.raises(UnknownKey):
        rogue_room.post(thread_id="t1", type="observation",
                        body={"text": "let me in"})


def test_CROSS_PARTICIPANT_SIGNATURE(store, room, signers):
    """Codex's key, pinned and valid, signing a message that says claude-code.

    The key is real and the signature verifies mathematically. It still fails:
    a key authenticates one identity, and the payload naming another does not
    move the pin.
    """
    envelope = bare_envelope("claude-code")
    header = auth_header(signer="claude-code", key_id="codex-1",
                         room_id=store.room_id())
    signature = signers["codex"].sign(signed_payload(envelope, header))
    forged = canonical.seal({**envelope,
                             AUTH_FIELD: {**header, "signature": signature}})
    raw_commit(store, forged, "cross-participant")

    with pytest.raises(KeyNotValidHere, match="pinned for 'codex'"):
        store.verify_store()


def test_a_participant_key_cannot_sign_a_human_decision(store, room, target,
                                                        consequential, signers):
    """PARTICIPANT_KEY_FOR_HUMAN_DECISION."""
    forged = Ed25519Signer(signers["claude-code"].key_path, signer="human",
                           key_id="claude-code-1")
    with pytest.raises(KeyNotValidHere, match="pinned for 'claude-code'"):
        HumanDecisionAuthority(store).record(
            consequential["request_id"], "approve", signer=forged)


def test_the_human_key_cannot_impersonate_a_participant(store, tmp_path,
                                                        signers):
    """HUMAN_KEY_FOR_PARTICIPANT: the pin is per role in both directions."""
    forged = Ed25519Signer(signers["human"].key_path, signer="codex",
                           key_id="human-1")
    codex_room = AgentRoom(store, "codex",
                           ParticipantCursor(tmp_path / "c", "codex"),
                           signer=forged)
    with pytest.raises(KeyNotValidHere, match="pinned for 'human'"):
        codex_room.post(thread_id="t1", type="observation", body={"text": "x"})


# ===== payload mutation, transplant, downgrade =============================

def signed_message(store, signers, identity="claude-code", **overrides):
    envelope = bare_envelope(identity, **overrides)
    return canonical.seal(sign_envelope(envelope, signers[identity],
                                        room_id=store.room_id()))


def test_SIGNED_PAYLOAD_MUTATION(store, room, signers):
    """One field changed after signing. The digest is recomputed, so the
    artifact is internally consistent — and still fails."""
    message = signed_message(store, signers)
    mutated = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    mutated["body"] = {"text": "something else entirely"}
    raw_commit(store, canonical.seal(mutated), "mutated body")

    with pytest.raises(InvalidSignature, match="does not verify"):
        store.verify_store()


def test_an_extra_semantic_field_injected_after_signing_is_rejected(
        store, room, signers):
    message = signed_message(store, signers)
    injected = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    # A field the schema does not know about, so nothing else rejects it
    # first and the signature is what has to catch it.
    injected["priority"] = "urgent, trust me"
    raw_commit(store, canonical.seal(injected), "injected claim")

    with pytest.raises(InvalidSignature):
        store.verify_store()


def test_SIGNATURE_TRANSPLANT_between_messages(store, room, signers):
    first = signed_message(store, signers)
    second = bare_envelope("claude-code")
    stolen = canonical.seal({**second, AUTH_FIELD: dict(first[AUTH_FIELD])})
    raw_commit(store, stolen, "transplanted signature")

    with pytest.raises(InvalidSignature):
        store.verify_store()


def test_a_signature_does_not_travel_between_threads(store, room, signers):
    original = signed_message(store, signers, thread_id="t1")
    moved = {k: v for k, v in original.items() if k != canonical.DIGEST_FIELD}
    moved["thread_id"] = "t2"
    raw_commit(store, canonical.seal(moved), "moved thread")
    with pytest.raises(InvalidSignature):
        store.verify_store()


def test_a_signature_does_not_travel_between_message_types(store, room,
                                                           signers):
    original = signed_message(store, signers, type="claim")
    retyped = {k: v for k, v in original.items() if k != canonical.DIGEST_FIELD}
    retyped["type"] = "test_result"
    raw_commit(store, canonical.seal(retyped), "retyped")
    with pytest.raises(InvalidSignature):
        store.verify_store()


def test_a_decision_cannot_be_flipped_from_approval_to_rejection(
        store, room, target, consequential, signers):
    HumanDecisionAuthority(store).record(consequential["request_id"], "reject",
                                         decision_id="hd-no",
                                         signer=signers["human"])
    stored = [m for m in store.thread_messages("t1")
              if m["type"] == "rejection"][0]
    flipped = {k: v for k, v in stored.items() if k != canonical.DIGEST_FIELD}
    flipped["type"] = "approval"
    flipped["decision"] = dict(flipped["decision"], decision="approve")
    flipped["message_id"] = uuid7()
    raw_commit(store, canonical.seal(flipped), "flipped verdict")

    with pytest.raises(InvalidSignature):
        store.verify_store()


def test_changing_the_key_id_after_signing_is_rejected(store, room, signers):
    message = signed_message(store, signers)
    swapped = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    swapped[AUTH_FIELD] = {**swapped[AUTH_FIELD], "key_id": "codex-1"}
    raw_commit(store, canonical.seal(swapped), "swapped key id")
    # The key id is inside the signed payload, so changing it breaks the
    # signature before the role check even matters.
    with pytest.raises((InvalidSignature, KeyNotValidHere)):
        store.verify_store()


def test_changing_the_signer_after_signing_is_rejected(store, room, signers):
    message = signed_message(store, signers)
    swapped = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    swapped[AUTH_FIELD] = {**swapped[AUTH_FIELD], "signer": "codex"}
    swapped["sender"] = {"agent": "codex"}
    raw_commit(store, canonical.seal(swapped), "swapped signer")
    with pytest.raises((InvalidSignature, KeyNotValidHere)):
        store.verify_store()


def test_AUTH_VERSION_DOWNGRADE(store, room, signers):
    message = signed_message(store, signers)
    downgraded = {k: v for k, v in message.items()
                  if k != canonical.DIGEST_FIELD}
    downgraded[AUTH_FIELD] = {**downgraded[AUTH_FIELD],
                              "auth_schema_version": 0}
    raw_commit(store, canonical.seal(downgraded), "version downgrade")
    with pytest.raises(UnknownAuthVersion, match="refused rather than"):
        store.verify_store()


def test_ALGORITHM_DOWNGRADE(store, room, signers):
    message = signed_message(store, signers)
    weakened = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    weakened[AUTH_FIELD] = {**weakened[AUTH_FIELD], "method": "none"}
    raw_commit(store, canonical.seal(weakened), "algorithm downgrade")
    with pytest.raises(UnknownMethod, match="not implemented"):
        store.verify_store()


def test_a_foreign_domain_signature_is_not_a_signature_here(store, room,
                                                            signers):
    message = signed_message(store, signers)
    moved = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    moved[AUTH_FIELD] = {**moved[AUTH_FIELD], "domain": "some-other-protocol"}
    raw_commit(store, canonical.seal(moved), "foreign domain")
    with pytest.raises(MalformedAuthRecord, match="another protocol"):
        store.verify_store()


def test_an_unsigned_extra_field_inside_the_auth_record_is_refused(store, room,
                                                                   signers):
    message = signed_message(store, signers)
    smuggled = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    smuggled[AUTH_FIELD] = {**smuggled[AUTH_FIELD], "note": "trust me"}
    raw_commit(store, canonical.seal(smuggled), "extra auth field")
    with pytest.raises(MalformedAuthRecord, match="unknown fields"):
        store.verify_store()


def test_an_oversized_signature_is_refused(store, room, signers):
    message = signed_message(store, signers)
    huge = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    huge[AUTH_FIELD] = {**huge[AUTH_FIELD], "signature": "A" * 5000}
    raw_commit(store, canonical.seal(huge), "oversized signature")
    with pytest.raises(MalformedAuthRecord, match="over the"):
        store.verify_store()


@pytest.mark.parametrize("key_id", [
    "../../etc/passwd", "a/b", "UPPER", "", "x" * 80, ".hidden", "key id",
])
def test_a_key_id_cannot_carry_path_or_encoding_weirdness(store, room, signers,
                                                          key_id):
    message = signed_message(store, signers)
    odd = {k: v for k, v in message.items() if k != canonical.DIGEST_FIELD}
    odd[AUTH_FIELD] = {**odd[AUTH_FIELD], "key_id": key_id}
    raw_commit(store, canonical.seal(odd), "odd key id")
    with pytest.raises(MalformedAuthRecord, match="key_id"):
        store.verify_store()


def test_duplicate_json_keys_are_refused_before_anything_else(store, room,
                                                              signers):
    """Strict parsing first: two `sender` keys is not a message to interpret."""
    message = signed_message(store, signers)
    text = canonical.canonical_text(message)
    doubled = text.replace('"sender":', '"sender": {"agent": "human"}, "sender":', 1)
    rel = store.message_path("t1", message["message_id"])
    path = store.workdir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doubled, encoding="utf-8")
    git(store.workdir, "add", "-f", "--", rel)
    git(store.workdir, "commit", "-q", "-m", "duplicate keys")

    with pytest.raises(Exception, match="[Dd]uplicate"):
        store.verify_store()


# ===== rotation and revocation =============================================

def test_FORGED_KEY_ROTATION(store, signers, keydir):
    """A participant cannot rotate itself into a new key."""
    policy = store.trust
    rogue = generate_ed25519_keypair(keydir, "rogue-2")
    with pytest.raises(TrustUpdateError, match="must be signed by 'human'"):
        policy.apply_update(build_update(
            policy, signers["codex"], action="rotate", participant="codex",
            old_key_id="codex-1", new_key_id="rogue-2",
            public_key=rogue["public_key"],
            effective_commit=store.current_tip()), store=store)


def test_an_unsigned_policy_update_installs_nothing(store, signers, keydir):
    policy = store.trust
    rogue = generate_ed25519_keypair(keydir, "rogue-3")
    update = build_update(policy, signers["human"], action="add",
                          participant="codex", new_key_id="rogue-3",
                          public_key=rogue["public_key"],
                          effective_commit=store.current_tip())
    update[AUTH_FIELD] = {**update[AUTH_FIELD], "signature":
                          base64.b64encode(b"\x00" * 64).decode()}
    with pytest.raises(TrustUpdateError, match="does not verify"):
        policy.apply_update(update, store=store)


def test_a_replayed_policy_update_is_refused(store, signers, keydir):
    """Generations are monotonic, so an old update cannot be applied twice."""
    policy = store.trust
    pair = generate_ed25519_keypair(keydir, "codex-2")
    update = build_update(policy, signers["human"], action="rotate",
                          participant="codex", old_key_id="codex-1",
                          new_key_id="codex-2", public_key=pair["public_key"],
                          effective_commit=store.current_tip())
    policy.apply_update(update, store=store)
    with pytest.raises(TrustUpdateError, match="generation must be exactly"):
        policy.apply_update(update, store=store)


def test_REVOKED_KEY_AFTER_ROTATION(store, room, signers, keydir, tmp_path):
    """The old key verifies history it signed, and nothing after its revocation."""
    before = room.post(thread_id="t1", type="observation",
                       body={"text": "signed with codex-1"})
    codex_room = AgentRoom(store, "codex",
                           ParticipantCursor(tmp_path / "codex", "codex"),
                           signer=signers["codex"])
    old_message = codex_room.post(thread_id="t1", type="observation",
                                  body={"text": "old key, valid at the time"})
    # Revocation is effective *at* a commit, inclusive - the fail-closed
    # direction - so the rotation point has to be a commit after the last one
    # the old key legitimately signed.
    room.post(thread_id="t1", type="observation", body={"text": "boundary"})
    rotation_point = store.current_tip()

    pair = generate_ed25519_keypair(keydir, "codex-2")
    store.trust.apply_update(build_update(
        store.trust, signers["human"], action="rotate", participant="codex",
        old_key_id="codex-1", new_key_id="codex-2",
        public_key=pair["public_key"], effective_commit=rotation_point),
        store=store)

    # History stays verifiable: the old message was signed while the key was.
    assert store.verify_store() >= 2
    assert store.resolve_message(old_message["message_id"])["type"] == \
        "observation"

    # But the revoked key signs nothing further.
    with pytest.raises(KeyNotValidHere, match="revoked"):
        codex_room.post(thread_id="t1", type="observation",
                        body={"text": "after revocation"})

    # The new key does.
    rotated = AgentRoom(store, "codex",
                        ParticipantCursor(tmp_path / "codex2", "codex"),
                        signer=Ed25519Signer(pair["private_key_path"],
                                             signer="codex", key_id="codex-2"))
    assert rotated.post(thread_id="t1", type="observation",
                        body={"text": "new key"})["status"] == "created"


def test_a_key_id_cannot_be_reused(store, signers, keydir):
    """TRUST_POLICY_KEY_ID_COLLISION: reuse would make history ambiguous."""
    pair = generate_ed25519_keypair(keydir, "collide")
    with pytest.raises(TrustUpdateError, match="already pinned"):
        store.trust.apply_update(build_update(
            store.trust, signers["human"], action="add", participant="codex",
            new_key_id="codex-1", public_key=pair["public_key"],
            effective_commit=store.current_tip()), store=store)


def test_pinning_a_human_credential_needs_proof_of_possession(store, signers,
                                                              keydir):
    policy = store.trust
    replacement = generate_ed25519_keypair(keydir, "human-2")
    update = build_update(
        policy, signers["human"], action="rotate", participant=HUMAN_ROLE,
        old_key_id="human-1", new_key_id="human-2",
        public_key=replacement["public_key"], custody=CUSTODY_DEVICE,
        effective_commit=store.current_tip(),
        new_key_signer=Ed25519Signer(replacement["private_key_path"],
                                     signer="human", key_id="human-2"))
    del update["new_key_proof"]
    with pytest.raises(TrustUpdateError, match="counter-signature"):
        policy.apply_update(update, store=store)


def test_a_human_credential_rotation_with_proof_succeeds(store, signers,
                                                         keydir):
    policy = store.trust
    replacement = generate_ed25519_keypair(keydir, "human-2")
    policy.apply_update(build_update(
        policy, signers["human"], action="rotate", participant=HUMAN_ROLE,
        old_key_id="human-1", new_key_id="human-2",
        public_key=replacement["public_key"], custody=CUSTODY_DEVICE,
        effective_commit=store.current_tip(),
        new_key_signer=Ed25519Signer(replacement["private_key_path"],
                                     signer="human", key_id="human-2")),
        store=store)
    assert policy.current_human_key()["key_id"] == "human-2"
    assert policy.key("human-1")["revoked_generation"] == policy.generation


# ===== the human ceremony ==================================================

def test_the_prepare_submit_ceremony_produces_an_authenticated_decision(
        store, room, target, consequential, signers):
    """ANDROID_KEYSTORE_FORMAT: the device signs exactly these bytes.

    `prepare()` hands out a payload and a digest; a phone shows the summary,
    unlocks the credential with a fingerprint and returns a raw Ed25519
    signature; `submit()` attaches it. The disposable key here stands in for
    the phone.
    """
    authority = HumanDecisionAuthority(store)
    prepared = authority.prepare(consequential["request_id"], "approve",
                                 decision_id="hd-device")
    assert prepared["summary"]["action_id"] == "activate-agent-room-transport"
    assert prepared["summary"]["parameters"]["branch"] == "agent-room"

    payload = base64.b64decode(prepared["payload_b64"])
    assert payload.startswith(b'{"auth":'), "canonical, domain-separated bytes"
    assert DOMAIN.encode() in payload

    signature = signers["human"].sign(payload)
    authority.submit(prepared, signature)

    result = authorise(store, consequential["request_id"],
                       workdir=target["path"])
    assert result["authorised"] is True
    assert result["human_provenance"]["role"] == HUMAN_ROLE
    assert result["human_provenance"]["custody"] == CUSTODY_DEVICE


def test_a_wrong_device_public_key_cannot_approve(store, room, target,
                                                  consequential, keydir):
    """WRONG_DEVICE_KEY: another phone's key is not this phone's key."""
    authority = HumanDecisionAuthority(store)
    prepared = authority.prepare(consequential["request_id"], "approve")
    other = generate_ed25519_keypair(keydir, "other-phone")
    signature = Ed25519Signer(other["private_key_path"], signer="human",
                              key_id="other-phone").sign(
        base64.b64decode(prepared["payload_b64"]))
    with pytest.raises(InvalidSignature):
        authority.submit(prepared, signature)


def test_a_signature_over_a_different_payload_cannot_approve(
        store, room, target, consequential, signers):
    """WRONG_PAYLOAD: the device must sign the decision, not something else."""
    authority = HumanDecisionAuthority(store)
    prepared = authority.prepare(consequential["request_id"], "approve")
    signature = signers["human"].sign(b"some other bytes entirely")
    with pytest.raises(InvalidSignature):
        authority.submit(prepared, signature)


def test_HUMAN_ASSERTION_REPLAY_fails(store, room, target, consequential,
                                      signers):
    """An assertion is bound to one decision, message id included.

    Replaying yesterday's fingerprint against today's action is the whole
    reason the payload covers the entire decision rather than a challenge
    nonce alone.
    """
    authority = HumanDecisionAuthority(store)
    first = authority.prepare(consequential["request_id"], "approve",
                              decision_id="hd-first")
    signature = signers["human"].sign(base64.b64decode(first["payload_b64"]))
    authority.submit(first, signature)

    second = authority.prepare(consequential["request_id"], "approve",
                               decision_id="hd-second")
    assert second["payload_sha256"] != first["payload_sha256"]
    with pytest.raises(InvalidSignature):
        authority.submit(second, signature)


def test_an_unsigned_store_refuses_to_release(tmp_path, target):
    """No trust policy, no release. There is no flag that turns this off."""
    plain = GitMessageStore.initialise(tmp_path / "plain", branch="agent-room")
    configure_identity(plain.workdir)
    with pytest.raises(NoTrustPolicy, match="no option to proceed"):
        authorise(plain, uuid7(), workdir=target["path"])


def test_no_trust_any_escape_hatch_exists_in_the_cli():
    from agent_room.cli import build_parser

    help_text = build_parser().format_help()
    for escape in ("--trust-any", "--no-auth", "--insecure", "--skip-verify"):
        assert escape not in help_text


# ===== rollback and the trust anchor =======================================

@pytest.fixture
def anchored(store, room, tmp_path):
    room.post(thread_id="t1", type="observation", body={"text": "first"})
    checkpoint = TrustCheckpoint.bootstrap(
        store, expected_genesis=store.room_id(),
        expected_trust_policy_sha256=policy_digest(store.trust),
        path=tmp_path / "checkpoint.json")
    return checkpoint


def test_a_descendant_tip_is_accepted(store, room, anchored):
    before = anchored.document["last_accepted_tip"]
    room.post(thread_id="t1", type="observation", body={"text": "second"})
    result = anchored.accept(store)
    assert result["advanced"] is True
    assert result["previous_tip"] == before
    assert anchored.document["last_accepted_tip"] == store.current_tip()


def test_accepting_the_same_tip_twice_is_idempotent(store, room, anchored):
    first = anchored.accept(store)
    second = anchored.accept(store)
    assert first["accepted_tip"] == second["accepted_tip"]
    assert second["advanced"] is False


def test_ROLLBACK_TO_ANCESTOR_is_rejected(store, room, anchored):
    """The branch itself is rolled back, which is the actual attack.

    Passing an ancestor as a *candidate* is refused earlier and for a
    different reason — the candidate is read from the ref, never from the
    caller — so the rollback has to be done to the ref to be tested at all.
    """
    ancestor = store.current_tip()
    room.post(thread_id="t1", type="observation", body={"text": "second"})
    anchored.accept(store)
    advanced = anchored.document["last_accepted_tip"]

    git(store.workdir, "reset", "-q", "--hard", ancestor)
    with pytest.raises(RollbackRejected, match="does not descend"):
        anchored.accept(store)
    assert anchored.document["last_accepted_tip"] == advanced


def test_NON_DESCENDANT_REPLACEMENT_is_rejected(store, room, signers, anchored,
                                                tmp_path):
    """A different, perfectly signed history on the same branch name."""
    accepted = anchored.document["last_accepted_tip"]
    room.post(thread_id="t1", type="observation", body={"text": "second"})
    anchored.accept(store)

    # Rewrite: drop back and build a divergent branch from the genesis.
    git(store.workdir, "reset", "-q", "--hard", store.room_id())
    replacement_room = AgentRoom(
        store, "claude-code",
        ParticipantCursor(tmp_path / "replacement", "claude-code"),
        signer=signers["claude-code"])
    replacement_room.post(thread_id="t1", type="observation",
                          body={"text": "a different history"})

    with pytest.raises(RollbackRejected, match="does not descend"):
        anchored.accept(store)


def test_a_failed_verification_does_not_advance_the_checkpoint(
        store, room, anchored):
    before = anchored.document["last_accepted_tip"]
    room.post(thread_id="t1", type="observation", body={"text": "real"})
    raw_commit(store, canonical.seal(bare_envelope("codex")), "forged")

    with pytest.raises(UnauthenticatedMessage):
        anchored.accept(store)
    assert anchored.document["last_accepted_tip"] == before
    reloaded = TrustCheckpoint.load(anchored.path)
    assert reloaded.document["last_accepted_tip"] == before


def test_FRESH_BOOTSTRAP_WITHOUT_A_PIN_fails(store, room, tmp_path):
    with pytest.raises(NoTrustAnchor, match="refused rather than defaulted"):
        TrustCheckpoint.bootstrap(
            store, expected_genesis=None,
            expected_trust_policy_sha256=policy_digest(store.trust),
            path=tmp_path / "cp.json")
    with pytest.raises(NoTrustAnchor):
        TrustCheckpoint.load(tmp_path / "never-written.json")


def test_a_WRONG_BOOTSTRAP_PIN_fails(store, room, tmp_path):
    with pytest.raises(AnchorMismatch, match="different history"):
        TrustCheckpoint.bootstrap(
            store, expected_genesis="0" * 39 + "1",
            expected_trust_policy_sha256=policy_digest(store.trust),
            path=tmp_path / "cp.json")
    assert not (tmp_path / "cp.json").exists()


def test_the_CORRECT_PINNED_BOOTSTRAP_succeeds(store, room, tmp_path):
    room.post(thread_id="t1", type="observation", body={"text": "x"})
    genesis = store.room_id()
    checkpoint = TrustCheckpoint.bootstrap(
        store, expected_genesis=genesis,
        expected_trust_policy_sha256=policy_digest(store.trust),
        expected_tip=store.current_tip(), path=tmp_path / "cp.json")
    assert checkpoint.document["genesis"] == genesis
    assert checkpoint.document["last_accepted_tip"] == store.current_tip()
    assert stat.S_IMODE(os.stat(tmp_path / "cp.json").st_mode) == 0o600


def test_a_trust_policy_generation_cannot_go_backwards(store, room, anchored,
                                                       signers, keydir):
    pair = generate_ed25519_keypair(keydir, "codex-9")
    store.trust.apply_update(build_update(
        store.trust, signers["human"], action="add", participant="codex",
        new_key_id="codex-9", public_key=pair["public_key"],
        effective_commit=store.current_tip()), store=store)
    anchored.accept(store)

    stale = TrustPolicy(json.loads(json.dumps(store.trust.document)))
    stale.document["generation"] = 1
    store.trust = stale
    with pytest.raises(RollbackRejected, match="generation went backwards"):
        anchored.accept(store)


# ===== secrets, permissions, logging =======================================

def test_no_private_key_material_reaches_the_trust_policy(store):
    text = canonical.canonical_text(store.trust.document)
    assert "PRIVATE KEY" not in text.upper()
    assert "BEGIN OPENSSH" not in text.upper()
    for entry in store.trust.document["keys"].values():
        assert "PUBLIC KEY" in entry["public_key"]


def test_a_trust_policy_refuses_private_key_material(store):
    document = json.loads(json.dumps(store.trust.document))
    document["keys"]["codex-1"]["public_key"] = \
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    with pytest.raises(Exception, match="never holds a private key"):
        TrustPolicy(document)


def test_generated_private_keys_are_owner_only(keydir):
    pair = generate_ed25519_keypair(keydir, "modes")
    mode = stat.S_IMODE(os.stat(pair["private_key_path"]).st_mode)
    assert mode == 0o600, oct(mode)
    assert stat.S_IMODE(os.stat(keydir).st_mode) == 0o700


def test_a_world_readable_signing_key_is_refused(keydir):
    pair = generate_ed25519_keypair(keydir, "leaky")
    os.chmod(pair["private_key_path"], 0o644)
    with pytest.raises(Exception, match="not a private key"):
        Ed25519Signer(pair["private_key_path"], signer="codex", key_id="leaky")


def test_no_private_material_is_passed_on_a_command_line():
    """S2-J: private keys go in as file paths, never as arguments."""
    import inspect

    import agent_room.auth as auth_mod

    source = inspect.getsource(auth_mod)
    assert "-passin" not in source and "-passout" not in source
    # The private key reaches openssl as `-inkey <path>`; the bytes never do.
    assert '"-inkey", str(self.key_path)' in source


def test_a_fingerprint_is_public_and_short(keydir):
    pair = generate_ed25519_keypair(keydir, "fp")
    fingerprint = public_key_fingerprint(pair["public_key"])
    assert fingerprint.startswith("SHA256:") and len(fingerprint) < 80
    assert "PRIVATE" not in fingerprint


def test_no_signature_material_leaks_into_a_proof_artifact(tmp_path, target):
    from agent_room.proof import run_proof

    record = run_proof(["python3", "-c", "print('clean')"],
                       cwd=target["path"], run_dir=tmp_path / "runs",
                       proof_id="leakcheck")
    artifact = open(record["artifact_path"]).read()
    assert "PRIVATE KEY" not in artifact.upper()


# ===========================================================================
# S2 corrective pass — supervisor review of a873a3c8…
# ===========================================================================

# ----- S2-C1: key validity intervals are mandatory and bounded -------------

def test_NEW_KEY_WITH_NULL_EFFECTIVE_COMMIT_is_refused(store, signers, keydir):
    """A key with no lower boundary was valid for *all of history*.

    Including commits that predate it — which is exactly how a newly installed
    key could authenticate a forged artifact from before it existed.
    """
    pair = generate_ed25519_keypair(keydir, "nullkey")
    with pytest.raises(TrustUpdateError, match="full Git object id"):
        store.trust.apply_update(build_update(
            store.trust, signers["human"], action="add", participant="codex",
            new_key_id="nullkey", public_key=pair["public_key"],
            effective_commit=None), store=store)


def test_REVOKE_WITH_NULL_EFFECTIVE_COMMIT_is_refused(store, signers):
    """A revocation without a boundary still authenticated historical commits."""
    with pytest.raises(TrustUpdateError, match="full Git object id"):
        store.trust.apply_update(build_update(
            store.trust, signers["human"], action="revoke", participant="codex",
            old_key_id="codex-1", effective_commit=None), store=store)


@pytest.mark.parametrize("boundary", [
    "HEAD", "main~1", "abc123", "z" * 40, "", 12345,
])
def test_a_malformed_boundary_is_refused(store, signers, keydir, boundary):
    pair = generate_ed25519_keypair(keydir, "badbound")
    with pytest.raises(TrustUpdateError, match="full Git object id|not a commit"):
        store.trust.apply_update(build_update(
            store.trust, signers["human"], action="add", participant="codex",
            new_key_id="badbound", public_key=pair["public_key"],
            effective_commit=boundary), store=store)


def test_a_boundary_from_an_unrelated_history_is_refused(store, signers,
                                                         keydir, tmp_path):
    """A commit id that exists somewhere else bounds nothing here."""
    other = tmp_path / "elsewhere"
    other.mkdir()
    git(other, "init", "-q", "-b", "w")
    configure_identity(other)
    (other / "f.txt").write_text("x\n", encoding="utf-8")
    git(other, "add", "-A")
    git(other, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "unrelated")
    foreign = git(other, "rev-parse", "HEAD").strip()

    pair = generate_ed25519_keypair(keydir, "foreignbound")
    with pytest.raises(TrustUpdateError, match="not a commit in this room"):
        store.trust.apply_update(build_update(
            store.trust, signers["human"], action="add", participant="codex",
            new_key_id="foreignbound", public_key=pair["public_key"],
            effective_commit=foreign), store=store)


def test_a_key_does_not_authenticate_before_its_effective_boundary(
        store, room, signers, keydir):
    """The interval, asserted directly against two points in history."""
    early = store.current_tip()
    room.post(thread_id="t1", type="observation", body={"text": "later"})
    boundary = store.current_tip()

    pair = generate_ed25519_keypair(keydir, "late-key")
    store.trust.apply_update(build_update(
        store.trust, signers["human"], action="add", participant="codex",
        new_key_id="late-key", public_key=pair["public_key"],
        effective_commit=boundary), store=store)
    entry = store.trust.key("late-key")

    with pytest.raises(KeyNotValidHere, match="had no authority"):
        store.trust.assert_valid_for(entry, role="codex", method="ed25519",
                                     at_commit=early,
                                     ancestry=store.is_strict_ancestor)
    # Inclusive at the boundary, and valid for its descendants.
    assert store.trust.assert_valid_for(
        entry, role="codex", method="ed25519", at_commit=boundary,
        ancestry=store.is_strict_ancestor)


def test_a_revoked_key_cannot_authenticate_a_raw_git_message_after_the_boundary(
        store, room, signers, keydir, tmp_path):
    """The write path blocked this by generation; history did not."""
    codex_room = AgentRoom(store, "codex",
                           ParticipantCursor(tmp_path / "codex", "codex"),
                           signer=signers["codex"])
    codex_room.post(thread_id="t1", type="observation",
                    body={"text": "legitimate, before revocation"})
    room.post(thread_id="t1", type="observation", body={"text": "marker"})
    boundary = store.current_tip()

    store.trust.apply_update(build_update(
        store.trust, signers["human"], action="revoke", participant="codex",
        old_key_id="codex-1", effective_commit=boundary), store=store)

    # Raw Git, so the write path's refusal is bypassed entirely.
    forged = canonical.seal(sign_envelope(
        bare_envelope("codex", body={"text": "after revocation"}),
        signers["codex"], room_id=store.room_id()))
    raw_commit(store, forged, "post-revocation forgery")

    with pytest.raises(KeyNotValidHere, match="revoked"):
        store.verify_store()


def test_the_current_write_path_enforces_the_same_interval(store, room,
                                                           signers, tmp_path):
    """`at_commit=None` used to skip boundaries entirely on the write path."""
    room.post(thread_id="t1", type="observation", body={"text": "marker"})
    boundary = store.current_tip()
    store.trust.apply_update(build_update(
        store.trust, signers["human"], action="revoke", participant="codex",
        old_key_id="codex-1", effective_commit=boundary), store=store)

    codex_room = AgentRoom(store, "codex",
                           ParticipantCursor(tmp_path / "codex", "codex"),
                           signer=signers["codex"])
    with pytest.raises(KeyNotValidHere, match="revoked"):
        codex_room.post(thread_id="t1", type="observation",
                        body={"text": "should not be writable"})


def test_a_policy_with_a_null_boundary_cannot_even_be_loaded(store):
    document = json.loads(json.dumps(store.trust.document))
    document["keys"]["codex-1"]["effective_commit"] = None
    with pytest.raises(Exception, match="history boundary"):
        TrustPolicy(document)


def test_the_bootstrap_human_key_is_effective_at_genesis(store):
    assert store.trust.key("human-1")["effective_commit"] == store.room_id()


# ----- S2-C2: the checkpoint records what it verified ----------------------

def test_a_candidate_that_is_not_the_room_head_is_refused(store, room,
                                                          signers, anchored,
                                                          tmp_path):
    """CANDIDATE_TIP_MISMATCH.

    A side descendant exists in the object database and descends from the
    accepted tip, while the branch points somewhere else. The old code
    verified the branch and recorded the side commit.
    """
    accepted = anchored.document["last_accepted_tip"]
    # Side descendant C, reachable but not the branch head.
    git(store.workdir, "checkout", "-q", "-b", "side", accepted)
    (store.workdir / "README.agent-room.md").write_text(
        "side\n", encoding="utf-8")
    git(store.workdir, "add", "-f", "--", "README.agent-room.md")
    git(store.workdir, "commit", "-q", "-m", "side descendant")
    side = git(store.workdir, "rev-parse", "HEAD").strip()
    git(store.workdir, "checkout", "-q", "agent-room")

    # Branch head B, legitimately advanced.
    room.post(thread_id="t1", type="observation", body={"text": "real B"})
    head = store.current_tip()
    assert side != head and store.is_strict_ancestor(accepted, side)

    with pytest.raises(CheckpointError, match="not the room's head"):
        anchored.accept(store, side)
    assert anchored.document["last_accepted_tip"] == accepted

    # The honest path still works.
    assert anchored.accept(store)["accepted_tip"] == head


@pytest.mark.parametrize("which", ["ancestor", "unrelated"])
def test_a_supplied_candidate_is_never_taken_from_the_caller(store, room,
                                                             anchored, which):
    accepted = anchored.document["last_accepted_tip"]
    room.post(thread_id="t1", type="observation", body={"text": "advance"})
    candidate = accepted if which == "ancestor" else "0" * 39 + "1"
    with pytest.raises(CheckpointError, match="not the room's head"):
        anchored.accept(store, candidate)
    assert anchored.document["last_accepted_tip"] == accepted


def test_the_checkpoint_does_not_advance_if_the_branch_moves_mid_verification(
        store, room, signers, anchored, monkeypatch, tmp_path):
    """A head that settles somewhere other than what was verified."""
    accepted = anchored.document["last_accepted_tip"]
    room.post(thread_id="t1", type="observation", body={"text": "first"})

    real_verify = store.verify_store
    moved = {}

    def verify_then_move():
        result = real_verify()
        if not moved:
            moved["yes"] = True
            AgentRoom(store, "claude-code",
                      ParticipantCursor(tmp_path / "racer", "claude-code"),
                      signer=signers["claude-code"]).post(
                thread_id="t1", type="observation", body={"text": "racer"})
        return result

    monkeypatch.setattr(store, "verify_store", verify_then_move)
    with pytest.raises(CheckpointError, match="moved from"):
        anchored.accept(store)
    assert anchored.document["last_accepted_tip"] == accepted


# ----- S2-C3: signatures are bound to one room ----------------------------

def sibling_room(tmp_path, signers, keydir, name="room-b"):
    """A second room pinning the *same* keys. Only the genesis differs."""
    other = GitMessageStore.initialise(tmp_path / name, branch="agent-room")
    configure_identity(other.workdir)
    human_pub = (keydir / "human-1.ed25519.pem")
    policy = TrustPolicy.bootstrap(
        room_id=other.room_id(), human_key_id="human-1",
        human_public_key=_public_of(keydir, "human-1"),
        human_custody=CUSTODY_DEVICE)
    other.trust = policy
    for role in ("claude-code", "codex", "release-recorder"):
        policy.apply_update(build_update(
            policy, signers["human"], action="add", participant=role,
            new_key_id=f"{role}-1", public_key=_public_of(keydir, f"{role}-1"),
            effective_commit=other.current_tip()), store=other)
    return other


def _public_of(keydir, key_id):
    from agent_room.auth import _openssl

    code, pub, _err = _openssl(["pkey", "-in",
                                str(keydir / f"{key_id}.ed25519.pem"),
                                "-pubout"])
    assert code == 0
    return pub.decode("ascii")


def test_CROSS_ROOM_SIGNATURE_REPLAY(store, room, signers, keydir, tmp_path):
    """The same keys, two rooms, one byte-identical authenticated message.

    Participant keys are expected to be reused across rooms, so a domain of
    "Agent Room v1" was not enough: it said what kind of thing was signed, not
    which room it belonged to.
    """
    posted = room.post(thread_id="t1", type="observation",
                       body={"text": "a message from room A"})
    original = store.read("t1", posted["message_id"])
    assert original["auth"]["room_id"] == store.room_id()

    other = sibling_room(tmp_path, signers, keydir)
    assert other.room_id() != store.room_id()
    raw_commit(other, original, "transplanted from room A")

    with pytest.raises(KeyNotValidHere, match="names room"):
        other.verify_store()


def transplant_thread(source, destination, thread_id="t1"):
    """Copy an entire authenticated thread across, in commit order.

    The whole thread rather than one message, so parent and evidence
    references resolve in the destination: otherwise the transplant is refused
    for a dangling reference and the room binding is never reached, which
    would make the test pass for the wrong reason.
    """
    for message in source.thread_messages(thread_id):
        raw_commit(destination, message, f"transplanted {message['type']}")


def test_a_human_approval_does_not_transplant_between_rooms(
        store, room, target, consequential, signers, keydir, tmp_path):
    HumanDecisionAuthority(store).record(consequential["request_id"],
                                         "approve", decision_id="hd-x",
                                         signer=signers["human"])
    assert any(m["type"] == "approval" for m in store.thread_messages("t1"))

    other = sibling_room(tmp_path, signers, keydir, name="room-c")
    transplant_thread(store, other)
    with pytest.raises(KeyNotValidHere, match="names room"):
        other.verify_store()


def test_an_execution_receipt_does_not_transplant_between_rooms(
        store, room, target, consequential, signers, keydir, tmp_path):
    HumanDecisionAuthority(store).record(consequential["request_id"],
                                         "approve", decision_id="hd-y",
                                         signer=signers["human"])
    reserve(store, consequential["request_id"], workdir=target["path"],
            signer=signers["release-recorder"])
    assert any(m["type"] == "execution_receipt"
               for m in store.thread_messages("t1"))

    other = sibling_room(tmp_path, signers, keydir, name="room-d")
    transplant_thread(store, other)
    with pytest.raises(KeyNotValidHere, match="names room"):
        other.verify_store()


def test_the_signed_payload_carries_the_room_identity(store, room):
    posted = room.post(thread_id="t1", type="observation", body={"text": "x"})
    stored = store.read("t1", posted["message_id"])
    header = {k: v for k, v in stored["auth"].items() if k != "signature"}
    payload = signed_payload(stored, header)
    assert store.room_id().encode() in payload
    assert stored["auth"]["auth_schema_version"] == 2


# ----- S2-C4: references are authenticated before they are used -----------

def test_SIGNED_REPLY_UNSIGNED_PARENT(store, room, signers):
    """A signed reply validated against a forged parent, via a targeted read."""
    parent = canonical.seal(bare_envelope("codex", type="question",
                                          body={"text": "unsigned parent"}))
    raw_commit(store, parent, "unsigned parent")

    child = canonical.seal(sign_envelope(
        bare_envelope("claude-code", type="answer",
                      parent_id=parent["message_id"],
                      body={"text": "a properly signed reply"}),
        signers["claude-code"], room_id=store.room_id()))
    raw_commit(store, child, "signed child")

    # The targeted read must fail, not only the whole-store walk.
    with pytest.raises(UnauthenticatedMessage):
        store.resolve_message(child["message_id"])
    with pytest.raises(UnauthenticatedMessage):
        store.verify_store()


def test_SIGNED_CLAIM_UNSIGNED_EVIDENCE(store, room, signers):
    """A `supported` claim cannot rest on evidence nobody signed."""
    evidence = canonical.seal(bare_envelope(
        "codex", type="evidence", body={"text": "forged evidence"},
        evidence=[{"kind": "repo", "repo": "pr0dus/cek",
                   "commit": "a" * 40, "path": "x.py"}]))
    raw_commit(store, evidence, "unsigned evidence")

    claim = canonical.seal(sign_envelope(bare_envelope(
        "claude-code", type="claim", body={"text": "it follows"},
        claim={"status": "supported", "scope": "at that commit",
               "revision_condition": "a counterexample",
               "evidence_basis": [evidence["message_id"]]}),
        signers["claude-code"], room_id=store.room_id()))
    raw_commit(store, claim, "signed claim on unsigned evidence")

    with pytest.raises(UnauthenticatedMessage):
        store.resolve_message(claim["message_id"])


def test_a_claim_cannot_rest_on_evidence_signed_by_the_wrong_role(
        store, room, signers):
    """Real signature, wrong identity for the key that made it."""
    envelope = bare_envelope("codex", type="evidence",
                             body={"text": "mis-signed evidence"},
                             evidence=[{"kind": "repo", "repo": "pr0dus/cek",
                                        "commit": "a" * 40, "path": "x.py"}])
    header = auth_header(signer="codex", key_id="claude-code-1",
                         room_id=store.room_id())
    signature = signers["claude-code"].sign(signed_payload(envelope, header))
    evidence = canonical.seal({**envelope,
                               AUTH_FIELD: {**header, "signature": signature}})
    raw_commit(store, evidence, "evidence signed by the wrong key")

    claim = canonical.seal(sign_envelope(bare_envelope(
        "claude-code", type="claim", body={"text": "it follows"},
        claim={"status": "supported", "scope": "at that commit",
               "revision_condition": "a counterexample",
               "evidence_basis": [evidence["message_id"]]}),
        signers["claude-code"], room_id=store.room_id()))
    raw_commit(store, claim, "signed claim on mis-signed evidence")

    with pytest.raises(KeyNotValidHere):
        store.resolve_message(claim["message_id"])


def test_the_write_path_will_not_reference_an_unauthenticated_message(
        store, room, signers):
    parent = canonical.seal(bare_envelope("codex", type="question",
                                          body={"text": "unsigned"}))
    raw_commit(store, parent, "unsigned parent")
    with pytest.raises(UnauthenticatedMessage):
        room.reply(parent["message_id"], type="answer",
                   body={"text": "replying to a forgery"})


def test_reference_authentication_does_not_recurse(store, room, signers):
    """Bounded: a chain of legitimate references still reads in one pass."""
    first = room.post(thread_id="t1", type="evidence",
                      body={"text": "root evidence"},
                      evidence=[{"id": "e1", "kind": "repo",
                                 "repo": "pr0dus/cek", "commit": "a" * 40,
                                 "path": "x.py"}])
    second = room.reply(first["message_id"], type="claim",
                        body={"text": "supported by e1"},
                        claim={"status": "supported", "scope": "narrow",
                               "revision_condition": "a counterexample",
                               "evidence_basis": [first["message_id"]]})
    third = room.reply(second["message_id"], type="observation",
                       body={"text": "and onwards"})
    assert store.resolve_message(third["message_id"])["type"] == "observation"
    assert store.verify_store() == 3


# ----- S2-C5: bootstrap pins both roots -----------------------------------

def test_a_correct_genesis_with_the_wrong_policy_root_is_refused(store, room,
                                                                 tmp_path):
    with pytest.raises(AnchorMismatch, match="different set"):
        TrustCheckpoint.bootstrap(
            store, expected_genesis=store.room_id(),
            expected_trust_policy_sha256="f" * 64,
            path=tmp_path / "cp.json")
    assert not (tmp_path / "cp.json").exists()


def test_a_wrong_genesis_with_the_correct_policy_root_is_refused(store, room,
                                                                 tmp_path):
    with pytest.raises(AnchorMismatch, match="different history"):
        TrustCheckpoint.bootstrap(
            store, expected_genesis="0" * 39 + "1",
            expected_trust_policy_sha256=policy_digest(store.trust),
            path=tmp_path / "cp.json")
    assert not (tmp_path / "cp.json").exists()


def test_bootstrap_without_a_policy_pin_is_refused(store, room, tmp_path):
    for pin in (None, "", "not-a-digest", "a" * 63):
        with pytest.raises(NoTrustAnchor, match="trust policy root"):
            TrustCheckpoint.bootstrap(
                store, expected_genesis=store.room_id(),
                expected_trust_policy_sha256=pin, path=tmp_path / "cp.json")
    assert not (tmp_path / "cp.json").exists()


def test_an_alternative_policy_root_cannot_bootstrap_the_same_genesis(
        store, room, keydir, tmp_path):
    """The attack the genesis pin alone does not stop.

    Same room history, a policy pinning a different human key. Without a
    second out-of-band root it verifies perfectly — under the attacker's keys.
    """
    impostor = generate_ed25519_keypair(keydir, "impostor-human")
    alternative = TrustPolicy.bootstrap(
        room_id=store.room_id(), human_key_id="impostor-human",
        human_public_key=impostor["public_key"])
    real_pin = policy_digest(store.trust)
    store.trust = alternative

    with pytest.raises(AnchorMismatch, match="different set"):
        TrustCheckpoint.bootstrap(
            store, expected_genesis=store.room_id(),
            expected_trust_policy_sha256=real_pin, path=tmp_path / "cp.json")


def test_a_changed_policy_at_the_same_generation_is_refused(store, room,
                                                            anchored, keydir):
    """The only legitimate way the pins move is a signed update, and a signed
    update advances the generation."""
    document = json.loads(json.dumps(store.trust.document))
    pair = generate_ed25519_keypair(keydir, "smuggled")
    document["keys"]["smuggled"] = {
        **document["keys"]["codex-1"], "key_id": "smuggled",
        "public_key": pair["public_key"],
    }
    store.trust = TrustPolicy(document)          # same generation, new key
    with pytest.raises(RollbackRejected, match="without advancing its generation"):
        anchored.accept(store)


def test_a_legitimate_signed_update_still_advances(store, room, anchored,
                                                   signers, keydir):
    pair = generate_ed25519_keypair(keydir, "codex-next")
    store.trust.apply_update(build_update(
        store.trust, signers["human"], action="add", participant="codex",
        new_key_id="codex-next", public_key=pair["public_key"],
        effective_commit=store.current_tip()), store=store)
    room.post(thread_id="t1", type="observation", body={"text": "after update"})
    result = anchored.accept(store)
    assert result["advanced"] is True
    assert anchored.document["trust_policy_sha256"] == policy_digest(store.trust)

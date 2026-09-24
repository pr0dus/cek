"""A monotonic trust anchor for the transport.

Every integrity check in this package authenticates the object graph it can
see. None of them can tell you that the graph you are looking at is the one
that was there yesterday — a remote can be force-replaced with a different,
perfectly well-formed, perfectly signed history before a fresh clone, and
local verification would pass on it happily.

So the room remembers. A checkpoint records the genesis this room was
bootstrapped against and the last remote tip that passed full verification,
and a new tip is accepted only when it **descends** from that one. Rollback to
an ancestor, replacement by an unrelated history and rewritten history are all
the same answer: not a descendant, refused.

**No trust on first use, and there are two roots.** A fresh device with no
checkpoint does not simply believe whatever tip the remote offers. Bootstrapping
requires a genesis identity supplied out of band — read from somewhere that is
not the remote being bootstrapped against — and the remote's actual root commit
has to match it.

A genesis alone is not enough, which was a real gap. The trust policy is
deliberately not on the room branch, so it is a *second* root: an attacker who
supplies both a plausible history and a policy pinning their own human key can
produce a branch that verifies perfectly under it. So bootstrapping also
requires the policy's digest out of band, and a later acceptance refuses a
changed policy digest at an unchanged generation — the only legitimate way for
that digest to move is a signed update, which advances the generation.

**The candidate is observed, never supplied.** The checkpoint records exactly
the history that passed verification. Accepting a caller's candidate while
verifying the branch head would let an arbitrary reachable object become the
new anchor, so the candidate is read from the configured ref, verified, and
re-read afterwards to catch a branch that moved underneath.

**The checkpoint only advances after everything else passes.** Namespace,
append-only history, digests, references, receipt lifecycle and signatures all
run first; a failure anywhere leaves the checkpoint exactly where it was, so a
bad fetch can never become the new baseline.

The honest limit: this file belongs to the service user. Someone who already
controls that user's local state can edit it, and then a rollback would be
accepted. That is not solved here — it is what S3's service isolation is for.
"""

import datetime as dt
import hashlib
import json
import os
import tempfile
from pathlib import Path

from . import canonical
from .errors import AgentRoomError

CHECKPOINT_SCHEMA_VERSION = 1

STATE_FILE_MODE = 0o600
STATE_DIR_MODE = 0o700

#: A full Git object id and nothing else: an anchor is an identity, and a
#: revision expression is not one.
OID_LENGTHS = (40, 64)

__all__ = [
    "CHECKPOINT_SCHEMA_VERSION", "CheckpointError", "NoTrustAnchor",
    "AnchorMismatch", "RollbackRejected", "TrustCheckpoint", "policy_digest",
]


class CheckpointError(AgentRoomError):
    """The transport trust anchor refused something."""


class NoTrustAnchor(CheckpointError):
    """No local checkpoint, and no out-of-band anchor was supplied.

    Deliberately not recoverable by trusting the remote: that is exactly the
    attack a first-use anchor exists to prevent.
    """


class AnchorMismatch(CheckpointError):
    """The remote's genesis is not the one this room was anchored to."""


class RollbackRejected(CheckpointError):
    """The candidate tip does not descend from the last accepted one."""


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_oid(value) -> bool:
    return (isinstance(value, str) and len(value) in OID_LENGTHS
            and all(c in "0123456789abcdef" for c in value))


def policy_digest(policy) -> str | None:
    """The out-of-band pin for a trust policy: SHA-256 over its canonical form.

    Public because an operator has to read it off one device and type it into
    another; there is nothing secret in a policy.
    """
    if policy is None:
        return None
    return hashlib.sha256(
        canonical.canonical_bytes(policy.document)).hexdigest()


#: Kept as the internal spelling used through this module.
_policy_digest = policy_digest


class TrustCheckpoint:
    """Local, durable, monotonic. Contains no private material."""

    def __init__(self, document: dict, *, path=None) -> None:
        self.document = document
        self.path = Path(path) if path else None
        self._validate()

    def _validate(self) -> None:
        document = self.document
        version = document.get("checkpoint_schema_version")
        if type(version) is not int or version != CHECKPOINT_SCHEMA_VERSION:
            raise CheckpointError(
                f"checkpoint_schema_version must be the integer "
                f"{CHECKPOINT_SCHEMA_VERSION}, got {version!r}"
            )
        for field in ("room_id", "genesis", "last_accepted_tip"):
            if not _is_oid(document.get(field)):
                raise CheckpointError(
                    f"checkpoint {field} {document.get(field)!r} must be a full "
                    "Git object id"
                )
        for name in ("private", "secret", "key_path"):
            if name in document:
                raise CheckpointError(
                    f"a checkpoint must contain no {name!r} field; it holds "
                    "public identities only"
                )

    # -- persistence -------------------------------------------------------
    @classmethod
    def load(cls, path) -> "TrustCheckpoint":
        path = Path(path)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise NoTrustAnchor(
                f"no trust checkpoint at {path}: {exc}. This room has never "
                "been anchored here, and a fresh device must be bootstrapped "
                "against a genesis identity obtained out of band - never "
                "against whatever the remote happens to offer."
            ) from exc
        document = canonical.strict_loads(raw)
        if not isinstance(document, dict):
            raise CheckpointError(f"{path} is not a checkpoint object")
        return cls(document, path=path)

    def save(self, path=None) -> Path:
        target = Path(path or self.path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=STATE_DIR_MODE)
        fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        try:
            os.fchmod(fd, STATE_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(canonical.canonical_text(self.document))
                handle.flush()
                os.fsync(handle.fileno())
            # Replace, so the checkpoint is never observed half-written: it
            # either names the old tip or the new one.
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self.path = target
        return target

    # -- bootstrap ---------------------------------------------------------
    @classmethod
    def bootstrap(cls, store, *, expected_genesis: str,
                  expected_trust_policy_sha256: str,
                  expected_tip: str | None = None, path=None) -> "TrustCheckpoint":
        """Anchor this room for the first time against two out-of-band roots.

        Both must come from somewhere other than the remote being anchored — a
        note, another device, the person who created the room. Supplying the
        remote's own answer back to it, or defaulting the policy pin from the
        policy file being checked, would be trust on first use with extra
        steps.
        """
        if not _is_oid(expected_genesis):
            raise NoTrustAnchor(
                f"expected_genesis {expected_genesis!r} must be a full Git "
                "object id obtained out of band; bootstrapping without one is "
                "refused rather than defaulted"
            )
        if not isinstance(expected_trust_policy_sha256, str) or \
                len(expected_trust_policy_sha256) != 64 or \
                not all(c in "0123456789abcdef"
                        for c in expected_trust_policy_sha256):
            raise NoTrustAnchor(
                "expected_trust_policy_sha256 must be the out-of-band digest "
                "of the trust policy root. A genesis commit alone does not "
                "say which human key is allowed to authenticate the history "
                "descending from it, so a policy with a different human root "
                "would verify an alternative history just as happily."
            )
        store.assert_authenticated("bootstrapping a trust anchor")
        observed_policy = _policy_digest(store.trust)
        if observed_policy != expected_trust_policy_sha256:
            raise AnchorMismatch(
                f"the supplied trust policy digests to {observed_policy[:12]}, "
                f"but this room was anchored to "
                f"{expected_trust_policy_sha256[:12]}. This is a different set "
                "of trust roots."
            )
        observed = store.room_id()
        if observed != expected_genesis:
            raise AnchorMismatch(
                f"the remote's root commit is {observed[:12]}, but this room "
                f"was anchored to {expected_genesis[:12]}. This is a different "
                "history wearing the same branch name."
            )
        # Observed, not supplied: the checkpoint has to name the history that
        # was actually verified.
        tip = store.current_tip()
        if expected_tip is not None:
            if not _is_oid(expected_tip):
                raise NoTrustAnchor(
                    f"expected_tip {expected_tip!r} must be a full Git object id")
            if tip != expected_tip:
                raise AnchorMismatch(
                    f"the remote tip is {tip[:12]}, not the out-of-band "
                    f"{expected_tip[:12]}"
                )
        # Full verification before the first checkpoint, not after.
        store.verify_store()
        document = {
            "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
            "room_id": observed,
            "genesis": expected_genesis,
            "last_accepted_tip": tip,
            "trust_generation": getattr(store.trust, "generation", None),
            "trust_policy_sha256": _policy_digest(store.trust),
            "bootstrapped_at": _now_iso(),
            "accepted_at": _now_iso(),
        }
        checkpoint = cls(document, path=path)
        if path:
            checkpoint.save(path)
        return checkpoint

    # -- advance -----------------------------------------------------------
    def accept(self, store, candidate_tip: str | None = None) -> dict:
        """Verify the room's head and, only then, advance the anchor.

        `candidate_tip` is an assertion about what the caller believes the head
        is, not a choice of what to anchor. It must equal the observed ref tip;
        anything else is refused rather than verified-here-recorded-there.
        """
        observed = store.current_tip()
        if candidate_tip is not None and candidate_tip != observed:
            raise CheckpointError(
                f"candidate tip {str(candidate_tip)[:12]} is not the room's "
                f"head {observed[:12]}. The checkpoint records the history "
                "that was verified, so the candidate is read from the ref and "
                "never taken from the caller - otherwise any reachable object "
                "could become the accepted anchor while a different one was "
                "checked."
            )
        candidate = observed
        if not _is_oid(candidate):
            raise CheckpointError(
                f"candidate tip {candidate!r} must be a full Git object id")

        observed_room = store.room_id()
        if observed_room != self.document["genesis"]:
            raise AnchorMismatch(
                f"this history's root is {observed_room[:12]}, not the "
                f"anchored genesis {self.document['genesis'][:12]}; an "
                "unrelated history is not an update"
            )

        accepted = self.document["last_accepted_tip"]
        if candidate != accepted and not store.is_strict_ancestor(accepted,
                                                                  candidate):
            raise RollbackRejected(
                f"candidate tip {candidate[:12]} does not descend from the "
                f"last accepted {accepted[:12]}. Rollback to an ancestor and "
                "replacement by a rewritten history look identical from here, "
                "and both are refused."
            )

        generation = getattr(store.trust, "generation", None)
        previous = self.document.get("trust_generation")
        if generation is not None and previous is not None and \
                generation < previous:
            raise RollbackRejected(
                f"the trust policy generation went backwards "
                f"({previous} -> {generation}); an older policy may pin keys "
                "that have since been revoked"
            )
        policy_digest = _policy_digest(store.trust)
        if generation == previous and \
                policy_digest != self.document.get("trust_policy_sha256"):
            raise RollbackRejected(
                "the trust policy changed without advancing its generation. "
                "The only legitimate way for the pinned keys to move is a "
                "signed update, and a signed update increments the generation."
            )

        # Everything else first. If any of this raises, the checkpoint below
        # is never reached and the anchor stays exactly where it was.
        verified = store.verify_store()

        # Re-observe: if the branch moved while we were verifying it, what we
        # checked is not what we would be recording.
        settled = store.current_tip()
        if settled != candidate:
            raise CheckpointError(
                f"the room head moved from {candidate[:12]} to "
                f"{settled[:12]} during verification; the anchor is not "
                "advanced to a history nobody checked"
            )

        self.document = {
            **self.document,
            "last_accepted_tip": candidate,
            "trust_generation": generation,
            "trust_policy_sha256": policy_digest,
            "accepted_at": _now_iso(),
        }
        self._validate()
        if self.path:
            self.save()
        return {"accepted_tip": candidate, "previous_tip": accepted,
                "verified_messages": verified,
                "advanced": candidate != accepted,
                "trust_generation": generation}

    def status(self) -> dict:
        return {k: v for k, v in self.document.items()}

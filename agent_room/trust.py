"""The trust policy: who may sign as whom, and until when.

A signature is only as meaningful as the answer to "whose key is that?". This
module holds that answer, and three properties matter more than its size.

**Public material only.** A trust policy contains public keys, key ids,
methods, roles and generations. No private key ever enters it, so it can be
read, copied and inspected freely.

**Not on the room branch.** The branch must not be able to rewrite its own
trust roots: if the keys that authenticate the branch's messages lived on the
branch, anyone who could write the branch could install their own. The policy
is local state, and changes to it require the human credential.

**Validity is a function of history, not of the clock.** A key is valid from an
effective commit and invalid from a revocation commit, both checked by Git
ancestry against the commit a message was added in. So a message signed before
a rotation stays verifiable afterwards, and a revoked key stops authenticating
new messages, without anyone having to trust a timestamp.

The honest limit: this is a local file owned by the service user. Someone who
already controls that user's local state can edit it. S3's isolation is what
would change that; until then, do not read this as tamper-proof.
"""

import datetime as dt
import json
import os
import tempfile
from pathlib import Path

from . import auth, canonical
from .errors import AgentRoomError

TRUST_SCHEMA_VERSION = 1

#: Its own domain, so a trust-policy update can never be confused with — or
#: replayed as — a message signature, and vice versa.
TRUST_UPDATE_DOMAIN = "agent-room.v1.trust-update"

HUMAN_ROLE = "human"

#: Every identity whose messages are treated as trusted. A signer outside this
#: set cannot be pinned, so its messages can never become trusted.
TRUSTED_ROLES = (
    HUMAN_ROLE, "claude-code", "codex", "openai-research",
    "release-recorder", "coordinator",
)

UPDATE_ACTIONS = ("add", "rotate", "revoke")

#: Key custody, recorded because it is the difference between "an attacker who
#: owns this host can sign as this participant" and "they cannot".
CUSTODY_HOST_FILE = "host-file"
CUSTODY_DEVICE = "android-keystore-device-bound"

POLICY_FILE_MODE = 0o600
POLICY_DIR_MODE = 0o700

__all__ = [
    "TRUST_SCHEMA_VERSION", "TRUST_UPDATE_DOMAIN", "TRUSTED_ROLES",
    "HUMAN_ROLE", "UPDATE_ACTIONS", "CUSTODY_HOST_FILE", "CUSTODY_DEVICE",
    "TrustError", "NoTrustPolicy", "UnknownKey", "KeyNotValidHere",
    "TrustUpdateError", "TrustPolicy", "update_payload", "build_update",
    "verify_envelope",
]


class TrustError(AgentRoomError):
    """The trust policy refused something."""


class NoTrustPolicy(TrustError):
    """A release-capable operation was attempted with no pinned trust policy."""


class UnknownKey(TrustError):
    """No such key id is pinned."""


class KeyNotValidHere(TrustError):
    """The key exists but may not authenticate this message.

    Wrong role, wrong method, not yet effective, or revoked by this point in
    history. All four are the same answer to the caller: not this one.
    """


class TrustUpdateError(TrustError):
    """A trust-policy update was refused."""


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: Excluded from the update payload for the same reason a signature cannot
#: cover itself: `auth` is the authority signature, and `new_key_proof` is the
#: incoming credential's counter-signature. Both sign the same bytes, and
#: neither is inside them.
UNSIGNED_UPDATE_FIELDS = (auth.AUTH_FIELD, "new_key_proof")


def update_payload(body: dict, header: dict) -> bytes:
    """The bytes a trust-policy update is signed over. One definition."""
    return canonical.canonical_bytes({
        "domain": TRUST_UPDATE_DOMAIN,
        "auth": {k: v for k, v in header.items() if k != "signature"},
        "update": {k: v for k, v in body.items()
                   if k not in UNSIGNED_UPDATE_FIELDS},
    })


class TrustPolicy:
    """Pinned public verification identities, versioned by generation."""

    def __init__(self, document: dict, *, path=None) -> None:
        self.document = document
        self.path = Path(path) if path else None
        self._validate()

    # -- construction ------------------------------------------------------
    @classmethod
    def bootstrap(cls, *, room_id: str, human_key_id: str,
                  human_public_key: str,
                  human_custody: str = CUSTODY_DEVICE, path=None) -> "TrustPolicy":
        """The initial anchor: one human credential and nothing else.

        Everything after this is a signed update, so the human credential is
        the root of the policy as well as the authority over consequential
        actions. Its public half is all that is stored.
        """
        document = {
            "trust_schema_version": TRUST_SCHEMA_VERSION,
            "room_id": room_id,
            "generation": 1,
            "created_at": _now_iso(),
            "keys": {
                human_key_id: {
                    "key_id": human_key_id,
                    "role": HUMAN_ROLE,
                    "method": auth.METHOD_ED25519,
                    "public_key": human_public_key,
                    "custody": human_custody,
                    "added_generation": 1,
                    "effective_commit": None,
                    "revoked_generation": None,
                    "revoked_effective_commit": None,
                    "replaces": None,
                }
            },
            "history": [],
        }
        policy = cls(document, path=path)
        if path:
            policy.save(path)
        return policy

    @classmethod
    def load(cls, path) -> "TrustPolicy":
        path = Path(path)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise NoTrustPolicy(
                f"cannot read the trust policy at {path}: {exc}. A "
                "release-capable operation has no pinned identities without "
                "one, and fails closed rather than trusting whatever it finds."
            ) from exc
        document = canonical.strict_loads(raw)
        if not isinstance(document, dict):
            raise TrustError(f"{path} is not a trust policy object")
        return cls(document, path=path)

    def save(self, path=None) -> Path:
        target = Path(path or self.path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=POLICY_DIR_MODE)
        fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        try:
            os.fchmod(fd, POLICY_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(canonical.canonical_text(self.document))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self.path = target
        return target

    # -- shape -------------------------------------------------------------
    def _validate(self) -> None:
        document = self.document
        version = document.get("trust_schema_version")
        if type(version) is not int or version != TRUST_SCHEMA_VERSION:
            raise TrustError(
                f"trust_schema_version must be the integer "
                f"{TRUST_SCHEMA_VERSION}, got {version!r}"
            )
        if not isinstance(document.get("room_id"), str) or \
                not document["room_id"].strip():
            raise TrustError("a trust policy must name the room it is for")
        generation = document.get("generation")
        if type(generation) is not int or generation < 1:
            raise TrustError(
                f"generation must be a positive integer, got {generation!r}")
        keys = document.get("keys")
        if not isinstance(keys, dict) or not keys:
            raise TrustError("a trust policy with no pinned keys trusts nobody")
        for key_id, entry in keys.items():
            if not auth.KEY_ID_RE.match(key_id):
                raise TrustError(
                    f"key id {key_id!r} must match {auth.KEY_ID_RE.pattern}")
            if not isinstance(entry, dict) or entry.get("key_id") != key_id:
                raise TrustError(
                    f"key entry {key_id!r} does not agree with its own id")
            if entry.get("role") not in TRUSTED_ROLES:
                raise TrustError(
                    f"key {key_id!r} names role {entry.get('role')!r}, which is "
                    f"not a trusted role: {list(TRUSTED_ROLES)}"
                )
            if entry.get("method") not in auth.KNOWN_METHODS:
                raise TrustError(
                    f"key {key_id!r} names method {entry.get('method')!r}")
            public_key = entry.get("public_key")
            if not isinstance(public_key, str) or \
                    "PRIVATE KEY" in public_key.upper():
                raise TrustError(
                    f"key {key_id!r} must carry PEM *public* key material; a "
                    "trust policy never holds a private key"
                )
        if not isinstance(document.get("history"), list):
            raise TrustError("a trust policy must carry its update history")

    # -- lookup ------------------------------------------------------------
    @property
    def generation(self) -> int:
        return self.document["generation"]

    @property
    def room_id(self) -> str:
        return self.document["room_id"]

    def key(self, key_id: str) -> dict:
        entry = self.document["keys"].get(key_id)
        if entry is None:
            raise UnknownKey(
                f"no key {key_id!r} is pinned in this trust policy; an "
                "unpinned key authenticates nothing"
            )
        return entry

    def keys_for(self, role: str) -> list:
        return [e for e in self.document["keys"].values()
                if e["role"] == role and e["revoked_generation"] is None]

    def current_human_key(self) -> dict:
        candidates = self.keys_for(HUMAN_ROLE)
        if not candidates:
            raise TrustError(
                "no current human credential is pinned; human authority cannot "
                "be established and no consequential action can be released"
            )
        if len(candidates) > 1:
            raise TrustError(
                f"{len(candidates)} human credentials are pinned "
                f"({[c['key_id'] for c in candidates]}); exactly one must be "
                "current, or 'the human approved' is ambiguous"
            )
        return candidates[0]

    def assert_valid_for(self, entry: dict, *, role: str, method: str,
                         at_commit=None, ancestry=None) -> dict:
        """May this key authenticate this signer, method and history point?"""
        key_id = entry["key_id"]
        if entry["role"] != role:
            raise KeyNotValidHere(
                f"key {key_id!r} is pinned for {entry['role']!r}, not "
                f"{role!r}; a key authenticates one identity and naming another "
                "in the payload does not change that"
            )
        if entry["method"] != method:
            raise KeyNotValidHere(
                f"key {key_id!r} is pinned for method {entry['method']!r}, but "
                f"the artifact claims {method!r}; an artifact does not get to "
                "choose the algorithm"
            )

        effective = entry.get("effective_commit")
        revoked = entry.get("revoked_effective_commit")
        if at_commit is None:
            # A message being written now. Current validity is the question.
            if entry.get("revoked_generation") is not None:
                raise KeyNotValidHere(
                    f"key {key_id!r} was revoked at generation "
                    f"{entry['revoked_generation']}; it cannot sign new messages"
                )
            return entry

        if ancestry is None:
            raise KeyNotValidHere(
                "key validity is decided by Git ancestry, and no ancestry "
                "oracle was supplied; refusing to guess"
            )
        if effective is not None and not (
                at_commit == effective or ancestry(effective, at_commit)):
            raise KeyNotValidHere(
                f"key {key_id!r} becomes effective at {effective[:12]}, which "
                f"is not an ancestor of {at_commit[:12]}; it had no authority "
                "at that point in history"
            )
        # Fail-closed boundary: a key revoked *effective* at a commit does not
        # authenticate that commit either. The conservative direction, and the
        # one a rotation should assume when choosing its effective point.
        if revoked is not None and (
                at_commit == revoked or ancestry(revoked, at_commit)):
            raise KeyNotValidHere(
                f"key {key_id!r} was revoked effective {revoked[:12]}, at or "
                f"before {at_commit[:12]}"
            )
        return entry

    # -- updates -----------------------------------------------------------
    def apply_update(self, update: dict, *, ancestry=None) -> dict:
        """Apply one human-signed rotation, revocation or addition.

        Refused unless the update is signed by the *current* human credential,
        carries exactly the next generation, and — when it replaces the human
        credential itself — is counter-signed by the incoming key, so nobody
        can pin a credential nobody holds.
        """
        if not isinstance(update, dict):
            raise TrustUpdateError("a trust update must be an object")
        record = auth.validate_auth_record(update.get(auth.AUTH_FIELD))
        if update.get("domain") != TRUST_UPDATE_DOMAIN:
            raise TrustUpdateError(
                f"update.domain must be {TRUST_UPDATE_DOMAIN!r}; a message "
                "signature is not a policy signature"
            )
        if update.get("room_id") != self.room_id:
            raise TrustUpdateError(
                f"update names room {update.get('room_id')!r}, this policy is "
                f"for {self.room_id!r}"
            )
        generation = update.get("generation")
        if type(generation) is not int or generation != self.generation + 1:
            raise TrustUpdateError(
                f"update generation must be exactly {self.generation + 1}, got "
                f"{generation!r}; generations are monotonic so an old update "
                "cannot be replayed"
            )
        action = update.get("action")
        if action not in UPDATE_ACTIONS:
            raise TrustUpdateError(
                f"unknown trust update action {action!r}; known: "
                f"{list(UPDATE_ACTIONS)}"
            )

        # Authority: the current human credential, and nothing else.
        if record["signer"] != HUMAN_ROLE:
            raise TrustUpdateError(
                f"a trust update must be signed by {HUMAN_ROLE!r}, not "
                f"{record['signer']!r}; participants do not rotate their own keys"
            )
        human = self.current_human_key()
        if record["key_id"] != human["key_id"]:
            raise TrustUpdateError(
                f"update is signed by key {record['key_id']!r}, but the current "
                f"human credential is {human['key_id']!r}"
            )
        self.assert_valid_for(human, role=HUMAN_ROLE, method=record["method"])
        payload = update_payload(update, record)
        if not auth.verify_signature(human["public_key"], payload,
                                     record["signature"],
                                     method=record["method"]):
            raise TrustUpdateError(
                "the trust update's signature does not verify under the "
                "current human credential; an unsigned or wrongly signed "
                "update installs nothing"
            )

        participant = update.get("participant")
        if participant not in TRUSTED_ROLES:
            raise TrustUpdateError(
                f"update names participant {participant!r}, which is not a "
                f"trusted role: {list(TRUSTED_ROLES)}"
            )
        effective = update.get("effective_commit")
        if effective is not None and not isinstance(effective, str):
            raise TrustUpdateError("effective_commit must be a commit id or null")

        keys = dict(self.document["keys"])
        if action in ("add", "rotate"):
            new_key_id = update.get("new_key_id")
            public_key = update.get("public_key")
            method = update.get("method", auth.METHOD_ED25519)
            if not isinstance(new_key_id, str) or \
                    not auth.KEY_ID_RE.match(new_key_id):
                raise TrustUpdateError(
                    f"new_key_id {new_key_id!r} must match "
                    f"{auth.KEY_ID_RE.pattern}")
            if new_key_id in keys:
                raise TrustUpdateError(
                    f"key id {new_key_id!r} is already pinned; ids are not "
                    "reused, because a reused id makes history ambiguous"
                )
            if not isinstance(public_key, str) or \
                    "PRIVATE KEY" in public_key.upper():
                raise TrustUpdateError(
                    "an update must carry PEM public key material")
            if method not in auth.KNOWN_METHODS:
                raise TrustUpdateError(f"unknown method {method!r}")

            if participant == HUMAN_ROLE:
                # Proof of possession: the incoming credential signs the same
                # payload. Without it a human could be locked out by pinning a
                # key nobody holds - including by accident.
                proof = update.get("new_key_proof")
                if not isinstance(proof, str) or not proof.strip():
                    raise TrustUpdateError(
                        "rotating the human credential requires "
                        "new_key_proof: a counter-signature by the incoming "
                        "credential over the same payload, so the replacement "
                        "is known to exist and to be held"
                    )
                if not auth.verify_signature(public_key, payload, proof,
                                             method=method):
                    raise TrustUpdateError(
                        "new_key_proof does not verify under the incoming "
                        "public key"
                    )

            old_key_id = update.get("old_key_id")
            if action == "rotate":
                if old_key_id not in keys:
                    raise TrustUpdateError(
                        f"rotate names old key {old_key_id!r}, which is not "
                        "pinned")
                old = dict(keys[old_key_id])
                if old["role"] != participant:
                    raise TrustUpdateError(
                        f"old key {old_key_id!r} is pinned for {old['role']!r}, "
                        f"not {participant!r}")
                old["revoked_generation"] = generation
                old["revoked_effective_commit"] = effective
                keys[old_key_id] = old

            keys[new_key_id] = {
                "key_id": new_key_id, "role": participant, "method": method,
                "public_key": public_key,
                "custody": update.get("custody", CUSTODY_HOST_FILE),
                "added_generation": generation,
                "effective_commit": effective,
                "revoked_generation": None,
                "revoked_effective_commit": None,
                "replaces": old_key_id if action == "rotate" else None,
            }
        else:  # revoke
            old_key_id = update.get("old_key_id")
            if old_key_id not in keys:
                raise TrustUpdateError(
                    f"revoke names key {old_key_id!r}, which is not pinned")
            old = dict(keys[old_key_id])
            if old["role"] != participant:
                raise TrustUpdateError(
                    f"key {old_key_id!r} is pinned for {old['role']!r}, not "
                    f"{participant!r}")
            old["revoked_generation"] = generation
            old["revoked_effective_commit"] = effective
            keys[old_key_id] = old

        self.document = {
            **self.document,
            "generation": generation,
            "keys": keys,
            "history": [*self.document["history"], update],
        }
        self._validate()
        if self.path:
            self.save()
        return self.document


def build_update(policy: TrustPolicy, signer, *, action: str,
                 participant: str, new_key_id: str | None = None,
                 public_key: str | None = None, old_key_id: str | None = None,
                 method: str = auth.METHOD_ED25519,
                 custody: str = CUSTODY_HOST_FILE,
                 effective_commit: str | None = None,
                 new_key_signer=None) -> dict:
    """Assemble and sign one trust-policy update.

    The signer must be the current human credential; `apply_update` checks
    that independently, so this is a convenience for building the record, not
    a way to bypass the check.
    """
    body = {
        "trust_update_schema_version": TRUST_SCHEMA_VERSION,
        "domain": TRUST_UPDATE_DOMAIN,
        "room_id": policy.room_id,
        "generation": policy.generation + 1,
        "action": action,
        "participant": participant,
        "old_key_id": old_key_id,
        "new_key_id": new_key_id,
        "public_key": public_key,
        "method": method,
        "custody": custody,
        "effective_commit": effective_commit,
        "created_at": _now_iso(),
    }
    header = auth.auth_header(signer=signer.signer, key_id=signer.key_id,
                              method=signer.method)
    if participant == HUMAN_ROLE and action in ("add", "rotate"):
        # Proof of possession has to cover the same bytes as the authority
        # signature, so it is produced against the payload built without it.
        if new_key_signer is None:
            raise TrustUpdateError(
                "pinning a human credential needs the incoming credential to "
                "counter-sign, so a key nobody holds cannot be installed"
            )
        body["new_key_proof"] = new_key_signer.sign(update_payload(body, header))
    payload = update_payload(body, header)
    body[auth.AUTH_FIELD] = {**header, "signature": signer.sign(payload)}
    return body


def verify_envelope(envelope, policy: TrustPolicy, *, at_commit=None,
                    ancestry=None) -> dict:
    """Authenticate one stored envelope. Fails closed at every step.

    The order is the order of trust: structure, then policy, then
    cryptography. Nothing about `sender.agent` is believed until a pinned key
    has signed the payload that contains it.
    """
    if policy is None:
        raise NoTrustPolicy(
            "no trust policy is pinned, so nothing can be authenticated")
    record = envelope.get(auth.AUTH_FIELD)
    if record is None:
        raise auth.UnauthenticatedMessage(
            f"message {envelope.get('message_id')} carries no authentication "
            f"record but claims to be from "
            f"{(envelope.get('sender') or {}).get('agent')!r}; a name is a "
            "claim, not an identity"
        )
    record = auth.validate_auth_record(record)

    claimed = (envelope.get("sender") or {}).get("agent")
    if record["signer"] != claimed:
        raise KeyNotValidHere(
            f"the signature is by {record['signer']!r} but the message says it "
            f"is from {claimed!r}; the two must be the same identity"
        )

    entry = policy.key(record["key_id"])
    policy.assert_valid_for(entry, role=record["signer"],
                            method=record["method"], at_commit=at_commit,
                            ancestry=ancestry)

    header = {k: v for k, v in record.items() if k != "signature"}
    if not auth.verify_signature(entry["public_key"],
                                 auth.signed_payload(envelope, header),
                                 record["signature"], method=record["method"]):
        raise auth.InvalidSignature(
            f"the signature on {envelope.get('message_id')} does not verify "
            f"under pinned key {record['key_id']!r}"
        )
    return {"signer": record["signer"], "key_id": record["key_id"],
            "method": record["method"], "role": entry["role"],
            "custody": entry.get("custody")}

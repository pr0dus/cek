"""Cryptographic provenance for room artifacts.

Until S2, `sender.agent` was a string in a file. Anyone who could write to the
Git remote could commit a structurally valid `approval` claiming to be the
human, and the gate would release on it — reproduced, and kept as a passing
test so the gap stayed visible. This module is what closes it: authority now
rests on a signature over the message, and the name in `sender.agent` is only a
claim that the signature has to corroborate.

**The signed object.** `signed_payload()` is the one function that defines what
a signature covers, and it covers the whole immutable envelope — message id,
thread, type, sender, recipient, project, parent lineage, body, evidence,
status flags, and the `action` / `decision` / `receipt` records that carry
authority — together with the auth header's own version, method, signer and key
id. Two fields are excluded, for one reason each: `envelope_sha256`, because it
is computed *after* the signature is attached and would otherwise be circular;
and `auth.signature`, because it cannot cover itself.

A domain string is inside the signed payload, so a signature made here cannot
be replayed as a signature in some other protocol, and the auth header is
inside it too, so an artifact cannot claim a weaker method than the one that
was actually signed.

**Order of operations**, which is also the order of trust:

1. build the unsigned immutable envelope;
2. sign the domain-separated canonical payload;
3. attach the auth record;
4. seal — the envelope digest then covers the signature as well.

**The primitive** is Ed25519 through the installed `openssl`. No custom
signature construction, no new Python dependency, fixed argv, sanitised
environment, bounded time and output, no shell. Private keys are passed as
owner-only files, never as arguments or environment variables.

**What this does not protect against.** Participant keys live on this host. An
attacker with arbitrary access to those private key files can sign as that
participant, and no amount of verification here changes that. What it does
establish is that a repository writer — or anyone who can commit to the room
branch without holding a key — cannot impersonate anyone. The human credential
is deliberately not on this host at all; see `docs/AGENT_ROOM_AUTH.md`.
"""

import base64
import binascii
import os
import re
import stat
import tempfile
from pathlib import Path

from . import canonical
from .errors import AgentRoomError
from .process import run_bounded, sanitised_env

AUTH_SCHEMA_VERSION = 1

#: Where the auth record lives on an envelope.
AUTH_FIELD = "auth"

#: Domain separator. Inside the signed payload, so a signature produced for an
#: Agent Room envelope cannot be presented as a signature for anything else.
DOMAIN = "agent-room.v1.envelope"

METHOD_ED25519 = "ed25519"
KNOWN_METHODS = frozenset({METHOD_ED25519})

#: Excluded from the signed payload. `envelope_sha256` is computed after the
#: signature is attached; `auth.signature` cannot cover itself.
UNSIGNED_FIELDS = (canonical.DIGEST_FIELD, AUTH_FIELD)

#: A key id is compared exactly and appears in file names and log lines, so it
#: gets the same narrow grammar as every other identifier here.
KEY_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")

#: An Ed25519 signature is 64 bytes, 88 base64 characters. The bound is
#: generous and finite: an auth record is not a place to put a payload.
MAX_SIGNATURE_CHARS = 512

#: Public keys are PEM SPKI. Bounded for the same reason.
MAX_PUBLIC_KEY_CHARS = 4096

OPENSSL = "openssl"
OPENSSL_TIMEOUT_SECONDS = 20
KEY_FILE_MODE = 0o600

__all__ = [
    "AUTH_SCHEMA_VERSION", "AUTH_FIELD", "DOMAIN", "METHOD_ED25519",
    "KNOWN_METHODS", "UNSIGNED_FIELDS", "KEY_ID_RE",
    "AuthError", "UnauthenticatedMessage", "MalformedAuthRecord",
    "UnknownAuthVersion", "UnknownMethod", "InvalidSignature", "SigningError",
    "signed_payload", "validate_auth_record", "auth_header",
    "sign_envelope", "verify_signature", "Ed25519Signer",
    "generate_ed25519_keypair", "public_key_fingerprint",
]


class AuthError(AgentRoomError):
    """Authentication of a room artifact failed."""


class UnauthenticatedMessage(AuthError):
    """A message that must be authenticated carries no auth record."""


class MalformedAuthRecord(AuthError):
    """The auth record is not structurally usable."""


class UnknownAuthVersion(MalformedAuthRecord):
    """An auth schema version this build does not implement."""


class UnknownMethod(MalformedAuthRecord):
    """A signature method this build does not implement."""


class InvalidSignature(AuthError):
    """The signature does not verify over the signed payload."""


class SigningError(AuthError):
    """A signature could not be produced."""


# -- the signed object ------------------------------------------------------

def auth_header(*, signer: str, key_id: str, method: str = METHOD_ED25519,
                version: int = AUTH_SCHEMA_VERSION) -> dict:
    """The part of the auth record that is itself signed."""
    return {
        "auth_schema_version": version,
        "domain": DOMAIN,
        "method": method,
        "signer": signer,
        "key_id": key_id,
    }


def signed_payload(envelope, header: dict) -> bytes:
    """The exact bytes a signature covers. One definition, used by both sides.

    The whole envelope minus the two fields that cannot be inside it, plus the
    auth header. Canonical JSON, so the bytes are a function of the content and
    not of anyone's serialiser.
    """
    body = {k: v for k, v in envelope.items() if k not in UNSIGNED_FIELDS}
    return canonical.canonical_bytes({
        "domain": DOMAIN,
        "auth": {k: v for k, v in header.items() if k != "signature"},
        "envelope": body,
    })


def validate_auth_record(auth) -> dict:
    """Structure only — no key lookup, no cryptography. Fails closed."""
    if not isinstance(auth, dict):
        raise MalformedAuthRecord(
            f"auth record must be an object, got {type(auth).__name__}")

    version = auth.get("auth_schema_version")
    if type(version) is not int or version != AUTH_SCHEMA_VERSION:
        raise UnknownAuthVersion(
            f"auth_schema_version must be the integer {AUTH_SCHEMA_VERSION}, "
            f"got {version!r}; an unknown version is refused rather than "
            "interpreted"
        )
    if auth.get("domain") != DOMAIN:
        raise MalformedAuthRecord(
            f"auth.domain must be {DOMAIN!r}, got {auth.get('domain')!r}; a "
            "signature from another protocol is not a signature here"
        )
    method = auth.get("method")
    if method not in KNOWN_METHODS:
        raise UnknownMethod(
            f"auth.method {method!r} is not implemented; known: "
            f"{sorted(KNOWN_METHODS)}"
        )
    signer = auth.get("signer")
    if not isinstance(signer, str) or not signer.strip():
        raise MalformedAuthRecord(
            f"auth.signer must be a non-empty string, got {signer!r}")
    key_id = auth.get("key_id")
    if not isinstance(key_id, str) or not KEY_ID_RE.match(key_id):
        raise MalformedAuthRecord(
            f"auth.key_id {key_id!r} must match {KEY_ID_RE.pattern}")
    signature = auth.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        raise MalformedAuthRecord(
            f"auth.signature must be a non-empty string, got {signature!r}")
    if len(signature) > MAX_SIGNATURE_CHARS:
        raise MalformedAuthRecord(
            f"auth.signature is {len(signature)} characters, over the "
            f"{MAX_SIGNATURE_CHARS} limit"
        )
    unknown = set(auth) - {"auth_schema_version", "domain", "method", "signer",
                           "key_id", "signature"}
    if unknown:
        raise MalformedAuthRecord(
            f"auth record has unknown fields {sorted(unknown)}; an unsigned "
            "field inside the auth record would be a place to hide something"
        )
    return auth


def decode_signature(signature: str) -> bytes:
    try:
        raw = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedAuthRecord(
            f"auth.signature is not valid base64: {exc}") from exc
    if not raw:
        raise MalformedAuthRecord("auth.signature decodes to nothing")
    return raw


# -- the primitive ----------------------------------------------------------

def _openssl(args, *, stdin: bytes | None = None) -> tuple:
    """One bounded, sanitised `openssl` call. Fixed argv, no shell."""
    result = run_bounded(
        [OPENSSL, *args], timeout=OPENSSL_TIMEOUT_SECONDS,
        env=sanitised_env(), input=stdin, max_output_bytes=64 * 1024,
    )
    if result.timed_out:
        raise AuthError(f"openssl {args[0]} timed out")
    return result.returncode, result.stdout, result.stderr


def _write_private(path: Path, data: bytes) -> None:
    """Owner-only from the moment it exists, not after."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEY_FILE_MODE)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def generate_ed25519_keypair(directory, key_id: str) -> dict:
    """Generate a disposable Ed25519 keypair. For tests and host participants.

    Never used for the human credential: that one is generated inside a trusted
    personal device's keystore and never exists here. See
    `docs/AGENT_ROOM_AUTH.md`.
    """
    if not KEY_ID_RE.match(key_id):
        raise SigningError(f"key_id {key_id!r} must match {KEY_ID_RE.pattern}")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory.chmod(0o700)
    except OSError:                                          # pragma: no cover
        pass
    private = directory / f"{key_id}.ed25519.pem"

    code, _out, err = _openssl(["genpkey", "-algorithm", "ed25519",
                                "-out", str(private)])
    if code != 0:
        raise SigningError(
            f"could not generate a key: {err.decode('utf-8', 'replace')[:200]}")
    os.chmod(private, KEY_FILE_MODE)

    code, pub, err = _openssl(["pkey", "-in", str(private), "-pubout"])
    if code != 0:
        raise SigningError(
            f"could not derive the public key: "
            f"{err.decode('utf-8', 'replace')[:200]}")
    return {"key_id": key_id, "private_key_path": str(private),
            "public_key": pub.decode("ascii"),
            "mode": oct(stat.S_IMODE(os.stat(private).st_mode)),
            "method": METHOD_ED25519}


def public_key_fingerprint(public_key_pem: str) -> str:
    """A short public identifier for a key. Safe to print; it is public."""
    import hashlib

    body = "".join(line.strip() for line in public_key_pem.strip().splitlines()
                   if not line.startswith("-----"))
    return "SHA256:" + hashlib.sha256(
        base64.b64decode(body or "")).hexdigest()[:32]


def verify_signature(public_key_pem: str, payload: bytes,
                     signature: str, *, method: str = METHOD_ED25519) -> bool:
    """Verify one signature. Returns a boolean; never raises on a bad signature."""
    if method not in KNOWN_METHODS:
        raise UnknownMethod(f"method {method!r} is not implemented")
    if not isinstance(public_key_pem, str) or \
            len(public_key_pem) > MAX_PUBLIC_KEY_CHARS:
        raise MalformedAuthRecord("public key material is missing or oversized")
    raw = decode_signature(signature)

    with tempfile.TemporaryDirectory(prefix="agent-room-verify-") as work:
        root = Path(work)
        pub, msg, sig = root / "pub.pem", root / "payload", root / "sig"
        pub.write_text(public_key_pem, encoding="ascii")
        msg.write_bytes(payload)
        sig.write_bytes(raw)
        code, _out, _err = _openssl([
            "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
            "-rawin", "-in", str(msg), "-sigfile", str(sig),
        ])
    return code == 0


class Ed25519Signer:
    """Signs as one participant with one host-held key.

    Deliberately not able to sign as anyone else: the signer name and key id
    are fixed at construction, and both end up inside the signed payload, so a
    signature made by this object can only ever authenticate that identity.
    """

    method = METHOD_ED25519

    def __init__(self, key_path, *, signer: str, key_id: str) -> None:
        self.key_path = Path(key_path)
        if not isinstance(signer, str) or not signer.strip():
            raise SigningError("a signer name is required")
        if not KEY_ID_RE.match(key_id or ""):
            raise SigningError(f"key_id {key_id!r} must match {KEY_ID_RE.pattern}")
        self.signer, self.key_id = signer, key_id
        if not self.key_path.exists():
            raise SigningError(f"no signing key at {self.key_path}")
        mode = stat.S_IMODE(os.stat(self.key_path).st_mode)
        if mode & 0o077:
            raise SigningError(
                f"signing key {self.key_path} is mode {oct(mode)}; a private "
                "key readable by anyone else is not a private key"
            )

    def sign(self, payload: bytes) -> str:
        with tempfile.TemporaryDirectory(prefix="agent-room-sign-") as work:
            root = Path(work)
            msg, sig = root / "payload", root / "sig"
            msg.write_bytes(payload)
            code, _out, err = _openssl([
                "pkeyutl", "-sign", "-inkey", str(self.key_path),
                "-rawin", "-in", str(msg), "-out", str(sig),
            ])
            if code != 0:
                raise SigningError(
                    f"signing failed: {err.decode('utf-8', 'replace')[:200]}")
            raw = sig.read_bytes()
        return base64.b64encode(raw).decode("ascii")


def sign_envelope(envelope: dict, signer) -> dict:
    """Attach an auth record. The caller seals afterwards, never before."""
    if canonical.DIGEST_FIELD in envelope:
        raise SigningError(
            "sign before sealing: the envelope digest must cover the signature, "
            "not the other way round"
        )
    header = auth_header(signer=signer.signer, key_id=signer.key_id,
                         method=signer.method)
    signature = signer.sign(signed_payload(envelope, header))
    return {**envelope, AUTH_FIELD: {**header, "signature": signature}}

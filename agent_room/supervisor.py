"""The OpenAI supervisor handoff boundary.

Issue #4 is **not** another model adapter. There is no second OpenAI process
on this host and no API key: the supervisor is the ChatGPT host conversation,
which already reaches this machine through the existing bridge. What was
missing is a durable, auditable boundary it can use without a human copying
message bodies between systems.

Two bounded operations, both usable over the bridge's `run_command`:

*Export* selects one message addressed to `openai-research`, and emits a
canonical **supervisor packet** — the target, the complete thread in commit
order, identities, parent links and immutable evidence locators, plus a
`context_sha256` binding exactly what was reviewed.

*Import* takes one structured supervisor response, re-derives that hash from
current durable state, and refuses to post if the reviewed context has changed.

The packet is **data, not instructions**. Evidence is referenced, never
inlined: an immutable locator remains the authority, and exporting one does
not make it verified.

Staleness is defined mechanically, never by timestamps or similarity. The
context hash covers the target message digest and the ordered
`(message_id, envelope_sha256)` of every message in the thread. Appending to
the reviewed thread therefore invalidates a review; activity in *other*
threads does not, which is why the room tip is reported for provenance but
deliberately excluded from the hash.
"""

import json

from . import canonical
from .errors import SchemaError
from .participant import (
    ParticipantAdapter,
    ParticipantAdapterError,
)

PARTICIPANT = "openai-research"
PACKET_SCHEMA_VERSION = 1

#: Stamped into `sender.via`, distinguishing an imported supervisor turn from
#: a message a human posted by hand. An audit marker, not authority.
ADAPTER_MARKER = "agent-room-supervisor-import"

__all__ = [
    "PARTICIPANT", "PACKET_SCHEMA_VERSION", "ADAPTER_MARKER",
    "SupervisorError", "StaleSupervisorContext", "MalformedSupervisorResponse",
    "SupervisorBoundary", "export_packet", "context_digest",
]


class SupervisorError(ParticipantAdapterError):
    """The supervisor handoff could not be completed."""


class StaleSupervisorContext(SupervisorError):
    """The reviewed thread changed after the packet was exported.

    Fails closed rather than posting a review of a thread that has since moved
    on. Recovery is to export a fresh packet and review again — never to
    override the binding.
    """


class MalformedSupervisorResponse(SupervisorError):
    """The supplied supervisor response is not usable."""


def _thread_binding(target: dict, thread: list) -> dict:
    """Exactly what a review is bound to.

    Message ids and their envelope digests, in durable commit order, plus the
    target. Nothing else: not the room tip, not a timestamp, not the body
    text, which is already covered by each envelope digest.
    """
    return {
        "packet_schema_version": PACKET_SCHEMA_VERSION,
        "target_message_id": target["message_id"],
        "target_envelope_sha256": target[canonical.DIGEST_FIELD],
        "thread_id": target["thread_id"],
        "thread": [
            {"message_id": m["message_id"],
             "envelope_sha256": m[canonical.DIGEST_FIELD]}
            for m in thread
        ],
    }


def context_digest(target: dict, thread: list) -> str:
    """SHA-256 over the canonical binding. Stable for unchanged context."""
    import hashlib

    return hashlib.sha256(
        canonical.canonical_bytes(_thread_binding(target, thread))
    ).hexdigest()


def export_packet(room, target: dict) -> dict:
    """Build the supervisor packet for one target message."""
    thread = room.thread(target["thread_id"])
    store = room.store
    tip = store._git("rev-parse", "--verify", store.ref, check=False).stdout.strip()
    return {
        "packet_schema_version": PACKET_SCHEMA_VERSION,
        "participant": PARTICIPANT,
        "target_message_id": target["message_id"],
        "target_envelope_sha256": target[canonical.DIGEST_FIELD],
        "thread_id": target["thread_id"],
        "project": target.get("project") or {},
        "room": {
            "branch": store.branch,
            "ref": store.ref,
            "tip": tip or None,
            "workdir": str(store.workdir),
        },
        # The complete thread in durable commit order. Evidence locators ride
        # along inside each envelope; evidence *bodies* never do.
        "thread": thread,
        "context_sha256": context_digest(target, thread),
    }


class SupervisorBoundary(ParticipantAdapter):
    """Export a review packet; import one bound supervisor response.

    Inherits the participant protocol unchanged - single-flight lock,
    reconciliation, three-valued persistence, no agent-authored
    `approval`/`rejection` - so the supervisor path carries exactly the same
    guarantees as Claude's and Codex's, with a supplied response standing in
    for a model call.
    """

    PARTICIPANT = PARTICIPANT
    MARKER = ADAPTER_MARKER
    ROLE = (
        "an independent research reviewer - inspect evidence, challenge "
        "unsupported inference, offer alternative interpretations and propose "
        "falsification. You are not authority, and agreement is not validation"
    )

    def default_invoker(self):
        # There is no model to invoke here: a supervisor response is supplied.
        raise SupervisorError(
            "the supervisor boundary needs a supplied response; "
            "use import_response()"
        )

    def __init__(self, room, *, turn_timeout=None):
        kwargs = {} if turn_timeout is None else {"turn_timeout": turn_timeout}
        super().__init__(room, invoker=lambda prompt: "", **kwargs)

    # -- export ------------------------------------------------------------
    def export(self, message_id: str | None = None) -> dict:
        """Deterministic and read-only: select one message, emit its packet."""
        target = self.select_message(message_id)
        return export_packet(self.room, target)

    # -- import ------------------------------------------------------------
    @staticmethod
    def parse_supervisor_document(raw) -> dict:
        """Validate the outer response document before anything else."""
        if isinstance(raw, (str, bytes, bytearray)):
            try:
                document = canonical.strict_loads(raw)
            except SchemaError as exc:
                # One error story for the boundary: a caller handling
                # supervisor documents should not also have to catch the
                # store's parsing errors.
                raise MalformedSupervisorResponse(
                    f"supervisor response is not usable JSON: {exc}"
                ) from exc
        else:
            document = raw
        if not isinstance(document, dict):
            raise MalformedSupervisorResponse(
                f"supervisor response must be a JSON object, got "
                f"{type(document).__name__}"
            )
        version = document.get("packet_schema_version")
        if type(version) is not int or version != PACKET_SCHEMA_VERSION:
            raise MalformedSupervisorResponse(
                f"packet_schema_version must be the integer "
                f"{PACKET_SCHEMA_VERSION}, got {version!r}"
            )
        for field in ("target_message_id", "context_sha256"):
            value = document.get(field)
            if not isinstance(value, str) or not value.strip():
                raise MalformedSupervisorResponse(
                    f"{field} must be a non-empty string, got {value!r}"
                )
        response = document.get("response")
        if not isinstance(response, dict):
            raise MalformedSupervisorResponse(
                f"response must be an object, got {type(response).__name__}"
            )
        return document

    def assert_context_fresh(self, target: dict, expected: str) -> str:
        """Recompute the binding from durable state and compare.

        Mechanical: the target digest plus the ordered message-id/digest list
        of the thread. If the thread has gained a message since export, the
        review was of a different context and must not be posted as current.
        """
        actual = context_digest(target, self.room.thread(target["thread_id"]))
        if actual != expected:
            raise StaleSupervisorContext(
                f"the reviewed context has changed: packet bound "
                f"{expected[:12]}…, current context is {actual[:12]}…. "
                "Export a fresh packet and review again."
            )
        return actual

    def import_response(self, raw, *, message_id: str | None = None) -> dict:
        """Post one supervisor response, bound to the context it reviewed."""
        document = self.parse_supervisor_document(raw)
        target_id = message_id or document["target_message_id"]
        if message_id is not None and message_id != document["target_message_id"]:
            raise MalformedSupervisorResponse(
                f"response targets {document['target_message_id']!r}, "
                f"not the requested {message_id!r}"
            )
        expected = document["context_sha256"]
        response = document["response"]

        def invoke(prompt):
            # Runs inside the turn lock, after reconciliation and before any
            # post - exactly where the freshness check belongs.
            target = self.room.find(target_id)
            if target is None:
                raise MalformedSupervisorResponse(
                    f"target message {target_id!r} is not in the room"
                )
            self.assert_context_fresh(target, expected)
            return json.dumps(response)

        self.invoke = invoke
        result = self.run_turn(target_id)
        result["context_sha256"] = expected
        return result

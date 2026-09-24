"""The narrow supervisor transport: three operations, and no way to say more.

The existing ChatGPT-Ubuntu bridge accepts an argv and runs it. That is a
remote shell with a queue in front of it, and it is why a write to its control
repository is a write to everything the service user owns. This module is the
replacement for the *unattended* Agent Room path, and its design premise is
the opposite one: the request schema simply has no field in which a command,
a path, a key, a branch or an identity can be expressed.

**Three operations.** Export one supervisor packet, import one context-bound
supervisor response, report bounded status. An unknown operation or an unknown
field fails closed. Nothing here calls a shell, spawns a process, reads a file
a request named, or invokes a model — the only subprocess surface in the whole
transport is the fixed Git helper in `control_store`, and a static test keeps
this module free of even a reference to one.

**It is not a signing oracle.** The service will hold the supervisor ingress
key. The only way untrusted input causes a signature is a successful,
context-bound `SupervisorBoundary.import_response`, where the identity, the
key, the room, the message id, the thread and the parent all come from the
service configuration and the room's own state. A request chooses the
*content* of a reviewer message and nothing else about it.

**The residual risk, stated plainly.** A compromised control-repository
credential can inject a bounded reviewer response into a thread that is
genuinely awaiting supervisor input. It cannot obtain shell, filesystem, human,
release, trust-policy, receipt or model-execution authority, and it cannot make
the service sign an arbitrary envelope. The repository credential is *not* an
independent cryptographic identity for ChatGPT, and this transport does not
pretend otherwise: it authenticates the channel's effects, not its author.
"""

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import canonical
from .auth import Ed25519Signer
from .checkpoint import TrustCheckpoint
from .control_store import (
    CONTROL_SCHEMA_VERSION,
    ControlError,
    ControlStore,
)
from .cursor import ParticipantCursor
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .ids import is_uuid7
from .room import AgentRoom
from .supervisor import PARTICIPANT as SUPERVISOR
from .supervisor import SupervisorBoundary
from .trust import TrustPolicy

#: Every operation an untrusted writer may name. Adding to this list is a
#: security decision, not a convenience one.
OPERATIONS = ("supervisor_export", "supervisor_import", "status")

#: Exactly the top-level fields a request may carry. Anything else is refused
#: rather than ignored: an ignored field is a field somebody is trying.
REQUEST_FIELDS = frozenset({
    "control_schema_version", "request_id", "created_at", "operation", "params",
})

#: What a supervisor response may be over this channel. An allowlist of
#: research and reviewer content, deliberately narrower than the ordinary
#: agent set: this is the one place untrusted input becomes a signed message,
#: so it carries reviewer opinion and nothing that acts.
REVIEWER_RESPONSE_TYPES = frozenset({
    "observation", "hypothesis", "claim", "evidence", "test_result",
    "question", "challenge", "proposed_test", "answer", "retraction",
})

#: Named so the refusal can say *why*, not merely "not allowed".
FORBIDDEN_RESPONSE_TYPES = {
    "approval": "human authority is not the transport's to exercise",
    "rejection": "human authority is not the transport's to exercise",
    "execution_receipt": "a receipt consumes a human approval",
    "decision_request": "a decision request puts a consequential action in "
                        "front of a human, which reviewer content may not do",
    "handoff": "routing is orchestration, not review",
}

#: Bounded per invocation, so a writer cannot turn one timer tick into an
#: unbounded amount of work.
DEFAULT_MAX_REQUESTS_PER_RUN = 8
DEFAULT_WORKER_TIMEOUT_SECONDS = 600
MAX_RESULT_DETAIL_CHARS = 4096

__all__ = [
    "OPERATIONS", "REQUEST_FIELDS", "REVIEWER_RESPONSE_TYPES",
    "FORBIDDEN_RESPONSE_TYPES", "TransportError", "TransportRefused",
    "TransportConfig", "TransportWorker", "validate_request",
]


class TransportError(AgentRoomError):
    """The transport could not complete an operation."""


class TransportRefused(TransportError):
    """The request was refused before anything happened.

    Distinct from a failure: nothing was attempted, so nothing needs
    reconciling. A refusal is recorded as a result so the far side learns
    why, but it is never a side effect.
    """


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bounded(text: str) -> str:
    text = str(text)
    if len(text) <= MAX_RESULT_DETAIL_CHARS:
        return text
    return text[:MAX_RESULT_DETAIL_CHARS] + "…[truncated]"


# -- configuration ----------------------------------------------------------

@dataclass(frozen=True)
class TransportConfig:
    """Service-owned. Never influenced by a request.

    Every path the worker will ever touch is fixed here, at deployment, by
    root. That is the whole reason the request schema can afford to have no
    path field: there is nothing for one to override.
    """

    room_workdir: str
    control_workdir: str
    trust_policy_path: str
    checkpoint_path: str
    state_dir: str
    signing_key_path: str
    signing_key_id: str
    room_branch: str = "agent-room"
    control_branch: str = "agent-room-control"
    room_remote: str | None = None
    control_remote: str | None = None
    max_requests_per_run: int = DEFAULT_MAX_REQUESTS_PER_RUN
    worker_timeout_seconds: int = DEFAULT_WORKER_TIMEOUT_SECONDS

    @classmethod
    def load(cls, path) -> "TransportConfig":
        raw = Path(path).read_text(encoding="utf-8")
        document = canonical.strict_loads(raw)
        if not isinstance(document, dict):
            raise TransportError(f"{path} is not a transport config object")
        known = {f for f in cls.__dataclass_fields__}
        unknown = sorted(set(document) - known)
        if unknown:
            raise TransportError(
                f"{path} has unknown configuration fields {unknown}; a "
                "transport config is an allowlist, not a bag of options")
        for secret in ("private_key", "token", "password", "secret"):
            if any(secret in key for key in document):
                raise TransportError(
                    f"{path} names a {secret!r} field; the config holds paths "
                    "and bounds, never secret values")
        return cls(**document)


# -- request validation -----------------------------------------------------

def validate_request(document) -> dict:
    """Structure only, fail-closed, before anything is touched."""
    if not isinstance(document, dict):
        raise TransportRefused("a control request must be a JSON object")
    unknown = sorted(set(document) - REQUEST_FIELDS)
    if unknown:
        raise TransportRefused(
            f"request has unknown fields {unknown}. The transport schema is "
            "closed: there is no command, path, signer, branch or identity "
            "field, and naming one is refused rather than ignored.")
    missing = sorted(REQUEST_FIELDS - set(document))
    if missing:
        raise TransportRefused(f"request is missing {missing}")

    version = document["control_schema_version"]
    if type(version) is not int or version != CONTROL_SCHEMA_VERSION:
        raise TransportRefused(
            f"control_schema_version must be the integer "
            f"{CONTROL_SCHEMA_VERSION}, got {version!r}")
    if not is_uuid7(document["request_id"]):
        raise TransportRefused(
            f"request_id {document['request_id']!r} is not a UUIDv7")
    created = document["created_at"]
    if not isinstance(created, str) or not re.match(
            r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", created):
        raise TransportRefused(f"created_at {created!r} is not canonical UTC")
    operation = document["operation"]
    if operation not in OPERATIONS:
        raise TransportRefused(
            f"unknown operation {operation!r}; this transport performs exactly "
            f"{list(OPERATIONS)} and nothing else")
    params = document["params"]
    if not isinstance(params, dict):
        raise TransportRefused("params must be an object")

    if operation == "status":
        _no_params(params, "status")
    elif operation == "supervisor_export":
        _export_params(params)
    else:
        _import_params(params)
    return document


def _no_params(params: dict, operation: str) -> None:
    if params:
        raise TransportRefused(
            f"{operation} takes no parameters, got {sorted(params)}")


def _export_params(params: dict) -> None:
    unknown = sorted(set(params) - {"message_id"})
    if unknown:
        raise TransportRefused(
            f"supervisor_export accepts only 'message_id', got extra "
            f"{unknown}. It cannot be pointed at a repository, a path or a "
            "branch.")
    message_id = params.get("message_id")
    if message_id is not None and not is_uuid7(message_id):
        raise TransportRefused(
            f"message_id {message_id!r} is not a UUIDv7")


def _import_params(params: dict) -> None:
    unknown = sorted(set(params) - {"response"})
    if unknown:
        raise TransportRefused(
            f"supervisor_import accepts only 'response', got extra {unknown}. "
            "The signer, key, identity, room, message id, thread and parent "
            "are all service state; a request supplies reviewer content only.")
    document = params.get("response")
    if not isinstance(document, dict):
        raise TransportRefused("response must be an object")
    response = document.get("response")
    if not isinstance(response, dict):
        raise TransportRefused("response.response must be an object")

    kind = response.get("type")
    reason = FORBIDDEN_RESPONSE_TYPES.get(kind)
    if reason is not None:
        raise TransportRefused(
            f"a transported supervisor response may not be {kind!r}: {reason}")
    if kind not in REVIEWER_RESPONSE_TYPES:
        raise TransportRefused(
            f"response type {kind!r} is not reviewer content; this channel "
            f"carries {sorted(REVIEWER_RESPONSE_TYPES)}")
    if response.get("action") is not None:
        raise TransportRefused(
            "a transported response may not carry an 'action': that is a "
            "consequential binding for a human to release")
    if response.get("human_approval_required") is True:
        raise TransportRefused(
            "a transported response may not set human_approval_required; "
            "reviewer content does not summon the human gate")
    for forbidden in ("decision", "receipt", "sender", "auth", "message_id",
                      "thread_id", "parent_id", "recipient"):
        if forbidden in response:
            raise TransportRefused(
                f"a transported response may not set {forbidden!r}; identity "
                "and placement are the service's, not the request's")


# -- the worker -------------------------------------------------------------

class TransportWorker:
    """One bounded invocation. No loop, no daemon, no scheduling."""

    def __init__(self, config: TransportConfig) -> None:
        self.config = config

    # -- service-owned wiring (nothing here is request-influenced) ---------
    def _room_store(self) -> GitMessageStore:
        return GitMessageStore(
            self.config.room_workdir, branch=self.config.room_branch,
            remote=self.config.room_remote,
            trust=TrustPolicy.load(self.config.trust_policy_path))

    def _boundary(self, store: GitMessageStore) -> SupervisorBoundary:
        room = AgentRoom(
            store, SUPERVISOR,
            ParticipantCursor(self.config.state_dir, SUPERVISOR),
            signer=Ed25519Signer(self.config.signing_key_path,
                                 signer=SUPERVISOR,
                                 key_id=self.config.signing_key_id),
        )
        return SupervisorBoundary(room)

    def _accept_checkpoint(self, store: GitMessageStore) -> dict:
        """Nothing reads or mutates the room before this passes.

        A fetch is not a reason to trust what arrived. Rollback, a
        non-descendant replacement, an invalid signature or a policy that
        moved without a signed update all stop here, and the checkpoint stays
        exactly where it was.
        """
        checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
        return checkpoint.accept(store)

    # -- operations --------------------------------------------------------
    def _op_status(self, store: GitMessageStore, _params: dict) -> dict:
        checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
        return {
            "room_id": store.room_id(),
            "room_tip": store.current_tip(),
            "verified_messages": store.verify_store(),
            "trust_generation": store.trust.generation,
            "checkpoint_tip": checkpoint.document["last_accepted_tip"],
            "operations": list(OPERATIONS),
        }

    def _op_supervisor_export(self, store: GitMessageStore,
                              params: dict) -> dict:
        packet = self._boundary(store).export(params.get("message_id"))
        # The packet already contains only room state and immutable evidence
        # locators; no file on this host is opened to produce it.
        return {"packet": packet}

    def _op_supervisor_import(self, store: GitMessageStore,
                              params: dict) -> dict:
        boundary = self._boundary(store)
        result = boundary.import_response(json.dumps(params["response"]))
        # Re-verify and advance to the head that actually settled, so success
        # is never reported against a room state nobody checked.
        settled = self._accept_checkpoint(store)
        return {"import": result, "checkpoint": settled}

    # -- the run -----------------------------------------------------------
    def run(self) -> dict:
        control = ControlStore(self.config.control_workdir,
                               self.config.control_branch)
        pending = control.pending()
        processed, summary = 0, []
        for entry in pending:
            if processed >= self.config.max_requests_per_run:
                break
            if control.has_result(entry["request_id"]):
                # Idempotent: a result already exists, so this request is done
                # whatever happened to the worker that handled it.
                continue
            summary.append(self._process(control, entry))
            processed += 1
        return {
            "pending": len(pending),
            "processed": processed,
            "remaining": max(len(pending) - processed, 0),
            "results": summary,
        }

    def _process(self, control: ControlStore, entry: dict) -> dict:
        request_id = entry["request_id"]
        try:
            document, request_sha256 = control.read_request(entry)
        except (ControlError, AgentRoomError) as exc:
            return self._record(control, request_id, "unreadable", "", "refused",
                                {"error": _bounded(exc)})

        status, detail, operation = "failed", {}, "unknown"
        try:
            validated = validate_request(document)
            operation = validated["operation"]
            if validated["request_id"] != request_id:
                raise TransportRefused(
                    f"request_id {validated['request_id']!r} does not match "
                    f"its own path {request_id!r}")
            store = self._room_store()
            # Checkpoint first, always: no export, no import, no status about
            # a room whose history has not been accepted.
            self._accept_checkpoint(store)
            handler = {
                "status": self._op_status,
                "supervisor_export": self._op_supervisor_export,
                "supervisor_import": self._op_supervisor_import,
            }[operation]
            detail = handler(store, validated["params"])
            status = "ok"
        except TransportRefused as exc:
            status, detail = "refused", {"error": _bounded(exc)}
        except AgentRoomError as exc:
            status = "failed"
            detail = {"error": _bounded(exc), "error_type": type(exc).__name__}
        return self._record(control, request_id, operation, request_sha256,
                            status, detail)

    def _record(self, control: ControlStore, request_id: str, operation: str,
                request_sha256: str, status: str, detail: dict) -> dict:
        result = {
            "control_schema_version": CONTROL_SCHEMA_VERSION,
            "request_id": request_id,
            "operation": operation,
            "request_sha256": request_sha256,
            "status": status,
            "completed_at": _now_iso(),
            "detail": detail,
        }
        try:
            control.write_result(request_id, result)
        except ControlError as exc:
            # The result did not fit or conflicted. Record the smallest honest
            # thing rather than nothing, so the far side is never left
            # guessing whether the operation ran.
            control.write_result(request_id, {
                **result, "status": "failed",
                "detail": {"error": _bounded(
                    f"result could not be stored as produced: {exc}")},
            })
        return {"request_id": request_id, "operation": operation,
                "status": status}

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
import time
from dataclasses import dataclass
from pathlib import Path

from . import canonical
from .auth import Ed25519Signer
from .checkpoint import TrustCheckpoint
from .control_store import (
    CONTROL_SCHEMA_VERSION,
    MAX_PENDING_REQUESTS,
    ControlConflict,
    ControlError,
    ControlStore,
)
from .cursor import ParticipantCursor
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .ids import is_uuid7
from .room import AgentRoom
from .remote_sync import (
    CANDIDATE_SUFFIX,
    MAX_DELIVERY_ATTEMPTS,
    Anchor,
    ControlRemote,
    RemoteRefMoved,
    RoomRemote,
    run_git,
)
from .supervisor import PARTICIPANT as SUPERVISOR
from .supervisor import SupervisorBoundary
from .supervisor import context_digest
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
    #: Pinned at first production bootstrap. It grants no authority — the
    #: queue's content is untrusted either way — but it stops an unrelated or
    #: replaced queue erasing the record of what has already been processed.
    control_genesis: str | None = None
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
        config = cls(**document)
        # The production path is the one that loads a config file. A worker
        # with no remotes is a worker something else has to synchronise, which
        # is the gap this corrective pass closed; tests may construct the
        # dataclass directly for local-only mode.
        missing = [name for name in ("room_remote", "control_remote")
                   if not getattr(config, name)]
        if missing:
            raise TransportError(
                f"{path} is missing {missing}. An unattended transport "
                "synchronises its own fixed remotes; without them something "
                "outside this worker would have to run Git, which is the "
                "broad path S3 exists to remove.")
        return config


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
    """One bounded invocation that owns the whole transport lifecycle.

    Recover, synchronise, process, deliver, exit. Nothing outside this worker
    runs Git for Agent Room: the previous version operated on local checkouts
    and left "somebody runs git pull" implicit, which is either a stale
    service or an unspecified broad synchronisation path.

    The order matters and is the state machine:

    1. **Recover.** A crash can leave a room commit that was never delivered.
       Reset to the last accepted checkpoint unless the remote already has it.
    2. **Synchronise the room.** Fetch to a candidate ref, verify it there in
       full, install only on success.
    3. **Synchronise the control queue.** Fetch, verify namespace and
       append-only history, require descent from the service's own anchor,
       install.
    4. **Deliver.** Results this service produced but has not confirmed on the
       remote go out before any new work is taken on.
    5. **Process.** Bounded new requests, each against verified state.

    A deadline runs across all of it, so `worker_timeout_seconds` is enforced
    here and not merely declared; `RuntimeMaxSec` remains the cgroup-level
    hard stop underneath.
    """

    def __init__(self, config: TransportConfig) -> None:
        self.config = config
        self._deadline = None

    # -- bounds ------------------------------------------------------------
    def _start_clock(self) -> None:
        self._deadline = time.monotonic() + self.config.worker_timeout_seconds

    def _check_clock(self, what: str) -> None:
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise TransportError(
                f"the worker deadline of {self.config.worker_timeout_seconds}s "
                f"passed before {what}; stopping rather than running on")

    # -- service-owned wiring (nothing here is request-influenced) ---------
    def _room_store(self) -> GitMessageStore:
        # Deliberately no `remote=`: the generic store push path rebases on a
        # non-fast-forward, which for a supervisor response would mean
        # delivering a review of a head that has since moved. Delivery here is
        # a compare-and-swap instead.
        return GitMessageStore(
            self.config.room_workdir, branch=self.config.room_branch,
            remote=None,
            trust=TrustPolicy.load(self.config.trust_policy_path))

    def _candidate_store(self) -> GitMessageStore:
        return GitMessageStore(
            self.config.room_workdir,
            branch=f"{self.config.room_branch}{CANDIDATE_SUFFIX}",
            remote=None,
            trust=TrustPolicy.load(self.config.trust_policy_path))

    def _room_remote(self) -> RoomRemote | None:
        if not self.config.room_remote:
            return None
        return RoomRemote(self.config.room_workdir, self.config.room_remote,
                          self.config.room_branch)

    def _control_remote(self) -> ControlRemote | None:
        if not self.config.control_remote:
            return None
        return ControlRemote(self.config.control_workdir,
                             self.config.control_remote,
                             self.config.control_branch)

    def _boundary(self, store: GitMessageStore) -> SupervisorBoundary:
        room = AgentRoom(
            store, SUPERVISOR,
            ParticipantCursor(self.config.state_dir, SUPERVISOR),
            signer=Ed25519Signer(self.config.signing_key_path,
                                 signer=SUPERVISOR,
                                 key_id=self.config.signing_key_id),
        )
        return SupervisorBoundary(room)

    def _ledger(self) -> Anchor:
        """What the *service* knows it has done.

        Not the control repository's opinion: that branch is written by an
        untrusted party, so a result file appearing there says nothing about
        whether this worker ran anything.
        """
        return Anchor(Path(self.config.state_dir) / "processed.json",
                      "processed-ledger")

    def _control_anchor(self) -> Anchor:
        return Anchor(Path(self.config.state_dir) / "control-anchor.json",
                      "control-anchor")

    # -- 1. recovery -------------------------------------------------------
    def recover_room(self) -> dict:
        """Undo a room commit a previous run made but never delivered.

        A commit that was never pushed is not history anyone else has seen, so
        discarding it loses nothing durable — and keeping it would mean either
        delivering a review of a head that has since moved, or carrying an
        un-auditable local divergence forward. If the remote turns out to have
        it after all, it stays and the ordinary sync installs it.
        """
        remote = self._room_remote()
        store = self._room_store()
        local = store.current_tip()
        if remote is None:
            # Local-only mode: "undelivered" has no meaning without a remote,
            # and local commits are simply the room. Nothing to recover.
            return {"recovered": False, "mode": "local", "tip": local}

        remote_tip = remote.remote_tip()
        if remote_tip is None or local == remote_tip:
            return {"recovered": False, "tip": local}
        if remote.contains_remotely(local):
            # The crash was after the push: it is durable, leave it.
            return {"recovered": False, "delivered_before_crash": True,
                    "tip": local}

        checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
        accepted = checkpoint.document["last_accepted_tip"]
        if local == accepted:
            return {"recovered": False, "tip": local}
        if not store.is_strict_ancestor(accepted, local):
            raise TransportError(
                f"the local room tip {str(local)[:12]} does not descend from "
                f"the accepted checkpoint {accepted[:12]}; refusing to guess "
                "what happened to this checkout")
        # Commits this worker made and never delivered. Nobody else has seen
        # them, so discarding loses nothing durable — and keeping them would
        # mean either delivering a review of a head that has since moved, or
        # carrying an unauditable local divergence forward. The verified
        # remote candidate is installed on top of the accepted state next.
        run_git(self.config.room_workdir, "reset", "--hard", "--quiet",
                accepted)
        return {"recovered": True, "discarded": local, "tip": accepted}

    # -- 2. room synchronisation ------------------------------------------
    def sync_room(self) -> dict:
        """Fetch a candidate, verify it where it sits, install only then."""
        remote = self._room_remote()
        checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
        if remote is None:
            # Local-only mode (tests, or a single-host room). The checkpoint
            # still gates every read: nothing is trusted because it is local.
            store = self._room_store()
            return {"mode": "local", **checkpoint.accept(store)}

        candidate_branch = f"{self.config.room_branch}{CANDIDATE_SUFFIX}"
        candidate = remote.fetch_candidate(candidate_branch)
        if candidate is None:
            store = self._room_store()
            return {"mode": "no-remote-ref", **checkpoint.accept(store)}

        report = checkpoint.verify_candidate(self._candidate_store())
        remote.install(report["candidate_tip"])
        # Persist for exactly the state now installed locally, re-verifying
        # and re-observing the ref as `accept` always does.
        settled = checkpoint.accept(self._room_store())
        return {"mode": "remote", "candidate": report["candidate_tip"],
                **settled}

    # -- 3. control synchronisation ---------------------------------------
    def sync_control(self) -> dict:
        """Fetch the queue, verify it, and refuse a rewritten one.

        The content is untrusted; the *history* is an availability anchor. If
        a force-push erased a result this service produced, forgetting that
        would mean running the request again.
        """
        control = ControlStore(self.config.control_workdir,
                               self.config.control_branch)
        anchor = self._control_anchor()
        remote = self._control_remote()
        if remote is None:
            control.verify_history()
            self._anchor_control(anchor, control)
            return {"mode": "local", "tip": control.current_tip()}

        candidate_branch = f"{self.config.control_branch}{CANDIDATE_SUFFIX}"
        candidate = remote.fetch_candidate(candidate_branch)
        if candidate is None:
            control.verify_history()
            self._anchor_control(anchor, control)
            return {"mode": "no-remote-ref", "tip": control.current_tip()}

        probe = ControlStore(self.config.control_workdir, candidate_branch)
        probe.verify_history()
        if probe.genesis() != self._expected_control_genesis(anchor, probe):
            raise TransportRefused(
                "the control remote's genesis is not the queue this service "
                "was bootstrapped against; an unrelated queue cannot replace "
                "the record of what has already been processed")
        accepted = anchor.get("last_accepted_tip")
        if accepted and candidate != accepted and not remote.is_ancestor(
                accepted, candidate):
            raise TransportRefused(
                f"the control remote {candidate[:12]} does not descend from "
                f"the last accepted {accepted[:12]}. A rewritten or rolled "
                "back queue would erase results this service already produced "
                "and invite it to repeat the work.")
        if candidate != control.current_tip():
            run_git(self.config.control_workdir, "merge", "--ff-only",
                    "--quiet", candidate)
        control.verify_history()
        self._anchor_control(anchor, control)
        return {"mode": "remote", "tip": control.current_tip()}

    def _expected_control_genesis(self, anchor: Anchor, probe) -> str:
        configured = self.config.control_genesis
        if configured:
            return configured
        recorded = anchor.get("genesis")
        return recorded if recorded else probe.genesis()

    def _anchor_control(self, anchor: Anchor, control: ControlStore) -> None:
        anchor.set(genesis=control.genesis(),
                   last_accepted_tip=control.current_tip())

    # -- 4. delivery of results this service produced ----------------------
    def deliver_results(self) -> list:
        """Get durable local results onto the remote before taking new work."""
        ledger = self._ledger()
        pending = dict(ledger.get("pending_results") or {})
        if not pending:
            return []
        control = ControlStore(self.config.control_workdir,
                               self.config.control_branch)
        remote = self._control_remote()
        delivered = []
        for request_id, document in list(pending.items()):
            self._check_clock("delivering a result")
            try:
                control.write_result(request_id, document)
                outcome = "written"
            except ControlConflict:
                # Somebody else already wrote a different result at this id.
                # Immutable means immutable: this fails closed rather than
                # overwriting, and the request is not retried.
                outcome = "conflict"
            except ControlError as exc:
                delivered.append({"request_id": request_id,
                                  "status": "deferred",
                                  "detail": _bounded(exc)})
                continue
            pending.pop(request_id)
            delivered.append({"request_id": request_id, "status": outcome})
        ledger.set(pending_results=pending)

        if remote is not None and delivered:
            self._push_control(control, remote)
        return delivered

    def _push_control(self, control: ControlStore, remote: ControlRemote) -> dict:
        """Bounded push. On a moved remote, verify it first and reconstruct."""
        for attempt in range(MAX_DELIVERY_ATTEMPTS):
            try:
                return remote.push()
            except RemoteRefMoved:
                self._check_clock("retrying the control push")
                self.sync_control()
                ledger = self._ledger()
                pending = dict(ledger.get("pending_results") or {})
                if not pending:
                    return {"pushed": False, "reason": "nothing left to deliver"}
                # Re-apply on top of the verified remote history. The paths are
                # unique per request, so nothing is overwritten and nothing of
                # the other writer's is discarded.
                for request_id, document in list(pending.items()):
                    try:
                        control.write_result(request_id, document)
                        pending.pop(request_id)
                    except ControlConflict:
                        pending.pop(request_id)
                ledger.set(pending_results=pending)
        raise TransportError(
            f"the control remote moved {MAX_DELIVERY_ATTEMPTS} times while "
            "delivering results; stopping rather than looping")

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
        return {"packet": packet}

    def _op_supervisor_import(self, store: GitMessageStore,
                              params: dict) -> dict:
        """Import under an exact lease on the head the review was bound to.

        The freshness check inside `import_response` is against local state.
        That is necessary and not sufficient: a remote writer can append to the
        reviewed thread between the check and the push, and a generic
        rebase-and-push would deliver the response on top of a context the
        supervisor never saw. So the push carries a lease on the exact head,
        and a moved ref sends us back to recompute the context rather than
        forward to retry harder.
        """
        remote = self._room_remote()
        document = params["response"]
        thread_before = self._reviewed_context(store, document)

        for attempt in range(MAX_DELIVERY_ATTEMPTS):
            self._check_clock("delivering a supervisor response")
            expected = store.current_tip()
            result = self._boundary(store).import_response(
                json.dumps(document))
            if remote is None:
                return {"import": result, "delivery": {"mode": "local"}}
            try:
                pushed = remote.push_with_lease(expected)
            except RemoteRefMoved:
                # The ref moved. Recompute the reviewed context against what
                # is there now; a changed context is stale, full stop.
                discarded = store.current_tip()
                run_git(self.config.room_workdir, "reset", "--hard", "--quiet",
                        expected)
                self.sync_room()
                fresh = self._room_store()
                if self._reviewed_context(fresh, document) != thread_before:
                    raise TransportRefused(
                        "the reviewed thread changed on the remote while this "
                        "response was being delivered. The review was of a "
                        "context that no longer exists, so it is not "
                        "delivered; export a fresh packet and review again.")
                store = fresh
                continue
            settled = self._accept_after_delivery(store)
            return {"import": result,
                    "delivery": {"mode": "remote", "tip": pushed["tip"],
                                 "lease": expected, "attempts": attempt + 1},
                    "checkpoint": settled}
        raise TransportError(
            f"the room remote moved {MAX_DELIVERY_ATTEMPTS} times while "
            "delivering one supervisor response; stopping rather than looping")

    def _reviewed_context(self, store: GitMessageStore, document: dict) -> str:
        """The digest of the thread this response claims to review, now."""
        target = store.resolve_message(document["target_message_id"])
        if target is None:
            raise TransportRefused(
                f"the reviewed target {document['target_message_id']} is not "
                "in this room")
        return context_digest(target, store.thread_messages(target["thread_id"]))

    def _accept_after_delivery(self, store: GitMessageStore) -> dict:
        """Re-observe the settled head and advance the checkpoint to it."""
        remote = self._room_remote()
        if remote is not None:
            candidate_branch = f"{self.config.room_branch}{CANDIDATE_SUFFIX}"
            candidate = remote.fetch_candidate(candidate_branch)
            if candidate and candidate != store.current_tip():
                checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
                checkpoint.verify_candidate(self._candidate_store())
                remote.install(candidate)
        checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
        return checkpoint.accept(self._room_store())

    # -- 5. the run --------------------------------------------------------
    def run(self) -> dict:
        self._start_clock()
        try:
            lifecycle = {
                "recover": self.recover_room(),
                "room": self.sync_room(),
                "control": self.sync_control(),
                "delivered": self.deliver_results(),
            }
        except AgentRoomError as exc:
            # A synchronisation failure is not a per-request result: it is a
            # statement that nothing about this room's state can be trusted
            # right now. No export, no import, no status, and no result
            # artifact claiming success for work that was never attempted.
            return {
                "pending": None, "processed": 0, "remaining": None,
                "results": [],
                "lifecycle": {"status": "failed",
                              "error": _bounded(exc),
                              "error_type": type(exc).__name__},
            }
        control = ControlStore(self.config.control_workdir,
                               self.config.control_branch)
        ledger = self._ledger()
        done = ledger.get("requests") or {}

        # Selection is against the service's own ledger, never against the
        # presence of a result file: both files on that branch are written by
        # the same untrusted party, so "there is a result" is that party's
        # claim and not a record of what this worker did. A forged result can
        # therefore not make an operation be skipped.
        unprocessed = [entry for entry in control.requests()
                       if entry["request_id"] not in done]
        if len(unprocessed) > MAX_PENDING_REQUESTS:
            raise TransportError(
                f"{len(unprocessed)} requests are unprocessed, over the "
                f"{MAX_PENDING_REQUESTS} backlog limit; a writer cannot make "
                "the worker take on an unbounded queue")

        processed, summary = 0, []
        for entry in unprocessed:
            if processed >= self.config.max_requests_per_run:
                break
            self._check_clock("selecting the next request")
            summary.append(self._process(control, entry))
            processed += 1
        pending = unprocessed

        if processed:
            lifecycle["delivered"] = (lifecycle["delivered"]
                                      + self.deliver_results())
        return {
            "pending": len(pending),
            "processed": processed,
            "remaining": max(len(pending) - processed, 0),
            "results": summary,
            "lifecycle": {"status": "ok", **lifecycle},
        }

    def _process(self, control: ControlStore, entry: dict) -> dict:
        request_id = entry["request_id"]
        try:
            document, request_sha256 = control.read_request(entry)
        except (ControlError, AgentRoomError) as exc:
            return self._record(request_id, "unreadable", "", "refused",
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
        return self._record(request_id, operation, request_sha256, status,
                            detail)

    def _record(self, request_id: str, operation: str, request_sha256: str,
                status: str, detail: dict) -> dict:
        """Durable in service state first, then queued for the control repo.

        The ledger is what stops a request being run twice; the control
        artifact is how the far side finds out. Writing the ledger first means
        a crash between the two costs a lost notification, never a repeated
        operation.
        """
        store_tip = None
        try:
            store_tip = self._room_store().current_tip()
        except AgentRoomError:
            pass
        result = {
            "control_schema_version": CONTROL_SCHEMA_VERSION,
            "request_id": request_id,
            "operation": operation,
            "request_sha256": request_sha256,
            "status": status,
            "completed_at": _now_iso(),
            # A success claim the far side can check against signed state
            # rather than having to trust this artifact's provenance.
            "room_tip": store_tip,
            "detail": detail,
        }
        ledger = self._ledger()
        requests = dict(ledger.get("requests") or {})
        requests[request_id] = {"operation": operation, "status": status,
                                "at": result["completed_at"],
                                "room_tip": store_tip}
        pending = dict(ledger.get("pending_results") or {})
        pending[request_id] = result
        ledger.set(requests=requests, pending_results=pending)
        return {"request_id": request_id, "operation": operation,
                "status": status}

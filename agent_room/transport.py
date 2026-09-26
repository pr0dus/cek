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
import hashlib
import json
import re
import time
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from . import canonical
from .auth import Ed25519Signer
from .checkpoint import TrustCheckpoint
from .control_store import (
    CONTROL_SCHEMA_VERSION,
    MAX_PENDING_REQUESTS,
    RESULTS_DIR,
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
    AmbiguousDelivery,
    Anchor,
    ControlRemote,
    RemoteRefMoved,
    RoomRemote,
    SyncError,
    run_git,
)
from .supervisor import PARTICIPANT as SUPERVISOR
from .supervisor import SupervisorBoundary
from .supervisor import context_digest
from .trust import TrustPolicy
from .transport_state import private_lock, WORKER_LOCK

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
        missing = [name for name in ("room_remote", "control_remote",
                                     "control_genesis")
                   if not getattr(config, name)]
        if missing:
            raise TransportError(
                f"{path} is missing {missing}. An unattended transport "
                "synchronises its own fixed remotes, and it pins the control "
                "history's root out of band: without the pin the first remote "
                "history a fresh service sees would choose its own replay "
                "anchor, which is trust on first use for the thing that stops "
                "erased results causing replay.")
        if not re.match(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z",
                        config.control_genesis):
            raise TransportError(
                f"{path} control_genesis {config.control_genesis!r} must be a "
                "full Git object id obtained out of band")
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

    1. **Reconcile.** Require both configured refs, verify the control queue,
       and reconcile uncertain imports before generic recovery or new work.
       Unknown delivery is never a terminal processed request.
    2. **Recover and synchronise the room.** Fetch to a candidate ref, verify
       it there in full, install only on success.
    3. **Deliver.** Results this service produced but has not confirmed on the
       remote go out before any new work is taken on.
    4. **Process.** Bounded new requests, each against verified state.

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
        if self.config.room_remote is None:
            return None
        return RoomRemote(self.config.room_workdir, self.config.room_remote,
                          self.config.room_branch,
                          trust=TrustPolicy.load(self.config.trust_policy_path),
                          checkpoint_path=self.config.checkpoint_path)

    def _control_remote(self) -> ControlRemote | None:
        if self.config.control_remote is None:
            return None
        return ControlRemote(self.config.control_workdir,
                             self.config.control_remote,
                             self.config.control_branch,
                             genesis=self.config.control_genesis,
                             anchor_path=Path(self.config.state_dir)/'control-anchor.json')

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
        if self._ledger().document["uncertain_imports"]:
            raise TransportError("uncertain imports must be reconciled before room recovery")
        remote = self._room_remote()
        store = self._room_store()
        local = store.current_tip()
        if remote is None:
            # Local-only mode: "undelivered" has no meaning without a remote,
            # and local commits are simply the room. Nothing to recover.
            return {"recovered": False, "mode": "local", "tip": local}

        remote_tip = remote.required_remote_tip()
        if local == remote_tip:
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
            anchor.advance_control(control, None,
                                   self.config.control_genesis or control.genesis())
            return {"mode": "local", "tip": control.current_tip()}

        candidate_branch = f"{self.config.control_branch}{CANDIDATE_SUFFIX}"
        candidate = remote.fetch_candidate(candidate_branch)
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
        # Commit against current disk state, before installation. A stale
        # object cannot restore an older accepted tip even outside run().
        anchor.advance_control(probe, remote, self._expected_control_genesis(anchor, probe))
        if candidate != control.current_tip():
            # `--ff-only` cannot install this when the local branch carries a
            # service result the remote has not seen, and that divergence is
            # ordinary under concurrent use. The local control checkout is
            # disposable working state: the authority for our own undelivered
            # results is the owner-only ledger, so the verified remote
            # candidate wins for Git history and the results are re-laid on
            # top of it afterwards.
            run_git(self.config.control_workdir, "reset", "--hard", "--quiet",
                    candidate)
        control.verify_history()
        # The anchor advances only to a tip actually observed on the remote —
        # never to a local-only result commit, which nobody else has seen.
        return {"mode": "remote", "tip": control.current_tip(),
                "anchor": candidate}

    def _expected_control_genesis(self, anchor: Anchor, probe) -> str:
        """The pin, never the fetched branch's own answer.

        Falling back to what the remote says would let the first history a
        fresh service sees choose its own replay anchor — trust on first use
        for exactly the thing that stops erased results causing replay.
        """
        configured = self.config.control_genesis
        if configured:
            return configured
        recorded = anchor.get("genesis")
        if recorded:
            return recorded
        raise TransportRefused(
            "no control genesis is pinned and none has been recorded: the "
            "control history's root must be supplied out of band before a "
            "remote queue can be accepted as this service's replay anchor")

    # -- 4. delivery of results this service produced ----------------------
    def materialise_pending(self, control: ControlStore) -> dict:
        """Write every still-pending result into the local control branch.

        Idempotent and repeatable. The local control checkout is disposable
        working state that can be reconstructed from the protected ledger, so
        this runs again after any sync that reset it.
        """
        ledger = self._ledger()
        pending = dict(ledger.document["pending_results"])
        for request_id, entry in pending.items():
            self._check_clock("materialising a result")
            try:
                control.write_result(request_id, entry["document"])
                entry["state"] = "materialised"
            except ControlConflict:
                # An immutable artifact already sits at this path with
                # different content. The service cannot deliver its own
                # result, and says so rather than overwriting.
                entry["state"] = "conflict"
            except ControlError as exc:
                entry["state"] = "deferred"
                entry["detail"] = _bounded(exc)
        ledger.set(pending_results=pending)
        return pending

    def deliver_results(self) -> list:
        """Deliver produced results, and clear them only once that is proven.

        A result leaves the protected ledger for exactly two reasons: the
        remote demonstrably holds byte-identical content, or an immutable
        conflicting artifact makes it permanently undeliverable. Committing it
        locally is not one of them — the earlier version cleared it there, so
        a remote that moved before the push lost the result entirely.
        """
        ledger = self._ledger()
        if not (ledger.document["pending_results"]):
            return []
        control = ControlStore(self.config.control_workdir,
                               self.config.control_branch)
        remote = self._control_remote()
        self.materialise_pending(control)

        push_state = "local"
        if remote is not None:
            push_state = self._push_control(control, remote)
        return self._confirm_results(control, remote, push_state)

    def _push_control(self, control: ControlStore, remote: ControlRemote) -> str:
        """Bounded push. A moved remote is verified and reconstructed on."""
        for _attempt in range(MAX_DELIVERY_ATTEMPTS):
            self._check_clock("pushing control results")
            try:
                remote.push()
                return "pushed"
            except RemoteRefMoved:
                # Divergence is ordinary under concurrent use: the remote
                # gained a request while we held a result. The verified remote
                # candidate wins for Git history, and our results are re-laid
                # on top from the ledger.
                self.sync_control()
                self.materialise_pending(control)
            except (AmbiguousDelivery, SyncError):
                # Cannot tell, or the push failed for a reason that says
                # nothing about acceptance. Delivery is never inferred from an
                # exit code: confirmation against the remote's own content
                # decides, and nothing is cleared on a guess.
                return "ambiguous"
        return "exhausted"

    def _confirm_results(self, control: ControlStore,
                         remote: ControlRemote | None,
                         push_state: str) -> list:
        """Clear a result only against evidence, never against an exit code."""
        ledger = self._ledger()
        pending = dict(ledger.document["pending_results"])
        outcomes = []
        observed = None
        if remote is not None:
            observed = self._remote_control_results(remote)

        for request_id, entry in list(pending.items()):
            document = entry["document"]
            if remote is None:
                # Local-only mode: the local branch is the only place a result
                # can be, so materialised is delivered.
                state = ("delivered" if entry.get("state") == "materialised"
                         else entry.get("state", "pending"))
            elif observed is None:
                state = "unknown"
            else:
                state = self._classify_remote(observed, request_id, document,
                                              entry)
            outcomes.append({"request_id": request_id, "status": state,
                             "push": push_state})
            if state in ("delivered", "conflict"):
                pending.pop(request_id)
            else:
                entry["state"] = state
        ledger.set(pending_results=pending)
        return outcomes

    def _remote_control_results(self, remote: ControlRemote):
        """The remote's own result artifacts, or None if it cannot be read."""
        probe_branch = f"{self.config.control_branch}{CANDIDATE_SUFFIX}-confirm"
        try:
            remote.fetch_candidate(probe_branch)
            probe = ControlStore(self.config.control_workdir, probe_branch)
            history = probe._history()
            return {
                path.rsplit("/", 1)[-1][: -len(".json")]:
                    probe._blob(path, commit)
                for path, commit in history.items()
                if path.startswith(f"{RESULTS_DIR}/")
            }
        except AgentRoomError:
            # Unreadable is not absent. Nothing is cleared on an unknown.
            return None

    @staticmethod
    def _classify_remote(observed: dict, request_id: str, document: dict,
                         entry: dict) -> str:
        expected = canonical.canonical_text(document).encode("utf-8")
        actual = observed.get(request_id)
        if actual is None:
            return "conflict" if entry.get("state") == "conflict" else "pending"
        if actual == expected:
            return "delivered"
        return "conflict"

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
                              params: dict, *, request_id: str,
                              request_sha256: str, attempts: int = 0) -> dict:
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
        if attempts == 0 and request_id in (self._ledger().document["uncertain_imports"]):
            raise TransportError("request has an uncertain import; reconcile it before new work")
        self._check_clock("constructing a supervisor response")
        expected = store.current_tip()
        result = self._boundary(store).import_response(json.dumps(document))
        if remote is None:
            return {"import": result, "delivery": {"mode": "local"}}
        message = store.resolve_message(result["response_message_id"])
        # Durable before the first push, including the crash-after-acceptance
        # window. Only reconciliation or a proven stale refusal removes this.
        ledger = self._ledger()
        uncertain = dict(ledger.document["uncertain_imports"])
        uncertain[request_id] = {
            "state": "uncertain_delivery", "request_id": request_id,
            "request_sha256": request_sha256, "params": params,
            "target_message_id": document["target_message_id"],
            "context_sha256": document["context_sha256"],
            "response_message_id": result["response_message_id"],
            "response_sha256": message[canonical.DIGEST_FIELD],
            "local_tip": store.current_tip(), "expected_remote_head": expected,
            "attempts": attempts + 1, "import": result,
        }
        ledger.set(uncertain_imports=uncertain)
        return self._deliver_uncertain_import(request_id)

    def _deliver_uncertain_import(self, request_id: str, *, inspections: int = 0) -> dict:
        """Reconcile one exact signed artifact before it can become terminal.

        Unknown: leave it and stop. Present: verify and accept. Absent on the
        same head: push the very same commit. Absent on a moved head: only a
        verified candidate may replace it; recompute context before rebuilding.
        """
        remote = self._room_remote()
        if remote is None:
            raise TransportError("an uncertain remote import cannot become local mode")
        if inspections >= MAX_DELIVERY_ATTEMPTS:
            raise AmbiguousDelivery("bounded remote reconciliation pass exhausted")
        entry = self._ledger().document["uncertain_imports"][request_id]
        self._check_clock("reconciling a supervisor response")
        local = self._room_store()
        candidate = remote.fetch_candidate(f"{self.config.room_branch}{CANDIDATE_SUFFIX}")
        checkpoint = TrustCheckpoint.load(self.config.checkpoint_path)
        checkpoint.verify_candidate(self._candidate_store())
        probe = self._candidate_store()
        found = probe.resolve_message(entry["response_message_id"])
        if found is not None:
            if found[canonical.DIGEST_FIELD] != entry["response_sha256"] or not remote.is_ancestor(
                    entry["local_tip"], candidate):
                raise TransportError("uncertain response identity/commit mismatch")
            remote.install(candidate)
            settled = checkpoint.accept(self._room_store())
            return {"import": entry["import"], "checkpoint": settled,
                    "delivery": {"mode": "remote", "tip": candidate,
                                 "lease": entry["expected_remote_head"],
                                 "status": "reconciled", "attempts": entry["attempts"]}}

        expected = entry["expected_remote_head"]
        if local.current_tip() != entry["local_tip"]:
            # A crash may have occurred after installing the verified absent
            # candidate below. That exact independently verified state is safe
            # to re-evaluate, but an arbitrary local branch is not.
            if local.current_tip() != candidate:
                raise TransportError("uncertain response local tip changed unexpectedly")
        elif candidate == expected:
            local.verify_store()
            message = local.resolve_message(entry["response_message_id"])
            if message is None or message[canonical.DIGEST_FIELD] != entry["response_sha256"]:
                raise TransportError("retained signed response is missing or changed")
            try:
                pushed = remote.push_with_lease(expected)
            except RemoteRefMoved:
                # Reinspect and verify; never discard on an exit-code guess.
                return self._deliver_uncertain_import(request_id, inspections=inspections + 1)
            settled = self._accept_after_delivery(local)
            return {"import": entry["import"], "checkpoint": settled,
                    "delivery": {"mode": "remote", "tip": pushed["tip"],
                                 "lease": expected, "attempts": entry["attempts"]}}

        # The exact response is proven absent from this verified descendant.
        # Only that known undelivered local suffix may be discarded. Installing
        # and checkpointing the verified remote leaves a deterministic restart
        # position if the worker dies before rechecking/rebuilding the request.
        if local.current_tip() == entry["local_tip"]:
            if not remote.is_ancestor(expected, entry["local_tip"]):
                raise TransportError("uncertain response does not descend from its lease")
            run_git(self.config.room_workdir, "reset", "--hard", "--quiet", candidate)
        checkpoint.accept(self._room_store())
        document = entry["params"]["response"]
        if self._reviewed_context(probe, document) != entry["context_sha256"]:
            raise TransportRefused("the reviewed thread changed remotely; proven-undelivered review is stale")
        if entry["attempts"] >= MAX_DELIVERY_ATTEMPTS:
            raise TransportRefused("bounded CAS reconstruction attempts exhausted; response proven absent")
        return self._op_supervisor_import(
            self._room_store(), entry["params"], request_id=request_id,
            request_sha256=entry["request_sha256"], attempts=entry["attempts"])

    def reconcile_imports(self) -> list:
        """Finish all uncertain imports before recovery or any new request."""
        results = []
        for request_id, entry in (self._ledger().document["uncertain_imports"]).items():
            try:
                detail = self._deliver_uncertain_import(request_id)
                status = "ok"
            except TransportRefused as exc:
                status, detail = "refused", {"error": _bounded(exc)}
            # Other errors deliberately escape: no terminal result can be
            # inferred when the remote or local evidence cannot be inspected.
            results.append(self._record(request_id, "supervisor_import",
                                        entry["request_sha256"], status, detail))
        return results

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
        # No state/Git/checkpoint read is allowed before this process owns the
        # full lifecycle. Configuration is root-owned; no request chooses it.
        with ExitStack() as stack:
            try:
                stack.enter_context(private_lock(self.config.state_dir, WORKER_LOCK))
            except AgentRoomError as exc:
                return {"pending": None, "processed": 0, "remaining": None,
                        "results": [], "lifecycle": {"status": "failed",
                        "error": _bounded(exc), "error_type": type(exc).__name__}}
            # Preserve existing error/delivery semantics once processing has
            # begun; it would be false to report zero work on a later error.
            return self._run_locked()

    def _run_locked(self) -> dict:
        self._start_clock()
        try:
            # Read owner state and require both configured refs before any
            # checkpoint, replay or result work. None is explicit test mode;
            # an absent configured branch is never local mode.
            self._ledger()
            self._control_anchor()
            for remote in (self._room_remote(), self._control_remote()):
                if remote is not None:
                    remote.required_remote_tip()
            control_sync = self.sync_control()
            reconciled = self.reconcile_imports()
            lifecycle = {
                "recover": self.recover_room(),
                "room": self.sync_room(),
                "control": control_sync,
                "reconciled": reconciled,
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
        done = ledger.document["requests"]

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
            if summary[-1]["status"] == "uncertain_delivery":
                # Stop this pass; no later request may build on the unaccepted
                # local response. The request remains unprocessed in the ledger.
                break
            processed += 1
        pending = unprocessed

        if processed:
            lifecycle["delivered"] = (lifecycle["delivered"]
                                      + self.deliver_results())
        return {
            "pending": len(pending),
            "processed": processed,
            "remaining": max(len(pending) - processed, 0),
            "results": reconciled + summary,
            "lifecycle": {"status": "uncertain_delivery" if self._ledger().document["uncertain_imports"]
                          else "ok", **lifecycle},
        }

    def _process(self, control: ControlStore, entry: dict) -> dict:
        request_id = entry["request_id"]
        if request_id in (self._ledger().document["uncertain_imports"]):
            return {"request_id": request_id, "operation": "supervisor_import",
                    "status": "uncertain_delivery"}
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
            if operation == "supervisor_import":
                detail = handler(store, validated["params"], request_id=request_id,
                                 request_sha256=request_sha256)
            else:
                detail = handler(store, validated["params"])
            status = "ok"
        except TransportRefused as exc:
            status, detail = "refused", {"error": _bounded(exc)}
        except AgentRoomError as exc:
            if request_id in (self._ledger().document["uncertain_imports"]):
                return {"request_id": request_id, "operation": operation,
                        "status": "uncertain_delivery", "error": _bounded(exc)}
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
        requests = dict(ledger.document["requests"])
        requests[request_id] = {"operation": operation, "status": status,
                                "at": result["completed_at"],
                                "room_tip": store_tip,
                                "result_sha256": hashlib.sha256(
                                    canonical.canonical_bytes(result)).hexdigest()}
        pending = dict(ledger.document["pending_results"])
        # `produced`: this service made it and has not proven it reached the
        # remote. It stays here through `materialised`, and leaves only on
        # `delivered` or a terminal `conflict`.
        pending[request_id] = {"document": result, "state": "produced",
                               "at": result["completed_at"]}
        uncertain = dict(ledger.document["uncertain_imports"])
        uncertain.pop(request_id, None)
        ledger.set(requests=requests, pending_results=pending,
                   uncertain_imports=uncertain)
        return {"request_id": request_id, "operation": operation,
                "status": status}

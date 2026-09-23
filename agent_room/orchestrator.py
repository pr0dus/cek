"""The smallest coordinator that can drive one work item through the room.

It is not a model. It holds no opinion about the work, writes no code, and
decides nothing: it selects the next durable message, invokes one bounded turn
through an already-qualified participant surface, and stops. Every state it
reports is *derived from the room*, never from a local counter — which is what
makes the whole qualification reconstructible after a restart.

Three ceilings bound one work item: implementation attempts, cross-provider
inspection rounds, supervisor correction rounds. Reaching one is a result, not
an error to route around. The coordinator stops and reports the unresolved
findings; it never manufactures convergence, and it never silently swaps in a
different provider when one of them is struggling.

Independence is mechanical too. Whoever produced an implementation attempt is
recorded as an author of the work, and the final inspection must come from a
provider that is not in that set — in a fresh process, which is the adapters'
job, not this module's. Two models agreeing is still not validation.

`NoWorkAvailable` is ordinary idle here. An empty inbox means there is nothing
to do right now, not that orchestration failed.
"""

from dataclasses import dataclass, asdict

from .cursor import ParticipantCursor
from .decision import evaluate_gate, pending_requests
from .errors import AgentRoomError
from .gitstore import GitMessageStore
from .participant import NoWorkAvailable
from .room import AgentRoom
from .supervisor import PARTICIPANT as SUPERVISOR

#: A router identity, so its routing messages are attributable in the log.
#: It never authors an implementation, an inspection or a decision.
COORDINATOR = "coordinator"

CLAUDE = "claude-code"
CODEX = "codex"
CODING_PARTICIPANTS = (CLAUDE, CODEX)

#: What counts as a round, by sender and message type, for messages that are
#: replies. Derived from durable messages only, so two processes reading the
#: same room agree — and a restarted coordinator resumes at the same counts
#: rather than at zero.
IMPLEMENTATION_TYPES = frozenset({"claim", "evidence", "test_result"})
INSPECTION_TYPES = frozenset({
    "challenge", "observation", "answer", "evidence", "test_result",
})
CORRECTION_TYPES = frozenset({"challenge", "question"})

__all__ = [
    "COORDINATOR", "CLAUDE", "CODEX", "CODING_PARTICIPANTS",
    "RoundBounds", "Assignment", "BoundExhausted", "IndependenceViolation",
    "Coordinator",
]


class BoundExhausted(AgentRoomError):
    """A round ceiling was reached. Carries what is still unresolved."""

    def __init__(self, message, *, kind: str, state: dict):
        super().__init__(message)
        self.kind = kind
        self.state = state


class IndependenceViolation(AgentRoomError):
    """The final inspection would not be independent of authorship."""


@dataclass(frozen=True)
class RoundBounds:
    """Explicit ceilings for one qualification task (contract §3)."""

    implementation_attempts: int = 2
    inspection_rounds: int = 2
    supervisor_corrections: int = 2


@dataclass(frozen=True)
class Assignment:
    """Who builds and who inspects, fixed before the work starts."""

    thread_id: str
    builder: str
    inspector: str

    def __post_init__(self):
        if self.builder == self.inspector:
            raise IndependenceViolation(
                f"builder and inspector are both {self.builder!r}; a provider "
                "cannot independently inspect its own work"
            )
        for role, name in (("builder", self.builder), ("inspector", self.inspector)):
            if name not in CODING_PARTICIPANTS:
                raise IndependenceViolation(
                    f"{role} must be one of {list(CODING_PARTICIPANTS)}, got "
                    f"{name!r}"
                )


class Coordinator:
    """Routes durable messages and invokes bounded turns. Holds no state."""

    def __init__(
        self,
        store: GitMessageStore,
        assignment: Assignment,
        *,
        state_root,
        bounds: RoundBounds = RoundBounds(),
    ) -> None:
        self.store = store
        self.assignment = assignment
        self.state_root = state_root
        self.bounds = bounds

    # -- rooms -------------------------------------------------------------
    def room_for(self, participant: str) -> AgentRoom:
        """One room per participant, each with its own local cursor.

        Independent cursor state is a requirement, not a convenience: a shared
        cursor would make one participant's acknowledgement silently mark a
        message read for another.
        """
        cursor = ParticipantCursor(self.state_root, participant)
        return AgentRoom(self.store, participant, cursor)

    # -- derived state -----------------------------------------------------
    def _thread(self, thread_id: str | None = None) -> list:
        return self.store.thread_messages(thread_id or self.assignment.thread_id)

    def rounds(self, thread_id: str | None = None) -> dict:
        """Count each kind of round from the durable thread alone."""
        builder, inspector = self.assignment.builder, self.assignment.inspector
        counts = {
            "implementation_attempts": 0,
            "inspection_rounds": 0,
            "supervisor_corrections": 0,
        }
        messages = self._thread(thread_id)
        by_id = {m["message_id"]: m for m in messages}
        for message in messages:
            # A round is always a response to something. The opening task
            # assignment has no parent, so it is routing, not a round - and
            # without this the supervisor's own task would be counted against
            # its correction ceiling before any correction existed.
            if message.get("parent_id") is None:
                continue
            sender, mtype = message["sender"].get("agent"), message["type"]
            parent = by_id.get(message["parent_id"])
            parent_sender = (parent or {}).get("sender", {}).get("agent")
            if sender == builder and mtype in IMPLEMENTATION_TYPES:
                counts["implementation_attempts"] += 1
            elif (sender == inspector and mtype in INSPECTION_TYPES
                  and parent_sender in (builder, COORDINATOR)):
                # An inspection round inspects the *work*. The inspector
                # replying straight to the supervisor - querying the task,
                # say - is taking part in the review conversation, and
                # charging that against the inspection budget would spend the
                # ceiling before any work existed to inspect.
                counts["inspection_rounds"] += 1
            elif sender == SUPERVISOR and mtype in CORRECTION_TYPES:
                counts["supervisor_corrections"] += 1
        return counts

    def authorship(self, thread_id: str | None = None) -> list:
        """Every participant that produced an implementation attempt.

        Any coding provider, not just the assigned builder — if the other one
        also edits, that is mixed authorship and must be visible rather than
        described as independent review.
        """
        authors = set()
        for message in self._thread(thread_id):
            if message.get("parent_id") is None:
                continue
            sender = message["sender"].get("agent")
            if sender in CODING_PARTICIPANTS and message["type"] in IMPLEMENTATION_TYPES:
                authors.add(sender)
        return sorted(authors)

    def remaining(self, thread_id: str | None = None) -> dict:
        counts = self.rounds(thread_id)
        limits = asdict(self.bounds)
        return {k: limits[k] - counts[k] for k in limits}

    def exhausted(self, thread_id: str | None = None) -> list:
        return sorted(k for k, left in self.remaining(thread_id).items() if left <= 0)

    # -- guards ------------------------------------------------------------
    def assert_within_bounds(self, kind: str, thread_id: str | None = None) -> int:
        """Refuse one more round of `kind` once the ceiling is reached."""
        limits = asdict(self.bounds)
        if kind not in limits:
            raise AgentRoomError(
                f"unknown round kind {kind!r}; known: {sorted(limits)}"
            )
        used = self.rounds(thread_id)[kind]
        if used >= limits[kind]:
            state = self.reconstruct(thread_id)
            raise BoundExhausted(
                f"{kind} ceiling reached ({used}/{limits[kind]}); stopping "
                "rather than continuing. Unresolved findings are in the "
                "reconstructed state.",
                kind=kind, state=state,
            )
        return limits[kind] - used

    def assert_independent_inspector(self, inspector: str,
                                     thread_id: str | None = None) -> list:
        """The final inspector must not have authored the work it inspects."""
        authors = self.authorship(thread_id)
        if inspector in authors:
            raise IndependenceViolation(
                f"{inspector!r} authored an implementation attempt in this "
                f"thread ({authors}), so its inspection is not independent; a "
                "fresh turn by the same provider is still self-review"
            )
        return authors

    # -- bounded turns -----------------------------------------------------
    def run_turn(self, adapter, message_id: str | None = None, *,
                 kind: str | None = None) -> dict:
        """One bounded turn through an already-qualified adapter.

        `kind` names the round this turn would consume, and is checked before
        the model is invoked. An empty inbox is idle, not a failure.
        """
        if kind is not None:
            self.assert_within_bounds(kind)
        try:
            return adapter.run_turn(message_id)
        except NoWorkAvailable as exc:
            return {
                "status": "idle",
                "participant": getattr(adapter, "participant", None),
                "detail": str(exc),
            }

    # -- reconstruction ----------------------------------------------------
    def reconstruct(self, thread_id: str | None = None) -> dict:
        """The complete qualification state, derived from durable artifacts.

        A pure function of the room: a fresh process with no memory of this
        one produces an identical result. That is the restart requirement made
        checkable rather than asserted.
        """
        thread_id = thread_id or self.assignment.thread_id
        messages = self._thread(thread_id)
        participants = sorted({m["sender"].get("agent") for m in messages})
        proofs, snapshots = set(), set()
        for message in messages:
            for ref in message.get("evidence") or []:
                if ref.get("kind") == "run" and ref.get("run_id"):
                    proofs.add(ref["run_id"])
            action = message.get("action")
            if action:
                snapshots.add(action["binding"]["snapshot_sha256"])

        # Reconstruction measures nothing: it reads durable state, it does not
        # go and look at a checkout or re-derive a supervisor packet. So every
        # gate it reports is an unmeasured one, and an unmeasured gate is
        # blocked by construction. Saying so explicitly matters more after an
        # approval exists than before - that is exactly when a reconstructed
        # record could otherwise be mistaken for a live release.
        gates = []
        for pending in pending_requests(self.store, thread_id):
            report = evaluate_gate(self.store, pending["request_message_id"])
            gates.append({
                "request_message_id": pending["request_message_id"],
                "action_id": pending["action_id"],
                "state": report["state"],
                "releasable": report["releasable"],
            })

        bound_gates = []
        for message in messages:
            if message["type"] != "decision_request" or not message.get("action"):
                continue
            report = evaluate_gate(self.store, message["message_id"])
            if report["releasable"]:
                # Unreachable while evaluate_gate fails closed on unmeasured
                # state. Kept because the alternative to an assertion here is
                # a reconstructed report that quietly says "go ahead".
                raise AgentRoomError(
                    f"reconstruction reported action "
                    f"{report['action_id']!r} as releasable without measuring "
                    "current state; the gate must fail closed"
                )
            bound_gates.append({
                "request_message_id": message["message_id"],
                "action_id": message["action"]["action_id"],
                "state": report["state"],
                "releasable": False,
                "unmeasured": report["unmeasured"],
            })
        decided = [
            {
                "request_message_id": m["decision"]["request_message_id"],
                "decision": m["decision"]["decision"],
                "decision_id": m["decision"]["decision_id"],
            }
            for m in messages if m["type"] in ("approval", "rejection")
        ]

        counts = self.rounds(thread_id)
        return {
            "thread_id": thread_id,
            "message_count": len(messages),
            "participants": participants,
            "builder": self.assignment.builder,
            "inspector": self.assignment.inspector,
            "authorship": self.authorship(thread_id),
            "rounds": counts,
            "bounds": asdict(self.bounds),
            "remaining": self.remaining(thread_id),
            "exhausted": self.exhausted(thread_id),
            "proof_run_ids": sorted(proofs),
            "snapshot_sha256s": sorted(snapshots),
            "pending_decisions": gates,
            #: Every bound decision request, decided or not, with the state it
            #: has when nothing has been measured. Never releasable.
            "bound_decision_gates": bound_gates,
            "gates_measured": False,
            "recorded_decisions": decided,
            "message_ids": [m["message_id"] for m in messages],
        }

"""Mechanical human authority: the decision record and the release gate.

Two things live here, and keeping them apart is the point.

**The authority surface.** `HumanDecisionAuthority` is the only caller of
`GitMessageStore.append_decision`, which is the only path in the package that
validates `agent_facing=False` and can therefore write an `approval` or a
`rejection`. Every agent surface — `AgentRoom.post`, the participant adapters,
the supervisor import boundary, and `append` itself — refuses those two types
outright. No participant or orchestrator module imports this class, and a test
asserts that.

That is capability separation, not cryptography. The design deferred signed
commits deliberately (§6), so this code never claims to *prove* a human acted.
What it guarantees is narrower and checkable: an agent cannot reach the write
path at all, well-formed or otherwise, and the operation is never invoked
automatically — the qualification stops and waits for a person.

**The gate.** `evaluate_gate` decides whether a consequential action is
releasable *now*. It is fail-closed in every direction: no decision blocks, a
rejection blocks, a decision from the wrong identity blocks, and an approval
whose bindings no longer match current state blocks. The bindings are the
inspected-state manifest digest (`snapshot.py`) and the supervisor packet
context digest (`supervisor.py`), so an approval stops releasing the moment
either the code or the reviewed conversation moves.

There is no timeout and no auto-approval. A pending decision blocks for as
long as it stays pending.
"""

import datetime as dt
import hashlib

from . import canonical
from .errors import AgentRoomError, ForbiddenOperation, UnresolvedReference
from .ids import uuid7
from .schema import (
    DECISION_SCHEMA_VERSION,
    DECISION_TYPES,
    DECISION_VERDICTS,
    HUMAN_PARTICIPANT,
    validate_action,
)

#: Reported by `evaluate_gate`. Exactly one is released; everything else is a
#: distinct reason for refusing, because "blocked" alone would hide whether a
#: human said no or simply has not been asked.
GATE_STATES = (
    "blocked_unbound",
    "blocked_no_decision",
    "blocked_unmeasured",
    "blocked_rejected",
    "blocked_stale",
    "released",
)

#: The measurements a caller must take *now* for an approval to release.
#: Both, always: an approval bound to a snapshot and a context releases only
#: while both still hold, and a gate that checked neither has established
#: nothing about either.
REQUIRED_OBSERVATIONS = ("snapshot_sha256", "supervisor_context_sha256")

__all__ = [
    "HUMAN_PARTICIPANT", "GATE_STATES", "REQUIRED_OBSERVATIONS", "DecisionError", "GateBlocked",
    "HumanDecisionAuthority", "binding_digest", "evaluate_gate",
    "assert_releasable", "pending_requests",
]


class DecisionError(AgentRoomError):
    """A human decision could not be recorded."""


class GateBlocked(AgentRoomError):
    """The bound consequential action is not releasable.

    Carries the full gate report, so a caller can say *why* it is blocked
    without re-deriving it.
    """

    def __init__(self, message, *, report: dict):
        super().__init__(message)
        self.report = report


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def binding_digest(decision: dict) -> str:
    """SHA-256 over exactly what is being decided, and nothing else.

    Deliberately excludes `decision_id` and `decided_at`: the digest answers
    "what was decided", not "which keystroke recorded it". Two decisions about
    the same action and the same state therefore share a binding digest, which
    is what lets the gate compare them without re-parsing prose.
    """
    payload = {
        "decision_schema_version": DECISION_SCHEMA_VERSION,
        "request_message_id": decision["request_message_id"],
        "request_envelope_sha256": decision["request_envelope_sha256"],
        "action_id": decision["action_id"],
        "action_scope": decision["action_scope"],
        "consequential": decision["consequential"],
        # The structured parameters are inside the digest: approving an
        # activation of branch X must not also approve branch Y, and prose
        # scope is not what a later check compares.
        "parameters": decision.get("parameters"),
        "binding": decision["binding"],
        "decision": decision["decision"],
    }
    return hashlib.sha256(canonical.canonical_bytes(payload)).hexdigest()


def _load_request(store, request_message_id: str) -> dict:
    request = store.resolve_message(request_message_id)
    if request is None:
        raise UnresolvedReference(
            f"no such message: {request_message_id!r}"
        )
    if request["type"] != "decision_request":
        raise DecisionError(
            f"message {request_message_id!r} is a {request['type']!r}, not a "
            "decision_request; there is nothing bound to decide"
        )
    return request


def _decisions_for(store, request: dict) -> tuple:
    """Every decision message hanging off this request, in commit order.

    Returns `(decisions, foreign)`. `foreign` holds any decision-typed reply
    whose sender is not the reserved human identity. Such a message can only
    exist if something bypassed the authority surface, so it is reported
    rather than counted — and its presence blocks.
    """
    decisions, foreign = [], []
    for message in store.thread_messages(request["thread_id"]):
        if message["type"] not in DECISION_TYPES:
            continue
        if message.get("parent_id") != request["message_id"]:
            continue
        if message["sender"].get("agent") != HUMAN_PARTICIPANT:
            foreign.append(message)
        else:
            decisions.append(message)
    return decisions, foreign


def pending_requests(store, thread_id: str | None = None) -> list:
    """Bound decision requests with no human decision recorded yet."""
    messages = (
        store.thread_messages(thread_id) if thread_id is not None
        else list(store.iter_messages())
    )
    pending = []
    for message in messages:
        if message["type"] != "decision_request" or not message.get("action"):
            continue
        decisions, _foreign = _decisions_for(store, message)
        if decisions:
            continue
        pending.append({
            "request_message_id": message["message_id"],
            "thread_id": message["thread_id"],
            "action_id": message["action"]["action_id"],
            "scope": message["action"]["scope"],
            "binding": message["action"]["binding"],
            "requested_by": message["sender"].get("agent"),
            "requested_at": message["timestamp"],
        })
    return pending


def evaluate_gate(
    store,
    request_message_id: str,
    *,
    snapshot_sha256: str | None = None,
    supervisor_context_sha256: str | None = None,
) -> dict:
    """ADVISORY diagnostic: is this bound action releasable right now?

    **Not the release path.** It accepts current measurements from the caller,
    and a caller can type anything — a red-team simply echoed the digests out
    of the decision request back in and got `released`. Every report it
    returns is marked `advisory: true` for that reason.

    `release.authorise` is the release-capable API: it derives both
    measurements itself from the binding's recipe and has no parameter through
    which a digest could be supplied. Use this one to *explain* a gate, never
    to act on it.

    Fail-closed at every step regardless.

    `snapshot_sha256` / `supervisor_context_sha256` are the state observed
    *now*, by the caller, from `snapshot.snapshot_manifest` and
    `supervisor.context_digest`. Supplying them is what makes a later code or
    conversation change invalidate an earlier approval; omitting them checks
    only the record's internal consistency, which is strictly weaker.
    """
    request = _load_request(store, request_message_id)
    action = request.get("action")
    report: dict = {
        # Advisory by construction: this function is *told* what current state
        # is. `release.authorise` measures it instead, and that is the only
        # release-capable path. Kept separate so a diagnostic read can never
        # be mistaken for an authorisation.
        "advisory": True,
        "request_message_id": request["message_id"],
        "thread_id": request["thread_id"],
        "request_envelope_sha256": request[canonical.DIGEST_FIELD],
        "action_id": (action or {}).get("action_id"),
        "action_scope": (action or {}).get("scope"),
        "bound": (action or {}).get("binding"),
        "observed": {
            "snapshot_sha256": snapshot_sha256,
            "supervisor_context_sha256": supervisor_context_sha256,
        },
        "decisions": [],
        "effective_decision": None,
        # Named here so every report - including the early returns above a
        # decision - says which measurements the caller did not take.
        "unmeasured": [
            name for name, value in (
                ("snapshot_sha256", snapshot_sha256),
                ("supervisor_context_sha256", supervisor_context_sha256),
            ) if value is None
        ],
        "reasons": [],
        "state": "blocked_unbound",
        "releasable": False,
    }

    if not action:
        report["reasons"].append(
            "the decision_request carries no bound action, so nothing about it "
            "is releasable; an unbound request can only be read by a human"
        )
        return report
    try:
        validate_action(action)
    except AgentRoomError as exc:
        report["reasons"].append(f"the bound action is malformed: {exc}")
        return report

    decisions, foreign = _decisions_for(store, request)
    report["decisions"] = [
        {
            "message_id": m["message_id"],
            "type": m["type"],
            "decision_id": m["decision"]["decision_id"],
            "decision": m["decision"]["decision"],
            "decided_at": m["decision"]["decided_at"],
        }
        for m in decisions
    ]
    for message in foreign:
        report["reasons"].append(
            f"decision {message['message_id']} was authored by "
            f"{message['sender'].get('agent')!r}, not the reserved human "
            "identity; it carries no authority"
        )

    if not decisions:
        report["state"] = "blocked_no_decision"
        if not report["reasons"]:
            report["reasons"].append(
                "no human decision has been recorded for this request; the "
                "action stays blocked indefinitely, and there is no timeout "
                "that would approve it"
            )
        return report
    if foreign:
        # A forged-looking record next to a real one is not a tie to resolve.
        report["state"] = "blocked_stale"
        return report

    # Last decision wins: a human may reject something they earlier approved,
    # and that later word must be the one the gate honours.
    effective = decisions[-1]
    record = effective["decision"]
    report["effective_decision"] = {
        "message_id": effective["message_id"],
        "type": effective["type"],
        "decision_id": record["decision_id"],
        "decision": record["decision"],
        "decided_at": record["decided_at"],
        "decision_binding_sha256": record["decision_binding_sha256"],
    }

    mismatches = []
    if record["request_envelope_sha256"] != request[canonical.DIGEST_FIELD]:
        mismatches.append(
            f"the decision was made against request digest "
            f"{record['request_envelope_sha256'][:12]}…, but the stored request "
            f"is {request[canonical.DIGEST_FIELD][:12]}…"
        )
    if record["action_id"] != action["action_id"]:
        mismatches.append(
            f"the decision names action {record['action_id']!r}, the request "
            f"names {action['action_id']!r}"
        )
    if record["action_scope"] != action["scope"]:
        mismatches.append(
            "the decision's action scope is not the scope the request asked about"
        )
    if record.get("consequential") != action["consequential"]:
        mismatches.append(
            "the decision and the request disagree about whether the action "
            "is consequential"
        )
    if record.get("parameters") != action.get("parameters"):
        mismatches.append(
            "the decision's structured action parameters are not the ones the "
            "request asked about"
        )
    # An approval for repo A must never release the same-looking snapshot in
    # repo B, so the project identity is compared like any other binding.
    if record["binding"].get("project") != action["binding"].get("project"):
        bound = (action["binding"].get("project") or {})
        decided = (record["binding"].get("project") or {})
        mismatches.append(
            f"the decision bound project {decided.get('repo')!r}@"
            f"{str(decided.get('commit'))[:12]}, the request bound "
            f"{bound.get('repo')!r}@{str(bound.get('commit'))[:12]}"
        )
    if record["binding"].get("measurement") != action["binding"].get("measurement"):
        mismatches.append(
            "the decision and the request disagree about how current state is "
            "to be measured"
        )
    if record["binding"].get("action_nonce") != action["binding"].get("action_nonce"):
        mismatches.append(
            "the decision names a different one-shot action nonce than the "
            "request"
        )
    for field in ("snapshot_sha256", "supervisor_context_sha256"):
        bound = action["binding"][field]
        decided = record["binding"].get(field)
        if decided != bound:
            mismatches.append(
                f"the decision bound {field} {str(decided)[:12]}…, the request "
                f"bound {bound[:12]}…"
            )
    recomputed = binding_digest(record)
    if record["decision_binding_sha256"] != recomputed:
        mismatches.append(
            "the decision's own binding digest does not match its contents"
        )

    # What the world looks like now. An unmeasured field is not a warning to
    # note alongside a release - it is a fact the gate does not have, and an
    # approval cannot be shown to still hold without it.
    observed = {
        "snapshot_sha256": snapshot_sha256,
        "supervisor_context_sha256": supervisor_context_sha256,
    }
    unmeasured = []
    for field in REQUIRED_OBSERVATIONS:
        value = observed[field]
        if value is None:
            unmeasured.append(
                f"{field} was not measured at gate time, so the gate cannot "
                "establish that the approved state still exists"
            )
            continue
        if value != action["binding"][field]:
            mismatches.append(
                f"{field} has moved since the decision: approved "
                f"{action['binding'][field][:12]}…, now {value[:12]}…"
            )
    if record["decision"] == "reject":
        report["state"] = "blocked_rejected"
        report["reasons"].append(
            f"the human rejected this action at {record['decided_at']} "
            f"(decision {record['decision_id']})"
        )
        report["reasons"].extend(mismatches)
        report["reasons"].extend(unmeasured)
        return report

    # A measured mismatch is reported ahead of a missing measurement: we
    # looked, and it had moved, which is the more actionable of the two.
    if mismatches:
        report["state"] = "blocked_stale"
        report["reasons"].extend(mismatches)
        report["reasons"].extend(unmeasured)
        return report

    if unmeasured:
        report["state"] = "blocked_unmeasured"
        report["reasons"].extend(unmeasured)
        return report

    report["state"] = "released"
    report["releasable"] = True
    return report


def assert_releasable(
    store,
    request_message_id: str,
    *,
    snapshot_sha256: str | None = None,
    supervisor_context_sha256: str | None = None,
) -> dict:
    """Raise `GateBlocked` unless the action is releasable right now.

    Both current measurements are required. They are named explicitly rather
    than swept up by `**kwargs` so a misspelled one is a `TypeError` at the
    call site instead of silently becoming an unmeasured - and therefore
    blocked, but for the wrong reason - gate check.
    """
    report = evaluate_gate(
        store, request_message_id,
        snapshot_sha256=snapshot_sha256,
        supervisor_context_sha256=supervisor_context_sha256,
    )
    if not report["releasable"]:
        raise GateBlocked(
            f"action {report['action_id']!r} is {report['state']}: "
            + "; ".join(report["reasons"] or ["no reason recorded"]),
            report=report,
        )
    return report


class HumanDecisionAuthority:
    """The separate explicit surface a person uses to approve or reject.

    Never constructed by participant or orchestrator code. Every binding in
    the record it writes is re-derived from the stored request rather than
    taken from the caller, so a mistyped digest cannot become an approval of
    something else — and `expect_*` arguments let the human assert what they
    believe they are approving and be refused if that belief is wrong.
    """

    PARTICIPANT = HUMAN_PARTICIPANT

    def __init__(self, store, *, participant: str = HUMAN_PARTICIPANT) -> None:
        if participant != HUMAN_PARTICIPANT:
            raise ForbiddenOperation(
                f"the human decision surface posts as {HUMAN_PARTICIPANT!r}, "
                f"not {participant!r}"
            )
        self.store = store
        self.participant = participant

    def describe(self, request_message_id: str) -> dict:
        """Exactly what a decision on this request would bind to.

        Read-only. This is what a person should be shown before deciding.
        """
        request = _load_request(self.store, request_message_id)
        action = request.get("action")
        if not action:
            raise DecisionError(
                f"decision_request {request_message_id} carries no bound "
                "action; there is nothing mechanical to approve"
            )
        validate_action(action)
        return {
            "request_message_id": request["message_id"],
            "request_envelope_sha256": request[canonical.DIGEST_FIELD],
            "thread_id": request["thread_id"],
            "requested_by": request["sender"].get("agent"),
            "requested_at": request["timestamp"],
            "project": request.get("project") or {},
            "action_id": action["action_id"],
            "action_scope": action["scope"],
            "consequential": action["consequential"],
            "parameters": action.get("parameters"),
            "binding": action["binding"],
            "body": request.get("body") or {},
        }

    def record(
        self,
        request_message_id: str,
        verdict: str,
        *,
        decision_id: str | None = None,
        note: str | None = None,
        expect_snapshot_sha256: str | None = None,
        expect_supervisor_context_sha256: str | None = None,
        expect_action_id: str | None = None,
        timestamp: str | None = None,
    ) -> dict:
        """Record one human approval or rejection, bound to the request."""
        if verdict not in DECISION_VERDICTS:
            raise DecisionError(
                f"decision must be one of {sorted(DECISION_VERDICTS)}, got "
                f"{verdict!r}"
            )
        described = self.describe(request_message_id)

        # The human's own statement of what they think they are deciding. A
        # disagreement is refused, never reconciled: that is the difference
        # between approving this action and approving whatever is in front of
        # the machine.
        expectations = {
            "action_id": (expect_action_id, described["action_id"]),
            "snapshot_sha256": (
                expect_snapshot_sha256, described["binding"]["snapshot_sha256"]),
            "supervisor_context_sha256": (
                expect_supervisor_context_sha256,
                described["binding"]["supervisor_context_sha256"]),
        }
        for field, (claimed, actual) in expectations.items():
            if claimed is not None and claimed != actual:
                raise DecisionError(
                    f"refusing to record a decision: you named {field} "
                    f"{claimed!r}, but request {request_message_id} is bound to "
                    f"{actual!r}"
                )

        decided_at = timestamp or _now_iso()
        record = {
            "decision_schema_version": DECISION_SCHEMA_VERSION,
            "decision_id": decision_id or f"hd-{uuid7()}",
            "decision": verdict,
            "decided_at": decided_at,
            "request_message_id": described["request_message_id"],
            "request_envelope_sha256": described["request_envelope_sha256"],
            "action_id": described["action_id"],
            "action_scope": described["action_scope"],
            "consequential": described["consequential"],
            "parameters": described["parameters"],
            "binding": described["binding"],
        }
        record["decision_binding_sha256"] = binding_digest(record)

        envelope = {
            "schema_version": 1,
            "message_id": uuid7(),
            "timestamp": decided_at,
            "sender": {"agent": self.participant, "via": "human-decision-surface"},
            "recipient": {"broadcast": True},
            "project": described["project"],
            "thread_id": described["thread_id"],
            "type": DECISION_VERDICTS[verdict],
            "parent_id": described["request_message_id"],
            "body": {
                "text": note or (
                    f"Human {verdict} of action {described['action_id']!r}, "
                    f"bound to snapshot "
                    f"{described['binding']['snapshot_sha256'][:12]}… and "
                    f"supervisor context "
                    f"{described['binding']['supervisor_context_sha256'][:12]}…."
                ),
            },
            "evidence": [],
            "status": "open",
            "reply_requested": False,
            "human_approval_required": False,
            "decision": record,
        }
        result = self.store.append_decision(canonical.seal(envelope))
        result["decision_id"] = record["decision_id"]
        result["decision"] = verdict
        result["decision_binding_sha256"] = record["decision_binding_sha256"]
        return result

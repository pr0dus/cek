"""The release path: derive current state, then consume the action once.

Two demonstrated failures shaped this module (Issue #13).

*The gate trusted the caller's arithmetic.* After Issue #5 a release required
both "current measurements" — but they were strings, and a red-team simply
echoed back the digests already sitting in the decision request to get
`released: true`. Measuring is not the caller's job to assert. So a
consequential binding carries a **recipe**, and everything here derives the
current snapshot and the current supervisor context itself. There is no
parameter through which a digest can be supplied; that is the whole point.

*An approval was reusable forever.* The same approval evaluated as releasable
again and again, which is not what a human means by "yes". A consequential
action now carries a one-shot nonce, and any receipt against that nonce
consumes it. Retrying needs a new decision, not a second use of the old one.

There is deliberately **no executor here.** Nothing in this module performs a
side effect, runs a command, or touches a remote. `authorise` is the exact
final recheck; `reserve` closes the nonce before a human acts; `reconcile`
records what happened afterwards. Building a generic privileged executor is
exactly the thing the audit asked us not to do, so we did not.

The circularity of binding a review to a thread that the decision request
itself extends is resolved explicitly, not with timestamps: the context recipe
names a **cutoff message**, the derived digest covers the thread up to it, and
anything appended afterwards other than the request, its decisions and its
receipts blocks the release as unreviewed.
"""

import datetime as dt
from pathlib import Path

from . import canonical, supervisor
from .decision import _decisions_for, _load_request, evaluate_gate
from .errors import AgentRoomError
from .ids import uuid7
from .schema import (
    RECEIPT_SCHEMA_VERSION,
    RECEIPT_STATUS,
    RECEIPT_UNRESOLVED,
    validate_action,
)
from .snapshot import snapshot_manifest

#: Message types that may legitimately follow the review cutoff without making
#: the release unreviewed: the request itself, the human's answer to it, and
#: the receipts that record what came of it.
POST_CUTOFF_ALLOWED = frozenset({
    "decision_request", "approval", "rejection", "execution_receipt",
})

__all__ = [
    "POST_CUTOFF_ALLOWED", "ReleaseError", "ReleaseBlocked",
    "derive_snapshot", "derive_context", "receipt_state",
    "authorise", "reserve", "reconcile",
]


class ReleaseError(AgentRoomError):
    """The release path could not evaluate the action."""


class ReleaseBlocked(ReleaseError):
    """The consequential action is not releasable. Carries the full report."""

    def __init__(self, message, *, report: dict):
        super().__init__(message)
        self.report = report


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _consequential_action(request: dict) -> dict:
    action = request.get("action")
    if not action:
        raise ReleaseError(
            f"decision_request {request['message_id']} binds no action; there "
            "is nothing to release"
        )
    validate_action(action)
    if action["consequential"] is not True:
        raise ReleaseError(
            f"action {action['action_id']!r} is not marked consequential; the "
            "release path is only for actions a human must gate"
        )
    return action


# -- derivation -------------------------------------------------------------

def derive_snapshot(recipe: dict, *, workdir) -> tuple:
    """Measure the current snapshot from the recipe. Nothing is supplied."""
    manifest = snapshot_manifest(workdir, recipe["base_commit"])
    if manifest["snapshot_schema_version"] != recipe["snapshot_schema_version"]:
        raise ReleaseError(
            f"the binding was measured with snapshot schema "
            f"{recipe['snapshot_schema_version']}, this build produces "
            f"{manifest['snapshot_schema_version']}; the two are not "
            "comparable and the decision must be retaken"
        )
    return manifest["manifest_sha256"], manifest


def derive_context(store, recipe: dict, *, request_message_id: str) -> tuple:
    """Recompute the reviewed context, and report anything appended after it.

    Returns `(digest, unreviewed)`. `unreviewed` lists messages that appeared
    after the review cutoff and are not part of deciding this request — each
    one is something the supervisor's review did not cover.
    """
    thread = store.thread_messages(recipe["thread_id"])
    by_id = {m["message_id"]: m for m in thread}
    target = by_id.get(recipe["target_message_id"])
    if target is None:
        raise ReleaseError(
            f"the reviewed target {recipe['target_message_id']} is not in "
            f"thread {recipe['thread_id']!r}"
        )
    index = next((i for i, m in enumerate(thread)
                  if m["message_id"] == recipe["cutoff_message_id"]), None)
    if index is None:
        raise ReleaseError(
            f"the review cutoff {recipe['cutoff_message_id']} is not in "
            f"thread {recipe['thread_id']!r}"
        )
    reviewed = thread[: index + 1]
    if target not in reviewed:
        raise ReleaseError(
            "the reviewed target message falls after the review cutoff, which "
            "cannot describe a review of it"
        )
    unreviewed = [
        {"message_id": m["message_id"], "type": m["type"],
         "sender": m["sender"].get("agent")}
        for m in thread[index + 1:]
        if not (m["type"] in POST_CUTOFF_ALLOWED
                and (m["message_id"] == request_message_id
                     or m.get("parent_id") == request_message_id))
    ]
    return supervisor.context_digest(target, reviewed), unreviewed


def _assert_project(action: dict, manifest: dict, workdir) -> dict:
    """The checkout must be the commit the decision named.

    An approval for repo A must never release the same-looking snapshot in
    repo B. The manifest's head is measured, not supplied, so this compares
    the approved commit against what is actually checked out here.
    """
    binding = action["binding"]["project"]
    observed = {"repo": binding["repo"], "commit": manifest["head_commit"],
                "workdir": str(Path(workdir).resolve())}
    if manifest["head_commit"] != binding["commit"]:
        raise ReleaseBlocked(
            f"the approved commit {binding['commit'][:12]} is not the head of "
            f"{Path(workdir).resolve()} (head is "
            f"{str(manifest['head_commit'])[:12]}); an approval for one state "
            "must not release another",
            report={"state": "blocked_wrong_target", "releasable": False,
                    "bound": binding, "observed": observed,
                    "action_id": action["action_id"],
                    "reasons": ["the checkout is not the approved commit"]},
        )
    return observed


# -- receipts ---------------------------------------------------------------

def receipt_state(store, request: dict) -> dict:
    """Every receipt for this request, and what they mean for the nonce."""
    nonce = request["action"]["binding"]["action_nonce"]
    receipts = [
        m["receipt"] for m in store.thread_messages(request["thread_id"])
        if m["type"] == "execution_receipt"
        and m.get("parent_id") == request["message_id"]
        and m["receipt"]["action_nonce"] == nonce
    ]
    latest = receipts[-1] if receipts else None
    return {
        "action_nonce": nonce,
        "receipts": [
            {k: r[k] for k in ("receipt_id", "status", "recorded_at")}
            for r in receipts
        ],
        "consumed": bool(receipts),
        "unresolved": bool(latest and latest["status"] in RECEIPT_UNRESOLVED),
        "latest": latest,
    }


def _write_receipt(store, request: dict, *, status: str, result: dict,
                   decision_id: str, receipt_id: str | None = None) -> dict:
    if status not in RECEIPT_STATUS:
        raise ReleaseError(
            f"receipt status must be one of {sorted(RECEIPT_STATUS)}, got "
            f"{status!r}"
        )
    action = request["action"]
    recorded_at = _now_iso()
    receipt = {
        "receipt_schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": receipt_id or f"rx-{uuid7()}",
        "action_nonce": action["binding"]["action_nonce"],
        "action_id": action["action_id"],
        "request_message_id": request["message_id"],
        "decision_id": decision_id,
        "status": status,
        "recorded_at": recorded_at,
        "result": result,
    }
    envelope = {
        "schema_version": 1,
        "message_id": uuid7(),
        "timestamp": recorded_at,
        "sender": {"agent": "release-recorder", "via": "agent-room-release"},
        "recipient": {"broadcast": True},
        "project": request.get("project") or {},
        "thread_id": request["thread_id"],
        "type": "execution_receipt",
        "parent_id": request["message_id"],
        "body": {"text": (
            f"Execution receipt {status!r} for action "
            f"{action['action_id']!r} (nonce "
            f"{action['binding']['action_nonce']}). This records what happened; "
            "it performs nothing."
        )},
        "evidence": [],
        "status": "open",
        "reply_requested": False,
        "human_approval_required": False,
        "receipt": receipt,
    }
    written = store.append_receipt(canonical.seal(envelope))
    written["receipt_id"] = receipt["receipt_id"]
    written["receipt_status"] = status
    return written


# -- the release path -------------------------------------------------------

def authorise(store, request_message_id: str, *, workdir) -> dict:
    """The exact final recheck. Derives everything; performs nothing.

    Raises `ReleaseBlocked` unless a human approved *this* action, the current
    state still matches what they approved, nothing unreviewed has been
    appended since the review cutoff, and the one-shot nonce is unconsumed.
    """
    request = _load_request(store, request_message_id)
    action = _consequential_action(request)
    binding = action["binding"]

    snapshot_sha256, manifest = derive_snapshot(
        binding["measurement"]["snapshot"], workdir=workdir)
    observed_project = _assert_project(action, manifest, workdir)
    context_sha256, unreviewed = derive_context(
        store, binding["measurement"]["context"],
        request_message_id=request["message_id"])

    report = evaluate_gate(
        store, request_message_id,
        snapshot_sha256=snapshot_sha256,
        supervisor_context_sha256=context_sha256,
    )
    report["derived"] = {
        "snapshot_sha256": snapshot_sha256,
        "supervisor_context_sha256": context_sha256,
        "project": observed_project,
        "measured_by": "release.authorise",
    }
    report["unreviewed_since_cutoff"] = unreviewed
    receipts = receipt_state(store, request)
    report["receipts"] = receipts

    if unreviewed:
        report["state"] = "blocked_unreviewed"
        report["releasable"] = False
        report["reasons"].append(
            f"{len(unreviewed)} message(s) were appended after the review "
            "cutoff and are not part of deciding this request; the approval "
            "does not cover them"
        )
    elif receipts["unresolved"]:
        report["state"] = "blocked_unresolved_execution"
        report["releasable"] = False
        report["reasons"].append(
            f"receipt {receipts['latest']['receipt_id']} left this action's "
            "outcome uncertain; it must be reconciled by a human before "
            "anything is attempted again, or it could be done twice"
        )
    elif receipts["consumed"]:
        report["state"] = "blocked_consumed"
        report["releasable"] = False
        report["reasons"].append(
            f"action nonce {receipts['action_nonce']} has already been used "
            f"({len(receipts['receipts'])} receipt(s)); a consequential action "
            "is one-shot and a retry needs a new human decision"
        )

    if not report["releasable"]:
        raise ReleaseBlocked(
            f"action {report['action_id']!r} is {report['state']}: "
            + "; ".join(report["reasons"] or ["no reason recorded"]),
            report=report,
        )

    decision = report["effective_decision"]
    return {
        "authorised": True,
        "authorised_at": _now_iso(),
        "request_message_id": request["message_id"],
        "action_id": action["action_id"],
        "action_nonce": binding["action_nonce"],
        # Structured, not prose. This is what an operator acts on, and what a
        # later check compares.
        "parameters": action["parameters"],
        "project": binding["project"],
        "derived": report["derived"],
        "decision_id": decision["decision_id"],
        "snapshot_entries": len(manifest["entries"]),
        "executor": None,
        "note": (
            "Nothing has been executed. This authorisation performs no side "
            "effect; the action is carried out manually and then recorded with "
            "release.reconcile()."
        ),
    }


def reserve(store, request_message_id: str, *, workdir,
            result: dict | None = None) -> dict:
    """Authorise, then immediately consume the nonce as `uncertain`.

    Written *before* the side effect, on purpose. If the operator's action
    half-happens, or nobody ever says what came of it, the action stays
    blocked and needs a human to reconcile it — which is the safe direction.
    Consuming the nonce afterwards instead would leave a window in which a
    second authorisation could be obtained for the same approval.
    """
    authorisation = authorise(store, request_message_id, workdir=workdir)
    request = _load_request(store, request_message_id)
    written = _write_receipt(
        store, request, status="uncertain",
        decision_id=authorisation["decision_id"],
        result=result or {"stage": "reserved",
                          "note": "no side effect has been attempted yet"},
    )
    return {"authorisation": authorisation, "receipt": written}


def reconcile(store, request_message_id: str, *, status: str, result: dict,
              receipt_id: str | None = None) -> dict:
    """Record what actually happened. Resolves a reserved action.

    Deliberately does not re-derive current state: by the time this is called
    the world has moved *because* the action was performed, and re-measuring
    would refuse every honest report of a completed action.
    """
    request = _load_request(store, request_message_id)
    _consequential_action(request)
    receipts = receipt_state(store, request)
    if not receipts["consumed"]:
        raise ReleaseError(
            "nothing to reconcile: this action has no receipt, so it was "
            "never reserved. Call reserve() before performing it."
        )
    if status in RECEIPT_UNRESOLVED:
        raise ReleaseError(
            f"reconciling with {status!r} would leave the action unresolved; "
            f"record one of {sorted(RECEIPT_STATUS - RECEIPT_UNRESOLVED)}"
        )
    decisions, _foreign = _decisions_for(store, request)
    decision_id = (decisions[-1]["decision"]["decision_id"] if decisions
                   else receipts["latest"]["decision_id"])
    return _write_receipt(store, request, status=status, result=result,
                          decision_id=decision_id, receipt_id=receipt_id)

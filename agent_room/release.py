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

import re

from . import auth, canonical, supervisor
from .decision import _decisions_for, _load_request, evaluate_gate
from .errors import AgentRoomError
from .ids import uuid7
from .schema import (
    RECEIPT_SCHEMA_VERSION,
    RECEIPT_STATUS,
    RECEIPT_UNRESOLVED,
    validate_action,
)
from . import trust
from .snapshot import _git as _snapshot_git, snapshot_manifest

#: Message types that may legitimately follow the review cutoff without making
#: the release unreviewed: the request itself, the human's answer to it, and
#: the receipts that record what came of it.
POST_CUTOFF_ALLOWED = frozenset({
    "decision_request", "approval", "rejection", "execution_receipt",
})

#: The remote whose URL names the repository, when one exists.
CANONICAL_REMOTE = "origin"

#: `git@host:owner/name` — the scp-like spelling, which is not a URL and has
#: to be recognised separately from `ssh://`.
SCP_REMOTE_RE = re.compile(r"\A(?:(?P<user>[^@/]+)@)?(?P<host>[^:/]+):(?P<path>.+)\Z")

#: The receipt lifecycle, as transitions rather than prose.
#: `unused -> uncertain -> executed|failed`, and nothing after a terminal.
RECEIPT_TERMINAL = frozenset({"executed", "failed"})

__all__ = [
    "POST_CUTOFF_ALLOWED", "CANONICAL_REMOTE", "RECEIPT_TERMINAL",
    "ReleaseError", "ReleaseBlocked", "RepositoryIdentityError",
    "canonical_repo_identity", "identity_matches",
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


class RepositoryIdentityError(ReleaseError):
    """The target checkout's repository identity is missing or ambiguous."""


def _normalise_remote_url(url: str) -> str:
    """One canonical spelling for the many ways a remote can be written.

    `https://github.com/pr0dus/cek.git`, `git@github.com:pr0dus/cek` and
    `ssh://git@github.com/pr0dus/cek/` all name the same repository, and a
    comparison that treated them as different would fail closed on ordinary
    checkouts until somebody "fixed" it by loosening the check.

    A local path has no host, so it is spelled `path:<realpath>` — distinct by
    construction from any hosted identity, which is what keeps a local clone
    of a GitHub repository from claiming to be it.
    """
    raw = url.strip()
    if not raw:
        raise RepositoryIdentityError("empty remote URL")
    for scheme in ("https://", "http://", "ssh://", "git://"):
        if raw.lower().startswith(scheme):
            rest = raw[len(scheme):]
            authority, _, path = rest.partition("/")
            host = authority.rpartition("@")[2].lower()
            return f"{host}/{path.strip('/').removesuffix('.git')}"
    if raw.lower().startswith("file://"):
        return f"path:{Path(raw[len('file://'):]).resolve()}"
    match = SCP_REMOTE_RE.match(raw)
    if match and not raw.startswith("/") and not raw.startswith("."):
        host = match.group("host").lower()
        return f"{host}/{match.group('path').strip('/').removesuffix('.git')}"
    return f"path:{Path(raw).resolve()}"


def canonical_repo_identity(workdir, *, remote: str = CANONICAL_REMOTE) -> dict:
    """Derive the target checkout's repository identity from the checkout.

    **Threat boundary, stated because it is narrow.** This reads the
    checkout's own remote configuration. Anyone who can write `.git/config`
    there can make it claim any identity, so this is not an authenticated
    binding — S2's signatures are. What it does establish is that a release is
    being run against the repository the approval named, rather than against a
    different checkout that merely happens to contain the same commit. That
    was a real hole: a commit can exist in any number of repositories.

    Fails closed on a missing identity, and on an ambiguous one — several
    remotes with no `origin` to arbitrate between them.
    """
    raw = _snapshot_git(Path(workdir), "config", "-z", "--get-regexp",
                        r"^remote\..*\.url", check=False)
    remotes: dict = {}
    for entry in raw.decode("utf-8", "surrogateescape").split("\0"):
        if not entry:
            continue
        key, _, value = entry.partition("\n")
        name = key[len("remote."):-len(".url")]
        if value.strip():
            remotes[name] = value.strip()

    if not remotes:
        raise RepositoryIdentityError(
            f"{Path(workdir).resolve()} has no configured remote, so its "
            "repository identity cannot be derived. A consequential release "
            "must know which repository it is acting on."
        )
    if remote in remotes:
        chosen, url = remote, remotes[remote]
    elif len(remotes) == 1:
        chosen, url = next(iter(remotes.items()))
    else:
        raise RepositoryIdentityError(
            f"{Path(workdir).resolve()} has {sorted(remotes)} but no "
            f"{remote!r}; the repository identity is ambiguous and a release "
            "must not guess which one the approval meant"
        )
    return {"remote": chosen, "url": url,
            "identity": _normalise_remote_url(url), "source": "git-remote-url"}


def identity_matches(bound: str, identity: str) -> bool:
    """Does a bound `owner/name` (or full `host/owner/name`) name this checkout?

    A bound value with no separator is refused rather than matched loosely: a
    bare name would match any host's repository of that name.
    """
    if not isinstance(bound, str) or "/" not in bound.strip("/"):
        raise RepositoryIdentityError(
            f"bound project.repo {bound!r} is not a repository identity; it "
            "needs at least 'owner/name', or a bare name would match any "
            "host's repository with that name"
        )
    wanted, actual = bound.strip("/").lower(), identity.lower()
    return actual == wanted or actual.endswith(f"/{wanted}")


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
    """The checkout must be the repository *and* the commit the decision named.

    Both halves matter, and only checking the commit was the hole: a commit
    can exist in any number of repositories, so an approval for `pr0dus/cek`
    would release against any clone or fork that had fetched it. The observed
    repository is derived from the checkout, never copied out of the binding.
    """
    binding = action["binding"]["project"]
    derived = canonical_repo_identity(workdir)
    observed = {"repo": derived["identity"], "remote": derived["remote"],
                "commit": manifest["head_commit"],
                "workdir": str(Path(workdir).resolve()),
                "source": derived["source"]}
    if not identity_matches(binding["repo"], derived["identity"]):
        raise ReleaseBlocked(
            f"the approval names repository {binding['repo']!r}, but "
            f"{Path(workdir).resolve()} is {derived['identity']!r} (from "
            f"remote {derived['remote']!r}). A commit can exist in more than "
            "one repository; an approval for one must not release another.",
            report={"state": "blocked_wrong_repository", "releasable": False,
                    "bound": binding, "observed": observed,
                    "action_id": action["action_id"],
                    "reasons": ["the checkout is not the approved repository"]},
        )
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


def assert_transition(state: dict, status: str) -> None:
    """The one-shot lifecycle, checked against the receipts that exist now.

    `unused -> uncertain -> executed|failed`. Callers hold the store's writer
    lock across this check and the append that follows it, because a check
    that is not atomic with its write is exactly how two callers both decide
    the nonce is free.
    """
    statuses = [r["status"] for r in state["receipts"]]
    nonce = state["action_nonce"]
    if status == "uncertain":
        if statuses:
            raise ReleaseBlocked(
                f"action nonce {nonce} is already reserved ({statuses}); a "
                "one-shot action cannot be reserved twice, and a second "
                "reservation would mean releasing it twice",
                report={"state": "blocked_consumed", "releasable": False,
                        "action_nonce": nonce, "receipts": statuses,
                        "reasons": ["the nonce is already consumed"]},
            )
        return
    if not statuses:
        raise ReleaseError(
            f"nothing to reconcile for nonce {nonce}: the action was never "
            "reserved. Reserve it before performing it, or the side effect "
            "happens while the nonce is still reusable."
        )
    if statuses[0] != "uncertain":
        raise ReleaseError(
            f"the receipt history for nonce {nonce} starts at {statuses[0]!r}, "
            "not a reservation; refusing to extend an impossible sequence"
        )
    settled = [s for s in statuses if s in RECEIPT_TERMINAL]
    if settled:
        raise ReleaseBlocked(
            f"action nonce {nonce} already settled as {settled[0]!r}; there is "
            "no transition out of a terminal state, and a retry needs a new "
            "human decision",
            report={"state": "blocked_consumed", "releasable": False,
                    "action_nonce": nonce, "receipts": statuses,
                    "reasons": [f"the action already settled as {settled[0]!r}"]},
        )


def _receipt_envelope(store, request: dict, *, status: str, result: dict,
                   decision_id: str, receipt_id: str | None = None,
                   signer=None) -> dict:
    """Build/sign a receipt, without writing it. Caller holds the writer lock."""
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
    if store.trust is not None:
        if signer is None:
            raise ReleaseError(
                "this store is authenticated: an execution receipt must be "
                "signed by the pinned release-recorder credential. A receipt "
                "consumes a human approval, so an unsigned one would let any "
                "writer spend somebody else's decision."
            )
        envelope = auth.sign_envelope(envelope, signer,
                                      room_id=store.room_id())
    return canonical.seal(envelope)


def _write_receipt(store, request: dict, **kwargs) -> dict:
    """Local reservation or terminal reconciliation; no remote reservation rebase."""
    envelope = _receipt_envelope(store, request, **kwargs)
    written = store.append_receipt(envelope)
    written["receipt_id"] = envelope["receipt"]["receipt_id"]
    written["receipt_status"] = envelope["receipt"]["status"]
    return written


# -- the release path -------------------------------------------------------

def assert_human_authenticated(store, decision_message_id: str) -> dict:
    """Independently re-authenticate the decision that is about to release.

    The read path already refuses an unsigned or wrongly signed artifact, so
    reaching here means it verified once. This asks again, on the release
    path, and asks a question the read path does not: is this signature by the
    key pinned for the **human role**? A perfectly valid `claude-code`
    signature is a perfectly valid signature and carries no human authority.

    Deliberately not "upstream must have checked": the whole point of a
    release gate is that it establishes its own preconditions.
    """
    store.assert_authenticated("releasing a consequential action")
    history = store._history()
    path = store._id_index().get(decision_message_id)
    if path is None:
        raise ReleaseError(
            f"decision {decision_message_id} is not in the room")
    envelope = store._load(path, history[path])
    provenance = store.authenticate(envelope, history[path])
    if provenance is None or provenance["role"] != trust.HUMAN_ROLE:
        raise ReleaseBlocked(
            f"decision {decision_message_id} is signed by "
            f"{(provenance or {}).get('signer')!r}, which is not the pinned "
            "human credential; only the human releases a consequential action",
            report={"state": "blocked_unauthenticated", "releasable": False,
                    "reasons": ["the decision is not signed by the human"]},
        )
    return provenance


def authorise(store, request_message_id: str, *, workdir) -> dict:
    """The exact final recheck. Derives everything; performs nothing.

    Raises `ReleaseBlocked` unless a human approved *this* action, the current
    state still matches what they approved, nothing unreviewed has been
    appended since the review cutoff, and the one-shot nonce is unconsumed.
    """
    store.assert_authenticated("releasing a consequential action")
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
    provenance = assert_human_authenticated(store, decision["message_id"])
    return {
        "authorised": True,
        "human_provenance": provenance,
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
        # The operator-facing contract, in the result rather than in prose
        # somewhere else. An earlier wording told the operator to perform the
        # action and then record it, which would have left the nonce reusable
        # for the whole time the side effect was happening.
        "action_permitted": False,
        "next_step": "release.reserve",
        "note": (
            "NOT PERMISSION TO ACT. Nothing has been executed and nothing may "
            "be performed from this result alone: the one-shot nonce is still "
            "unconsumed, so the same approval could be authorised again in "
            "parallel. The operator sequence is reserve() first - which "
            "rechecks all of this and consumes the nonce atomically - then "
            "perform the action by hand, then reconcile()."
        ),
    }


def reserve(store, request_message_id: str, *, workdir, signer=None,
            result: dict | None = None, checkpoint_path=None, state_path=None) -> dict:
    """The operator-facing command: recheck and consume the nonce, atomically.

    This is the *only* thing that precedes a manual action. It runs the final
    recheck and consumes the one-shot nonce as `uncertain` in a single
    critical section, so two operators cannot both find the nonce free.

    Written *before* the side effect, on purpose. If the action half-happens,
    or nobody ever says what came of it, it stays blocked and needs a human to
    reconcile — the safe direction. Consuming the nonce afterwards would leave
    the whole duration of the side effect as a window for a second release.
    """
    if store.remote is not None:
        from .release_delivery import RemoteReservation
        return RemoteReservation(store, checkpoint_path=checkpoint_path,
                                 state_path=state_path).reserve(
            request_message_id, workdir=workdir, signer=signer, result=result)
    # Explicitly local-only semantics, not production-qualified release.
    # One critical section over check-and-consume. The append inside takes the
    # same lock, which is why it is re-entrant within a store instance.
    with store.writer_lock():
        authorisation = authorise(store, request_message_id, workdir=workdir)
        request = _load_request(store, request_message_id)
        assert_transition(receipt_state(store, request), "uncertain")
        written = _write_receipt(
            store, request, status="uncertain", signer=signer,
            decision_id=authorisation["decision_id"],
            result=result or {"stage": "reserved",
                              "note": "no side effect has been attempted yet"},
        )
    authorisation = dict(authorisation)
    authorisation["action_permitted"] = True
    authorisation["next_step"] = "perform the action manually, then reconcile()"
    authorisation["note"] = (
        "The nonce is now consumed as 'uncertain'. Perform the action by hand "
        "and then record what happened with reconcile(). Nothing here "
        "performed it."
    )
    return {"authorisation": authorisation, "receipt": written}


def reconcile(store, request_message_id: str, *, status: str, result: dict,
              receipt_id: str | None = None, signer=None, checkpoint_path=None,
              state_path=None, workdir=None) -> dict:
    """Record what actually happened. Resolves a reserved action.

    Deliberately does not re-derive current state: by the time this is called
    the world has moved *because* the action was performed, and re-measuring
    would refuse every honest report of a completed action.
    """
    if store.remote is not None:
        from .release_delivery import RemoteReservation
        if workdir is None:
            raise ReleaseError('remote reconciliation requires the fixed target workdir')
        return RemoteReservation(store, checkpoint_path=checkpoint_path,
                                 state_path=state_path).reconcile(
            request_message_id, workdir=workdir, status=status, result=result,
            receipt_id=receipt_id, signer=signer)
    return _reconcile_local(store, request_message_id, status=status, result=result,
                            receipt_id=receipt_id, signer=signer)


def _reconcile_local(store, request_message_id, *, status, result, receipt_id=None, signer=None):
    if status in RECEIPT_UNRESOLVED:
        raise ReleaseError(
            f"reconciling with {status!r} would leave the action unresolved; "
            f"record one of {sorted(RECEIPT_STATUS - RECEIPT_UNRESOLVED)}"
        )
    # Same critical section discipline as reserve(): the terminal transition is
    # checked and written without a gap, so two concurrent reconciliations
    # cannot both settle one action.
    with store.writer_lock():
        request = _load_request(store, request_message_id)
        _consequential_action(request)
        receipts = receipt_state(store, request)
        assert_transition(receipts, status)
        decisions, _foreign = _decisions_for(store, request)
        decision_id = (decisions[-1]["decision"]["decision_id"] if decisions
                       else receipts["latest"]["decision_id"])
        return _write_receipt(store, request, status=status, result=result,
                              decision_id=decision_id, receipt_id=receipt_id,
                              signer=signer)

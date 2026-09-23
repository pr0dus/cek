"""Envelope contract and epistemic rules.

Two rule sets live here and are deliberately kept apart:

*Envelope validation* is structural — does the message carry the fields the
Issue #1 contract requires, with the right shapes.

*Claim validation* is epistemic, and reuses `PROCESS.md`'s ledger vocabulary
verbatim. There is no generic `validated` state. `supported` is evidence-
scoped, never universal truth, so it demands a stated scope, a revision
condition, and an admissible evidence basis. Citing evidence never promotes a
claim by itself — only a later message asserting the change can.
"""

from typing import Any, Mapping

import re

from .errors import (
    ClaimStateError,
    ForbiddenOperation,
    SchemaError,
    UnresolvedReference,
)
from .ids import is_uuid7

SCHEMA_VERSION = 1

MESSAGE_TYPES = frozenset({
    "observation", "hypothesis", "claim", "evidence", "test_result",
    "question", "challenge", "proposed_test",
    "answer", "retraction",
    "decision_request", "approval", "rejection", "handoff",
})

#: Withheld from agent-facing post/reply for Issues #2-#4 (design §6).
#: Mechanical human authority is Issue #5's problem, so rather than pretend to
#: verify a human we simply do not expose these types to an agent.
AGENT_FORBIDDEN_TYPES = frozenset({"approval", "rejection"})

#: Conversation flow only. Carries no epistemic weight.
LIFECYCLE_STATUS = frozenset({"open", "answered", "superseded", "withdrawn"})

#: PROCESS.md ledger vocabulary, used verbatim.
CLAIM_STATUS = frozenset({"proposed", "challenged", "supported", "retracted"})

EVIDENCE_KINDS = frozenset({"repo", "run", "external", "agent_output"})

#: LLM_OUTPUT != EVIDENCE. An agent's own output may be referenced, but it
#: cannot be what supports a claim, nor can it close a challenge.
INADMISSIBLE_FOR_SUPPORT = frozenset({"agent_output"})
ADMISSIBLE_FOR_SUPPORT = EVIDENCE_KINDS - INADMISSIBLE_FOR_SUPPORT

#: A pinned commit must be a full Git object ID: 40 hex for SHA-1, 64 for
#: SHA-256. An abbreviation is not an immutable identity - it can become
#: ambiguous as a repository grows, and it reads as a commit while not being
#: one.
FULL_COMMIT_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

#: The all-zero object id is syntactically a full oid but names nothing. Git
#: itself uses it as the null sentinel, so accepting it would let "pinned"
#: evidence point at no object at all.
NULL_OBJECT_IDS = frozenset({"0" * 40, "0" * 64})

#: A thread_id becomes a Git path segment and is parsed back out of
#: `git log --name-status` output line by line. Anything Git would quote or
#: escape - whitespace, control characters, separators, non-ASCII - could break
#: that parse or make a committed message undiscoverable, so the vocabulary is
#: deliberately narrow: ASCII letters/digits then letters/digits/./_/-, first
#: character alphanumeric (excluding leading dots), bounded at 64 characters.
THREAD_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
THREAD_ID_MAX = 64

REQUIRED_FIELDS = (
    "schema_version", "message_id", "timestamp", "sender", "recipient",
    "project", "thread_id", "type", "body", "status",
    "reply_requested", "human_approval_required",
)

#: Types that assert something and may therefore carry a `claim` object.
ASSERTION_TYPES = frozenset({
    "observation", "hypothesis", "claim", "evidence", "test_result",
})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SchemaError(message)


#: Sender metadata beyond the identity is free-form but must stay scalar, so
#: routing/audit fields cannot smuggle nested structures past filtering.
SCALAR_TYPES = (str, int, float, bool)


def _validate_sender(sender: dict) -> None:
    agent = sender.get("agent")
    _require(
        isinstance(agent, str) and agent.strip() != "",
        f"sender.agent must be a non-empty string, got "
        f"{type(agent).__name__} {agent!r}",
    )
    for key, value in sender.items():
        if key == "agent":
            continue
        _require(
            isinstance(value, SCALAR_TYPES),
            f"sender.{key} must be a scalar (str/int/float/bool), got "
            f"{type(value).__name__} {value!r}",
        )


def _validate_recipient(recipient: dict) -> None:
    """A message must actually be addressed to someone.

    `broadcast` must be a real boolean: a truthy string like "false" would
    otherwise silently make a directed message visible room-wide.
    """
    if "broadcast" in recipient:
        _require(
            isinstance(recipient["broadcast"], bool),
            f"recipient.broadcast must be a boolean, got "
            f"{type(recipient['broadcast']).__name__} {recipient['broadcast']!r}",
        )
    if "agent" in recipient:
        agent = recipient["agent"]
        _require(
            isinstance(agent, str) and agent.strip() != "",
            f"recipient.agent must be a non-empty string, got "
            f"{type(agent).__name__} {agent!r}",
        )
    _require(
        recipient.get("broadcast") is True or bool(recipient.get("agent")),
        "recipient must name an agent or set broadcast: true",
    )


def _validate_project(project: dict) -> None:
    repo = project.get("repo")
    if repo is not None:
        _require(
            isinstance(repo, str) and repo.strip() != "",
            f"project.repo must be a non-empty string, got "
            f"{type(repo).__name__} {repo!r}",
        )
    commit = project.get("commit")
    if commit is not None:
        _require(
            isinstance(commit, str) and bool(FULL_COMMIT_RE.match(commit))
            and commit not in NULL_OBJECT_IDS,
            f"project.commit {commit!r} must be a full non-null Git object ID",
        )


def _require_relative_path(value, label: str) -> None:
    _require(
        isinstance(value, str) and value.strip() != "",
        f"{label} must be a non-empty string, got {type(value).__name__} {value!r}",
    )
    _require(
        not value.startswith("/") and ".." not in value.split("/"),
        f"{label} {value!r} must be a repository-relative path without '..'",
    )


def _validate_pinned_commit(ref: dict, i: int, verifier=None) -> None:
    commit = ref.get("commit")
    _require(
        bool(commit),
        f"evidence[{i}] of kind {ref.get('kind')!r} must pin an immutable commit",
    )
    _require(
        isinstance(commit, str) and bool(FULL_COMMIT_RE.match(commit)),
        f"evidence[{i}].commit {commit!r} is not a full Git object ID "
        "(40 hex for SHA-1, 64 for SHA-256); an abbreviation is not an "
        "immutable identity",
    )
    _require(
        commit not in NULL_OBJECT_IDS,
        f"evidence[{i}].commit is the all-zero object id, which names nothing",
    )
    # Existence is only checkable for objects this machine actually has. When
    # the referenced repository is not available locally the full locator is
    # preserved and existence is deliberately NOT fabricated - see
    # docs/AGENT_ROOM_STORE.md.
    if verifier is not None and hasattr(verifier, "commit_object_state"):
        state = verifier.commit_object_state(commit)
        if state == "not-a-commit":
            raise SchemaError(
                f"evidence[{i}].commit {commit} exists locally but is not a commit"
            )


def _validate_repo_locator(ref: dict, i: int) -> None:
    _require(
        isinstance(ref.get("repo"), str) and ref["repo"].strip() != "",
        f"evidence[{i}] of kind 'repo' must name a non-empty repo",
    )
    _require_relative_path(ref.get("path"), f"evidence[{i}].path")
    if "lines" in ref:
        lines = ref["lines"]
        _require(
            isinstance(lines, list) and len(lines) == 2
            and all(isinstance(n, int) and not isinstance(n, bool) for n in lines),
            f"evidence[{i}].lines must be a two-integer range, got {lines!r}",
        )
        start, end = lines
        _require(
            start >= 1 and end >= start,
            f"evidence[{i}].lines {lines!r} must be a positive ascending range",
        )


def _validate_run_locator(ref: dict, i: int) -> None:
    """A run must be findable again: a stable run_id, or an artifact path."""
    run_id, path = ref.get("run_id"), ref.get("path")
    _require(
        run_id is not None or path is not None,
        f"evidence[{i}] of kind 'run' must carry a stable locator: "
        "'run_id' or a repository-relative artifact 'path'",
    )
    if run_id is not None:
        _require(
            isinstance(run_id, str) and run_id.strip() != "",
            f"evidence[{i}].run_id must be a non-empty string, got "
            f"{type(run_id).__name__} {run_id!r}",
        )
    if path is not None:
        _require_relative_path(path, f"evidence[{i}].path")


def _validate_external_locator(ref: dict, i: int) -> None:
    """External evidence must at least say where it is."""
    url = ref.get("url")
    _require(
        isinstance(url, str) and url.strip() != "",
        f"evidence[{i}] of kind 'external' must carry a non-empty 'url' "
        f"locator, got {type(url).__name__} {url!r}",
    )


def validate_evidence(evidence: Any, verifier=None) -> None:
    _require(isinstance(evidence, list), "evidence must be a list")
    seen_ids: set = set()
    for i, ref in enumerate(evidence):
        _require(isinstance(ref, dict), f"evidence[{i}] must be an object")
        ref_id = ref.get("id")
        if ref_id is not None:
            # Shape first: these ids are used as dict/set keys during basis
            # resolution, so an array or object would escape as a raw
            # TypeError instead of a controlled schema error.
            _require(
                isinstance(ref_id, str) and ref_id.strip() != "",
                f"evidence[{i}].id must be a non-empty string, got "
                f"{type(ref_id).__name__} {ref_id!r}",
            )
            # Duplicate ids would collapse when basis entries are resolved,
            # making admissibility depend on list order - an inadmissible
            # entry could hide behind an admissible one with the same id.
            _require(
                ref_id not in seen_ids,
                f"evidence[{i}].id {ref_id!r} is duplicated; evidence ids must "
                "be unique within a message",
            )
            seen_ids.add(ref_id)
        kind = ref.get("kind")
        _require(
            kind in EVIDENCE_KINDS,
            f"evidence[{i}].kind {kind!r} not in {sorted(EVIDENCE_KINDS)}",
        )
        if kind in ("repo", "run"):
            _validate_pinned_commit(ref, i, verifier)
        if kind == "repo":
            _validate_repo_locator(ref, i)
        elif kind == "run":
            _validate_run_locator(ref, i)
        elif kind == "external":
            _validate_external_locator(ref, i)


def message_is_admissible_support(message: dict) -> bool:
    """Documented cross-message admissibility rule.

    A referenced message supports a claim only if it carries at least one
    evidence entry of an admissible kind (`repo`, `run`, `external`). A message
    whose evidence is exclusively `agent_output`, or which carries none at all,
    is never support: that is `LLM_OUTPUT != EVIDENCE` made mechanical, and it
    is what stops two agents citing each other into `supported`.
    """
    for ref in message.get("evidence") or []:
        if isinstance(ref, dict) and ref.get("kind") in ADMISSIBLE_FOR_SUPPORT:
            return True
    return False


def validate_claim(claim, evidence=None, resolver=None, *, check_references: bool = True) -> None:
    """Apply PROCESS.md's ledger rules to a claim object.

    `check_references=False` performs structural checks only, skipping
    cross-message resolution. It exists so a message can be loaded raw while
    another message's references are being resolved, which is what keeps graph
    validation from recursing without bound.
    """
    _require(isinstance(claim, dict), "claim must be an object")
    status = claim.get("status")
    if status not in CLAIM_STATUS:
        raise ClaimStateError(
            f"claim.status {status!r} not in {sorted(CLAIM_STATUS)}; "
            "there is no generic 'validated' state"
        )

    if status != "supported":
        return

    # PROCESS.md rule 1: supported is evidence-scoped, never universal truth.
    if not str(claim.get("scope") or "").strip():
        raise ClaimStateError("claim.status 'supported' requires a non-empty scope")
    # PROCESS.md rule 3: no revision condition means 'proposed' at best.
    if not str(claim.get("revision_condition") or "").strip():
        raise ClaimStateError(
            "claim.status 'supported' requires a non-empty revision_condition"
        )

    basis = claim.get("evidence_basis") or []
    _require(isinstance(basis, list), "claim.evidence_basis must be a list")
    if not basis:
        raise ClaimStateError(
            "claim.status 'supported' requires a non-empty evidence_basis"
        )

    # Same reasoning as evidence ids: a basis entry is used as a lookup key,
    # so its shape must be checked before it is used as one.
    seen_basis: set = set()
    for i, entry in enumerate(basis):
        if not isinstance(entry, str) or entry.strip() == "":
            raise ClaimStateError(
                f"claim.evidence_basis[{i}] must be a non-empty string, got "
                f"{type(entry).__name__} {entry!r}"
            )
        if entry in seen_basis:
            raise ClaimStateError(
                f"claim.evidence_basis[{i}] {entry!r} is duplicated; a basis "
                "entry must be cited once"
            )
        seen_basis.add(entry)

    in_message = {
        ref["id"]: ref
        for ref in (evidence or [])
        if isinstance(ref, dict) and ref.get("id")
    }

    for entry in basis:
        # 1. An id naming evidence carried by this very message.
        ref = in_message.get(entry)
        if ref is not None:
            if ref.get("kind") in INADMISSIBLE_FOR_SUPPORT:
                raise ClaimStateError(
                    f"evidence {entry!r} is of kind {ref.get('kind')!r}, which is "
                    "not admissible support for 'supported' "
                    "(LLM_OUTPUT != EVIDENCE)"
                )
            continue

        # 2. Otherwise it must resolve to another message in the store.
        if not check_references:
            continue
        if resolver is None:
            raise UnresolvedReference(
                f"evidence_basis {entry!r} names neither evidence carried by this "
                "message nor anything resolvable; no resolver was available to "
                "check it, so it fails closed"
            )
        referenced = resolver.resolve_message(entry)
        if referenced is None:
            raise UnresolvedReference(
                f"evidence_basis {entry!r} does not resolve to evidence in this "
                "message or to any message in the store"
            )
        if not message_is_admissible_support(referenced):
            raise ClaimStateError(
                f"message {entry!r} carries no admissible evidence "
                f"({sorted(ADMISSIBLE_FOR_SUPPORT)}), so it cannot support a "
                "claim; agent output alone is never support"
            )


def validate_envelope(
    envelope: Mapping[str, Any],
    *,
    agent_facing: bool = True,
    resolver: Any = None,
    check_references: bool = True,
) -> None:
    """Structural and epistemic validation. Raises rather than repairing.

    `resolver` supplies `resolve_message(message_id)`. When present, references
    are resolved for real: a parent must exist and share the thread, and every
    evidence basis entry must resolve and be admissible.

    `check_references=False` restricts validation to this envelope alone. Reads
    use it for the raw phase so that resolving one message's references cannot
    recurse into resolving the referenced message's own references.
    """
    _require(isinstance(envelope, dict), "envelope must be an object")

    missing = [f for f in REQUIRED_FIELDS if f not in envelope]
    _require(not missing, f"envelope missing required fields: {missing}")

    _require(
        envelope["schema_version"] == SCHEMA_VERSION,
        f"unsupported schema_version {envelope['schema_version']!r}",
    )
    _require(
        is_uuid7(envelope["message_id"]),
        f"message_id {envelope['message_id']!r} is not a UUIDv7",
    )

    mtype = envelope["type"]
    _require(mtype in MESSAGE_TYPES, f"unknown message type {mtype!r}")
    if agent_facing and mtype in AGENT_FORBIDDEN_TYPES:
        raise ForbiddenOperation(
            f"agent-facing operations cannot author {mtype!r} messages; "
            "mechanical human authority arrives in Issue #5"
        )

    _require(
        envelope["status"] in LIFECYCLE_STATUS,
        f"status {envelope['status']!r} not in {sorted(LIFECYCLE_STATUS)}",
    )

    for field in ("thread_id", "timestamp"):
        _require(
            isinstance(envelope[field], str) and envelope[field].strip(),
            f"{field} must be a non-empty string",
        )
    _require(
        bool(THREAD_ID_RE.match(envelope["thread_id"])),
        f"thread_id {envelope['thread_id']!r} is not a safe path segment: "
        f"expected 1-{THREAD_ID_MAX} ASCII characters matching "
        "[A-Za-z0-9][A-Za-z0-9._-]*",
    )

    for field in ("sender", "recipient", "project", "body"):
        _require(isinstance(envelope[field], dict), f"{field} must be an object")
    _validate_sender(envelope["sender"])
    _validate_recipient(envelope["recipient"])
    _validate_project(envelope["project"])

    for field in ("reply_requested", "human_approval_required"):
        _require(isinstance(envelope[field], bool), f"{field} must be a boolean")

    parent = envelope.get("parent_id")
    if parent is not None:
        _require(is_uuid7(parent), f"parent_id {parent!r} is not a UUIDv7")

    # A challenge or retraction that references nothing cannot be audited
    # back to what it contests or withdraws.
    if mtype in ("challenge", "retraction"):
        _require(
            envelope.get("parent_id") is not None,
            f"a {mtype} must reference the message_id it "
            f"{'contests' if mtype == 'challenge' else 'retracts'}",
        )

    # The design says decision_request always implies human approval; accepting
    # it with the flag false would let an agent request a decision that no
    # gate is watching for.
    if mtype == "decision_request":
        _require(
            envelope["human_approval_required"] is True,
            "decision_request requires human_approval_required=true",
        )

    if parent is not None and resolver is not None and check_references:
        parent_message = resolver.resolve_message(parent)
        if parent_message is None:
            raise UnresolvedReference(
                f"parent_id {parent!r} does not resolve to a stored message"
            )
        if parent_message["thread_id"] != envelope["thread_id"]:
            raise SchemaError(
                f"parent {parent!r} belongs to thread "
                f"{parent_message['thread_id']!r}, not {envelope['thread_id']!r}; "
                "a reply may not cross threads"
            )

    validate_evidence(envelope.get("evidence", []), resolver)

    if "claim" in envelope and envelope["claim"] is not None:
        _require(
            mtype in ASSERTION_TYPES,
            f"message type {mtype!r} may not carry a claim object",
        )
        validate_claim(
            envelope["claim"], envelope.get("evidence", []), resolver,
            check_references=check_references,
        )

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

import datetime as dt
import ipaddress
import re
from urllib.parse import urlsplit

from . import limits
from .errors import (
    ClaimStateError,
    ForbiddenOperation,
    SchemaError,
    UnresolvedReference,
)
from .ids import is_uuid7

SCHEMA_VERSION = 1

#: The one timestamp spelling the room emits and accepts: UTC, second
#: precision, trailing Z. Anything else is ambiguous to compare or sort.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

MESSAGE_TYPES = frozenset({
    "observation", "hypothesis", "claim", "evidence", "test_result",
    "question", "challenge", "proposed_test",
    "answer", "retraction",
    "decision_request", "approval", "rejection", "handoff",
    "execution_receipt",
})

#: Withheld from agent-facing post/reply (design §6). Rather than pretend to
#: verify a human, these types are simply not exposed to an agent at all; the
#: only write path that accepts them is `GitMessageStore.append_decision`.
#: `execution_receipt` joins them in Issue #13: a receipt is what makes a
#: consequential action one-shot, so an agent that could author one could
#: either consume somebody else's approval or claim an execution that never
#: happened.
AGENT_FORBIDDEN_TYPES = frozenset({"approval", "rejection", "execution_receipt"})

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

#: The identity reserved for the only participant that is not an AI. Agent
#: surfaces refuse to post under it, so a `sender.agent` of "human" cannot be
#: worn by a model — attribution is still provenance rather than proof, but it
#: is at least not forgeable through the ordinary post path.
HUMAN_PARTICIPANT = "human"
RESERVED_PARTICIPANTS = frozenset({HUMAN_PARTICIPANT})

#: The two message types that carry mechanical human authority (Issue #5).
#: They are the only types allowed to carry a `decision` record, and the only
#: types agent-facing operations may never author.
DECISION_TYPES = frozenset({"approval", "rejection"})

RECEIPT_SCHEMA_VERSION = 1

#: A receipt records what happened to a released action. Any of them consumes
#: the action's nonce: an action is one-shot, and a retry needs a new human
#: decision rather than a second use of the old one.
RECEIPT_STATUS = frozenset({"executed", "failed", "uncertain"})

#: `uncertain` means nobody knows whether the side effect happened. It blocks
#: until a human reconciles it, because the alternative is doing it twice.
RECEIPT_UNRESOLVED = frozenset({"uncertain"})

DECISION_SCHEMA_VERSION = 1

#: approve/reject spelled once, mapped to the envelope type that carries it.
#: A record whose verdict disagrees with its envelope type is refused rather
#: than resolved in favour of either.
DECISION_VERDICTS = {"approve": "approval", "reject": "rejection"}

#: An action identifier is a stable slug, not prose: it is compared exactly
#: when a decision is matched to the action it releases.
ACTION_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")

#: One-shot identity for a consequential action. Opaque; compared exactly.
NONCE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{7,63}\Z")

#: Recipes the release path knows how to *derive*, versus digests a caller can
#: type. A release must never be satisfiable by echoing back a string.
MEASUREMENT_KINDS = {
    "snapshot": "git-worktree-manifest",
    "context": "agent-room-thread-context",
}

#: Structured parameters for each consequential action the room can put in
#: front of a human. Prose in `scope` is for the human; these are what a later
#: check compares. An action id with no entry here cannot be consequential.
ACTION_PARAMETERS = {
    "activate-agent-room-transport": {
        "repo": str,
        "branch": str,
        "expect_branch_absent": bool,
    },
    "merge-agent-room-infrastructure": {
        "repo": str,
        "base_branch": str,
        "head_branch": str,
        "expect_head_commit": str,
    },
}

#: A decision id must survive being read back out of an artifact or a log
#: line, so the same narrow grammar applies.
DECISION_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

#: What a consequential action must be bound to before a human decision about
#: it can mean anything. Both are full SHA-256: the inspected-state manifest
#: (snapshot.py) and the supervisor packet context (supervisor.py).
BINDING_FIELDS = ("snapshot_sha256", "supervisor_context_sha256")


def _require_sha256(value, label: str) -> str:
    _require(
        isinstance(value, str) and bool(SHA256_RE.match(value)),
        f"{label} must be a full lower-case SHA-256 hex digest, got "
        f"{type(value).__name__} {value!r}",
    )
    return value


def validate_measurement(measurement, label: str = "binding.measurement") -> None:
    """The recipe the release path uses to derive current state itself.

    This is the difference between "the caller says the snapshot is X" and
    "the snapshot is X". A red-team simply echoed the two digests out of the
    decision request back into the gate and got a release; the fix is that a
    consequential binding must carry enough to *recompute* both, and the
    release path recomputes them.
    """
    _require(isinstance(measurement, dict), f"{label} must be an object")
    snapshot = measurement.get("snapshot")
    _require(isinstance(snapshot, dict), f"{label}.snapshot must be an object")
    _require(
        snapshot.get("kind") == MEASUREMENT_KINDS["snapshot"],
        f"{label}.snapshot.kind must be "
        f"{MEASUREMENT_KINDS['snapshot']!r}, got {snapshot.get('kind')!r}",
    )
    base = snapshot.get("base_commit")
    _require(
        isinstance(base, str) and bool(FULL_COMMIT_RE.match(base))
        and base not in NULL_OBJECT_IDS,
        f"{label}.snapshot.base_commit {base!r} must be a full non-null "
        "Git object id",
    )
    version = snapshot.get("snapshot_schema_version")
    _require(
        type(version) is int and version > 0,
        f"{label}.snapshot.snapshot_schema_version must be a positive integer, "
        f"got {version!r}",
    )

    context = measurement.get("context")
    _require(isinstance(context, dict), f"{label}.context must be an object")
    _require(
        context.get("kind") == MEASUREMENT_KINDS["context"],
        f"{label}.context.kind must be {MEASUREMENT_KINDS['context']!r}, "
        f"got {context.get('kind')!r}",
    )
    thread_id = context.get("thread_id")
    _require(
        isinstance(thread_id, str) and bool(THREAD_ID_RE.match(thread_id)),
        f"{label}.context.thread_id {thread_id!r} is not a valid thread id",
    )
    for field in ("target_message_id", "cutoff_message_id"):
        _require(
            is_uuid7(context.get(field)),
            f"{label}.context.{field} {context.get(field)!r} is not a UUIDv7",
        )


def validate_action_parameters(action_id: str, parameters,
                               label: str = "action.parameters") -> None:
    """Structured parameters, so a later check compares values and not prose."""
    expected = ACTION_PARAMETERS.get(action_id)
    if expected is None:
        raise SchemaError(
            f"{action_id!r} has no structured parameter definition, so it "
            f"cannot be a consequential action. Known: "
            f"{sorted(ACTION_PARAMETERS)}"
        )
    _require(isinstance(parameters, dict), f"{label} must be an object")
    missing = sorted(set(expected) - set(parameters))
    unknown = sorted(set(parameters) - set(expected))
    _require(not missing, f"{label} is missing {missing} for {action_id!r}")
    _require(not unknown, f"{label} has unknown fields {unknown} for {action_id!r}")
    for field, want in expected.items():
        value = parameters[field]
        # `bool` is a subclass of `int`; exact types only, so a truthy string
        # cannot stand in for a boolean precondition.
        _require(
            type(value) is want,
            f"{label}.{field} must be {want.__name__}, got "
            f"{type(value).__name__} {value!r}",
        )
        if want is str:
            _require_str(value, f"{label}.{field}")


def validate_binding(binding, label: str = "binding", *,
                     consequential: bool = False) -> None:
    """What a decision is bound to.

    Both digests are always mandatory: a decision bound to only one of them
    would release an action after the other had moved.

    A *consequential* binding must carry more, because a digest on its own
    names a state without saying which repository it belongs to or how to
    recompute it. An approval for repo A must never release the same-looking
    snapshot in repo B, and a release must derive rather than be told.
    """
    _require(isinstance(binding, dict), f"{label} must be an object")
    for field in BINDING_FIELDS:
        _require(field in binding, f"{label} is missing {field}")
        _require_sha256(binding[field], f"{label}.{field}")

    project = binding.get("project")
    if consequential:
        _require(
            isinstance(project, dict),
            f"{label}.project is mandatory for a consequential action: an "
            "approval must name the repository it approves",
        )
        _validate_project(project)
        _require_str(project.get("repo"), f"{label}.project.repo")
        _require(
            project.get("commit") is not None,
            f"{label}.project.commit is mandatory for a consequential action",
        )
        _require(
            binding.get("measurement") is not None,
            f"{label}.measurement is mandatory for a consequential action; "
            "without it the release path could only be told the current "
            "state, never derive it",
        )
        validate_measurement(binding["measurement"], f"{label}.measurement")
        nonce = binding.get("action_nonce")
        _require(
            isinstance(nonce, str) and bool(NONCE_RE.match(nonce)),
            f"{label}.action_nonce {nonce!r} must match {NONCE_RE.pattern}; a "
            "consequential action is one-shot and needs an identity to consume",
        )
    else:
        if project is not None:
            _require(isinstance(project, dict), f"{label}.project must be an object")
            _validate_project(project)
        if binding.get("measurement") is not None:
            validate_measurement(binding["measurement"], f"{label}.measurement")


def validate_action(action, label: str = "action") -> None:
    """The bound, consequential thing a `decision_request` is asking about.

    Optional by design. A `decision_request` may legitimately ask a human an
    open question, and one without a bound action simply can never release
    anything: `agent_room.decision.evaluate_gate` refuses it. What is refused
    here is a *malformed* binding masquerading as a real one.
    """
    _require(isinstance(action, dict), f"{label} must be an object")
    action_id = action.get("action_id")
    _require(
        isinstance(action_id, str) and bool(ACTION_ID_RE.match(action_id)),
        f"{label}.action_id {action_id!r} must match "
        "[a-z0-9][a-z0-9._-]{0,63}",
    )
    _require_str(action.get("scope"), f"{label}.scope")
    consequential = _require_bool(action.get("consequential"),
                                  f"{label}.consequential")
    validate_binding(action.get("binding"), f"{label}.binding",
                     consequential=consequential)
    if consequential:
        _require(
            action.get("parameters") is not None,
            f"{label}.parameters is mandatory for a consequential action; "
            "scope prose is for the human, parameters are what is checked",
        )
        validate_action_parameters(action_id, action["parameters"],
                                   f"{label}.parameters")
    elif action.get("parameters") is not None:
        validate_action_parameters(action_id, action["parameters"],
                                   f"{label}.parameters")


def validate_decision(decision, envelope: Mapping[str, Any]) -> None:
    """A human decision record, bound to exactly what was decided.

    Every binding field is required, and the envelope type must agree with the
    verdict. Nothing here proves a human authored it — that is capability
    separation's job (`decision.HumanDecisionAuthority`), not the schema's.
    What the schema guarantees is that an approval names, immutably, the
    request, the inspected state and the reviewed context it approved.
    """
    _require(isinstance(decision, dict), "decision must be an object")
    version = decision.get("decision_schema_version")
    _require(
        type(version) is int and version == DECISION_SCHEMA_VERSION,
        f"decision.decision_schema_version must be the integer "
        f"{DECISION_SCHEMA_VERSION}, got {type(version).__name__} {version!r}",
    )
    decision_id = decision.get("decision_id")
    _require(
        isinstance(decision_id, str) and bool(DECISION_ID_RE.match(decision_id)),
        f"decision.decision_id {decision_id!r} must match "
        "[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
    )
    verdict = _require_enum(
        decision.get("decision"), frozenset(DECISION_VERDICTS), "decision.decision"
    )
    expected_type = DECISION_VERDICTS[verdict]
    _require(
        envelope["type"] == expected_type,
        f"decision.decision {verdict!r} must be carried by a "
        f"{expected_type!r} message, not {envelope['type']!r}",
    )
    decided_at = _require_str(decision.get("decided_at"), "decision.decided_at")
    try:
        dt.datetime.strptime(decided_at, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise SchemaError(
            f"decision.decided_at {decided_at!r} is not canonical UTC "
            f"({TIMESTAMP_FORMAT}): {exc}"
        ) from exc
    request_id = decision.get("request_message_id")
    _require(
        is_uuid7(request_id),
        f"decision.request_message_id {request_id!r} is not a UUIDv7",
    )
    # Lineage is not optional for a decision: the record must hang off the
    # request in the thread as well as name it, so a reader walking the thread
    # cannot miss it.
    _require(
        envelope.get("parent_id") == request_id,
        f"a {envelope['type']} must reply to the decision_request it decides "
        f"({request_id!r}), got parent_id {envelope.get('parent_id')!r}",
    )
    _require_sha256(
        decision.get("request_envelope_sha256"), "decision.request_envelope_sha256"
    )
    action_id = decision.get("action_id")
    _require(
        isinstance(action_id, str) and bool(ACTION_ID_RE.match(action_id)),
        f"decision.action_id {action_id!r} must match "
        "[a-z0-9][a-z0-9._-]{0,63}",
    )
    _require_str(decision.get("action_scope"), "decision.action_scope")
    consequential = _require_bool(decision.get("consequential"),
                                  "decision.consequential")
    validate_binding(decision.get("binding"), "decision.binding",
                     consequential=consequential)
    if consequential:
        validate_action_parameters(action_id, decision.get("parameters"),
                                   "decision.parameters")
    _require_sha256(
        decision.get("decision_binding_sha256"), "decision.decision_binding_sha256"
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SchemaError(message)


def _require_str(value, label: str) -> str:
    """A non-empty string, with no coercion.

    `str(value)` would turn `[]` into "[]" and quietly accept it; membership
    tests on a list or dict raise a bare TypeError the CLI does not contract
    to catch. Type first, then content.
    """
    _require(
        isinstance(value, str) and value.strip() != "",
        f"{label} must be a non-empty string, got {type(value).__name__} {value!r}",
    )
    return value


def _require_bool(value, label: str) -> bool:
    _require(
        isinstance(value, bool),
        f"{label} must be a boolean, got {type(value).__name__} {value!r}",
    )
    return value


def _require_enum(value, allowed: frozenset, label: str):
    """Check the type before membership, so lists/dicts cannot raise TypeError."""
    _require(
        isinstance(value, str),
        f"{label} must be a string, got {type(value).__name__} {value!r}",
    )
    _require(value in allowed, f"{label} {value!r} not in {sorted(allowed)}")
    return value


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


#: Anything Git or a shell would treat specially, or that cannot survive a
#: subprocess argument, is refused before the value reaches a Git command.
CONTROL_CHARS = frozenset(chr(c) for c in range(0x20)) | {"\x7f"}


def _require_relative_path(value, label: str) -> None:
    _require_str(value, label)
    bad = sorted({c for c in value if c in CONTROL_CHARS})
    _require(
        not bad,
        f"{label} contains control characters {[hex(ord(c)) for c in bad]}; "
        "such a path cannot be passed safely to Git",
    )
    _require(
        not value.startswith("/"),
        f"{label} {value!r} must be repository-relative, not absolute",
    )
    _require(
        ".." not in value.split("/"),
        f"{label} {value!r} must not contain a '..' traversal segment",
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


def _validate_repo_locator(ref: dict, i: int, verifier=None) -> None:
    _require_str(ref.get("repo"), f"evidence[{i}].repo")
    _require_relative_path(ref.get("path"), f"evidence[{i}].path")
    # Only what is locally decidable. If this machine holds the pinned commit,
    # the cited path must exist in it; if it does not hold the object, the
    # locator is preserved and nothing is fetched - see the boundary note in
    # docs/AGENT_ROOM_STORE.md.
    if verifier is not None and hasattr(verifier, "commit_path_state"):
        state = verifier.commit_path_state(ref["commit"], ref["path"])
        if state == "absent":
            raise SchemaError(
                f"evidence[{i}].path {ref['path']!r} does not exist in locally "
                f"available commit {ref['commit'][:8]}"
            )
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


def _validate_run_locator(ref: dict, i: int, verifier=None) -> None:
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
        # Same rule as repo evidence: if we hold the commit, the artifact
        # must really be in it. A run_id-only locator implies no lookup.
        if verifier is not None and hasattr(verifier, "commit_path_state"):
            if verifier.commit_path_state(ref["commit"], path) == "absent":
                raise SchemaError(
                    f"evidence[{i}].path {path!r} does not exist in locally "
                    f"available commit {ref['commit'][:8]}"
                )


#: A host made only of digits and dots is claiming to be IPv4. If it is not a
#: valid IPv4 address it must be rejected, not quietly re-read as a DNS name -
#: `256.1.2.3` is nobody's hostname.
IPV4_SHAPED_RE = re.compile(r"\A[0-9.]+\Z")


def _validate_url_host(host: str, url: str, i: int) -> None:
    """Host must be a valid IP literal or a valid DNS/IDNA hostname."""
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if IPV4_SHAPED_RE.match(host):
        raise SchemaError(
            f"evidence[{i}].url {url!r} has an IPv4-shaped host {host!r} that "
            "is not a valid IPv4 address"
        )
    if host.startswith("[") or ":" in host:
        raise SchemaError(
            f"evidence[{i}].url {url!r} has a malformed IP literal host {host!r}"
        )
    try:
        encoded = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise SchemaError(
            f"evidence[{i}].url {url!r} has a host that is not valid IDNA: {exc}"
        ) from exc
    labels = encoded.rstrip(".").split(".")
    _require(
        all(labels) and len(encoded) <= 253,
        f"evidence[{i}].url {url!r} has a malformed host {host!r}",
    )
    for label in labels:
        _require(
            1 <= len(label) <= 63
            and all(c.isalnum() or c == "-" for c in label)
            and not label.startswith("-") and not label.endswith("-"),
            f"evidence[{i}].url {url!r} has an invalid host label {label!r}",
        )


def _validate_external_locator(ref: dict, i: int) -> None:
    """External evidence must be a syntactically usable absolute URL.

    Syntax only. Issue #2 deliberately does not make an HTTP request to prove
    the artifact is reachable: the store preserves references, it does not
    attest to external availability.
    """
    url = _require_str(ref.get("url"), f"evidence[{i}].url")
    bad = sorted({c for c in url if c in CONTROL_CHARS or c.isspace()})
    _require(
        not bad,
        f"evidence[{i}].url contains whitespace or control characters "
        f"{[hex(ord(c)) for c in bad]}",
    )
    # A backslash is not a path separator in a URL, but several parsers treat
    # it as one - an ambiguity that has no place in a stored locator.
    _require(
        "\\" not in url,
        f"evidence[{i}].url {url!r} must not contain a backslash",
    )
    for pos, char in enumerate(url):
        if char == "%":
            escape = url[pos + 1:pos + 3]
            _require(
                len(escape) == 2 and all(c in "0123456789abcdefABCDEF" for c in escape),
                f"evidence[{i}].url {url!r} has an invalid percent escape "
                f"at position {pos}",
            )
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        # Malformed IPv6 literals and out-of-range ports raise here.
        raise SchemaError(f"evidence[{i}].url {url!r} is not parseable: {exc}") from exc
    _require(
        parsed.scheme in ("http", "https"),
        f"evidence[{i}].url {url!r} must be an absolute http:// or https:// URL, "
        f"got scheme {parsed.scheme!r}",
    )
    _require(bool(parsed.netloc), f"evidence[{i}].url {url!r} has no authority")
    _require(bool(host), f"evidence[{i}].url {url!r} has no host")
    # Credentials never belong in a stored evidence locator, and their
    # presence is also what makes `user@@host` ambiguous to parse.
    _require(
        "@" not in parsed.netloc,
        f"evidence[{i}].url {url!r} must not carry userinfo/credentials",
    )
    _require(
        parsed.username is None and parsed.password is None,
        f"evidence[{i}].url {url!r} must not carry userinfo/credentials",
    )
    if port is not None:
        _require(
            1 <= port <= 65535,
            f"evidence[{i}].url {url!r} has an out-of-range port {port}",
        )
    _validate_url_host(host, url, i)


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
        kind = _require_enum(ref.get("kind"), EVIDENCE_KINDS, f"evidence[{i}].kind")
        if kind in ("repo", "run"):
            _validate_pinned_commit(ref, i, verifier)
        if kind == "repo":
            _validate_repo_locator(ref, i, verifier)
        elif kind == "run":
            _validate_run_locator(ref, i, verifier)
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
    if not isinstance(status, str):
        raise ClaimStateError(
            f"claim.status must be a string, got {type(status).__name__} {status!r}"
        )
    if status not in CLAIM_STATUS:
        raise ClaimStateError(
            f"claim.status {status!r} not in {sorted(CLAIM_STATUS)}; "
            "there is no generic 'validated' state"
        )

    if status != "supported":
        return

    # PROCESS.md rule 1: supported is evidence-scoped, never universal truth.
    # No str() coercion - an array must fail, not stringify into "[]".
    for field in ("scope", "revision_condition"):
        value = claim.get(field)
        if not isinstance(value, str) or value.strip() == "":
            raise ClaimStateError(
                f"claim.status 'supported' requires a non-empty string {field}, "
                f"got {type(value).__name__} {value!r}"
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


def validate_receipt(receipt, envelope: Mapping[str, Any]) -> None:
    """An immutable record of what happened to a released action.

    A receipt is what makes an action one-shot. It is deliberately not
    agent-authorable: whoever can write one can either consume somebody's
    approval or assert an execution that never happened.
    """
    _require(isinstance(receipt, dict), "receipt must be an object")
    version = receipt.get("receipt_schema_version")
    _require(
        type(version) is int and version == RECEIPT_SCHEMA_VERSION,
        f"receipt.receipt_schema_version must be the integer "
        f"{RECEIPT_SCHEMA_VERSION}, got {version!r}",
    )
    receipt_id = receipt.get("receipt_id")
    _require(
        isinstance(receipt_id, str) and bool(DECISION_ID_RE.match(receipt_id)),
        f"receipt.receipt_id {receipt_id!r} must match "
        "[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
    )
    nonce = receipt.get("action_nonce")
    _require(
        isinstance(nonce, str) and bool(NONCE_RE.match(nonce)),
        f"receipt.action_nonce {nonce!r} must match {NONCE_RE.pattern}",
    )
    action_id = receipt.get("action_id")
    _require(
        isinstance(action_id, str) and bool(ACTION_ID_RE.match(action_id)),
        f"receipt.action_id {action_id!r} must match [a-z0-9][a-z0-9._-]{{0,63}}",
    )
    request_id = receipt.get("request_message_id")
    _require(
        is_uuid7(request_id),
        f"receipt.request_message_id {request_id!r} is not a UUIDv7",
    )
    _require(
        envelope.get("parent_id") == request_id,
        f"an execution_receipt must reply to the decision_request it records "
        f"({request_id!r}), got parent_id {envelope.get('parent_id')!r}",
    )
    _require_enum(receipt.get("status"), RECEIPT_STATUS, "receipt.status")
    recorded_at = _require_str(receipt.get("recorded_at"), "receipt.recorded_at")
    try:
        dt.datetime.strptime(recorded_at, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise SchemaError(
            f"receipt.recorded_at {recorded_at!r} is not canonical UTC "
            f"({TIMESTAMP_FORMAT}): {exc}"
        ) from exc
    _require_str(receipt.get("decision_id"), "receipt.decision_id")
    _require(
        isinstance(receipt.get("result"), dict),
        "receipt.result must be an object",
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

    version = envelope["schema_version"]
    # `True == 1` in Python, so an explicit type test is required here.
    _require(
        type(version) is int and version == SCHEMA_VERSION,
        f"schema_version must be the integer {SCHEMA_VERSION}, got "
        f"{type(version).__name__} {version!r}",
    )
    _require(
        is_uuid7(envelope["message_id"]),
        f"message_id {envelope['message_id']!r} is not a UUIDv7",
    )

    mtype = _require_enum(envelope["type"], MESSAGE_TYPES, "type")
    if agent_facing and mtype in AGENT_FORBIDDEN_TYPES:
        raise ForbiddenOperation(
            f"agent-facing operations cannot author {mtype!r} messages; "
            "the human decision surface (agent_room.decision) is the only "
            "path to one, and no agent may reach it"
        )

    _require_enum(envelope["status"], LIFECYCLE_STATUS, "status")

    _require_str(envelope["thread_id"], "thread_id")
    timestamp = _require_str(envelope["timestamp"], "timestamp")
    try:
        dt.datetime.strptime(timestamp, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise SchemaError(
            f"timestamp {timestamp!r} is not canonical UTC "
            f"({TIMESTAMP_FORMAT}): {exc}"
        ) from exc
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
        _require_bool(envelope[field], field)

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
        if envelope.get("action") is not None:
            validate_action(envelope["action"])
    elif envelope.get("action") is not None:
        raise SchemaError(
            f"message type {mtype!r} may not carry an 'action' binding; only "
            "a decision_request names an action a human may release"
        )

    # A decision record belongs to exactly the two authority-bearing types,
    # and both of them require one. An approval that binds to nothing could
    # not be checked against anything later.
    if mtype == "execution_receipt":
        _require(
            envelope.get("receipt") is not None,
            "an execution_receipt must carry a 'receipt' record",
        )
        validate_receipt(envelope["receipt"], envelope)
    elif envelope.get("receipt") is not None:
        raise SchemaError(
            f"message type {mtype!r} may not carry a 'receipt'; only an "
            "execution_receipt records what happened to a released action"
        )

    if mtype in DECISION_TYPES:
        _require(
            envelope.get("decision") is not None,
            f"a {mtype} must carry a 'decision' record binding it to the "
            "request, snapshot and supervisor context it decides",
        )
        validate_decision(envelope["decision"], envelope)
    elif envelope.get("decision") is not None:
        raise SchemaError(
            f"message type {mtype!r} may not carry a 'decision' record; only "
            f"{sorted(DECISION_TYPES)} carry mechanical human authority"
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

    # Bounded before anything durable happens. An unbounded body or evidence
    # list is not an attack on its own, but committing one is irreversible.
    body_text = envelope["body"].get("text")
    if isinstance(body_text, str):
        limits.assert_within(len(body_text), limits.MAX_BODY_TEXT_CHARS,
                             "body.text", "characters")
    evidence = envelope.get("evidence", [])
    if isinstance(evidence, list):
        limits.assert_within(len(evidence), limits.MAX_EVIDENCE_ITEMS,
                             "evidence", "items")

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

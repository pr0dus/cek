"""The untrusted control branch: requests in, results out, nothing else.

Everything on this branch is written by whoever holds the transport
repository credential, and that writer is explicitly in the threat model. So
this store treats its own contents as hostile input: a closed path grammar, a
strict parser, hard size bounds, append-only history, and one immutable result
per request.

It is deliberately **not** the room's message store. The room branch carries
signed research state; this one carries an RPC queue for exactly three narrow
operations. Sharing a store between them would mean one namespace rule, one
set of limits and one blast radius for two very different kinds of content.

The Git helper here is the only subprocess surface the transport has, and it
exists because Git is unavoidable. Its argv is constructed internally, never
from a request; there is no shell, the environment is sanitised, hooks are
disabled, and every call is bounded in time and output. `transport.py` itself
contains no subprocess reference at all, and a static test keeps it that way.
"""

import datetime as dt
import hashlib
import os
import re
from pathlib import Path

from . import canonical
from .errors import AgentRoomError
from .ids import is_uuid7
from .process import run_bounded, sanitised_env

CONTROL_SCHEMA_VERSION = 1

#: The closed namespace. Three shapes, nothing else on the branch.
CONTROL_GENESIS = "README.agent-room-control.md"
REQUESTS_DIR = ".agent-room-control/requests"
RESULTS_DIR = ".agent-room-control/results"

REQUEST_RE = re.compile(
    r"\A" + re.escape(REQUESTS_DIR) + r"/([0-9a-f-]+)\.json\Z")
RESULT_RE = re.compile(
    r"\A" + re.escape(RESULTS_DIR) + r"/([0-9a-f-]+)\.json\Z")

#: Regular, non-executable files. A symlink, an executable bit or a gitlink on
#: a branch a hostile writer controls is not content, it is a lever.
ALLOWED_BLOB_MODE = "100644"

GIT_TIMEOUT_SECONDS = 60

#: Applied to every Git call. A hook on an attacker-writable branch would be
#: attacker-supplied code running inside the transport.
HARDENED_GIT_CONFIG = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.ext.allow=never",
)

#: Hard bounds. The writer is untrusted, so every one of these is a promise
#: about memory and work rather than a formatting preference.
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_PENDING_REQUESTS = 256
MAX_TRACKED_PATHS = 4096

__all__ = [
    "CONTROL_SCHEMA_VERSION", "CONTROL_GENESIS", "REQUESTS_DIR", "RESULTS_DIR",
    "MAX_REQUEST_BYTES", "MAX_RESULT_BYTES", "MAX_PENDING_REQUESTS",
    "ControlError", "ControlNamespaceViolation", "ControlAppendOnlyViolation",
    "ControlConflict", "ControlStore",
]


class ControlError(AgentRoomError):
    """The control branch refused something."""


class ControlNamespaceViolation(ControlError):
    """A tracked path or mode the control protocol does not define."""


class ControlAppendOnlyViolation(ControlError):
    """A request or result artifact was modified, deleted or re-added."""


class ControlConflict(ControlError):
    """The same request id already exists with different content."""


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify(path: str) -> str | None:
    """"genesis", "request", "result", or None for anything undefined."""
    if path == CONTROL_GENESIS:
        return "genesis"
    match = REQUEST_RE.match(path)
    if match:
        return "request" if is_uuid7(match.group(1)) else None
    match = RESULT_RE.match(path)
    if match:
        return "result" if is_uuid7(match.group(1)) else None
    return None


class ControlStore:
    """One control branch in one checkout. Read hostile, write narrow."""

    def __init__(self, workdir, branch: str = "agent-room-control") -> None:
        self.workdir = Path(workdir)
        if not re.match(r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z", branch) or \
                ".." in branch:
            raise ControlError(f"unsafe control branch name {branch!r}")
        self.branch = branch
        self.ref = f"refs/heads/{branch}"

    # -- git ---------------------------------------------------------------
    def _git(self, *args: str, check: bool = True):
        """Fixed argv, no shell, sanitised environment, bounded.

        Nothing from a request ever reaches this. The only caller-varying
        values are paths this class constructs from validated uuid7 ids.
        """
        result = run_bounded(
            ["git", "--no-replace-objects", *HARDENED_GIT_CONFIG, *args],
            cwd=self.workdir, timeout=GIT_TIMEOUT_SECONDS,
            env=sanitised_env(GIT_NO_REPLACE_OBJECTS="1",
                              GIT_TERMINAL_PROMPT="0"),
            max_output_bytes=8 * 1024 * 1024,
        )
        if result.timed_out:
            raise ControlError(f"git {args[0]} timed out in {self.workdir}")
        if check and result.returncode != 0:
            raise ControlError(
                f"git {' '.join(args)} failed ({result.returncode}): "
                f"{result.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return result

    @classmethod
    def initialise(cls, workdir, branch: str = "agent-room-control"):
        """Create the control branch as an orphan history."""
        path = Path(workdir)
        path.mkdir(parents=True, exist_ok=True)
        store = cls(path, branch)
        store._git("init", "-q")
        store._git("checkout", "-q", "--orphan", branch)
        store._git("rm", "-rq", "--cached", ".", check=False)
        (path / CONTROL_GENESIS).write_text(
            "# agent-room-control\n\n"
            "Untrusted request/result queue for the narrow Agent Room "
            "supervisor transport.\n"
            "Everything here is written by the transport credential holder "
            "and is treated as hostile input.\n\n"
            f"Paths:\n- {REQUESTS_DIR}/<uuid7>.json\n"
            f"- {RESULTS_DIR}/<uuid7>.json\n",
            encoding="utf-8")
        store._git("add", "--", CONTROL_GENESIS)
        store._commit("agent-room-control: initialise")
        return store

    def _commit(self, message: str, *pathspec: str) -> str:
        args = ["-c", "user.name=agent-room-transport",
                "-c", "user.email=agent-room-transport@localhost",
                "commit", "-q", "-m", message]
        if pathspec:
            args += ["--", *pathspec]
        self._git(*args)
        return self._git("rev-parse", "HEAD").stdout.decode().strip()

    # -- namespace ---------------------------------------------------------
    def assert_namespace_closed(self) -> dict:
        """Every tracked entry is a control artifact, with the right mode."""
        proc = self._git("ls-tree", "-r", "-z", "--full-tree", self.ref)
        counts = {"genesis": 0, "request": 0, "result": 0}
        entries = proc.stdout.decode("utf-8", "surrogateescape").split("\0")
        if len(entries) > MAX_TRACKED_PATHS:
            raise ControlError(
                f"control branch tracks more than {MAX_TRACKED_PATHS} paths; "
                "refusing to scan an unbounded tree")
        for entry in entries:
            if not entry:
                continue
            meta, _, path = entry.partition("\t")
            fields = meta.split()
            if len(fields) < 3:
                raise ControlError(f"malformed tree entry {entry!r}")
            mode, object_type = fields[0], fields[1]
            kind = classify(path)
            if kind is None:
                raise ControlNamespaceViolation(
                    f"unexpected tracked path on the control branch: {path!r}. "
                    f"The branch holds exactly {CONTROL_GENESIS}, "
                    f"{REQUESTS_DIR}/<uuid7>.json and "
                    f"{RESULTS_DIR}/<uuid7>.json")
            if object_type != "blob" or mode != ALLOWED_BLOB_MODE:
                raise ControlNamespaceViolation(
                    f"{path!r} is a {object_type} with mode {mode}; control "
                    "artifacts are plain non-executable files")
            counts[kind] += 1
        return counts

    def _history(self) -> dict:
        """path -> add commit, refusing any later mutation of an artifact."""
        self.assert_namespace_closed()
        proc = self._git("log", self.ref, "--reverse", "--format=%H",
                         "--name-status", "-z", "--no-renames")
        tokens = proc.stdout.decode("utf-8", "surrogateescape").split("\0")
        added: dict = {}
        genesis_seen = False
        commit = ""
        i = 0
        while i < len(tokens):
            token = tokens[i].strip()
            i += 1
            if not token:
                continue
            if len(token) >= 40 and all(c in "0123456789abcdef" for c in token):
                commit = token
                continue
            status, path = token, tokens[i] if i < len(tokens) else ""
            i += 1
            kind = classify(path)
            if kind is None:
                raise ControlNamespaceViolation(
                    f"commit {commit} touches undefined path {path!r}")
            if kind == "genesis":
                if not status.startswith("A") or genesis_seen:
                    raise ControlAppendOnlyViolation(
                        f"{path} is immutable; {status!r} in {commit}")
                genesis_seen = True
                continue
            if not status.startswith("A"):
                raise ControlAppendOnlyViolation(
                    f"{path} was {status!r} in commit {commit}; control "
                    "artifacts are append-only and a modified or deleted "
                    "request is evidence of tampering, not an update")
            if path in added:
                raise ControlAppendOnlyViolation(
                    f"{path} was added twice (second add in {commit})")
            added[path] = commit
        return added

    # -- reads -------------------------------------------------------------
    def _blob(self, path: str, commit: str) -> bytes:
        return self._git("cat-file", "blob", f"{commit}:{path}").stdout

    def _load(self, path: str, commit: str, limit: int) -> dict:
        raw = self._blob(path, commit)
        if len(raw) > limit:
            raise ControlError(
                f"{path} is {len(raw)} bytes, over the {limit} byte limit")
        document = canonical.strict_loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ControlError(f"{path} is not a JSON object")
        return document

    def pending(self) -> list:
        """Requests with no result yet, oldest first, bounded."""
        history = self._history()
        requests, results = {}, set()
        for path, commit in history.items():
            match = REQUEST_RE.match(path)
            if match:
                requests[match.group(1)] = (path, commit)
                continue
            match = RESULT_RE.match(path)
            if match:
                results.add(match.group(1))
        waiting = [rid for rid in requests if rid not in results]
        if len(waiting) > MAX_PENDING_REQUESTS:
            raise ControlError(
                f"{len(waiting)} requests are pending, over the "
                f"{MAX_PENDING_REQUESTS} backlog limit. A writer cannot make "
                "the worker scan an unbounded queue; clear the backlog or "
                "raise the bound deliberately.")
        return [
            {"request_id": rid, "path": requests[rid][0],
             "commit": requests[rid][1]}
            for rid in waiting
        ]

    def read_request(self, entry: dict) -> tuple:
        raw = self._blob(entry["path"], entry["commit"])
        if len(raw) > MAX_REQUEST_BYTES:
            raise ControlError(
                f"request {entry['request_id']} is {len(raw)} bytes, over the "
                f"{MAX_REQUEST_BYTES} byte limit")
        document = canonical.strict_loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ControlError("a control request must be a JSON object")
        return document, hashlib.sha256(raw).hexdigest()

    def has_result(self, request_id: str) -> bool:
        return f"{RESULTS_DIR}/{request_id}.json" in self._history()

    # -- writes ------------------------------------------------------------
    def submit_request(self, document: dict) -> dict:
        """Test/operator helper: append one request artifact.

        Production requests arrive by push from the supervisor side; this is
        how the tests play that writer.
        """
        request_id = document.get("request_id")
        if not is_uuid7(request_id or ""):
            raise ControlError(f"request_id {request_id!r} is not a UUIDv7")
        return self._append(f"{REQUESTS_DIR}/{request_id}.json", document,
                            MAX_REQUEST_BYTES, f"request {request_id}")

    def write_result(self, request_id: str, document: dict) -> dict:
        if not is_uuid7(request_id):
            raise ControlError(f"request_id {request_id!r} is not a UUIDv7")
        return self._append(f"{RESULTS_DIR}/{request_id}.json", document,
                            MAX_RESULT_BYTES, f"result {request_id}")

    def _append(self, rel: str, document: dict, limit: int,
                message: str) -> dict:
        payload = canonical.canonical_text(document).encode("utf-8")
        if len(payload) > limit:
            raise ControlError(
                f"{rel} would be {len(payload)} bytes, over the {limit} byte "
                "limit; refusing before anything durable happens")
        history = self._history()
        if rel in history:
            existing = self._blob(rel, history[rel])
            if existing == payload:
                return {"status": "duplicate", "path": rel,
                        "commit": history[rel]}
            raise ControlConflict(
                f"{rel} already exists with different content; control "
                "artifacts are immutable and are never overwritten")
        target = self.workdir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        os.umask(0o077)
        target.write_text(canonical.canonical_text(document), encoding="utf-8")
        self._git("add", "--", rel)
        return {"status": "created", "path": rel,
                "commit": self._commit(f"agent-room-control: {message}", rel)}

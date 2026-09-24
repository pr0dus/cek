"""Fetching, verifying and pushing the two fixed remotes.

The worker versioned in S3 operated on local checkouts and left "somebody runs
git pull" implicit — which is either a stale service or an unspecified broad
synchronisation path, and both are the thing S3 exists to remove. This module
gives the narrow worker the whole lifecycle, without giving it a command
surface: every ref, remote and path here comes from service configuration, and
nothing in a control request reaches any of it.

Two rules shape the design.

**A fetched head is not a trusted head.** `git pull`, or fetch-then-reset,
installs the remote's answer and verifies afterwards — by which time the local
branch has already become whatever arrived. Here a candidate lands on a
*separate local ref*, is verified there in full against the S2 trust policy
and checkpoint, and is installed only if it passes. A candidate that fails
leaves the room exactly where it was.

**Delivery is a compare-and-swap.** A supervisor response reviewed against
head H must not be rebased onto H+1 and pushed as though it still applied.
The push carries an exact lease on H, so it lands only while the remote is
still H; if the ref moved, the reviewed context is recomputed against the new
head and a changed context fails stale rather than being retried harder.

The Git helper is the only subprocess surface in the transport. Its argv is
built from constants and values this module validated; there is no shell, the
environment is sanitised, hooks are disabled, and every call is bounded.
"""

import datetime as dt
import json
import os
import re
import tempfile
from pathlib import Path

from . import canonical
from .errors import AgentRoomError
from .process import run_bounded, sanitised_env

GIT_TIMEOUT_SECONDS = 120
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024

#: Applied to every Git call the transport makes. A hook on a branch an
#: attacker can write would be attacker-supplied code inside the transport.
HARDENED_GIT_CONFIG = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.ext.allow=never",
    "-c", "advice.detachedHead=false",
)

#: Where a fetched-but-unverified room head is parked. A real local branch, so
#: the ordinary store can be pointed at it for verification, and one nobody
#: checks out.
CANDIDATE_SUFFIX = "-candidate"

#: How many times delivery may be reconstructed when the remote moved but the
#: reviewed context did not. Small and fixed: a retry loop against a moving
#: remote is a busy-wait with a security question attached.
MAX_DELIVERY_ATTEMPTS = 3

OID_RE = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
REF_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
REMOTE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

STATE_FILE_MODE = 0o600
STATE_DIR_MODE = 0o700

__all__ = [
    "GIT_TIMEOUT_SECONDS", "MAX_DELIVERY_ATTEMPTS", "CANDIDATE_SUFFIX",
    "SyncError", "RemoteRefMoved", "CandidateRejected", "AmbiguousDelivery",
    "run_git",
    "Anchor", "RoomRemote", "ControlRemote",
]


class SyncError(AgentRoomError):
    """A remote synchronisation step failed."""


class RemoteRefMoved(SyncError):
    """The remote ref was not what the lease expected."""


class RemoteRefMissing(SyncError):
    """A configured remote no longer advertises its mandatory exact ref."""


class CandidateRejected(SyncError):
    """A fetched candidate did not verify, so it was not installed."""


class AmbiguousDelivery(SyncError):
    """The push failed, and whether the remote accepted it is unknown.

    A distinct state on purpose. "The client saw an error" and "the remote did
    not take it" are different facts, and a network failure after acceptance
    makes them come apart. Inferring delivery from an exit code would mean
    either losing a delivered result or producing a second one; this says so
    instead, and the caller reconciles against the remote rather than guessing.
    """


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate(value, pattern, label) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise SyncError(f"{label} {value!r} is not a safe identifier")
    if ".." in value:
        raise SyncError(f"{label} {value!r} contains a traversal segment")
    return value


def run_git(workdir, *args: str, check: bool = True):
    """One bounded, sanitised Git call. Fixed argv, no shell.

    The only subprocess surface the transport has. Nothing from a control
    request reaches it: callers pass constants, configured names this module
    has validated, and object ids it read from Git itself.
    """
    result = run_bounded(
        ["git", "--no-replace-objects", *HARDENED_GIT_CONFIG, *args],
        cwd=Path(workdir), timeout=GIT_TIMEOUT_SECONDS,
        env=sanitised_env(GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0",
                          GIT_ASKPASS="/bin/false"),
        max_output_bytes=MAX_GIT_OUTPUT_BYTES,
    )
    if result.timed_out:
        raise SyncError(f"git {args[0]} timed out in {workdir}")
    if check and result.returncode != 0:
        raise SyncError(
            f"git {' '.join(args[:3])} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return result


def _out(result) -> str:
    return result.stdout.decode("utf-8", "replace").strip()


class Anchor:
    """Service-owned durable state. Public identities only, owner-only file.

    Used for the control branch's monotonic anchor and the worker's processed
    ledger: both answer "what does the *service* know", which is a different
    question from "what does the untrusted repository currently say".
    """

    def __init__(self, path, kind: str) -> None:
        self.path = Path(path)
        self.kind = kind
        self.document = self._load()

    def _load(self) -> dict:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # The only "not initialised yet" there is.
            return {"kind": self.kind, "created_at": _now_iso()}
        except OSError as exc:
            # Permission denied, an I/O error or a bad path are *not* an empty
            # ledger. Treating them as one is fail-open: a processed-request
            # ledger that silently became empty would let every request run
            # again. Recovery is an explicit human procedure, not a default.
            raise SyncError(
                f"cannot read the {self.kind} at {self.path}: {exc}. This is "
                "not treated as 'not initialised': an unreadable ledger that "
                "became empty would let processed requests run a second time."
            ) from exc
        document = canonical.strict_loads(raw)
        if not isinstance(document, dict) or document.get("kind") != self.kind:
            raise SyncError(f"{self.path} is not a {self.kind} anchor")
        return document

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=STATE_DIR_MODE)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            os.fchmod(fd, STATE_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(canonical.canonical_text(self.document))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get(self, key, default=None):
        return self.document.get(key, default)

    def set(self, **values) -> None:
        self.document.update(values)
        self.document["updated_at"] = _now_iso()
        self.save()


class _Remote:
    """Shared fetch/observe plumbing for one fixed branch on one fixed remote."""

    def __init__(self, workdir, remote: str, branch: str) -> None:
        self.workdir = Path(workdir)
        self.remote = _validate(remote, REMOTE_RE, "remote")
        self.branch = _validate(branch, REF_NAME_RE, "branch")
        self.ref = f"refs/heads/{self.branch}"

    def local_tip(self) -> str | None:
        result = run_git(self.workdir, "rev-parse", "--verify", self.ref,
                         check=False)
        return _out(result) if result.returncode == 0 else None

    def remote_tip(self) -> str | None:
        """What the remote says the ref is, without fetching objects."""
        result = run_git(self.workdir, "ls-remote", "--exit-code", self.remote,
                         self.ref, check=False)
        if result.returncode == 2:
            return None
        if result.returncode != 0:
            raise SyncError(f"cannot inspect configured remote ref {self.ref}")
        lines = _out(result).splitlines()
        fields = lines[0].split() if len(lines) == 1 else []
        if len(fields) != 2 or fields[1] != self.ref or not OID_RE.fullmatch(fields[0]):
            raise SyncError(f"invalid exact-ref advertisement for {self.ref}")
        return fields[0]

    def required_remote_tip(self) -> str:
        tip = self.remote_tip()
        if tip is None:
            raise RemoteRefMissing(f"remote ref missing: {self.remote} {self.ref}")
        return tip

    def fetch_candidate(self, candidate_branch: str) -> str:
        """Park the remote head on a separate local ref. Verify it there.

        Deliberately not `git pull`: installing first and checking afterwards
        means the local branch has already become whatever arrived.
        """
        _validate(candidate_branch, REF_NAME_RE, "candidate branch")
        result = run_git(
            self.workdir, "fetch", "--no-tags", "--prune", "--quiet",
            self.remote,
            f"+{self.ref}:refs/heads/{candidate_branch}", check=False)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", "replace").strip()
            # Only ls-remote's documented no-match status establishes absence;
            # an authentication/network error containing "not found" does not.
            self.required_remote_tip()
            raise SyncError(f"fetch of {self.ref} failed: {stderr[:300]}")
        observed = run_git(self.workdir, "rev-parse", "--verify",
                           f"refs/heads/{candidate_branch}", check=False)
        if observed.returncode != 0 or not OID_RE.fullmatch(_out(observed)):
            raise SyncError(f"cannot resolve fetched candidate for {self.ref}")
        return _out(observed)

    def is_ancestor(self, earlier: str, later: str) -> bool:
        result = run_git(self.workdir, "merge-base", "--is-ancestor",
                         earlier, later, check=False)
        if result.returncode not in (0, 1):
            raise SyncError(
                f"ancestry query {earlier[:8]}..{later[:8]} failed")
        return result.returncode == 0


class RoomRemote(_Remote):
    """The signed room branch: fetch, verify a candidate, install, push by lease."""

    def install(self, candidate_oid: str) -> str:
        """Fast-forward the working branch to an already-verified candidate.

        `--ff-only` is the guard: if the local branch is not an ancestor of the
        candidate, this refuses rather than rewriting local history. The
        candidate has been verified by the caller before this is reached.
        """
        _validate(candidate_oid, OID_RE, "candidate oid")
        local = self.local_tip()
        if local == candidate_oid:
            return candidate_oid
        run_git(self.workdir, "merge", "--ff-only", "--quiet", candidate_oid)
        installed = self.local_tip()
        if installed != candidate_oid:
            raise SyncError(
                f"install left the branch at {str(installed)[:12]}, not the "
                f"verified candidate {candidate_oid[:12]}")
        return installed

    def push_with_lease(self, expected_remote_oid: str) -> dict:
        """Push only while the remote ref is still exactly what we reviewed.

        The lease is the atomic comparison, not a licence to rewrite: our
        commit is a fast-forward from the expected head, so nothing valid is
        ever discarded.

        A non-zero exit is *not* taken as "the remote did not accept it". The
        remote can accept an update and the acknowledgement can still be lost,
        so any failure is reconciled against the ref itself before it is
        classified — delivered, moved, or honestly unknown.
        """
        local = self.local_tip()
        if local is None:
            raise SyncError("nothing to push: the local room branch is unborn")
        self.required_remote_tip()  # Never bootstrap/recreate a production ref.
        _validate(expected_remote_oid, OID_RE, "expected remote oid")
        lease = f"{self.ref}:{expected_remote_oid}"
        try:
            result = run_git(
                self.workdir, "push", f"--force-with-lease={lease}",
                self.remote, f"{self.ref}:{self.ref}", check=False)
        except SyncError as exc:
            return self._classify_failed_push(local, expected_remote_oid, str(exc))
        if result.returncode == 0:
            return {"pushed": True, "tip": local}

        stderr = result.stderr.decode("utf-8", "replace").strip()
        return self._classify_failed_push(local, expected_remote_oid, stderr)

    def _classify_failed_push(self, local: str, expected: str | None,
                              stderr: str) -> dict:
        """Ask the remote what happened, rather than reading the exit code."""
        try:
            landed = self.contains_remotely(local)
        except SyncError as exc:
            raise AmbiguousDelivery(
                f"the push of {self.ref} failed ({stderr[:120]}) and the "
                f"remote could not be inspected ({exc}); whether the response "
                "was delivered is unknown, and it will be reconciled rather "
                "than sent again"
            ) from exc
        if landed:
            # Accepted, acknowledgement lost. Delivered is delivered.
            return {"pushed": True, "tip": local, "ack": "recovered"}

        observed = self.remote_tip()
        if observed is not None and observed != expected:
            raise RemoteRefMoved(
                f"the remote {self.ref} is no longer "
                f"{str(expected)[:12]}; the lease refused the push rather "
                "than delivering a review of a head that has moved")
        raise AmbiguousDelivery(
            f"the push of {self.ref} failed ({stderr[:200]}) and the remote "
            f"neither contains {local[:12]} nor demonstrably moved; the "
            "delivery state is unknown")

    def contains_remotely(self, oid: str) -> bool:
        """Is this commit already on the remote ref? Reconciliation, not hope."""
        remote = self.required_remote_tip()
        if remote == oid:
            return True
        fetched = self.fetch_candidate(f"{self.branch}{CANDIDATE_SUFFIX}-probe")
        return bool(fetched) and self.is_ancestor(oid, fetched)


class ControlRemote(_Remote):
    """The untrusted control branch: bounded fetch in, bounded push out."""

    def push(self) -> dict:
        """Fast-forward-only push with an exact lease. Never discarding.

        Like the room push, a failure is reconciled rather than believed: the
        caller confirms each pending result against the remote's own content,
        so a lost acknowledgement does not lose a result and does not produce
        a second one.
        """
        local = self.local_tip()
        observed = self.fetch_candidate(f"{self.branch}{CANDIDATE_SUFFIX}-push")
        # Retain fast-forward-only semantics, with an exact lease so deletion
        # between inspection and push cannot silently recreate the queue.
        if local is None or not self.is_ancestor(observed, local):
            raise RemoteRefMoved("the control remote moved before delivery")
        result = run_git(self.workdir, "push",
                         f"--force-with-lease={self.ref}:{observed}", self.remote,
                         f"{self.ref}:{self.ref}", check=False)
        if result.returncode == 0:
            return {"pushed": True, "tip": local}
        stderr = result.stderr.decode("utf-8", "replace").strip()
        if "non-fast-forward" in stderr or "rejected" in stderr or \
                "fetch first" in stderr:
            raise RemoteRefMoved(
                f"the control remote moved; {self.ref} was not pushed. The "
                "remote candidate must be fetched and verified before "
                "retrying, and history is never discarded to make room.")
        if local is not None and self.remote_tip() == local:
            return {"pushed": True, "tip": local, "ack": "recovered"}
        raise AmbiguousDelivery(
            f"the control push failed ({stderr[:200]}) and the remote tip is "
            "not the local one; each pending result is confirmed against the "
            "remote's content before anything is cleared")

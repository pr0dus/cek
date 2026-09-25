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
branch has already become whatever arrived. Here a candidate is ingested in a
bounded private quarantine and verified against the S2 trust policy and
checkpoint. Only then is its bounded object graph promoted to a separate
candidate ref. A rejected candidate cannot pollute the persistent object store.

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
import secrets
from pathlib import Path

from . import canonical
from .errors import AgentRoomError
from . import protected_state
from .process import run_bounded, sanitised_env
from .transport_state import private_directory, private_lock, check_file, STATE_LOCK, StateError

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

#: Where the quarantine-verified candidate is parked for the caller's final
#: exact-tip recheck before installation. Nobody checks out this branch.
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
    if result.timed_out or result.output_limited:
        raise SyncError(f"git {args[0]} time/output bound exceeded in {workdir}")
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
        self._base_raw = self._read()
        self.document = self._decode(self._base_raw)

    def _read(self):
        try:
            with private_directory(self.path.parent) as directory:
                try:
                    fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
                except FileNotFoundError:
                    return None
                with os.fdopen(fd, 'rb') as handle:
                    if check_file(handle.fileno()).st_size > 16 * 1024 * 1024:
                        raise StateError('protected state exceeds 16 MiB limit; explicit maintenance required')
                    raw = handle.read(16 * 1024 * 1024 + 1)
                    if len(raw) > 16 * 1024 * 1024:
                        raise StateError('protected state grew beyond read limit')
                    return raw
        except FileNotFoundError:
            # The only "not initialised yet" there is.
            return None
        except (OSError, StateError) as exc:
            # Permission denied, an I/O error or a bad path are *not* an empty
            # ledger. Treating them as one is fail-open: a processed-request
            # ledger that silently became empty would let every request run
            # again. Recovery is an explicit human procedure, not a default.
            raise SyncError(
                f"cannot read the {self.kind} at {self.path}: {exc}. This is "
                "not treated as 'not initialised': an unreadable ledger that "
                "became empty would let processed requests run a second time."
            ) from exc

    def _decode(self, raw):
        if raw is None:
            initial = {"kind": self.kind, "created_at": _now_iso()}
            if self.kind == 'processed-ledger':
                initial.update(requests={}, pending_results={}, uncertain_imports={})
            return initial
        document = canonical.strict_loads(raw)
        try:
            protected_state.validate(document, self.kind)
        except protected_state.ProtectedStateError as exc:
            raise SyncError(str(exc)) from exc
        return document

    def save(self) -> None:
        if self.kind == 'control-anchor':
            raise SyncError('control anchor requires verified monotonic advance')
        with private_lock(self.path.parent, STATE_LOCK):
            raw = self._read()
            if raw != self._base_raw:
                raise SyncError('stale transport state object; reload before mutation')
            previous = self._decode(raw)
            if self.kind == 'processed-ledger':
                completed = previous['requests']
                proposed = self.document.get('requests')
                if not isinstance(proposed, dict):
                    raise SyncError('invalid protected requests map')
                if any(proposed.get(k) != v for k, v in completed.items()):
                    raise SyncError('completed request records cannot be removed or changed')
            self._write(previous)

    def _write(self, previous):
        """Caller owns STATE_LOCK and has rechecked current durable state."""
        self.document['revision'] = previous.get('revision', 0) + 1
        self.document['updated_at'] = _now_iso()
        protected_state.validate(self.document, self.kind)
        with private_directory(self.path.parent) as directory:
            tmp = f'.state-{secrets.token_hex(16)}.tmp'
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         os.O_CLOEXEC | os.O_NOFOLLOW, STATE_FILE_MODE, dir_fd=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(canonical.canonical_text(self.document))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
                self._base_raw = canonical.canonical_text(self.document).encode('utf-8')
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=directory)
                except FileNotFoundError:
                    pass
                raise

    def advance_control(self, control, remote, genesis):
        """Re-read at commit time; only a verified observed control tip advances.

        No generic set/save can write a control anchor. A fresh-state comparison
        here also refuses a stale caller even if it bypasses the run mutex.
        None is explicit local-test mode, never a missing configured remote.
        """
        if self.kind != 'control-anchor':
            raise SyncError('not a control anchor')
        with private_lock(self.path.parent, STATE_LOCK):
            raw = self._read()
            current = self._decode(raw)
            control.verify_history()
            tip = control.current_tip()
            if not tip or control.genesis() != genesis:
                raise SyncError('control genesis does not match the pinned root')
            if raw is not None and current['genesis'] != genesis:
                raise SyncError('persisted control genesis changed')
            if remote is not None and remote.required_remote_tip() != tip:
                raise SyncError('control tip is not the observed authoritative remote head')
            accepted = current['last_accepted_tip'] if raw is not None else None
            if accepted and accepted != tip:
                result = control._git('merge-base', '--is-ancestor', accepted, tip, check=False)
                if result.returncode != 0:
                    raise SyncError('control anchor cannot regress or change ancestry')
            self.document = current
            self._base_raw = raw
            if accepted == tip:
                return
            self.document.update(genesis=genesis, last_accepted_tip=tip, updated_at=_now_iso())
            self._write(current.copy())

    def get(self, key, default=None):
        return self.document.get(key, default)

    def set(self, **values) -> None:
        self.document.update(values)
        self.document["updated_at"] = _now_iso()
        self.save()


class _Remote:
    """Shared fetch/observe plumbing for one fixed branch on one fixed remote."""

    def __init__(self, workdir, remote: str, branch: str, *, trust=None,
                 checkpoint_path=None, genesis=None, anchor_path=None) -> None:
        self.workdir = Path(workdir)
        self.trust = trust
        self.checkpoint_path = checkpoint_path
        self.genesis = genesis
        self.anchor_path = anchor_path
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
        """Verify in bounded quarantine, then promote to a separate ref.

        Callers still recheck before moving their working branch/checkpoint.
        """
        _validate(candidate_branch, REF_NAME_RE, "candidate branch")
        from .git_ingestion import fetch_verified, IngestionError
        self.required_remote_tip()
        try:
            return fetch_verified(self.workdir, self.remote, self.ref,
                                  f'refs/heads/{candidate_branch}', self._verify_quarantine)
        except IngestionError as exc:
            # Missing is proven only by exact ls-remote no-match, never by a
            # fetch diagnostic that might instead be an authentication error.
            self.required_remote_tip()
            raise CandidateRejected(str(exc)) from exc

    def is_ancestor(self, earlier: str, later: str) -> bool:
        result = run_git(self.workdir, "merge-base", "--is-ancestor",
                         earlier, later, check=False)
        if result.returncode not in (0, 1):
            raise SyncError(
                f"ancestry query {earlier[:8]}..{later[:8]} failed")
        return result.returncode == 0


class RoomRemote(_Remote):
    """The signed room branch: fetch, verify a candidate, install, push by lease."""

    def _verify_quarantine(self, path, branch, tip):
        from .checkpoint import TrustCheckpoint, RollbackRejected
        from .gitstore import GitMessageStore
        from .git_ingestion import verify_local_artifacts
        if self.trust is None or self.checkpoint_path is None:
            raise SyncError('room ingestion requires pinned trust and checkpoint')
        checkpoint = TrustCheckpoint.load(self.checkpoint_path)
        ancestry = run_git(path, 'rev-list', tip).stdout.decode().splitlines()
        if checkpoint.document['last_accepted_tip'] not in ancestry:
            raise RollbackRejected('candidate does not descend from the last accepted tip')
        probe = GitMessageStore(path, branch=branch, trust=self.trust)
        report = checkpoint.verify_candidate(probe)
        verify_local_artifacts(GitMessageStore(self.workdir, branch=self.branch, trust=self.trust), probe)
        if report['candidate_tip'] != tip:
            raise SyncError('quarantine verification tip changed')

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
        except AgentRoomError as exc:
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

    def _verify_quarantine(self, path, branch, tip):
        from .control_store import ControlStore, MAX_REQUEST_BYTES, MAX_RESULT_BYTES
        if self.genesis is None or self.anchor_path is None:
            raise SyncError('control ingestion requires genesis pinned out of band and anchor path')
        anchor = Anchor(self.anchor_path, 'control-anchor')
        if anchor._base_raw is not None and anchor.document['genesis'] != self.genesis:
            raise SyncError('persisted control genesis changed')
        probe = ControlStore(path, branch)
        probe.verify_history()
        if probe.genesis() != self.genesis:
            raise SyncError('control genesis does not match pinned authority')
        if anchor._base_raw is not None:
            accepted = anchor.document['last_accepted_tip']
            if run_git(path, 'merge-base', '--is-ancestor', accepted, tip, check=False).returncode != 0:
                raise SyncError('control candidate does not descend from the accepted anchor; cannot regress')
        for artifact, commit in probe._history().items():
            size = int(_out(run_git(path, 'cat-file', '-s', f'{commit}:{artifact}')))
            if size > min(MAX_REQUEST_BYTES, MAX_RESULT_BYTES):
                raise SyncError('control payload exceeds ingestion limit')

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

"""Independently observed proof, recorded as an immutable artifact.

A builder saying "tests pass" is a report about a run nobody else watched. The
qualification harness therefore runs the agreed command itself and records what
it saw: the exact argv, the exit status, digests over the full output, a
bounded tail for humans, and the repository/snapshot identity the run was
against.

Issue #13 closed four holes in that, each one demonstrated rather than argued:

*The proof id reached the filesystem.* `proof_id="../escaped-proof"` wrote
outside the run directory. Ids now have a narrow grammar, and the resolved
artifact path is asserted to be inside the resolved run directory — so a
symlinked run directory cannot smuggle a write out either.

*"Immutable" artifacts were overwritable.* Two runs with the same id wrote the
same path and the second changed it. Artifacts are now content-addressed by
their own digest, created with `O_EXCL`, and left read-only. Re-running an id
produces a second artifact; it never rewrites the first.

*Timeouts left descendants running.* Proofs start their own process group and
the whole group is torn down on timeout — see `process.run_bounded`.

*Ignored files could change what ran without changing the binding.* A proof
now executes in a clean checkout reconstructed from the exact bound commit, so
an untracked or ignored `sitecustomize.py` beside the source is not there at
all. Three rules keep the rest honest: a non-zero exit is a result, a denied
command is evidence and is never retried differently, and artifacts live
outside the inspected checkout.
"""

import datetime as dt
import hashlib
import io
import os
import re
import shutil
import tarfile
import tempfile
import time
from pathlib import Path

from . import canonical
from .errors import AgentRoomError
from .limits import (
    MAX_PROOF_ARTIFACT_BYTES,
    MAX_PROOF_STREAM_BYTES,
    LimitExceeded,
    assert_within,
)
from .snapshot import FULL_OID_RE, verify_manifest
from .process import isolated_env, run_bounded, sanitised_env

PROOF_SCHEMA_VERSION = 2
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_TAIL_BYTES = 4096
GIT_TIMEOUT_SECONDS = 120

#: A proof id is a filename component and nothing else. No separators, no
#: traversal, no control characters, no leading dot — the grammar is what
#: makes containment provable rather than hopeful.
PROOF_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

#: Directories and files created here. Sensitive enough not to inherit a
#: group-writable umask; the artifact itself is read-only once written.
RUN_DIR_MODE = 0o700
ARTIFACT_MODE = 0o400

#: Excluded from `proof_sha256` because they describe where the record was
#: stored, not what was observed.
UNHASHED_FIELDS = ("artifact_path", "artifact_sha256", "proof_sha256")

__all__ = [
    "PROOF_SCHEMA_VERSION", "PROOF_ID_RE", "ProofError", "ProofArtifactConflict",
    "run_proof", "run_isolated_proof", "isolated_checkout", "proof_digest",
    "verify_proof", "verify_artifact", "proof_evidence", "validate_proof_id",
]


class ProofError(AgentRoomError):
    """The proof could not be observed or recorded."""


class ProofArtifactConflict(ProofError):
    """An artifact already exists at the content-addressed path.

    Only reachable when two runs produced byte-identical records, which is not
    a collision to resolve by overwriting.
    """


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_proof_id(proof_id) -> str:
    if not isinstance(proof_id, str) or not PROOF_ID_RE.match(proof_id):
        raise ProofError(
            f"proof_id {proof_id!r} must match {PROOF_ID_RE.pattern}: a single "
            "filename component, no path separators and no traversal. A proof "
            "id reaches the filesystem, so it is validated, not sanitised."
        )
    return proof_id


def _prepare_run_dir(run_dir, cwd_path: Path) -> Path:
    out_dir = Path(run_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=RUN_DIR_MODE)
    # Set explicitly as well as at creation: mkdir's mode is masked by umask,
    # and an existing directory keeps whatever it had.
    try:
        out_dir.chmod(RUN_DIR_MODE)
    except OSError:                                          # pragma: no cover
        pass
    resolved = out_dir.resolve()
    if resolved == cwd_path or cwd_path in resolved.parents:
        raise ProofError(
            f"proof artifacts must live outside the inspected checkout, but "
            f"{resolved} is inside {cwd_path}; writing there would change the "
            "state the proof is about"
        )
    return resolved


def _contained(run_dir: Path, name: str) -> Path:
    """Resolve an artifact path and prove it stayed inside `run_dir`."""
    candidate = (run_dir / name).resolve()
    if candidate != run_dir / name and run_dir not in candidate.parents:
        raise ProofError(
            f"artifact path {candidate} escapes the run directory {run_dir}"
        )
    if run_dir not in candidate.parents:
        raise ProofError(
            f"artifact path {candidate} is not inside the run directory {run_dir}"
        )
    return candidate


def proof_digest(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k not in UNHASHED_FIELDS}
    return hashlib.sha256(canonical.canonical_bytes(payload)).hexdigest()


def verify_proof(record: dict) -> None:
    recorded = record.get("proof_sha256")
    actual = proof_digest(record)
    if recorded != actual:
        raise ProofError(
            f"proof digest mismatch: recorded {recorded!r}, recomputed {actual}"
        )


def verify_artifact(path) -> dict:
    """Re-read a stored artifact and rehash it.

    The evidence locator names an observation; this is what makes that name
    resolve to bytes nobody has changed since. Both digests are checked: the
    file's own, and the record's.
    """
    artifact = Path(path)
    try:
        raw = artifact.read_bytes()
    except OSError as exc:
        raise ProofError(f"cannot read proof artifact {artifact}: {exc}") from exc
    stored = canonical.strict_loads(raw.decode("utf-8"))
    if not isinstance(stored, dict):
        raise ProofError(f"proof artifact {artifact} is not a JSON object")
    verify_proof({k: v for k, v in stored.items()
                  if k not in ("stdout", "stderr")})
    digest = hashlib.sha256(raw).hexdigest()
    expected = artifact.name.rsplit("-", 1)[-1][: -len(".json")]
    if not stored["proof_sha256"].startswith(expected):
        raise ProofError(
            f"proof artifact {artifact.name} does not carry the proof digest "
            f"its filename claims ({expected})"
        )
    return {"artifact_sha256": digest, "proof_sha256": stored["proof_sha256"],
            "record": stored}


def _tail(raw: bytes, limit: int) -> str:
    """The last `limit` bytes, decoded leniently. Truncation is stated."""
    if len(raw) <= limit:
        return raw.decode("utf-8", "replace")
    return (
        f"…[{len(raw) - limit} earlier bytes omitted]…\n"
        + raw[-limit:].decode("utf-8", "replace")
    )


def _write_artifact(run_dir: Path, proof_id: str, record: dict,
                    stdout: bytes, stderr: bytes) -> dict:
    """Content-addressed, exclusive-create, read-only once written."""
    body = {k: v for k, v in record.items() if k not in UNHASHED_FIELDS}
    body["proof_sha256"] = record["proof_sha256"]
    # Bounded at the source, so what is here is all that was ever accepted.
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        body[name] = raw.decode("utf-8", "replace")
    payload = canonical.canonical_text(body).encode("utf-8")
    assert_within(len(payload), MAX_PROOF_ARTIFACT_BYTES, "proof artifact")

    name = f"{proof_id}-{record['proof_sha256'][:16]}.json"
    artifact = _contained(run_dir, name)
    try:
        fd = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL, ARTIFACT_MODE)
    except FileExistsError as exc:
        raise ProofArtifactConflict(
            f"{artifact.name} already exists. Proof artifacts are write-once "
            "and content-addressed, so an identical digest means this exact "
            "observation is already recorded; it is never overwritten."
        ) from exc
    except OSError as exc:
        raise ProofError(f"cannot create proof artifact {artifact}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
    except OSError as exc:                                   # pragma: no cover
        raise ProofError(f"cannot write proof artifact {artifact}: {exc}") from exc
    return {"artifact_path": str(artifact),
            "artifact_sha256": hashlib.sha256(payload).hexdigest()}


def run_proof(
    command,
    *,
    cwd,
    run_dir,
    proof_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    env: dict | None = None,
    repo_commit: str | None = None,
    snapshot_sha256: str | None = None,
    tail_bytes: int = DEFAULT_TAIL_BYTES,
    isolation: dict | None = None,
) -> dict:
    """Run one command, observe it, and write an immutable record."""
    argv = [str(a) for a in command]
    if not argv:
        raise ProofError("a proof needs a command to run")
    validate_proof_id(proof_id)
    cwd_path = Path(cwd).resolve()
    out_dir = _prepare_run_dir(run_dir, cwd_path)

    started, clock = _now_iso(), time.monotonic()
    status, exit_status, error, teardown = "completed", None, None, ""
    stdout, stderr = b"", b""
    limited = False
    try:
        result = run_bounded(
            argv, cwd=cwd_path, timeout=timeout,
            env=env if env is not None else isolated_env(),
            max_output_bytes=MAX_PROOF_STREAM_BYTES,
        )
        stdout, stderr, teardown = result.stdout, result.stderr, result.teardown
        limited = result.output_limited
        if result.timed_out:
            status = "timeout"
            error = f"timed out after {timeout}s; process group {teardown}"
        elif limited:
            # Fail closed and say so. The command is never re-run with a
            # looser bound: a proof that floods its output is a result.
            status = "output_limited"
            error = (
                f"{', '.join(result.limited_streams)} exceeded the "
                f"{MAX_PROOF_STREAM_BYTES} byte hard limit; the process group "
                f"was {teardown}"
            )
        else:
            exit_status = result.returncode
    except AgentRoomError as exc:
        # Denied, missing, or unexecutable. Recorded as the outcome; never
        # worked around by running something else.
        status = "denied"
        error = f"{type(exc).__name__}: {exc}"

    record = {
        "proof_schema_version": PROOF_SCHEMA_VERSION,
        "proof_id": proof_id,
        "command": argv,
        "cwd": str(cwd_path),
        "status": status,
        "exit_status": exit_status,
        "error": error,
        "teardown": teardown,
        "started_at": started,
        "finished_at": _now_iso(),
        "duration_seconds": round(time.monotonic() - clock, 3),
        "repo_commit": repo_commit,
        "snapshot_sha256": snapshot_sha256,
        "isolation": isolation or {"mode": "in-place",
                                   "binds_execution_state": False},
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_tail": _tail(stdout, tail_bytes),
        "stderr_tail": _tail(stderr, tail_bytes),
        # Says exactly what the digests cover. When a hard output bound was
        # reached the process was killed mid-stream, so they cover the bytes
        # that were accepted and there are no "complete" bytes to speak of.
        "output_limited": limited,
        "digest_covers": "captured-prefix" if limited else "complete-output",
    }
    record["proof_sha256"] = proof_digest(record)
    record.update(_write_artifact(out_dir, proof_id, record, stdout, stderr))
    return record


def isolated_checkout(repo, commit: str, dest) -> dict:
    """Reconstruct exactly one commit's tracked content into `dest`.

    `git archive` rather than a worktree or a copy: the result contains the
    committed tree and nothing else — no `.git`, no untracked files, no ignored
    files, no `sitecustomize.py` that happened to be sitting beside the source.
    That is what makes a proof reproducible from a binding instead of from
    whatever the builder's machine also had lying around.

    The commit must be a full object id naming a commit. `HEAD`, `main~2` and
    `v1.0^{}` are all things `git archive` would happily accept and none of
    them is an immutable identity; a proof bound to one would be bound to
    whatever that expression resolved to at the time.
    """
    repo_path, dest_path = Path(repo), Path(dest)
    if not isinstance(commit, str) or not FULL_OID_RE.match(commit):
        raise ProofError(
            f"commit {commit!r} must be a full Git object id; revision syntax "
            "is not an immutable identity and cannot bind a proof"
        )
    kind = run_bounded(
        ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
         "cat-file", "-t", commit],
        cwd=repo_path, timeout=GIT_TIMEOUT_SECONDS, env=sanitised_env(),
    )
    if kind.stdout.decode("ascii", "replace").strip() != "commit":
        raise ProofError(
            f"{commit} is not a commit object in {repo_path}"
        )
    result = run_bounded(
        ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
         "archive", "--format=tar", commit],
        cwd=repo_path, timeout=GIT_TIMEOUT_SECONDS, env=sanitised_env(),
    )
    if result.returncode != 0:
        raise ProofError(
            f"cannot archive {commit} from {repo_path}: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    dest_path.mkdir(parents=True, exist_ok=True, mode=RUN_DIR_MODE)
    files = 0
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts:
                raise ProofError(
                    f"archive of {commit} contains an unsafe path {name!r}"
                )
            if member.issym() or member.islnk():
                raise ProofError(
                    f"archive of {commit} contains a link ({name!r}); a proof "
                    "checkout must not reach outside itself"
                )
            if member.isfile():
                files += 1
        # `filter="data"` is tar's own hardening: it refuses absolute paths,
        # traversal and links, and drops modes and ownership. The explicit
        # checks above stay because they name *why* each shape is refused, and
        # because a filter that changes behaviour between versions is not
        # something a trust boundary should depend on alone.
        archive.extractall(dest_path, filter="data")
    return {"mode": "git-archive", "commit": commit, "root": str(dest_path),
            "tracked_files": files, "binds_execution_state": True}


def run_isolated_proof(
    command,
    *,
    repo,
    commit: str,
    run_dir,
    proof_id: str,
    manifest: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    keep_checkout: bool = False,
    **kwargs,
) -> dict:
    """Run a proof against a clean checkout of `commit`, not a working tree.

    If a `manifest` is supplied it must describe exactly that commit with
    nothing uncommitted, because otherwise the checkout and the binding are
    different states and the proof would be evidence about neither.
    """
    validate_proof_id(proof_id)
    if manifest is not None:
        # Verify before believing anything it says. A manifest is just a dict
        # until its digest is recomputed from its own contents.
        verify_manifest(manifest)
        if manifest.get("head_commit") != commit:
            raise ProofError(
                f"the manifest was measured at head {manifest.get('head_commit')}, "
                f"not {commit}; an isolated proof must run on the state that "
                "was measured"
            )
        counts = manifest.get("counts") or {}
        # Staged counts too, and its omission was the hole: a staged change is
        # not in the commit, so `git archive` silently leaves it out and the
        # proof describes a state nobody measured.
        dirty = {k: counts.get(k, 0)
                 for k in ("staged_vs_head", "unstaged", "untracked")}
        if any(dirty.values()):
            raise ProofError(
                f"the measured state has uncommitted content ({dirty}); commit "
                "it before binding a proof to it, or the isolated checkout "
                "cannot reproduce what was measured. A staged change counts: "
                "the archive is built from the commit, not from the index."
            )
        # The binding comes from the verified manifest, never from the caller.
        supplied = kwargs.pop("snapshot_sha256", None)
        if supplied is not None and supplied != manifest["manifest_sha256"]:
            raise ProofError(
                f"the supplied snapshot digest {supplied[:12]}… contradicts the "
                f"manifest's own {manifest['manifest_sha256'][:12]}…; an "
                "isolated proof derives its binding from the manifest it "
                "verified"
            )
        kwargs["snapshot_sha256"] = manifest["manifest_sha256"]
    elif kwargs.get("snapshot_sha256") is not None:
        raise ProofError(
            "a snapshot digest without the manifest it came from binds "
            "nothing checkable; pass the manifest instead"
        )

    parent = Path(run_dir).resolve().parent
    workdir = Path(tempfile.mkdtemp(prefix=f"agent-room-proof-{proof_id}-",
                                    dir=parent))
    try:
        isolation = isolated_checkout(repo, commit, workdir / "tree")
        return run_proof(
            command, cwd=workdir / "tree", run_dir=run_dir, proof_id=proof_id,
            timeout=timeout, repo_commit=commit, isolation=isolation,
            env=isolated_env(), **kwargs,
        )
    finally:
        if not keep_checkout:
            shutil.rmtree(workdir, ignore_errors=True)


def proof_evidence(record: dict, *, commit: str) -> dict:
    """The proof as an Agent Room `run` evidence locator.

    `run_id` is the proof digest, so the reference names the observation
    itself rather than a mutable file path — a locator that cannot be swapped
    for a different run after the fact, and which `verify_artifact` can check
    the stored bytes against.
    """
    return {
        "kind": "run",
        "commit": commit,
        "run_id": record["proof_sha256"],
    }

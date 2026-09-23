"""Independently observed proof, recorded as an immutable artifact.

A builder saying "tests pass" is a report about a run nobody else watched. The
qualification harness therefore runs the agreed command itself and records
what it saw: the exact argv, the exit status, digests over the full output,
a bounded tail for humans, and the repository/snapshot identity the run was
against.

Three rules keep this honest.

*A non-zero exit is a result, not a harness failure.* A falsification test that
fails is exactly the outcome worth recording.

*A denied command is evidence.* If the command cannot be executed — permission
refused, not found, timed out — that is recorded as the outcome. It is never
retried with different flags or quietly downgraded to a different command.

*Artifacts live outside the checkout.* Writing a run log into the repository
being inspected would change the very snapshot the proof is about.
"""

import datetime as dt
import hashlib
import os
import subprocess
import time
from pathlib import Path

from . import canonical
from .errors import AgentRoomError

PROOF_SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_TAIL_BYTES = 4096

#: Excluded from `proof_sha256` because they describe where the record was
#: stored, not what was observed.
UNHASHED_FIELDS = ("artifact_path", "artifact_sha256", "proof_sha256")

__all__ = [
    "PROOF_SCHEMA_VERSION", "ProofError", "run_proof", "proof_digest",
    "verify_proof", "proof_evidence",
]


class ProofError(AgentRoomError):
    """The proof could not be observed or recorded."""


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _tail(raw: bytes, limit: int) -> str:
    """The last `limit` bytes, decoded leniently. Truncation is stated."""
    if len(raw) <= limit:
        return raw.decode("utf-8", "replace")
    return (
        f"…[{len(raw) - limit} earlier bytes omitted]…\n"
        + raw[-limit:].decode("utf-8", "replace")
    )


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
) -> dict:
    """Run one command, observe it, and write an immutable record."""
    argv = [str(a) for a in command]
    if not argv:
        raise ProofError("a proof needs a command to run")
    cwd_path = Path(cwd).resolve()
    out_dir = Path(run_dir).resolve()
    if out_dir == cwd_path or cwd_path in out_dir.parents:
        raise ProofError(
            f"proof artifacts must live outside the inspected checkout, but "
            f"{out_dir} is inside {cwd_path}; writing there would change the "
            "state the proof is about"
        )
    out_dir.mkdir(parents=True, exist_ok=True)

    started, clock = _now_iso(), time.monotonic()
    status, exit_status, error = "completed", None, None
    stdout, stderr = b"", b""
    try:
        proc = subprocess.run(
            argv, cwd=cwd_path, capture_output=True, timeout=timeout,
            env=env if env is not None else os.environ.copy(),
        )
        exit_status, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        error = f"timed out after {timeout}s"
    except (OSError, ValueError) as exc:
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
        "started_at": started,
        "finished_at": _now_iso(),
        "duration_seconds": round(time.monotonic() - clock, 3),
        "repo_commit": repo_commit,
        "snapshot_sha256": snapshot_sha256,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_tail": _tail(stdout, tail_bytes),
        "stderr_tail": _tail(stderr, tail_bytes),
    }
    record["proof_sha256"] = proof_digest(record)

    artifact = out_dir / f"{proof_id}.json"
    payload = canonical.canonical_text({
        **{k: v for k, v in record.items() if k not in UNHASHED_FIELDS},
        "proof_sha256": record["proof_sha256"],
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
    })
    artifact.write_text(payload, encoding="utf-8")
    record["artifact_path"] = str(artifact)
    record["artifact_sha256"] = hashlib.sha256(
        payload.encode("utf-8")).hexdigest()
    return record


def proof_evidence(record: dict, *, commit: str) -> dict:
    """The proof as an Agent Room `run` evidence locator.

    `run_id` is the proof digest, so the reference names the observation
    itself rather than a mutable file path — a locator that cannot be
    swapped for a different run after the fact.
    """
    return {
        "kind": "run",
        "commit": commit,
        "run_id": record["proof_sha256"],
    }

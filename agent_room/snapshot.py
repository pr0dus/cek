"""Deterministic manifest of the state that was actually inspected.

Issue #5 borrows this from the Claudex loop for one reason: a review is only
meaningful about a *specific* state, and a builder's own list of what it
changed is a report, not a measurement. So nothing here is supplied by the
builder. Every path is discovered from Git and every digest is computed from
the bytes on disk.

Four independent comparisons are recorded per path, because "changed" is not
one question:

- base vs worktree — what a reviewer would actually read;
- base vs index — what is staged;
- index vs worktree — what is staged but since edited again;
- untracked — files Git is not yet tracking at all.

Deletions, symlinks and mode changes are entries like any other. A symlink is
hashed over its *target*, never followed: following it would silently hash a
file outside the snapshot.

`manifest_sha256` covers all of it. If the checkout moves after a review, the
recomputed manifest differs, and the earlier review is stale for the new
state. That is the whole mechanism — no timestamps, no similarity.
"""

import hashlib
import os
import re
import subprocess
from pathlib import Path

from . import canonical
from .errors import AgentRoomError

SNAPSHOT_SCHEMA_VERSION = 1
GIT_TIMEOUT_SECONDS = 60

#: Same rule the envelope schema uses: an abbreviation is not an identity.
FULL_OID_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

#: Not hashed, so it is excluded from the digest payload rather than being
#: allowed to make an otherwise identical snapshot machine-specific.
UNHASHED_FIELDS = ("manifest_sha256",)

__all__ = [
    "SNAPSHOT_SCHEMA_VERSION", "SnapshotError",
    "snapshot_manifest", "manifest_digest", "verify_manifest",
]


class SnapshotError(AgentRoomError):
    """The inspected state could not be measured."""


def _git(workdir: Path, *args: str, check: bool = True) -> bytes:
    """Raw bytes, because a path may be any byte sequence but NUL."""
    command = ["git", "--no-replace-objects", *args]
    try:
        proc = subprocess.run(
            command, cwd=workdir, capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SnapshotError(f"git {' '.join(args)} timed out in {workdir}") from exc
    except (ValueError, OSError) as exc:
        raise SnapshotError(
            f"git {' '.join(args)} could not be executed in {workdir}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if check and proc.returncode != 0:
        raise SnapshotError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


def _decode(raw: bytes) -> str:
    """Paths are surrogate-escaped rather than rejected.

    A non-UTF-8 filename is unusual but legal, and dropping it would be the
    one failure mode this manifest exists to prevent.
    """
    return raw.decode("utf-8", "surrogateescape")


def _name_status(workdir: Path, *args: str) -> dict:
    """Parse `--name-status -z` into {path: status letter}.

    `-z` is not optional: without it Git quotes unusual paths, and a quoted
    path would parse into something that is not the file on disk.
    """
    out = _git(workdir, "diff", "--name-status", "-z", "--no-renames", *args)
    tokens = out.split(b"\0")
    result: dict = {}
    i = 0
    while i + 1 < len(tokens):
        status = tokens[i].decode("ascii", "replace").strip()
        path = tokens[i + 1]
        i += 2
        if not status:
            continue
        result[_decode(path)] = status[:1]
    return result


def _untracked(workdir: Path) -> list:
    out = _git(workdir, "ls-files", "-z", "--others", "--exclude-standard")
    return [_decode(p) for p in out.split(b"\0") if p]


def _entry(workdir: Path, path: str, base_wt, base_index, index_wt,
           tracked: bool) -> dict:
    """Measure one path on disk. Never follows a symlink."""
    full = workdir / path
    kind, mode, size, digest = "absent", None, None, None
    try:
        st = os.lstat(full)
    except OSError:
        st = None
    if st is not None:
        mode = format(st.st_mode, "06o")
        if os.path.islink(full):
            kind = "symlink"
            target = os.readlink(full).encode("utf-8", "surrogateescape")
            size = len(target)
            digest = hashlib.sha256(target).hexdigest()
        elif os.path.isdir(full):
            # A gitlink (submodule) or a path replaced by a directory. Recorded
            # as what it is; its contents are not this repository's state.
            kind = "directory"
        elif os.path.isfile(full):
            kind = "file"
            data = full.read_bytes()
            size = len(data)
            digest = hashlib.sha256(data).hexdigest()
        else:
            kind = "special"
    return {
        "path": path,
        "tracked": tracked,
        "base_vs_worktree": base_wt,
        "base_vs_index": base_index,
        "index_vs_worktree": index_wt,
        "kind": kind,
        "mode": mode,
        "size": size,
        "sha256": digest,
    }


def manifest_digest(manifest: dict) -> str:
    payload = {k: v for k, v in manifest.items() if k not in UNHASHED_FIELDS}
    return hashlib.sha256(canonical.canonical_bytes(payload)).hexdigest()


def verify_manifest(manifest: dict) -> None:
    recorded = manifest.get("manifest_sha256")
    actual = manifest_digest(manifest)
    if recorded != actual:
        raise SnapshotError(
            f"snapshot manifest digest mismatch: recorded {recorded!r}, "
            f"recomputed {actual}"
        )


def snapshot_manifest(workdir, base_commit: str) -> dict:
    """Measure the inspected state of `workdir` against `base_commit`."""
    path = Path(workdir)
    if not isinstance(base_commit, str) or not FULL_OID_RE.match(base_commit):
        raise SnapshotError(
            f"base_commit {base_commit!r} must be a full Git object id; an "
            "abbreviation is not an immutable baseline"
        )
    kind = _git(path, "cat-file", "-t", base_commit, check=False)
    if kind.decode("ascii", "replace").strip() != "commit":
        raise SnapshotError(
            f"base_commit {base_commit} is not a commit in {path}"
        )

    base_wt = _name_status(path, base_commit)
    base_index = _name_status(path, "--cached", base_commit)
    index_wt = _name_status(path)
    untracked = _untracked(path)

    head = _git(path, "rev-parse", "HEAD", check=False).decode("ascii", "replace").strip()
    tracked_paths = set(base_wt) | set(base_index) | set(index_wt)
    entries = [
        _entry(path, p, base_wt.get(p), base_index.get(p), index_wt.get(p), True)
        for p in sorted(tracked_paths)
    ]
    entries += [
        _entry(path, p, None, None, None, False)
        for p in sorted(set(untracked) - tracked_paths)
    ]
    entries.sort(key=lambda e: e["path"])

    # Exact bytes of the diff a reviewer would read, so a change that leaves
    # the per-file digests alone (a mode flip, say) still moves the manifest.
    diff = _git(
        path, "diff", "--no-color", "--no-ext-diff", "--no-textconv",
        "--no-renames", "--binary", base_commit, "--",
    )

    manifest = {
        "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "base_commit": base_commit,
        "head_commit": head or None,
        "entries": entries,
        "counts": {
            "changed_vs_base": sum(1 for e in entries if e["base_vs_worktree"]),
            "staged": sum(1 for e in entries if e["base_vs_index"]),
            "unstaged": sum(1 for e in entries if e["index_vs_worktree"]),
            "deleted": sum(1 for e in entries if e["base_vs_worktree"] == "D"),
            "untracked": sum(1 for e in entries if not e["tracked"]),
            "symlinks": sum(1 for e in entries if e["kind"] == "symlink"),
        },
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
    }
    manifest["manifest_sha256"] = manifest_digest(manifest)
    return manifest

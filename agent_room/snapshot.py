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
from .process import run_bounded, sanitised_env

SNAPSHOT_SCHEMA_VERSION = 2
GIT_TIMEOUT_SECONDS = 60

#: What this manifest does and does not bind, stated inside the hashed payload
#: so it cannot be read as a stronger claim than it is. Tracked content is
#: measured byte for byte; ignored content is *named* but never hashed, and a
#: proof that must be bound to execution state runs in an isolated checkout
#: (`proof.run_isolated_proof`) rather than in this working tree.
BINDS = "tracked-content-only"

#: Ignored paths listed individually before the list is truncated. `git` is
#: asked to collapse ignored directories, so a virtualenv is one entry, not
#: forty thousand.
MAX_IGNORED_SAMPLE = 256

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
    """Raw bytes, because a path may be any byte sequence but NUL.

    Runs with a sanitised environment and hooks disabled. Measuring a
    repository with the caller's `GIT_DIR`, `GIT_OBJECT_DIRECTORY` or
    `core.hooksPath` in force would measure whatever those pointed at, and
    would execute whatever a hook in the inspected repository contained.
    """
    command = [
        "git", "--no-replace-objects",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        *args,
    ]
    result = run_bounded(
        command, cwd=workdir, timeout=GIT_TIMEOUT_SECONDS,
        env=sanitised_env(GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0"),
    )
    if result.timed_out:
        raise SnapshotError(f"git {' '.join(args)} timed out in {workdir}")
    if check and result.returncode != 0:
        raise SnapshotError(
            f"git {' '.join(args)} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def assert_object_hygiene(workdir: Path) -> None:
    """Refuse to measure a checkout whose object resolution is overridden.

    Replacement refs, grafts and alternate object directories all make Git
    answer a question about objects that are not the ones committed here.
    `--no-replace-objects` disables one of them for our own commands; their
    *presence* still says this is not a checkout whose measurements mean what
    they appear to mean.
    """
    replaced = _git(workdir, "for-each-ref", "--format=%(refname)",
                    "refs/replace/", check=False)
    refs = [r for r in replaced.decode("utf-8", "replace").split() if r]
    if refs:
        raise SnapshotError(
            f"{workdir} has history replacement refs ({refs[:3]}); a snapshot "
            "of it would not describe the committed objects"
        )
    git_dir = Path(
        _git(workdir, "rev-parse", "--git-common-dir").decode().strip() or ".git")
    if not git_dir.is_absolute():
        git_dir = workdir / git_dir
    for name, what in (("info/grafts", "a legacy graft file"),
                       ("objects/info/alternates", "alternate object directories")):
        candidate = git_dir / name
        try:
            if candidate.exists() and candidate.read_text(encoding="utf-8").strip():
                raise SnapshotError(
                    f"{candidate} is non-empty ({what}); object resolution in "
                    "this checkout is not self-contained, so a measurement of "
                    "it cannot be trusted"
                )
        except OSError as exc:
            raise SnapshotError(f"cannot read {candidate}: {exc}") from exc


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


def _ignored(workdir: Path) -> dict:
    """Name the ignored paths; never hash their contents.

    Ignored files can change what a command in this tree actually executes — a
    `sitecustomize.py` is the demonstrated case — so a manifest that omitted
    them entirely invited the reading that it bound execution state. It did
    not, and it still does not.

    What is recorded is the *set of names*, digested. Adding or removing an
    ignored path moves the manifest; editing one already present does not, and
    that limitation is why `binds` says `tracked-content-only` and why a proof
    that must be bound to execution state runs from an isolated checkout
    instead of from here. Hashing a virtualenv would be theatre, not binding.
    """
    out = _git(workdir, "ls-files", "-z", "--others", "--ignored",
               "--exclude-standard", "--directory", "--no-empty-directory")
    paths = sorted(_decode(p) for p in out.split(b"\0") if p)
    return {
        "count": len(paths),
        "paths_sha256": hashlib.sha256(
            canonical.canonical_bytes(paths)).hexdigest(),
        "sample": paths[:MAX_IGNORED_SAMPLE],
        "sample_truncated": len(paths) > MAX_IGNORED_SAMPLE,
        "contents_measured": False,
    }


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
    assert_object_hygiene(path)
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
        "binds": BINDS,
        "base_commit": base_commit,
        "head_commit": head or None,
        "entries": entries,
        "ignored": _ignored(path),
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

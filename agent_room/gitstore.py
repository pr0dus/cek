"""Git-backed append-only message store.

Git is the durable substrate, reusing what the existing bridge already proves
at ~1000 requests (design §1.6): a dedicated branch gives history, auth,
replication and audit for free, with no database and no daemon.

Two properties matter and are enforced here rather than assumed:

*Append-only.* One immutable file per message. A second write of the same
message_id with identical content is idempotent; with different content it is
refused. History is never rewritten to resolve a conflict.

*Deterministic ordering.* Reads come from commit history, never from the
filesystem — `git log` in commit order, exactly as the bridge discovers
requests. Filenames are UUIDv7s and mtimes are an artifact of checkout, so
neither may decide order.

Append-only is enforced *mechanically*, not assumed. Every message blob is read
from the commit that added it, and the full history of the message tree is
scanned for any later modify/delete/rename. A digest alone cannot catch a
rewrite — an attacker who edits a message can simply recompute it — so the
add-event history is the authority, and any later mutation of a committed path
fails the read closed.

Writes are pinned to the configured branch. A store aimed at `agent-room` must
be physically unable to commit onto `main` or repurpose someone's checkout.
"""

import json
import subprocess
from pathlib import Path
from typing import Iterator

from . import canonical
from .errors import (
    AgentRoomError,
    AppendOnlyViolation,
    ConflictError,
    PushRaceError,
    WrongBranchError,
)
from .schema import validate_envelope

MESSAGES_DIR = ".agent-room/messages"
DEFAULT_BRANCH = "agent-room"
GIT_TIMEOUT_SECONDS = 60
DEFAULT_PUSH_RETRIES = 3


class GitMessageStore:
    """Append-only message log on a dedicated Git branch.

    `workdir` is a git repository whose checkout is dedicated to `branch`.
    `remote` is optional: without it the store is purely local, which is what
    the tests use and what keeps unit runs off any real transport branch.
    """

    def __init__(
        self,
        workdir: str | Path,
        branch: str = DEFAULT_BRANCH,
        remote: str | None = None,
        *,
        push_retries: int = DEFAULT_PUSH_RETRIES,
        author: tuple[str, str] = ("agent-room", "agent-room@localhost"),
    ) -> None:
        self.workdir = Path(workdir)
        self.branch = branch
        self.remote = remote
        self.push_retries = int(push_retries)
        if self.push_retries < 1:
            raise ValueError("push_retries must be >= 1")
        self.author = author

    # -- git plumbing ------------------------------------------------------
    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.workdir,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
        if check and proc.returncode != 0:
            raise AgentRoomError(
                f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
            )
        return proc

    @classmethod
    def initialise(
        cls, workdir: str | Path, branch: str = DEFAULT_BRANCH, **kwargs
    ) -> "GitMessageStore":
        """Create `workdir` as a repo with `branch` as an orphan history.

        Orphan because the room must never carry research code, and its branch
        must never be merged into main (design §7.1).
        """
        path = Path(workdir)
        path.mkdir(parents=True, exist_ok=True)
        store = cls(path, branch, **kwargs)
        if not (path / ".git").exists():
            store._git("init", "-q")

        has_branch = store._git("rev-parse", "--verify", branch, check=False).returncode == 0
        current = store.current_branch()

        if has_branch:
            # Never switch someone's checkout for them; just refuse.
            if current != branch:
                raise WrongBranchError(
                    f"{path} already exists with {current or 'a detached HEAD'} "
                    f"checked out; refusing to repurpose it for room branch "
                    f"{branch!r}. Use a dedicated checkout."
                )
            return store

        # Creating the branch is only safe in a repo that is not already
        # somebody's working checkout.
        has_commits = store._git("rev-parse", "--verify", "HEAD", check=False).returncode == 0
        if has_commits:
            raise WrongBranchError(
                f"{path} is an existing repository on {current or 'a detached HEAD'} "
                f"and has no {branch!r} branch; refusing to create room history "
                "inside an unrelated checkout. Use a dedicated directory."
            )

        store._git("checkout", "-q", "--orphan", branch)
        store._git("rm", "-rq", "--cached", ".", check=False)
        readme = path / "README.agent-room.md"
        readme.write_text(
            "# agent-room\n\n"
            "Dedicated append-only branch for Agent Room message traffic.\n"
            "This branch is separate from main and must never be merged into it.\n\n"
            f"Paths:\n- {MESSAGES_DIR}/<thread_id>/<message_id>.json\n",
            encoding="utf-8",
        )
        store._git("add", "README.agent-room.md")
        store._commit("agent-room: initialise append-only message branch")
        return store

    def _commit(self, message: str) -> str:
        self.assert_room_branch()
        self._git(
            "-c", f"user.name={self.author[0]}",
            "-c", f"user.email={self.author[1]}",
            "commit", "-q", "-m", message,
        )
        return self._git("rev-parse", "HEAD").stdout.strip()

    # -- paths -------------------------------------------------------------
    @staticmethod
    def message_path(thread_id: str, message_id: str) -> str:
        return f"{MESSAGES_DIR}/{thread_id}/{message_id}.json"

    # -- branch pinning ----------------------------------------------------
    def current_branch(self) -> str | None:
        """The checked-out branch name, or None on a detached HEAD."""
        proc = self._git("symbolic-ref", "--quiet", "--short", "HEAD", check=False)
        return proc.stdout.strip() or None

    def assert_room_branch(self) -> None:
        """Fail closed unless this checkout is the configured room branch.

        Called before every write, commit and rebase. The room branch must
        never be merged into main (design §7.1); the mirror of that rule is
        that room traffic must never be committed onto anything else.
        """
        current = self.current_branch()
        if current != self.branch:
            raise WrongBranchError(
                f"{self.workdir} has {current or 'a detached HEAD'} checked out, "
                f"not the configured room branch {self.branch!r}; refusing to write"
            )

    # -- history (the authority for what was actually committed) -----------
    def _history(self) -> dict:
        """Map message path -> add commit, rejecting any later mutation.

        One `git log` over the message tree. A path must appear exactly once
        as an addition and never again: a later M/D/R means committed history
        was rewritten, which the append-only model forbids.
        """
        tip = self._git("rev-parse", self.branch, check=False)
        if tip.returncode != 0:
            return {}
        tip_sha = tip.stdout.strip()
        cached = getattr(self, "_history_cache", None)
        if cached is not None and cached[0] == tip_sha:
            return cached[1]

        proc = self._git(
            "log", self.branch, "--reverse", "--format=%H",
            "--name-status", "--no-renames", "--", MESSAGES_DIR,
            check=False,
        )
        if proc.returncode != 0:
            return {}

        added: dict[str, str] = {}
        commit = ""
        for line in proc.stdout.splitlines():
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if "\t" not in line and len(line) >= 40 and all(
                c in "0123456789abcdef" for c in line.strip()
            ):
                commit = line.strip()
                continue
            parts = line.split("\t")
            status = parts[0].strip()
            paths = [p for p in parts[1:] if p]
            for path in paths:
                if not (path.startswith(f"{MESSAGES_DIR}/") and path.endswith(".json")):
                    continue
                if status.startswith("A"):
                    if path in added:
                        raise AppendOnlyViolation(
                            f"{path} was added twice (second add in {commit})"
                        )
                    added[path] = commit
                else:
                    raise AppendOnlyViolation(
                        f"{path} was {status!r} in commit {commit} after being "
                        "committed; message history is append-only and must not "
                        "be modified, deleted or renamed"
                    )

        self._history_cache = (tip_sha, added)
        return added

    def verify_append_only(self) -> int:
        """Re-scan history. Raises on violation; returns the message count."""
        return len(self._history())

    # -- reads (from the add commit, never the branch tip) -----------------
    def _blob_at(self, commit: str, path: str) -> str | None:
        proc = self._git("show", f"{commit}:{path}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    def _load(self, path: str, commit: str) -> dict:
        """Read one message as originally committed, fully validated."""
        raw = self._blob_at(commit, path)
        if raw is None:
            raise AppendOnlyViolation(
                f"{path} is missing from its own add commit {commit}"
            )
        envelope = json.loads(raw)
        canonical.verify(envelope)
        # Structural validation at the trust boundary: a correctly resealed
        # but malformed artifact, or one written by another participant's
        # library, must still fail loudly. agent_facing=False so the reserved
        # Issue #5 types stay structurally readable.
        validate_envelope(envelope, agent_facing=False)
        return envelope

    def exists(self, thread_id: str, message_id: str) -> bool:
        return self.message_path(thread_id, message_id) in self._history()

    def read(self, thread_id: str, message_id: str) -> dict:
        """Load one message as committed. Raises on tamper or deletion."""
        path = self.message_path(thread_id, message_id)
        history = self._history()
        if path not in history:
            raise AgentRoomError(f"no such message: {thread_id}/{message_id}")
        return self._load(path, history[path])

    def _added_paths_in_order(self, subdir: str | None = None) -> list[str]:
        """Message paths in commit-add order — the deterministic ordering.

        Mirrors the bridge's proven discovery: only *added* files, in commit
        order. Independent of mtime and of filename sort.
        """
        prefix = f"{MESSAGES_DIR}/{subdir}/" if subdir else f"{MESSAGES_DIR}/"
        return [p for p in self._history() if p.startswith(prefix)]

    def thread_ids(self) -> list[str]:
        threads: list[str] = []
        for path in self._added_paths_in_order():
            thread = path.split("/")[2]
            if thread not in threads:
                threads.append(thread)
        return threads

    def thread_messages(self, thread_id: str) -> list[dict]:
        """Every message in a thread, in deterministic commit-add order."""
        history = self._history()
        return [
            self._load(path, history[path])
            for path in self._added_paths_in_order(thread_id)
        ]

    def iter_messages(self) -> Iterator[dict]:
        history = self._history()
        for path in self._added_paths_in_order():
            yield self._load(path, history[path])

    def resolve_message(self, message_id: str) -> dict | None:
        """Look a message up by id alone. Used to resolve references."""
        history = self._history()
        for path in history:
            if path.rsplit("/", 1)[-1] == f"{message_id}.json":
                return self._load(path, history[path])
        return None

    # -- append ------------------------------------------------------------
    def append(self, envelope: dict, *, resolver=None) -> dict:
        """Commit one sealed envelope.

        Returns `{"status": "created"|"duplicate", "commit": sha, ...}`.
        Identical re-submission is idempotent; same id with different content
        raises `ConflictError` and never overwrites.

        Validation happens here, not only in the caller: `append` is an
        exported trust boundary, so a malformed envelope with a correct digest
        must be refused even when it arrives through the low-level library.
        """
        self.assert_room_branch()
        canonical.verify(envelope)
        validate_envelope(
            envelope,
            agent_facing=False,
            resolver=resolver if resolver is not None else self,
        )

        thread_id = envelope["thread_id"]
        message_id = envelope["message_id"]
        rel = self.message_path(thread_id, message_id)

        history = self._history()
        if rel in history:
            existing = self._load(rel, history[rel])
            if existing.get(canonical.DIGEST_FIELD) == envelope[canonical.DIGEST_FIELD]:
                return {
                    "status": "duplicate",
                    "message_id": message_id,
                    "thread_id": thread_id,
                    "commit": history[rel],
                    "path": rel,
                }
            raise ConflictError(
                f"message_id {message_id} already exists with a different digest "
                f"({existing.get(canonical.DIGEST_FIELD)} != "
                f"{envelope[canonical.DIGEST_FIELD]}); refusing to overwrite"
            )

        target = self.workdir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # Written in canonical form so the committed bytes are exactly what
        # the digest covers.
        target.write_text(canonical.canonical_text(envelope), encoding="utf-8")
        self._git("add", rel)
        commit = self._commit(f"agent-room: {envelope['type']} {message_id}")

        result = {
            "status": "created",
            "message_id": message_id,
            "thread_id": thread_id,
            "commit": commit,
            "path": rel,
        }
        if self.remote:
            result["push"] = self.push()
        return result

    # -- push with bounded retry -------------------------------------------
    def push(self) -> dict:
        """Push with bounded fetch/rebase-or-retry. Never loops forever.

        Two writers never target the same message path, so a race shows up
        only as a non-fast-forward on the branch ref (design §5). Rebasing our
        own commits on top of theirs preserves both.
        """
        if not self.remote:
            return {"pushed": False, "reason": "no remote configured"}

        self.assert_room_branch()
        last_error = ""
        for attempt in range(1, self.push_retries + 1):
            proc = self._git("push", self.remote, f"{self.branch}:{self.branch}", check=False)
            if proc.returncode == 0:
                return {"pushed": True, "attempts": attempt}
            last_error = proc.stderr.strip()

            # Only a *fetchable* remote branch can have moved under us. If the
            # fetch fails there is nothing to rebase onto, and the rejection
            # was something other than a race (a hook, permissions, a missing
            # branch) - retry within the bound and report that instead of
            # misattributing it to a failed rebase.
            fetched = self._git("fetch", "-q", self.remote, self.branch, check=False)
            if fetched.returncode != 0:
                continue

            rebase = self._git("rebase", "-q", "FETCH_HEAD", check=False)
            if rebase.returncode != 0:
                self._git("rebase", "--abort", check=False)
                raise PushRaceError(
                    f"rebase onto {self.remote}/{self.branch} failed on attempt "
                    f"{attempt}: {rebase.stderr.strip() or last_error}"
                )
        raise PushRaceError(
            f"push rejected after {self.push_retries} attempts: {last_error}"
        )

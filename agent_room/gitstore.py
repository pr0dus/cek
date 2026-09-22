"""Git-backed append-only message store.

Git is the durable substrate, reusing what the existing bridge already proves
at ~1000 requests (design §1.6): a dedicated branch gives history, auth,
replication and audit for free, with no database and no daemon.

Two properties matter and are enforced here rather than assumed:

*Append-only.* One immutable file per message. A second write of the same
message_id with identical content is idempotent; with different content it is
refused. History is never rewritten to resolve a conflict.

*Deterministic ordering.* Reads come from commit history, never from the
filesystem — `git log --diff-filter=A` in commit order, exactly as the bridge
discovers requests. Filenames are UUIDv7s and mtimes are an artifact of
checkout, so neither may decide order.
"""

import json
import subprocess
from pathlib import Path
from typing import Iterator

from . import canonical
from .errors import AgentRoomError, ConflictError, PushRaceError

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
        existing = store._git("rev-parse", "--verify", branch, check=False)
        if existing.returncode != 0:
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

    # -- reads (history, never the filesystem) -----------------------------
    def _show(self, path: str) -> str | None:
        proc = self._git("show", f"{self.branch}:{path}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    def exists(self, thread_id: str, message_id: str) -> bool:
        return self._show(self.message_path(thread_id, message_id)) is not None

    def read(self, thread_id: str, message_id: str) -> dict:
        """Load one message, verifying its digest. Raises on tamper."""
        raw = self._show(self.message_path(thread_id, message_id))
        if raw is None:
            raise AgentRoomError(f"no such message: {thread_id}/{message_id}")
        envelope = json.loads(raw)
        canonical.verify(envelope)
        return envelope

    def _added_paths_in_order(self, subdir: str | None = None) -> list[str]:
        """Message paths in commit-add order — the deterministic ordering.

        Mirrors the bridge's proven discovery: only *added* files, in commit
        order. Independent of mtime and of filename sort.
        """
        target = f"{MESSAGES_DIR}/{subdir}" if subdir else MESSAGES_DIR
        proc = self._git(
            "log", self.branch, "--reverse", "--diff-filter=A",
            "--format=%H", "--name-only", "--", target,
            check=False,
        )
        if proc.returncode != 0:
            return []
        seen: list[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith(f"{MESSAGES_DIR}/") and line.endswith(".json"):
                if line not in seen:
                    seen.append(line)
        return seen

    def thread_ids(self) -> list[str]:
        threads: list[str] = []
        for path in self._added_paths_in_order():
            thread = path.split("/")[2]
            if thread not in threads:
                threads.append(thread)
        return threads

    def thread_messages(self, thread_id: str) -> list[dict]:
        """Every message in a thread, in deterministic commit-add order."""
        out = []
        for path in self._added_paths_in_order(thread_id):
            raw = self._show(path)
            if raw is None:
                continue
            envelope = json.loads(raw)
            canonical.verify(envelope)
            out.append(envelope)
        return out

    def iter_messages(self) -> Iterator[dict]:
        for path in self._added_paths_in_order():
            raw = self._show(path)
            if raw is None:
                continue
            envelope = json.loads(raw)
            canonical.verify(envelope)
            yield envelope

    # -- append ------------------------------------------------------------
    def append(self, envelope: dict) -> dict:
        """Commit one sealed envelope.

        Returns `{"status": "created"|"duplicate", "commit": sha, ...}`.
        Identical re-submission is idempotent; same id with different content
        raises `ConflictError` and never overwrites.
        """
        canonical.verify(envelope)
        thread_id = envelope["thread_id"]
        message_id = envelope["message_id"]
        rel = self.message_path(thread_id, message_id)

        existing_raw = self._show(rel)
        if existing_raw is not None:
            existing = json.loads(existing_raw)
            if existing.get(canonical.DIGEST_FIELD) == envelope[canonical.DIGEST_FIELD]:
                return {
                    "status": "duplicate",
                    "message_id": message_id,
                    "thread_id": thread_id,
                    "commit": self._git("rev-parse", self.branch).stdout.strip(),
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

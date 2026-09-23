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

import fcntl
import json
import os
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import canonical
from .errors import (
    AgentRoomError,
    AppendOnlyViolation,
    ConflictError,
    DeliveryError,
    DirtyCheckoutError,
    GitTimeout,
    LockTimeout,
    PushRaceError,
    SchemaError,
    UnresolvedReference,
    WrongBranchError,
)
from .ids import is_uuid7
from .schema import THREAD_ID_RE, validate_envelope

MESSAGES_DIR = ".agent-room/messages"
DEFAULT_BRANCH = "agent-room"
GIT_TIMEOUT_SECONDS = 60
DEFAULT_PUSH_RETRIES = 3
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
LOCK_POLL_SECONDS = 0.05
WRITER_LOCK_NAME = "agent-room-writer.lock"


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
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
        author: tuple[str, str] = ("agent-room", "agent-room@localhost"),
    ) -> None:
        self.workdir = Path(workdir)
        self.branch = branch
        self.remote = remote
        self.push_retries = int(push_retries)
        if self.push_retries < 1:
            raise ValueError("push_retries must be >= 1")
        self.lock_timeout = float(lock_timeout)
        if self.lock_timeout < 0:
            raise ValueError("lock_timeout must be >= 0")
        self.author = author

    # -- git plumbing ------------------------------------------------------
    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=self.workdir,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitTimeout(
                f"git {' '.join(args)} timed out after {GIT_TIMEOUT_SECONDS}s "
                f"in {self.workdir}",
                command=("git", *args),
                timeout=GIT_TIMEOUT_SECONDS,
            ) from exc
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
        dir_existed = path.exists()
        pre_existing_contents = sorted(p.name for p in path.iterdir()) if dir_existed else []
        git_existed = (path / ".git").exists()
        path.mkdir(parents=True, exist_ok=True)

        store = cls(path, branch, **kwargs)

        if git_existed:
            # A pre-existing repository is somebody's checkout. The only safe
            # case is that it is *already* the room branch; anything else -
            # including an unborn branch with untracked project files, where
            # HEAD has no commits yet - is refused rather than repurposed.
            on_branch = store.current_branch() == branch
            has_branch = store._git(
                "rev-parse", "--verify", branch, check=False
            ).returncode == 0
            if has_branch and on_branch:
                return store
            raise WrongBranchError(
                f"{path} is a pre-existing git repository with "
                f"{store.current_branch() or 'an unborn/detached HEAD'} checked out; "
                f"refusing to repurpose it as room branch {branch!r}. Only a "
                "repository created by Agent Room may be initialised. Use a "
                "dedicated empty directory."
            )

        if dir_existed and pre_existing_contents:
            raise WrongBranchError(
                f"{path} already exists and is not empty ({pre_existing_contents[:5]}); "
                f"refusing to create room history inside it. Use a dedicated "
                "empty directory."
            )

        store._git("init", "-q")
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

    def _commit(self, message: str, *pathspec: str) -> str:
        self.assert_room_branch()
        args = [
            "-c", f"user.name={self.author[0]}",
            "-c", f"user.email={self.author[1]}",
            "commit", "-q", "-m", message,
        ]
        if pathspec:
            args += ["--", *pathspec]
        self._git(*args)
        return self._git("rev-parse", "HEAD").stdout.strip()

    # -- paths -------------------------------------------------------------
    @staticmethod
    def message_path(thread_id: str, message_id: str) -> str:
        return f"{MESSAGES_DIR}/{thread_id}/{message_id}.json"

    @staticmethod
    def identity_from_path(path: str) -> tuple[str, str]:
        """The (thread_id, message_id) a committed path asserts."""
        parts = path.split("/")
        if len(parts) != 4 or not parts[3].endswith(".json"):
            raise SchemaError(f"{path} is not a valid message path")
        return parts[2], parts[3][: -len(".json")]

    # -- single-writer lock ------------------------------------------------
    def _git_dir(self) -> Path:
        out = self._git("rev-parse", "--absolute-git-dir", check=False)
        if out.returncode != 0:
            raise AgentRoomError(f"{self.workdir} is not a git repository")
        return Path(out.stdout.strip())

    @contextmanager
    def writer_lock(self):
        """Exclusive lock over mutation of this one checkout.

        Two processes sharing a checkout share a Git index, so without this one
        can commit the other's staged message. `flock` is advisory but
        sufficient here: every writer goes through this class.

        The wait is bounded by `lock_timeout` and then raises - a stuck holder
        must never hang a caller. This is a lock, not a poller: it acquires and
        returns, and nothing runs in the background.
        """
        lock_path = self._git_dir() / WRITER_LOCK_NAME
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + self.lock_timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"another process holds the Agent Room writer lock for "
                            f"{self.workdir} (waited {self.lock_timeout}s)"
                        )
                    time.sleep(LOCK_POLL_SECONDS)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def assert_clean_checkout(self) -> None:
        """Fail closed unless the dedicated checkout has nothing pending.

        `git commit` takes the index, so a rewrite of an existing message that
        someone already staged would ride along inside an otherwise innocent
        message commit - and then be pushed as legitimate history.
        """
        proc = self._git("status", "--porcelain", check=False)
        if proc.returncode != 0:
            raise AgentRoomError(f"cannot inspect {self.workdir}: {proc.stderr.strip()}")
        pending = [line for line in proc.stdout.splitlines() if line.strip()]
        if pending:
            raise DirtyCheckoutError(
                f"{self.workdir} has uncommitted or staged changes and is not a "
                f"clean room checkout: {pending[:5]}"
            )

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
    def _assert_linear(self) -> None:
        """Refuse merge commits anywhere in the branch.

        This transport resolves concurrency by rebase, so a merge adds no
        capability. It does add a hiding place: a merge commit's own A/M/D
        changes are not reported by default `git log` traversal, so a message
        could be rewritten or deleted inside one and never appear in the scan.
        Linear history is what makes the scan complete.
        """
        proc = self._git("rev-list", "--merges", self.branch, check=False)
        if proc.returncode != 0:
            return
        merges = [line for line in proc.stdout.split() if line]
        if merges:
            raise AppendOnlyViolation(
                f"{self.branch} contains merge commits ({merges[:3]}); the room "
                "branch must be linear so that every message change is visible "
                "to history verification"
            )

    @staticmethod
    def _is_canonical_message_path(path: str) -> bool:
        parts = path.split("/")
        if len(parts) != 4 or parts[0] != ".agent-room" or parts[1] != "messages":
            return False
        if not parts[3].endswith(".json"):
            return False
        return bool(THREAD_ID_RE.match(parts[2])) and is_uuid7(parts[3][: -len(".json")])

    def _history(self) -> dict:
        """Map message path -> add commit, rejecting any later mutation.

        One NUL-delimited `git log` over the message tree. `-z` matters:
        without it Git quotes paths containing spaces or non-ASCII, and a
        quoted path would not match the prefix test and would silently vanish
        from verification. A path must appear exactly once as an addition and
        never again; a path that is not a canonical message path fails closed
        rather than being skipped.
        """
        tip = self._git("rev-parse", self.branch, check=False)
        if tip.returncode != 0:
            return {}
        tip_sha = tip.stdout.strip()
        cached = getattr(self, "_history_cache", None)
        if cached is not None and cached[0] == tip_sha:
            return cached[1]

        self._assert_linear()

        proc = self._git(
            "log", self.branch, "--reverse", "--format=%H",
            "--name-status", "-z", "--no-renames", "--", MESSAGES_DIR,
            check=False,
        )
        if proc.returncode != 0:
            return {}

        added: dict[str, str] = {}
        commit_seq: dict[str, int] = {}
        commit = ""
        tokens = [t for t in proc.stdout.split("\0")]
        i = 0
        while i < len(tokens):
            token = tokens[i].strip()
            i += 1
            if not token:
                continue
            if len(token) >= 40 and all(c in "0123456789abcdef" for c in token):
                commit = token
                if commit not in commit_seq:
                    commit_seq[commit] = len(commit_seq)
                continue
            # Otherwise this is a status token; the path is the next token.
            status = token
            if i >= len(tokens):
                raise AppendOnlyViolation(
                    f"malformed git status output near {status!r} in {commit}"
                )
            path = tokens[i]
            i += 1
            if not path.startswith(f"{MESSAGES_DIR}/"):
                continue
            if not self._is_canonical_message_path(path):
                raise AppendOnlyViolation(
                    f"{path!r} (in commit {commit}) is under {MESSAGES_DIR}/ but "
                    "is not a canonical <thread_id>/<uuid7>.json message path; "
                    "refusing to verify a history containing unrecognised paths"
                )
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

        # A message_id must be unique across the whole room, not just within
        # a thread path: resolve_message() looks up by id alone, so the same
        # id under two threads would make every reference to it ambiguous.
        by_id: dict[str, str] = {}
        for path in added:
            mid = path.rsplit("/", 1)[-1][: -len(".json")]
            if mid in by_id:
                raise ConflictError(
                    f"message_id {mid} appears at more than one path "
                    f"({by_id[mid]} and {path}); ids must be unique room-wide"
                )
            by_id[mid] = path

        self._history_cache = (tip_sha, added, by_id, commit_seq)
        return added

    def _id_index(self) -> dict:
        """message_id -> path, for the whole room."""
        self._history()
        return self._history_cache[2]

    def is_strict_ancestor(self, earlier: str, later: str) -> bool:
        """True iff `earlier` is an ancestor of `later` and not the same commit.

        Ancestry, not log position: `git log` order is a traversal artifact and
        would call two sibling commits ordered when neither can see the other.
        Causality has to mean "this already existed on the path that led here".
        """
        if earlier == later:
            return False
        cache = getattr(self, "_ancestry_cache", None)
        if cache is None:
            cache = self._ancestry_cache = {}
        key = (earlier, later)
        if key not in cache:
            cache[key] = self._git(
                "merge-base", "--is-ancestor", earlier, later, check=False
            ).returncode == 0
        return cache[key]

    def verify_append_only(self) -> int:
        """Re-scan history. Raises on violation; returns the message count."""
        return len(self._history())

    # -- reads (from the add commit, never the branch tip) -----------------
    def _blob_at(self, commit: str, path: str) -> str | None:
        proc = self._git("show", f"{commit}:{path}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    def _load_raw(self, path: str, commit: str) -> dict:
        """Phase one: the message itself, with no reference resolution.

        Structural validation at the trust boundary - a correctly resealed but
        malformed artifact, or one written by another participant's library,
        must still fail loudly. `agent_facing=False` so the reserved Issue #5
        types stay structurally readable.
        """
        raw = self._blob_at(commit, path)
        if raw is None:
            raise AppendOnlyViolation(
                f"{path} is missing from its own add commit {commit}"
            )
        envelope = canonical.strict_loads(raw)
        canonical.verify(envelope)
        validate_envelope(envelope, agent_facing=False, check_references=False)

        # The path is how history indexes a message; the envelope is what
        # consumers read. If they disagree, resolve_message() would hand back
        # a body claiming an identity that is not indexed under it. Bind them
        # before this artifact can take part in any reference resolution.
        expected_thread, expected_id = self.identity_from_path(path)
        if envelope["thread_id"] != expected_thread:
            raise SchemaError(
                f"{path} is committed under thread {expected_thread!r} but its "
                f"envelope says {envelope['thread_id']!r}"
            )
        if envelope["message_id"] != expected_id:
            raise SchemaError(
                f"{path} is committed under message id {expected_id!r} but its "
                f"envelope says {envelope['message_id']!r}"
            )
        return envelope

    def _resolve_raw(self, message_id: str) -> dict | None:
        """Resolve by id for *reference checking only* - phase-one load.

        Returning a raw message is what bounds the recursion: validating A
        resolves B structurally and stops, rather than validating B's own
        references and so on around a cycle.
        """
        path = self._id_index().get(message_id)
        if path is None:
            return None
        return self._load_raw(path, self._history()[path])

    @property
    def _raw_resolver(self):
        """Resolves against everything already committed.

        Correct for `append`, where the new message is by definition later
        than all existing history.
        """
        store = self

        class _Resolver:
            @staticmethod
            def resolve_message(message_id: str):
                return store._resolve_raw(message_id)

        return _Resolver()

    def _resolver_as_of(self, commit: str):
        """Resolves only messages whose add commit is a strict ancestor.

        Historical causality: a message may rely only on state that existed on
        the history leading to it. Self-reference, same-commit and sibling
        references all fail, because none of them satisfies strict ancestry.
        """
        store = self

        class _AsOfResolver:
            @staticmethod
            def resolve_message(message_id: str):
                path = store._id_index().get(message_id)
                if path is None:
                    return None
                other = store._history()[path]
                if not store.is_strict_ancestor(other, commit):
                    raise UnresolvedReference(
                        f"reference to {message_id} is not historically valid: "
                        f"its add commit {other[:8]} is not a strict ancestor of "
                        f"the referencing message's add commit {commit[:8]}; a "
                        "message may only rely on state that existed when it "
                        "was committed"
                    )
                return store._load_raw(path, other)

            @staticmethod
            def commit_object_state(sha: str) -> str:
                return store.commit_object_state(sha)

        return _AsOfResolver()

    def commit_object_state(self, sha: str) -> str:
        """Whether a pinned object id is locally present, and if so what it is.

        Returns "commit", "not-a-commit", or "absent". Evidence usually pins a
        commit in a *different* repository that this machine may not have; in
        that case the full locator is preserved and existence is deliberately
        not fabricated. Only objects we actually hold are checked.
        """
        if self._git("cat-file", "-e", sha, check=False).returncode != 0:
            return "absent"
        kind = self._git("cat-file", "-t", sha, check=False).stdout.strip()
        return "commit" if kind == "commit" else "not-a-commit"

    def _load(self, path: str, commit: str) -> dict:
        """Read one message as committed, with references resolved.

        Phase two: a `supported` claim citing another message, or a reply whose
        parent lives elsewhere in the room, is validated against history rather
        than being rejected merely because reads had no resolver - and only
        against history that predates this message.
        """
        envelope = self._load_raw(path, commit)
        validate_envelope(
            envelope,
            agent_facing=False,
            resolver=self._resolver_as_of(commit),
            check_references=True,
        )
        return envelope

    def current_add_commit(self, path: str, fallback: str | None = None) -> str | None:
        """The commit that currently adds `path`, after any rebase.

        A non-fast-forward rebase rewrites local commit SHAs, so the SHA
        captured before a push may no longer identify the message that is
        actually in the branch. Falls back when history cannot be read at all -
        reporting a stale SHA is still better than reporting none.
        """
        proc = self._git(
            "log", self.branch, "--reverse", "--diff-filter=A",
            "--format=%H", "-z", "--", path, check=False,
        )
        if proc.returncode == 0:
            for token in proc.stdout.split("\0"):
                token = token.strip()
                if len(token) >= 40 and all(c in "0123456789abcdef" for c in token):
                    return token
        return fallback

    def verify_store(self) -> int:
        """Walk every committed message and check the whole contract.

        Append-only history and global id uniqueness come from `_history()`;
        path/envelope identity, digest, structure, parent/thread validity,
        historical causality and evidence admissibility come from loading each
        message. This is the gate delivery needs: `verify_append_only()` alone
        would not notice a freshly fetched artifact that is malformed,
        misfiled, or cites something that did not yet exist.
        """
        history = self._history()
        for path, commit in history.items():
            self._load(path, commit)
        return len(history)

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
        """Look a message up by id alone, room-wide."""
        path = self._id_index().get(message_id)
        if path is None:
            return None
        return self._load(path, self._history()[path])

    # -- append ------------------------------------------------------------
    def append(self, envelope: dict, *, resolver=None) -> dict:
        """Commit one sealed envelope.

        Returns `{"status": "created"|"duplicate", "commit": sha, ...}`.
        Identical re-submission is idempotent; the same id with different
        content — or under a different thread — raises `ConflictError` and
        never overwrites.

        Validation happens here, not only in the caller: `append` is an
        exported trust boundary, so a malformed envelope with a correct digest
        must be refused even when it arrives through the low-level library.
        """
        self.assert_room_branch()
        canonical.verify(envelope)
        # Every WRITE path in this package is agent-facing for Issues #2-#4:
        # `append` is exported, so validating it leniently would be a
        # privileged bypass around AgentRoom.post for exactly the two reserved
        # types. Reads stay agent_facing=False so Issue #5 records remain
        # readable when that authority-bearing path is built.
        validate_envelope(
            envelope,
            agent_facing=True,
            resolver=resolver if resolver is not None else self._raw_resolver,
        )

        thread_id = envelope["thread_id"]
        message_id = envelope["message_id"]
        rel = self.message_path(thread_id, message_id)

        with self.writer_lock():
            # Whole checkout must be clean before we stage anything, or a
            # rewrite someone already staged would be committed alongside.
            self.assert_clean_checkout()
            # Never build on corrupt history. A local-only store must refuse
            # this just as the delivery path does: otherwise a store with no
            # remote would happily extend an artifact that is correctly hashed
            # but semantically invalid.
            self.verify_store()

            existing_path = self._id_index().get(message_id)
            if existing_path is not None:
                if existing_path != rel:
                    raise ConflictError(
                        f"message_id {message_id} already exists at "
                        f"{existing_path}; ids are unique room-wide and cannot "
                        f"be reused under thread {thread_id!r}"
                    )
                existing = self._load_raw(existing_path, self._history()[existing_path])
                if existing.get(canonical.DIGEST_FIELD) == envelope[canonical.DIGEST_FIELD]:
                    return {
                        "status": "duplicate",
                        "message_id": message_id,
                        "thread_id": thread_id,
                        "commit": self._history()[existing_path],
                        "path": rel,
                    }
                raise ConflictError(
                    f"message_id {message_id} already exists with a different "
                    f"digest ({existing.get(canonical.DIGEST_FIELD)} != "
                    f"{envelope[canonical.DIGEST_FIELD]}); refusing to overwrite"
                )

            target = self.workdir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            # Written in canonical form so the committed bytes are exactly
            # what the digest covers.
            target.write_text(canonical.canonical_text(envelope), encoding="utf-8")
            self._git("add", "--", rel)
            # Commit this path only. Even if something else reached the index
            # between the clean check and here, it cannot ride along.
            try:
                commit = self._commit(
                    f"agent-room: {envelope['type']} {message_id}", rel
                )
            except GitTimeout as exc:
                # The commit may or may not have landed. Guessing either way is
                # wrong: reporting failure invites a repost under a fresh UUID,
                # reporting success may be false. Look and say what is true.
                landed = self.current_add_commit(rel)
                if landed is None:
                    raise
                raise DeliveryError(
                    f"message {message_id} was committed at {landed} but the "
                    f"commit command did not return cleanly: {exc}. "
                    "Retry delivery with push(); do not repost.",
                    message_id=message_id,
                    commit=landed,
                    path=rel,
                    cause=exc,
                ) from exc

            result = {
                "status": "created",
                "locally_committed": True,
                "pushed": False,
                "message_id": message_id,
                "thread_id": thread_id,
                "commit": commit,
                "path": rel,
            }
            if self.remote:
                # The message is already durable locally. If delivery fails the
                # caller must learn *what was written*, or a naive retry of
                # post() would mint a second UUID for the same logical message
                # and duplicate it in permanent history.
                try:
                    result["push"] = self._push_locked()
                    result["pushed"] = bool(result["push"].get("pushed"))
                except AgentRoomError as exc:
                    # A rebase during the push may have rewritten our commit,
                    # so report the SHA that actually holds the message now.
                    current = self.current_add_commit(rel, commit)
                    raise DeliveryError(
                        f"message {message_id} is committed locally at {current} "
                        f"but was not delivered to {self.remote}: {exc}. "
                        "Retry delivery with push(); do not repost.",
                        message_id=message_id,
                        commit=current,
                        path=rel,
                        cause=exc,
                    ) from exc
                result["commit"] = self.current_add_commit(rel, commit)
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

        with self.writer_lock():
            return self._push_locked()

    def _push_locked(self) -> dict:
        """Push body, assuming the writer lock is already held."""
        self.assert_room_branch()
        # Never hand invalid history to the remote. The full gate - not just
        # append-only - because a rebase can pull in a freshly fetched artifact
        # that is malformed, misfiled or cites something that did not yet
        # exist, none of which an M/D/R scan would notice.
        self.verify_store()
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
            self.verify_store()
        raise PushRaceError(
            f"push rejected after {self.push_retries} attempts: {last_error}"
        )

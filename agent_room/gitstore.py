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
import hashlib
import json
import os
import secrets
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import canonical, limits
from .errors import (
    AgentRoomError,
    AppendOnlyViolation,
    ConflictError,
    DeliveryError,
    DirtyCheckoutError,
    ForbiddenOperation,
    GitTimeout,
    InvalidBranchName,
    HistoryUnavailable,
    LockTimeout,
    PushAmbiguous,
    PushRaceError,
    ReceiptStateError,
    SchemaError,
    UnresolvedReference,
    WrongBranchError,
)
from . import namespace
from .ids import is_uuid7
from .namespace import NamespaceViolation
from . import trust as trust_module
from .trust import NoTrustPolicy
from .process import sanitised_env
from .schema import DECISION_TYPES, THREAD_ID_RE, validate_envelope

MESSAGES_DIR = ".agent-room/messages"
DEFAULT_BRANCH = "agent-room"
GIT_TIMEOUT_SECONDS = 60
DEFAULT_PUSH_RETRIES = 3
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
CONTROL_OR_SPACE = frozenset(chr(c) for c in range(0x21)) | {"\x7f"}

#: Applied to every Git invocation this store makes. Hooks in a room checkout
#: would be attacker-supplied code running inside verification; `protocol.ext`
#: would let a configured remote name a command to run. Neither has any part
#: in a message transport.
HARDENED_GIT_CONFIG = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.ext.allow=never",
)
LOCK_POLL_SECONDS = 0.05
WRITER_LOCK_NAME = "agent-room-writer.lock"

#: Git revision syntax that must never appear in a configured branch name.
#: `refs/heads/` + one of these still resolves as an expression.
REVISION_SYNTAX = ("~", "^", ":", "?", "*", "[", "\\", "@{", "..")


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
        trust=None,
    ) -> None:
        self.workdir = Path(workdir)
        #: Pinned public verification identities, or None for the legacy
        #: unauthenticated mode. When set, every artifact read out of history
        #: must carry a signature by a key this policy pins, and every artifact
        #: written must too. When unset nothing is authenticated - which is why
        #: every release-capable path refuses a store without one.
        self.trust = trust
        #: Validated once, before any ref is built from it.
        self.branch = self._validate_branch_name(branch)
        #: The only revision authority. A short name can be shadowed by a tag
        #: of the same name, so `agent-room` must never be used to resolve a
        #: tip, scan history, fetch, push or reconcile a remote.
        self.ref = f"refs/heads/{branch}"
        self.remote = remote
        self.push_retries = int(push_retries)
        if self.push_retries < 1:
            raise ValueError("push_retries must be >= 1")
        self.lock_timeout = float(lock_timeout)
        if self.lock_timeout < 0:
            raise ValueError("lock_timeout must be >= 0")
        self.author = author
        #: Who holds `writer_lock()` and how deeply they have nested it.
        #: Guarded by `_lock_state`, which is held only while these two are
        #: read or written - never across the critical section itself. See the
        #: re-entrancy note on `writer_lock`.
        self._lock_state = threading.Lock()
        self._lock_owner: int | None = None
        self._lock_depth = 0

    # -- git plumbing ------------------------------------------------------
    def _git_bytes(self, *args: str) -> bytes:
        """Run git and return stdout as exact bytes.

        Hashing must see the object's real bytes; a text-mode round trip could
        normalise them and make a forged object hash correctly.
        """
        command = ["git", "--no-replace-objects", *HARDENED_GIT_CONFIG, *args]
        try:
            proc = subprocess.run(
                command, cwd=self.workdir, capture_output=True,
                timeout=GIT_TIMEOUT_SECONDS, env=self._clean_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise GitTimeout(
                f"git {' '.join(args)} timed out", command=tuple(command),
                timeout=GIT_TIMEOUT_SECONDS,
            ) from exc
        except (ValueError, OSError) as exc:
            raise AgentRoomError(
                f"git {' '.join(args)} could not be executed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if proc.returncode != 0:
            raise AgentRoomError(
                f"git {' '.join(args)} failed ({proc.returncode}): "
                f"{proc.stderr.decode('utf-8', 'replace').strip()}"
            )
        return proc.stdout

    #: Caller environment variables that can redirect object lookup, replace
    #: history, or move the repository out from under us. Verification must not
    #: inherit them: the answer has to describe *this* checkout.
    UNSAFE_GIT_ENV = (
        "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE", "GIT_DIR", "GIT_WORK_TREE",
        "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT", "GIT_NAMESPACE",
    )

    def _clean_env(self) -> dict:
        """Strip anything that can redirect objects, config or execution.

        `UNSAFE_GIT_ENV` names the Git-specific redirections; `process.
        sanitised_env` removes the broader class — interpreter and loader
        variables that change what a hook or a credential helper would run if
        one were ever reached.
        """
        env = sanitised_env({k: v for k, v in os.environ.items()
                             if k not in self.UNSAFE_GIT_ENV})
        env["GIT_NO_REPLACE_OBJECTS"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    def _git(self, *args: str, check: bool = True,
             input: str | None = None) -> subprocess.CompletedProcess:
        # --no-replace-objects: a replace ref must never quietly rewrite what
        # verification sees. Their *presence* is rejected separately.
        command = ["git", "--no-replace-objects", *HARDENED_GIT_CONFIG, *args]
        try:
            proc = subprocess.run(
                command,
                cwd=self.workdir,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT_SECONDS,
                input=input,
                env=self._clean_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise GitTimeout(
                f"git {' '.join(args)} timed out after {GIT_TIMEOUT_SECONDS}s "
                f"in {self.workdir}",
                command=tuple(command),
                timeout=GIT_TIMEOUT_SECONDS,
            ) from exc
        except (ValueError, OSError) as exc:
            # Malformed arguments or an OS-level failure must stay inside the
            # Agent Room contract rather than leaking a raw Python error.
            raise AgentRoomError(
                f"git {' '.join(args)} could not be executed in "
                f"{self.workdir}: {type(exc).__name__}: {exc}"
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
        # A random nonce in the genesis, because the room identity *is* the
        # root commit and signatures are bound to it. Without this, two rooms
        # created in the same second from the same template produce byte
        # identical genesis commits - same tree, same author, same message,
        # same timestamp - and therefore the same identity, which would make
        # the room binding bind nothing. Not a secret: it is committed, and
        # its only job is to be different.
        readme.write_text(
            "# agent-room\n\n"
            "Dedicated append-only branch for Agent Room message traffic.\n"
            "This branch is separate from main and must never be merged into it.\n\n"
            f"Paths:\n- {MESSAGES_DIR}/<thread_id>/<message_id>.json\n\n"
            f"Room nonce: {secrets.token_hex(16)}\n",
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
    @staticmethod
    def _validate_branch_name(branch) -> str:
        """Require a literal branch name, not a revision expression.

        `refs/heads/agent-room~1` is still resolvable by Git, so prefixing the
        namespace is not enough on its own: the name itself has to be proven
        literal before any ref is constructed from it.
        """
        if not isinstance(branch, str) or not branch:
            raise InvalidBranchName(
                f"branch must be a non-empty string, got "
                f"{type(branch).__name__} {branch!r}"
            )
        for token in REVISION_SYNTAX:
            if token in branch:
                raise InvalidBranchName(
                    f"branch {branch!r} contains Git revision syntax {token!r}; "
                    "a room branch must be a literal branch name"
                )
        if branch.startswith("-"):
            # Would be read as an option by any Git invocation that takes it
            # positionally.
            raise InvalidBranchName(f"branch {branch!r} must not start with '-'")
        if branch.startswith("/") or branch.endswith("/") or branch.endswith("."):
            raise InvalidBranchName(f"branch {branch!r} is not a valid branch name")
        if any(c in branch for c in CONTROL_OR_SPACE):
            raise InvalidBranchName(
                f"branch {branch!r} contains whitespace or control characters"
            )
        # Git's own rules are the authority for everything else.
        proc = subprocess.run(
            ["git", "check-ref-format", f"refs/heads/{branch}"],
            capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0:
            raise InvalidBranchName(
                f"branch {branch!r} is not a valid Git branch name "
                f"(git check-ref-format rejected refs/heads/{branch})"
            )
        return branch

    def _git_dir(self) -> Path:
        out = self._git("rev-parse", "--absolute-git-dir", check=False)
        if out.returncode != 0:
            raise AgentRoomError(f"{self.workdir} is not a git repository")
        return Path(out.stdout.strip())

    def _git_common_dir(self) -> Path:
        """The repository-wide Git directory.

        In a linked worktree the worktree-specific git dir is *not* where
        legacy grafts live - they live in the common dir, so checking only the
        worktree dir would miss a graft installed there.
        """
        out = self._git("rev-parse", "--path-format=absolute",
                        "--git-common-dir", check=False)
        if out.returncode != 0 or not out.stdout.strip():
            # Older Git without --path-format: fall back to the worktree dir
            # rather than silently skipping the check.
            legacy = self._git("rev-parse", "--git-common-dir", check=False)
            if legacy.returncode != 0 or not legacy.stdout.strip():
                raise HistoryUnavailable(
                    f"cannot resolve the common Git directory for {self.workdir}"
                )
            return (self.workdir / legacy.stdout.strip()).resolve()
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

        **Re-entrant for the thread that holds it, and only for that thread.**
        A caller that must decide and write atomically - `release.reserve`
        checking a one-shot nonce and then consuming it - holds this across
        both, and the append inside takes it again. `flock` is per open file
        description, so the nested `os.open` would deny itself; recognising
        the owning thread and reusing its descriptor is what makes the nesting
        safe.

        Re-entrancy is owned by a thread, never by the instance. An earlier
        version counted depth on the store alone, so a *second* thread sharing
        one store saw a non-zero depth, concluded it was nested, and walked
        into the critical section somebody else was holding. The counters are
        now read and written under `_lock_state` and keyed to the owner's
        thread id, so a different thread is never nested and always takes the
        ordinary bounded path.

        That path still blocks correctly within one process: `flock` treats
        two descriptors for the same file independently, so a second thread's
        `LOCK_EX` is denied by the lock this store already holds on another
        descriptor - the same answer another process would get. `_lock_state`
        is deliberately not held across the body, so two stores can never
        deadlock on each other's guards.
        """
        me = threading.get_ident()
        with self._lock_state:
            nested = self._lock_depth > 0 and self._lock_owner == me
            if nested:
                self._lock_depth += 1
        if nested:
            try:
                yield
            finally:
                with self._lock_state:
                    self._lock_depth -= 1
            return

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
                            f"another writer holds the Agent Room writer lock "
                            f"for {self.workdir} (waited {self.lock_timeout}s)"
                        )
                    time.sleep(LOCK_POLL_SECONDS)
            with self._lock_state:
                self._lock_owner, self._lock_depth = me, 1
            try:
                yield
            finally:
                with self._lock_state:
                    self._lock_depth, self._lock_owner = 0, None
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
    def assert_no_history_overrides(self) -> None:
        """Refuse a checkout whose history can be locally rewritten.

        `refs/replace/*` and the legacy `.git/info/grafts` both make Git show
        a history that is not the committed one. Verification runs with
        `--no-replace-objects`, but a checkout carrying such overrides is not
        a trustworthy place to verify from, so their presence is rejected
        outright rather than merely bypassed.

        Local-checkout integrity; distinct from the documented pre-clone
        force-push boundary, which Git cannot settle at all.
        """
        replaced = self._git("for-each-ref", "--format=%(refname)", "refs/replace/",
                             check=False)
        if replaced.returncode != 0:
            raise HistoryUnavailable(
                f"cannot enumerate replacement refs in {self.workdir}: "
                f"{replaced.stderr.strip()}"
            )
        refs = [line for line in replaced.stdout.split() if line]
        if refs:
            raise HistoryUnavailable(
                f"{self.workdir} has history replacement refs ({refs[:3]}); "
                "refusing to verify a checkout whose history can be locally "
                "rewritten. Remove them with `git replace -d`."
            )

        # Both the worktree dir and the common dir: a linked worktree keeps
        # grafts in the latter.
        candidates = {self._git_dir() / "info" / "grafts",
                      self._git_common_dir() / "info" / "grafts"}
        for grafts in sorted(candidates):
            try:
                if grafts.exists() and grafts.read_text(encoding="utf-8").strip():
                    raise HistoryUnavailable(
                        f"{grafts} is a non-empty legacy graft file; refusing to "
                        "verify a checkout whose history can be locally rewritten."
                    )
            except OSError as exc:
                raise HistoryUnavailable(f"cannot read {grafts}: {exc}") from exc

        # Alternates are the third way to answer an object query from
        # somewhere else. A room whose objects may come from a directory
        # outside it is not a room whose history we can verify.
        alternates = {self._git_dir() / "objects" / "info" / "alternates",
                      self._git_common_dir() / "objects" / "info" / "alternates"}
        for alternate in sorted(alternates):
            try:
                if alternate.exists() and alternate.read_text(encoding="utf-8").strip():
                    raise HistoryUnavailable(
                        f"{alternate} names alternate object directories; room "
                        "objects must come from this repository alone, or "
                        "verification is describing someone else's objects."
                    )
            except OSError as exc:
                raise HistoryUnavailable(f"cannot read {alternate}: {exc}") from exc

    def assert_history_available(self) -> None:
        """Fail closed unless complete local history is readable.

        A shallow clone cannot prove append-only semantics: the commits that
        would show a rewrite may simply not be present. "I cannot see the
        history" and "the history is clean" are different answers, and only
        one of them is safe to act on.
        """
        self.assert_no_history_overrides()
        shallow = self._git("rev-parse", "--is-shallow-repository", check=False)
        if shallow.returncode != 0:
            raise HistoryUnavailable(
                f"cannot determine whether {self.workdir} is shallow: "
                f"{shallow.stderr.strip()}"
            )
        if shallow.stdout.strip() == "true":
            raise HistoryUnavailable(
                f"{self.workdir} is a shallow repository; append-only history "
                "cannot be verified from a truncated clone. Fetch full history "
                "(git fetch --unshallow) before verifying, appending or pushing."
            )
        # show-ref --verify has exact-ref semantics: it will not resolve an
        # expression, only a literal ref that exists.
        if self._git("show-ref", "--verify", "--quiet", self.ref,
                     check=False).returncode != 0:
            raise HistoryUnavailable(
                f"configured room branch {self.branch!r} does not exist in "
                f"{self.workdir}; refusing to report an empty history for a "
                "branch that is simply missing"
            )

    def _assert_linear(self) -> None:
        """Refuse merge commits anywhere in the branch.

        This transport resolves concurrency by rebase, so a merge adds no
        capability. It does add a hiding place: a merge commit's own A/M/D
        changes are not reported by default `git log` traversal, so a message
        could be rewritten or deleted inside one and never appear in the scan.
        Linear history is what makes the scan complete.
        """
        proc = self._git("rev-list", "--merges", self.ref, check=False)
        if proc.returncode != 0:
            raise HistoryUnavailable(
                f"merge scan of {self.branch} failed: {proc.stderr.strip()}"
            )
        merges = [line for line in proc.stdout.split() if line]
        if merges:
            raise AppendOnlyViolation(
                f"{self.branch} contains merge commits ({merges[:3]}); the room "
                "branch must be linear so that every message change is visible "
                "to history verification"
            )

    def assert_namespace_closed(self) -> dict:
        """Every tracked entry at the tip is a protocol artifact, or fail.

        History says which paths were *touched*; this says what is actually
        there now, including the two things a path alone cannot: the object
        type and the file mode. A symlink, an executable or a gitlink is
        refused here even if its path looked plausible.
        """
        proc = self._git("ls-tree", "-r", "-z", "--full-tree", self.ref,
                         check=False)
        if proc.returncode != 0:
            raise HistoryUnavailable(
                f"cannot list the tree of {self.ref} in {self.workdir}: "
                f"{proc.stderr.strip()}"
            )
        counts = {"genesis": 0, "message": 0}
        for entry in proc.stdout.split("\0"):
            if not entry:
                continue
            meta, _, path = entry.partition("\t")
            fields = meta.split()
            if len(fields) < 3:
                raise HistoryUnavailable(
                    f"malformed tree entry {entry!r} on {self.ref}"
                )
            counts[namespace.assert_allowed_entry(fields[0], fields[1], path)] += 1
        return counts

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
        # Authenticate before discovery or cache reuse: a corrupt tree can
        # hide paths that would otherwise trigger the per-artifact gate.
        self.assert_object_integrity()
        tip = self._git("rev-parse", self.ref, check=False)
        if tip.returncode != 0:
            raise HistoryUnavailable(
                f"cannot resolve {self.ref}: {tip.stderr.strip()}"
            )
        tip_sha = tip.stdout.strip()
        cached = getattr(self, "_history_cache", None)
        if cached is not None and cached[0] == tip_sha:
            return cached[1]

        self._assert_linear()
        self.assert_namespace_closed()

        # Deliberately no pathspec: the scan covers every tracked path on the
        # branch. Restricting it to the message tree is what let a committed
        # `.gitattributes` sit beside the messages and verify clean.
        proc = self._git(
            "log", self.ref, "--reverse", "--format=%H",
            "--name-status", "-z", "--no-renames",
            check=False,
        )
        if proc.returncode != 0:
            # Never a silent {}: an unreadable history is not an empty room.
            raise HistoryUnavailable(
                f"history query on {self.ref} failed: {proc.stderr.strip()}"
            )

        added: dict[str, str] = {}
        commit_seq: dict[str, int] = {}
        genesis: str | None = None
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
            kind = namespace.classify(path)
            if kind is None:
                raise NamespaceViolation(
                    f"commit {commit} touches a path the room protocol does "
                    f"not define: {namespace.describe_refusal(path)}"
                )
            if kind == "genesis":
                # One immutable marker, written when the branch was created.
                # A later add or edit of it rewrites the branch's own identity,
                # so it is refused like any other mutation.
                if not status.startswith("A"):
                    raise AppendOnlyViolation(
                        f"{path} was {status!r} in commit {commit}; the genesis "
                        "marker is immutable"
                    )
                if genesis is not None:
                    raise AppendOnlyViolation(
                        f"{path} was added twice (second add in {commit})"
                    )
                genesis = commit
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
        if key in cache:
            return cache[key]
        proc = self._git("merge-base", "--is-ancestor", earlier, later, check=False)
        if proc.returncode not in (0, 1):
            # Anything other than the documented yes/no is an operational
            # failure. Caching it as "not an ancestor" would poison every
            # later answer for this store instance.
            raise AgentRoomError(
                f"ancestry query {earlier[:8]}..{later[:8]} failed "
                f"({proc.returncode}): {proc.stderr.strip()}"
            )
        cache[key] = proc.returncode == 0
        return cache[key]

    def verify_append_only(self) -> int:
        """Re-scan history. Raises on violation; returns the message count."""
        return len(self._history())

    # -- reads (from the add commit, never the branch tip) -----------------
    def _object_format(self) -> str:
        cached = getattr(self, "_object_format_cache", None)
        if cached is None:
            proc = self._git("rev-parse", "--show-object-format", check=False)
            cached = self._object_format_cache = (
                proc.stdout.strip() if proc.returncode == 0 else "sha1"
            ) or "sha1"
        return cached

    def _hash_blob(self, content: bytes) -> str:
        """Git's object id for this blob content, computed locally."""
        algo = self._object_format()
        header = b"blob %d\0" % len(content)
        if algo == "sha256":
            return hashlib.sha256(header + content).hexdigest()
        return hashlib.sha1(header + content).hexdigest()

    def _blob_at(self, commit: str, path: str) -> str | None:
        """Blob content, proven to hash to the object id the tree names.

        A loose object file can be replaced with different, validly compressed
        content under its old name: Git will hand that content back, and the
        envelope can simply be resealed around it. Only recomputing the object
        id from the bytes catches that.
        """
        spec = f"{commit}:{path}"
        oid_proc = self._git("rev-parse", "--verify", "--quiet", spec, check=False)
        oid = oid_proc.stdout.strip()
        if oid_proc.returncode != 0 or not oid:
            return None
        content = self._git_bytes("cat-file", "blob", oid)
        actual = self._hash_blob(content)
        if actual != oid:
            raise AppendOnlyViolation(
                f"object corruption: {path} at {commit[:8]} is stored as {oid} "
                f"but its content hashes to {actual}; the object database has "
                "been altered under the committed object id"
            )
        return canonical.decode_artifact(content, f"stored artifact {path}")

    def _discard_uncommitted(self, rel: str) -> None:
        """Unstage and remove a message artifact that was never committed.

        Called only when absence is *proven*. Never when persistence is
        unknown - deleting a file that may already be committed content would
        be exactly the wrong move.
        """
        try:
            self._git("reset", "-q", "--", rel, check=False)
            target = self.workdir / rel
            if target.exists():
                target.unlink()
        except (AgentRoomError, OSError):
            # Cleanup is best-effort; failing to tidy must not mask the real
            # outcome we are about to report.
            pass

    def assert_object_integrity(self) -> None:
        """Fail closed on any reachable-object corruption in the room history.

        Always check the object contents: an object can be replaced under its
        existing OID while preserving its file size and mtime. Neither file
        metadata nor an unchanged ref tip can authenticate the object graph.
        """
        # fsck takes an object, not a ref name; resolving first also means a
        # missing branch is reported as unavailable history, not corruption.
        self.assert_history_available()
        tip = self._git("rev-parse", "--verify", self.ref, check=False).stdout.strip()
        if not tip:
            raise HistoryUnavailable(f"cannot resolve {self.ref} for integrity check")
        proc = self._git(
            "fsck", "--strict", "--no-dangling", "--no-reflogs", tip,
            check=False,
        )
        if proc.returncode != 0:
            raise AppendOnlyViolation(
                f"git fsck --strict rejected the object database backing "
                f"{self.ref}: {(proc.stderr or proc.stdout).strip()[:500]}"
            )

    def _load_raw(self, path: str, commit: str) -> dict:
        """Phase one: the message itself, with no reference resolution.

        The integrity gate runs first. Hashing the blob alone is not enough:
        the commit and tree objects that *select* that blob can themselves be
        forged under their existing ids, so a read could return authentic-
        looking content chosen by a corrupt tree.

        Structural validation at the trust boundary - a correctly resealed but
        malformed artifact, or one written by another participant's library,
        must still fail loudly. `agent_facing=False` so the reserved Issue #5
        types stay structurally readable.
        """
        self.assert_object_integrity()
        raw = self._blob_at(commit, path)
        if raw is None:
            raise AppendOnlyViolation(
                f"{path} is missing from its own add commit {commit}"
            )
        envelope = canonical.strict_loads(raw)
        canonical.require_mapping(envelope, f"stored artifact {path}")
        canonical.verify(envelope)
        validate_envelope(
            envelope, agent_facing=False, check_references=False,
            resolver=self._artifact_verifier,
        )

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
    def _artifact_verifier(self):
        """Artifact verification without any graph traversal.

        Phase-one loading may defer resolving *other messages* to avoid
        recursion, but it must never defer checking this message's own
        evidence. Otherwise a `supported` claim could cite an out-of-band
        evidence message whose repo/run locator is itself invalid, and the
        citation would be admitted because the referenced message merely
        carried `kind=repo`.
        """
        store = self

        class _Verifier:
            @staticmethod
            def commit_object_state(sha: str) -> str:
                return store.commit_object_state(sha)

            @staticmethod
            def commit_path_state(sha: str, path: str) -> str:
                return store.commit_path_state(sha, path)

        return _Verifier()

    @property
    def _write_resolver(self):
        """The store's own authority for validating a message being written.

        Deliberately not caller-supplied: an exported `append` that accepted an
        arbitrary resolver would let a caller assert that a parent or evidence
        message exists when it does not. References are decided against this
        store's committed history, and artifact verification is the same as on
        the read side so a blob cannot be accepted as a pinned commit and only
        discovered to be unreadable afterwards.
        """
        store = self

        class _Resolver:
            @staticmethod
            def resolve_message(message_id: str):
                # Same rule as the read path: a new message may not be
                # validated against an unauthenticated parent or piece of
                # evidence. Bounded - the reference is authenticated, never
                # recursively resolved.
                path = store._id_index().get(message_id)
                if path is None:
                    return None
                add_commit = store._history()[path]
                referenced = store._load_raw(path, add_commit)
                store.authenticate(referenced, add_commit)
                return referenced

            @staticmethod
            def commit_object_state(sha: str) -> str:
                return store.commit_object_state(sha)

            @staticmethod
            def commit_path_state(sha: str, path: str) -> str:
                return store.commit_path_state(sha, path)

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
                referenced = store._load_raw(path, other)
                # Authenticate the reference before its content validates
                # anything. Otherwise a signed claim could be validated against
                # an unsigned parent or forged evidence, and a targeted read
                # would hand it back as trusted even though `verify_store()`
                # would later fail on the forgery. No recursion into *its*
                # references: the top-level read owns the recursive semantics,
                # and this stays bounded.
                store.authenticate(referenced, other)
                return referenced

            @staticmethod
            def commit_object_state(sha: str) -> str:
                return store.commit_object_state(sha)

            @staticmethod
            def commit_path_state(sha: str, path: str) -> str:
                return store.commit_path_state(sha, path)

        return _AsOfResolver()

    def _batch_check(self, spec: str) -> str | None:
        """Object type for `spec`, or None when Git says it is missing.

        `cat-file --batch-check` reports a missing object as data ("missing")
        with a zero exit status, which is the point: a non-zero status then
        means a real operational failure and can be raised instead of being
        misread as "this object does not exist". Treating every non-zero code
        as absence would silently downgrade an unreadable object database to
        "foreign evidence we cannot check".
        """
        if any(c in spec for c in ("\0", "\n")):
            raise AgentRoomError(f"refusing to query malformed object spec {spec!r}")
        proc = self._git("cat-file", "--batch-check", check=False, input=f"{spec}\n")
        if proc.returncode != 0:
            raise AgentRoomError(
                f"object lookup for {spec!r} failed in {self.workdir}: "
                f"{proc.stderr.strip() or 'git exited ' + str(proc.returncode)}"
            )
        # Git can exit 0 and print "<sha> missing" while stderr carries an
        # inflate/unpack/permission diagnostic for a locally *corrupt* object.
        # Reporting that as a clean absence would downgrade a damaged object
        # database to "foreign evidence we are not expected to have".
        diagnostics = proc.stderr.strip()
        if diagnostics:
            raise AgentRoomError(
                f"object lookup for {spec!r} reported a read failure in "
                f"{self.workdir}: {diagnostics}"
            )
        line = proc.stdout.strip()
        if not line:
            raise AgentRoomError(f"empty object lookup result for {spec!r}")
        parts = line.split()
        if parts[-1] in ("missing", "ambiguous"):
            return None
        if len(parts) < 2:
            raise AgentRoomError(f"unparseable object lookup result {line!r}")
        return parts[1]

    def commit_object_state(self, sha: str) -> str:
        """Whether a pinned object id is locally present, and if so what it is.

        Returns "commit", "not-a-commit", or "absent". Evidence usually pins a
        commit in a *different* repository that this machine may not have; in
        that case the full locator is preserved and existence is deliberately
        not fabricated. Only objects we actually hold are checked.
        """
        kind = self._batch_check(sha)
        if kind is None:
            return "absent"
        return "commit" if kind == "commit" else "not-a-commit"

    def commit_path_state(self, sha: str, path: str) -> str:
        """Whether `path` exists in a locally available commit.

        Returns "present", "absent", or "unknown" when the commit is not held
        locally. Nothing is fetched: an unavailable foreign repository keeps
        its immutable locator and the store makes no claim about it.
        """
        if self.commit_object_state(sha) != "commit":
            return "unknown"
        return "absent" if self._batch_check(f"{sha}:{path}") is None else "present"

    def current_tip(self) -> str:
        """The branch tip, resolved through the ref rather than a short name."""
        proc = self._git("rev-parse", "--verify", self.ref, check=False)
        if proc.returncode != 0:
            raise HistoryUnavailable(
                f"cannot resolve {self.ref} in {self.workdir}: "
                f"{proc.stderr.strip()}"
            )
        return proc.stdout.strip()

    def room_id(self) -> str:
        """The branch's root commit: a deterministic identity for this room.

        Used as the trust policy's subject and as the checkpoint genesis. A
        root commit cannot be changed without rewriting the entire history,
        which is exactly the property an out-of-band anchor needs.
        """
        proc = self._git("rev-list", "--max-parents=0", self.ref, check=False)
        roots = [line for line in proc.stdout.split() if line]
        if proc.returncode != 0 or not roots:
            raise HistoryUnavailable(
                f"cannot determine the root commit of {self.ref} in "
                f"{self.workdir}: {proc.stderr.strip()}"
            )
        if len(roots) > 1:
            raise HistoryUnavailable(
                f"{self.ref} has {len(roots)} root commits ({roots[:3]}); a "
                "room has one origin, and several means grafted history"
            )
        return roots[0]

    @property
    def authenticated(self) -> bool:
        return self.trust is not None

    def assert_authenticated(self, what: str = "this operation") -> None:
        """Refuse a release-capable operation on an unauthenticated store."""
        if self.trust is None:
            raise NoTrustPolicy(
                f"{what} needs a pinned trust policy: without one, "
                "`sender.agent` is just a string and any Git writer can claim "
                "any identity. There is deliberately no option to proceed "
                "without authentication."
            )

    def authenticate(self, envelope: dict, commit: str | None) -> dict | None:
        """Verify provenance of one artifact as it was committed.

        Called from the read path, so what is authenticated is the stored
        bytes: the envelope here was parsed out of the blob at its own add
        commit and its digest already checked, not handed in by a caller.

        `commit` places the message in history, which is what lets a key that
        has since been rotated still verify the messages it signed while it was
        valid — and stops a revoked key authenticating anything after its
        revocation point.

        `commit=None` means "a message being written now". It does **not** mean
        "skip the history boundary": the message will descend from the current
        tip, so that is the point it is validated at. A key that is not yet
        effective cannot sign early, and a revoked one cannot sign late.
        """
        if self.trust is None:
            return None
        at_commit = commit if commit is not None else self.current_tip()
        return trust_module.verify_envelope(
            envelope, self.trust, at_commit=at_commit,
            ancestry=self.is_strict_ancestor, room_id=self.room_id(),
        )

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
        # Provenance last in the order, first in authority: nothing above this
        # line has established *who* wrote it, only that the artifact is
        # well-formed and internally consistent. An unsigned or wrongly signed
        # message raises here, so it never reaches an inbox, a claim, a gate or
        # an audit path - it fails the whole read rather than being returned
        # with a warning nobody checks.
        self.authenticate(envelope, commit)
        return envelope

    def local_persistence_state(self, path: str) -> tuple:
        """Three-state answer: `(commit | None, state, error | None)`.

        `state` is "present", "absent" or "unknown". Proven absence is a fact,
        not uncertainty: a caller that knows nothing was written can safely
        retry, while a caller facing genuine uncertainty must not.
        """
        try:
            proc = self._git(
                "log", self.ref, "--reverse", "--diff-filter=A",
                "--format=%H", "-z", "--", path, check=False,
            )
        except AgentRoomError as exc:
            return None, "unknown", exc
        if proc.returncode != 0:
            return None, "unknown", AgentRoomError(
                f"add-commit lookup for {path} failed: {proc.stderr.strip()}"
            )
        for token in proc.stdout.split("\0"):
            token = token.strip()
            if len(token) >= 40 and all(c in "0123456789abcdef" for c in token):
                return token, "present", None
        return None, "absent", None

    def recover_add_commit(self, path: str) -> tuple:
        """`(commit | None, known, error | None)` - known covers present/absent.

        A wrong commit is worse than an honest "unknown"; the whole point of
        the field is audit.
        """
        commit, state, error = self.local_persistence_state(path)
        if state == "absent":
            return None, True, None
        return commit, state == "present", error

    def current_add_commit(self, path: str, fallback: str | None = None) -> str | None:
        """The commit that currently adds `path`, after any rebase.

        A non-fast-forward rebase rewrites local commit SHAs, so the SHA
        captured before a push may no longer identify the message that is
        actually in the branch. Falls back when history cannot be read at all -
        reporting a stale SHA is still better than reporting none.
        """
        proc = self._git(
            "log", self.ref, "--reverse", "--diff-filter=A",
            "--format=%H", "-z", "--", path, check=False,
        )
        if proc.returncode == 0:
            for token in proc.stdout.split("\0"):
                token = token.strip()
                if len(token) >= 40 and all(c in "0123456789abcdef" for c in token):
                    return token
        return fallback

    RECEIPT_TERMINAL = frozenset({"executed", "failed"})

    @staticmethod
    def assert_receipt_state_machine(messages) -> dict:
        """One-shot means one lifecycle per nonce, checked against history.

        `unused -> uncertain -> executed|failed`, and nothing after a terminal
        state. The write path enforces this under the writer lock; this is the
        same rule applied to a history someone else produced, because a branch
        that already contains two reservations for one nonce is evidence the
        action was released twice and must not be read past.
        """
        sequences: dict = {}
        for envelope in messages:
            if envelope.get("type") != "execution_receipt":
                continue
            receipt = envelope["receipt"]
            key = (envelope["thread_id"], receipt["request_message_id"],
                   receipt["action_nonce"])
            sequences.setdefault(key, []).append((envelope, receipt))

        for (thread_id, request_id, nonce), entries in sequences.items():
            where = f"nonce {nonce} on request {request_id} in thread {thread_id!r}"
            first_env, first = entries[0][0], entries[0][1]
            if first["status"] != "uncertain":
                raise ReceiptStateError(
                    f"the first receipt for {where} is {first['status']!r}; a "
                    "one-shot action is reserved as 'uncertain' before it is "
                    f"performed, so {first_env['message_id']} records an "
                    "outcome for an action that was never reserved"
                )
            terminal = None
            for envelope, receipt in entries[1:]:
                if receipt['decision_id'] != first['decision_id']:
                    raise ReceiptStateError(
                        f'{where}: terminal receipt changes reservation decision provenance')
                if receipt["status"] == "uncertain":
                    raise ReceiptStateError(
                        f"{envelope['message_id']} is a second reservation for "
                        f"{where}; a one-shot action cannot be reserved twice, "
                        "and a history containing two reservations means it "
                        "was released twice"
                    )
                if terminal is not None:
                    raise ReceiptStateError(
                        f"{envelope['message_id']} adds a second terminal "
                        f"receipt for {where}, which already settled as "
                        f"{terminal!r}; there is no transition out of a "
                        "terminal state"
                    )
                terminal = receipt["status"]
        return {
            key: [r["status"] for _e, r in entries]
            for key, entries in sequences.items()
        }

    def verify_store(self) -> int:
        """Walk every committed message and check the whole contract.

        Append-only history and global id uniqueness come from `_history()`;
        path/envelope identity, digest, structure, parent/thread validity,
        historical causality and evidence admissibility come from loading each
        message. This is the gate delivery needs: `verify_append_only()` alone
        would not notice a freshly fetched artifact that is malformed,
        misfiled, or cites something that did not yet exist.

        The receipt lifecycle is checked here too, because an impossible
        sequence of receipts is a statement about the past that no later read
        should be allowed to build on.
        """
        history = self._history()
        loaded = [self._load(path, commit) for path, commit in history.items()]
        self.assert_receipt_state_machine(loaded)
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
    def append(self, envelope: dict) -> dict:
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
            resolver=self._write_resolver,
        )
        return self._append_validated(envelope)

    def append_decision(self, envelope: dict) -> dict:
        """Append one human `approval` or `rejection`. Deliberately NOT agent-facing.

        This is the whole mechanical trust boundary for Issue #5, and it is a
        capability separation rather than a cryptographic one (design §6, which
        explicitly defers signed commits). Nothing here proves a human pressed
        a key. What it guarantees is that the two authority-bearing types are
        unreachable from every agent surface — `AgentRoom.post`, the
        participant adapters, the supervisor boundary and `append` all validate
        `agent_facing=True` and refuse them — so the only way one enters
        history is a caller that deliberately reached for this method.

        `agent_room.decision.HumanDecisionAuthority` is that caller, and no
        participant or orchestrator code may reference it.
        """
        self.assert_room_branch()
        canonical.verify(envelope)
        mtype = envelope.get("type")
        if mtype not in DECISION_TYPES:
            raise ForbiddenOperation(
                f"append_decision carries human authority and accepts only "
                f"{sorted(DECISION_TYPES)}, not {mtype!r}; ordinary messages "
                "go through append()"
            )
        validate_envelope(
            envelope,
            agent_facing=False,
            resolver=self._write_resolver,
        )
        return self._append_validated(envelope)

    def append_receipt(self, envelope: dict, *, publish: bool = True) -> dict:
        """Append one `execution_receipt`. Deliberately NOT agent-facing.

        A receipt is what makes a consequential action one-shot. An agent that
        could write one could consume a human's approval before the human
        acted, or assert an execution that never happened — so it shares the
        decision record's capability boundary: `append` and every participant
        surface refuse the type, and only `agent_room.release` reaches here.
        """
        self.assert_room_branch()
        canonical.verify(envelope)
        mtype = envelope.get("type")
        if mtype != "execution_receipt":
            raise ForbiddenOperation(
                f"append_receipt accepts only 'execution_receipt', not "
                f"{mtype!r}; ordinary messages go through append()"
            )
        validate_envelope(
            envelope,
            agent_facing=False,
            resolver=self._write_resolver,
        )
        if self.remote and publish and envelope["receipt"]["status"] == "uncertain":
            raise ForbiddenOperation("remote reservations require release's exact-head CAS delivery")
        return self._append_validated(envelope, publish=publish)

    def _append_validated(self, envelope: dict, *, publish: bool = True) -> dict:
        """Shared commit path. Validation has already happened above."""
        # The last check before anything becomes permanent: an oversize
        # artifact must fail here rather than after it is in history.
        limits.assert_within(
            len(canonical.canonical_bytes(envelope)),
            limits.MAX_ENVELOPE_BYTES, "canonical envelope")
        # An authenticated room accepts nothing unsigned, including from its
        # own library callers. `at_commit=None` asks the policy about *current*
        # validity, which is the right question for a message being written
        # now: a revoked key signs nothing further.
        if self.trust is not None:
            self.authenticate(envelope, None)
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
                commit_known = True
            except AgentRoomError as exc:
                # The commit sequence includes `git commit` AND the rev-parse
                # that reads its result; either can fail after the commit has
                # actually landed. Guessing is unsafe in both directions:
                # "failed" invites a repost that duplicates the message,
                # "succeeded" may be false. Reconcile, then say what is known.
                landed, state, recovery_error = self.local_persistence_state(rel)
                if state == "absent":
                    # Proven absence is a fact, not uncertainty. Drop the
                    # staged-but-uncommitted artifact so the checkout is not
                    # left dirty and blocking an honest retry. Only safe
                    # because we have *proof* nothing was committed.
                    self._discard_uncommitted(rel)
                    raise DeliveryError(
                        f"message {message_id} was NOT committed: {exc}. "
                        "Nothing was written; the staged artifact has been "
                        "discarded and the message may be posted again.",
                        message_id=message_id, path=rel,
                        commit=None, commit_known=True,
                        locally_committed=False, locally_committed_known=True,
                        pushed=False, pushed_known=True,
                        status="not_created",
                        cause=exc, recovery_error=recovery_error,
                    ) from exc
                landed_known = state == "present"
                if landed_known:
                    raise DeliveryError(
                        f"message {message_id} was committed at {landed} but the "
                        f"commit sequence did not return cleanly: {exc}. "
                        "The message is durable; retry delivery with push(), "
                        "do not repost.",
                        message_id=message_id, path=rel,
                        commit=landed, commit_known=True,
                        locally_committed=True, locally_committed_known=True,
                        pushed=False, pushed_known=True,
                        status="created",
                        cause=exc, recovery_error=recovery_error,
                    ) from exc
                raise DeliveryError(
                    f"message {message_id} may or may not have been committed: "
                    f"{exc}; reconciliation also failed. Do NOT repost - inspect "
                    f"{rel} on {self.branch} first.",
                    message_id=message_id, path=rel,
                    commit=None, commit_known=False,
                    locally_committed=None, locally_committed_known=False,
                    pushed=False, pushed_known=True,
                    status="unknown",
                    cause=exc, recovery_error=recovery_error,
                ) from exc

            result = {
                "status": "created",
                "locally_committed": True,
                "locally_committed_known": True,
                "pushed": False,
                "pushed_known": True,
                "message_id": message_id,
                "thread_id": thread_id,
                "commit": commit,
                "commit_known": commit_known,
                "path": rel,
            }
            if self.remote and publish:
                # The message is already durable locally. If delivery fails the
                # caller must learn *what was written*, or a naive retry of
                # post() would mint a second UUID for the same logical message
                # and duplicate it in permanent history.
                try:
                    push_result = self._push_locked()
                except AgentRoomError as exc:
                    # A rebase during the push may have rewritten our commit,
                    # so re-derive it - and say so honestly if we cannot.
                    current, known, recovery_error = self.recover_add_commit(rel)
                    ambiguous = isinstance(exc, PushAmbiguous)
                    delivered = exc.pushed if ambiguous else False
                    delivered_known = exc.pushed_known if ambiguous else True
                    verdict = (
                        "delivery is UNKNOWN - the remote may already hold it"
                        if not delivered_known else
                        f"was not delivered to {self.remote}"
                    )
                    raise DeliveryError(
                        f"message {message_id} is committed locally at "
                        f"{current if known else '<commit unknown>'} but {verdict}"
                        f": {exc}. Retry delivery with push() for this same "
                        "message; do not repost.",
                        message_id=message_id,
                        commit=current,
                        commit_known=known,
                        path=rel,
                        cause=exc,
                        recovery_error=recovery_error or getattr(exc, "recovery_error", None),
                        pushed=delivered,
                        pushed_known=delivered_known,
                    ) from exc

                # Push succeeded. A failed receipt lookup afterwards must not
                # be reported as a delivery failure - the message did land.
                result["push"] = push_result
                result["pushed"] = push_result.get("pushed")
                result["pushed_known"] = push_result.get("pushed_known", True)
                current, known, recovery_error = self.recover_add_commit(rel)
                result["commit"] = current
                result["commit_known"] = known
                if recovery_error is not None:
                    result["recovery_error"] = str(recovery_error)
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

    def _reconcile_push(self, tip: str) -> tuple:
        """Bounded check of whether the remote already has our tip.

        One `ls-remote`, no fetch. Returns `(pushed, known, error)`. We can
        prove delivery when the remote ref equals what we pushed, and prove
        non-delivery when the branch is absent entirely; anything else stays
        honestly unknown rather than being guessed either way.
        """
        try:
            proc = self._git("ls-remote", self.remote, self.ref, check=False)
        except AgentRoomError as exc:
            return None, False, exc
        if proc.returncode != 0:
            return None, False, AgentRoomError(
                f"ls-remote {self.remote} failed: {proc.stderr.strip()}"
            )
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        if not lines:
            # The exact branch ref is absent, so nothing we pushed landed.
            return False, True, None
        remote_sha = lines[0].split()[0]
        if remote_sha == tip:
            return True, True, None

        # The remote moved. Our push may still have landed and been built on
        # by another writer, so fetch that exact ref and test ancestry rather
        # than assuming rejection.
        fetched = self._git("fetch", "-q", self.remote, self.ref, check=False)
        if fetched.returncode != 0:
            return None, False, AgentRoomError(
                f"reconciliation fetch of {self.ref} failed: {fetched.stderr.strip()}"
            )
        head = self._git("rev-parse", "FETCH_HEAD", check=False).stdout.strip()
        if not head:
            return None, False, AgentRoomError("reconciliation fetch produced no head")
        try:
            if head == tip or self.is_strict_ancestor(tip, head):
                return True, True, None
        except AgentRoomError as exc:
            return None, False, exc
        # The ref exists and demonstrably does not contain our tip.
        return False, True, None

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
            tip = self._git("rev-parse", self.ref, check=False).stdout.strip()
            try:
                proc = self._git(
                    "push", self.remote, f"{self.ref}:{self.ref}", check=False)
            except AgentRoomError as exc:
                # The remote may have accepted the ref before the connection
                # or the result was lost. Reporting "not pushed" here would be
                # a guess, and the damaging kind: it invites a repost.
                pushed, known, recon_error = self._reconcile_push(tip)
                if pushed is True:
                    return {"pushed": True, "pushed_known": True,
                            "attempts": attempt, "reconciled": True}
                raise PushAmbiguous(
                    f"push to {self.remote} did not return a result: {exc}"
                    + ("" if known else " and delivery could not be settled"),
                    pushed=pushed, pushed_known=known,
                    cause=exc, recovery_error=recon_error,
                ) from exc
            if proc.returncode == 0:
                return {"pushed": True, "pushed_known": True, "attempts": attempt}

            # A nonzero result is not proof of non-delivery either: the remote
            # can accept the ref while the client still sees a failure.
            # Reconcile before classifying this as a rejection or a race.
            last_error = proc.stderr.strip()
            settled, settled_known, recon_error = self._reconcile_push(tip)
            if settled is True:
                return {"pushed": True, "pushed_known": True,
                        "attempts": attempt, "reconciled": True}
            if not settled_known:
                raise PushAmbiguous(
                    f"push to {self.remote} returned {proc.returncode} and "
                    f"delivery could not be settled: {last_error}",
                    pushed=None, pushed_known=False,
                    cause=AgentRoomError(last_error or "push failed"),
                    recovery_error=recon_error,
                )

            # Only a *fetchable* remote branch can have moved under us. If the
            # fetch fails there is nothing to rebase onto, and the rejection
            # was something other than a race (a hook, permissions, a missing
            # branch) - retry within the bound and report that instead of
            # misattributing it to a failed rebase.
            fetched = self._git("fetch", "-q", self.remote, self.ref, check=False)
            if fetched.returncode != 0:
                continue

            # Authority-bearing reservations are never reparented by generic
            # participant delivery, even through a later explicit push().
            remote_tip = self._git("rev-parse", "FETCH_HEAD").stdout.strip()
            for path, commit in self._history().items():
                message = self._load(path, commit)
                if (message["type"] == "execution_receipt"
                        and message["receipt"]["status"] == "uncertain"
                        and commit != remote_tip
                        and not self.is_strict_ancestor(commit, remote_tip)):
                    raise PushRaceError("a provisional reservation cannot use generic Git rebase")

            # Transport bookkeeping identity only - it carries no approval
            # authority. Without it a participant checkout with no global Git
            # config cannot complete an ordinary concurrent-writer rebase.
            rebase = self._git(
                "-c", f"user.name={self.author[0]}",
                "-c", f"user.email={self.author[1]}",
                "rebase", "-q", "FETCH_HEAD", check=False)
            if rebase.returncode != 0:
                self._git("rebase", "--abort", check=False)
                raise PushRaceError(
                    f"rebase onto {self.remote}/{self.branch} failed on attempt "
                    f"{attempt}: {rebase.stderr.strip() or last_error}"
                )
            self.verify_store()
        # Retry exhaustion is not by itself proof of non-delivery: an earlier
        # attempt may have been accepted while its acknowledgement was lost.
        # Settle it before classifying, or stay honestly unknown.
        final_tip = self._git("rev-parse", self.ref, check=False).stdout.strip()
        settled, settled_known, recon_error = self._reconcile_push(final_tip)
        if settled is True:
            return {"pushed": True, "pushed_known": True,
                    "attempts": self.push_retries, "reconciled": True}
        if not settled_known:
            raise PushAmbiguous(
                f"push to {self.remote} failed after {self.push_retries} "
                f"attempts and delivery could not be settled: {last_error}",
                pushed=None, pushed_known=False,
                cause=AgentRoomError(last_error or "push failed"),
                recovery_error=recon_error,
            )
        raise PushRaceError(
            f"push rejected after {self.push_retries} attempts: {last_error}"
        )

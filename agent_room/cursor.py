"""Participant-local read/acknowledge state.

Deliberately *not* in Git. Acknowledgement is one participant's bookkeeping,
not shared research state, and writing it to the message log would mean a read
mutates history. The store's own rule — messages are immutable once committed
— would then be false.

So: acknowledging records a message_id in a local JSON file and never touches
the message artifact. The file is rebuildable (worst case, everything reverts
to unread) and its loss costs nothing but re-reading.

Acknowledgement is not agreement. It records only that a participant has seen
a message.
"""

import fcntl
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from . import canonical
from .errors import CursorStateError, LockTimeout

SCHEMA_VERSION = 1
LOCK_TIMEOUT_SECONDS = 10.0
LOCK_POLL_SECONDS = 0.05


class ParticipantCursor:
    """Tracks which messages one participant has acknowledged."""

    def __init__(self, state_dir: str | Path, participant: str) -> None:
        if not participant or "/" in participant:
            raise ValueError(f"invalid participant name: {participant!r}")
        self.state_dir = Path(state_dir)
        self.participant = participant
        self.path = self.state_dir / f"cursor-{participant}.json"
        self._state = self._load()

    def _empty(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "participant": self.participant,
            "acknowledged": {},
        }

    def _load(self) -> dict:
        """Read and validate the cursor file.

        Corruption is reported, not silently discarded. Recovery is documented
        and trivial - delete the file and everything reverts to unread - but a
        cursor that has been tampered with or truncated is worth noticing
        rather than quietly forgetting.
        """
        if not self.path.exists():
            return self._empty()
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise CursorStateError(f"cannot read {self.path}: {exc}") from exc

        try:
            state = canonical.strict_loads(raw)
        except Exception as exc:
            raise CursorStateError(
                f"{self.path} is not valid cursor JSON: {exc}. "
                "Delete the file to reset this participant to unread."
            ) from exc

        if not isinstance(state, dict):
            raise CursorStateError(
                f"{self.path} must contain a JSON object, got "
                f"{type(state).__name__}. Delete the file to reset to unread."
            )
        version = state.get("schema_version")
        if type(version) is not int or version != SCHEMA_VERSION:
            raise CursorStateError(
                f"{self.path} has unsupported schema_version {version!r}"
            )
        owner = state.get("participant")
        if not isinstance(owner, str) or owner != self.participant:
            raise CursorStateError(
                f"{self.path} belongs to participant {owner!r}, not "
                f"{self.participant!r}"
            )
        acknowledged = state.get("acknowledged")
        if acknowledged is None:
            acknowledged = state["acknowledged"] = {}
        if not isinstance(acknowledged, dict):
            raise CursorStateError(
                f"{self.path} has a malformed 'acknowledged' field: expected an "
                f"object, got {type(acknowledged).__name__}"
            )
        for key, entry in acknowledged.items():
            if not isinstance(key, str) or not key:
                raise CursorStateError(
                    f"{self.path} has a non-string acknowledged key {key!r}"
                )
            if not isinstance(entry, dict):
                raise CursorStateError(
                    f"{self.path} has a malformed acknowledged entry for {key!r}: "
                    f"expected an object, got {type(entry).__name__}"
                )
        return state

    def _save(self) -> None:
        """Atomic replace, so an interrupted write cannot truncate the cursor."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.state_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    @contextmanager
    def _file_lock(self):
        """Exclusive lock over this cursor file, bounded by a deadline.

        Without it, two processes acknowledging different messages would each
        write back the state they loaded, and the later write would silently
        drop the earlier acknowledgement.
        """
        self.state_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_dir / f"cursor-{self.participant}.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"another process holds the cursor lock for "
                            f"{self.participant!r} (waited {LOCK_TIMEOUT_SECONDS}s)"
                        )
                    time.sleep(LOCK_POLL_SECONDS)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def acknowledge(self, message_id: str, *, at: str) -> None:
        """Mark one message seen. Never modifies the message artifact.

        Re-reads under the lock before writing, so a concurrent
        acknowledgement of a *different* message is preserved rather than
        clobbered by this process's stale copy.
        """
        with self._file_lock():
            self._state = self._load()
            self._state["acknowledged"][message_id] = {"acknowledged_at": at}
            self._save()

    def is_acknowledged(self, message_id: str) -> bool:
        return message_id in self._load()["acknowledged"]

    def acknowledged_ids(self) -> set[str]:
        return set(self._load()["acknowledged"])

    def unread(self, envelopes) -> list[dict]:
        """Messages addressed to this participant that it has not acknowledged."""
        acked = self.acknowledged_ids()
        out = []
        for env in envelopes:
            if env["message_id"] in acked:
                continue
            if env["sender"].get("agent") == self.participant:
                continue  # your own messages are not your inbox
            recipient = env.get("recipient") or {}
            if recipient.get("broadcast") or recipient.get("agent") == self.participant:
                out.append(env)
        return out

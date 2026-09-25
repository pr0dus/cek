"""Private, bounded OS locks for transport lifecycle and durable state writes.

These are service configuration paths, never request parameters. The worker
lock encloses the whole run; the separate state lock protects compare/write
even when a stale Anchor object survives across runs. Neither lock is removed
on release (unlinking a lock would create two independent lock inodes).
"""
import fcntl
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from .errors import AgentRoomError

LOCK_TIMEOUT_SECONDS = 5.0
WORKER_LOCK = 'transport-worker.lock'
STATE_LOCK = 'transport-state.lock'


class StateError(AgentRoomError):
    """Unsafe, stale or unavailable transport state."""


class WorkerBusy(StateError):
    """Another process owns the bounded lifecycle critical section."""


@contextmanager
def private_directory(path):
    """Open every component without following symlinks; pin the private root."""
    path = Path(path).absolute()
    fd = None
    try:
        if '..' in path.parts:
            raise StateError('state path contains traversal')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise StateError('transport state root must be owner-owned mode 0700')
        yield fd
    except OSError as exc:
        raise StateError(f'cannot open private transport state: {exc}') from exc
    finally:
        if fd is not None:
            os.close(fd)


def check_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise StateError('transport state/lock must be one owner-owned regular 0600 file')
    return info


@contextmanager
def private_lock(root, name):
    if name not in (WORKER_LOCK, STATE_LOCK):
        raise StateError('unknown transport lock')
    with private_directory(root) as directory:
        fd = None
        try:
            fd = os.open(name, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC |
                         os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            identity = check_file(fd)
            deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise WorkerBusy('transport lock busy; no request performed')
                    time.sleep(0.025)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino):
                raise StateError('transport lock identity changed while waiting')
            check_file(fd)
            yield
        except OSError as exc:
            raise StateError(f'cannot acquire transport lock: {exc}') from exc
        finally:
            if fd is not None:
                # close releases flock on normal/exception exit; kernel does
                # the same on death. No unlink, owner PID guess or stale reset.
                os.close(fd)

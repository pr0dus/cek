"""Root-installed fixed service starter. No credentials, model, argv API.

Invoked only by two root-owned path units. A wake carries no authority: the
non-root worker verifies the signed task and its durable invocation journal.
"""
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys

from . import custody
from .tasks import ROLES, require


def consume(path, user):
    """Pin directory chain, never traverse caller-installed symlinks as root."""
    path = Path(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        require(info.st_uid == pwd.getpwnam(user).pw_uid and
                stat.S_IMODE(info.st_mode) == 0o700, 'wake directory ownership')
        try:
            info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        require(stat.S_ISREG(info.st_mode) and info.st_uid == pwd.getpwnam(user).pw_uid
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                'wake hint is not a private file')
        os.unlink(path.name, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def run(role):
    require(role in ROLES and os.geteuid() == 0, 'fixed admin dispatcher only')
    item = custody.layout(role)
    # Consume before start: arrivals during work remain for the path unit's
    # post-exit recheck. Service Restart=on-failure reconciles launch ambiguity;
    # role intent prevents another model attempt, including after a host reboot.
    consume('/var/lib/agent-room/state/task-wake-' + role, 'agentroom')
    consume(Path(item['state']) / 'task-more', item['user'])
    unit = {'codex': 'agent-room-codex.service',
            'claude-code': 'agent-room-claude.service'}[role]
    return subprocess.run(['/usr/bin/systemctl', 'start', unit], timeout=1250,
                          env={'PATH': '/usr/bin:/bin'}, check=False).returncode


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'one fixed role')
    raise SystemExit(run(sys.argv[1]))

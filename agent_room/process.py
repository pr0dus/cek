"""Bounded subprocess execution with a sanitised environment.

Two defects live at this boundary, and both were demonstrated rather than
theorised (Issue #13).

*A timeout killed the parent and left the family.* `subprocess.run(timeout=…)`
terminates the process it started and then waits; a grandchild that the child
spawned keeps running, holding pipes, CPU and whatever else it was doing. So
every security-sensitive invocation here starts its own session
(`start_new_session=True`) and, on timeout or interruption, signals the whole
process **group** — SIGTERM, a bounded grace period, then SIGKILL.

*The environment was inherited whole.* A caller-controlled `PYTHONPATH`,
`LD_PRELOAD` or `GIT_DIR` silently changes what a "clean" run executes or what
a "verification" command resolves. The variables that can redirect execution or
object lookup are therefore removed by name, and the interpreter is told not to
read user site directories.

None of this survives an attacker with arbitrary root on the host, and this
module does not pretend otherwise. It closes the gap between "the command we
asked for" and "the command that actually ran" for an unprivileged caller.
"""

import os
import signal
import subprocess
import time
from dataclasses import dataclass

from .errors import AgentRoomError

#: How long a terminated process group gets to exit before it is killed.
GROUP_TERM_GRACE_SECONDS = 5.0

#: Variables removed by exact name. Each one can change which code runs, or
#: which objects a Git command resolves, without appearing in the argv.
UNSAFE_ENV_NAMES = frozenset({
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "CDPATH",
    "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB", "NODE_OPTIONS",
    "PYTHONSTARTUP", "PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE",
    "PYTHONEXECUTABLE", "PYTHONWARNINGS", "PYTHONINSPECT",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES",
})

#: Variables removed by prefix. `GIT_*` as a class, because the dangerous
#: members keep growing and an allowlist is the only safe direction here.
UNSAFE_ENV_PREFIXES = ("GIT_", "PYTHON", "LD_", "DYLD_")

#: Kept when building an isolated execution environment. Everything else is
#: dropped: a proof runs with what it needs to find a program and write in its
#: own directory, and nothing that redirects either.
ISOLATED_ENV_KEEP = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "USER", "LOGNAME",
    "TERM", "TMPDIR",
)

#: Forced into an isolated environment. `NOUSERSITE` matters most: without it
#: `~/.local/lib/python*/site-packages` is on `sys.path`, which is a writable
#: directory outside any snapshot this room measures.
ISOLATED_ENV_FORCE = {
    "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
}

__all__ = [
    "GROUP_TERM_GRACE_SECONDS", "UNSAFE_ENV_NAMES", "UNSAFE_ENV_PREFIXES",
    "ISOLATED_ENV_KEEP", "ISOLATED_ENV_FORCE",
    "ProcessError", "BoundedResult", "sanitised_env", "isolated_env",
    "terminate_group", "run_bounded",
]


class ProcessError(AgentRoomError):
    """A bounded subprocess could not be started or reaped."""


def _is_unsafe(name: str) -> bool:
    return name in UNSAFE_ENV_NAMES or name.startswith(UNSAFE_ENV_PREFIXES)


def sanitised_env(base: dict | None = None, **extra) -> dict:
    """The caller's environment minus everything that can redirect execution."""
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items() if not _is_unsafe(k)}
    env.update(extra)
    return env


def isolated_env(**extra) -> dict:
    """A minimal environment for running a proof.

    An allowlist, not a filter: a proof is supposed to be reproducible from the
    state it was measured against, and every variable that survives is one more
    input nobody measured.
    """
    env = {k: os.environ[k] for k in ISOLATED_ENV_KEEP if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update(ISOLATED_ENV_FORCE)
    env.update(extra)
    return env


def terminate_group(pid: int, *, grace: float = GROUP_TERM_GRACE_SECONDS) -> str:
    """SIGTERM the process group, then SIGKILL what is left.

    Returns what it took: "already-gone", "terminated" or "killed". The pid
    must be a session/group leader — `run_bounded` makes it one.
    """
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return "already-gone"
    except OSError as exc:                                  # pragma: no cover
        raise ProcessError(f"cannot read process group of {pid}: {exc}") from exc

    # Never signal our own group: that would take down the caller along with
    # the child, which is a far worse failure than a surviving grandchild.
    if pgid == os.getpgrp():                                # pragma: no cover
        raise ProcessError(
            f"child {pid} is in this process's own group ({pgid}); refusing to "
            "signal it. The child must be started with start_new_session=True."
        )

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return "already-gone"

    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return "terminated"
        time.sleep(0.05)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return "terminated"
    return "killed"


@dataclass
class BoundedResult:
    """What a bounded run produced, including how it ended."""

    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    #: "" | "already-gone" | "terminated" | "killed" — what the teardown did.
    teardown: str = ""


def run_bounded(
    argv,
    *,
    cwd=None,
    env: dict | None = None,
    input: bytes | None = None,
    timeout: float,
    grace: float = GROUP_TERM_GRACE_SECONDS,
) -> BoundedResult:
    """Run one command in its own process group, bounded by `timeout`.

    On timeout the entire group is torn down before returning, so no
    descendant outlives the call. Whatever output was produced first is still
    returned: a timed-out run's partial output is evidence.
    """
    argv = [str(a) for a in argv]
    if not argv:
        raise ProcessError("a bounded run needs a command")
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # The whole point: a new session makes this process a group leader,
            # so its descendants share a group we can signal as one.
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        raise ProcessError(
            f"could not run {argv[0]!r}: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
        return BoundedResult(proc.returncode, stdout or b"", stderr or b"")
    except subprocess.TimeoutExpired:
        teardown = terminate_group(proc.pid, grace=grace)
        try:
            stdout, stderr = proc.communicate(timeout=grace)
        except subprocess.TimeoutExpired:                   # pragma: no cover
            proc.kill()
            stdout, stderr = proc.communicate()
        return BoundedResult(proc.returncode, stdout or b"", stderr or b"",
                             timed_out=True, teardown=teardown)
    except BaseException:
        # Ctrl-C, or anything else unwinding through here, must not leave the
        # family running either.
        terminate_group(proc.pid, grace=grace)
        proc.wait()
        raise

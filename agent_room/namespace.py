"""The closed namespace of the room branch.

`verify_store()` used to authenticate `.agent-room/messages/**` and ignore
everything else on the branch. A red-team commit of `.gitattributes` beside
the message tree therefore passed verification untouched (Issue #13, HIGH E).

That is the wrong shape for a trust boundary. A branch is not "the paths we
happen to look at"; it is every tracked byte, and anything else on it is
either part of the protocol or an intrusion. So the protocol enumerates what
may exist, and everything outside that list fails closed — including the
files Git itself gives meaning to.

`.gitattributes` is the clearest example of why this is not pedantry. A filter
or `text` attribute changes what the bytes of a checked-out file are, which
would let a committed artifact and its verified digest disagree by design.
`.gitmodules` introduces content this repository does not hold. Hooks and
config artifacts execute. None of them belong in a message transport.

Modes matter as much as paths. A symlink is a pointer out of the namespace, an
executable bit is an invitation, and a gitlink is a whole other repository. The
protocol stores one thing: non-executable regular files containing JSON.
"""

import re

from .errors import AgentRoomError
from .ids import is_uuid7
from .schema import THREAD_ID_RE

#: The one file that is not a message: a human-readable marker committed when
#: the branch is created, so a person who lands on it knows what it is.
GENESIS_PATH = "README.agent-room.md"

MESSAGES_DIR = ".agent-room/messages"

#: A regular, non-executable file. Nothing else is storable content here.
ALLOWED_BLOB_MODE = "100644"

#: What each rejected mode would mean if it were allowed.
MODE_MEANINGS = {
    "100755": "an executable file",
    "120000": "a symbolic link, which points outside the verified namespace",
    "160000": "a gitlink to another repository whose content this branch does "
              "not hold",
}

#: Named only to make the refusal message useful; they are refused by the
#: allowlist regardless, like every other unexpected path.
NOTABLY_FORBIDDEN = (
    ".gitattributes", ".gitmodules", ".gitignore", ".mailmap",
    ".git-blame-ignore-revs",
)

MESSAGE_PATH_RE = re.compile(
    r"\A" + re.escape(MESSAGES_DIR) + r"/([^/]+)/([^/]+)\.json\Z"
)

__all__ = [
    "GENESIS_PATH", "MESSAGES_DIR", "ALLOWED_BLOB_MODE", "MODE_MEANINGS",
    "NOTABLY_FORBIDDEN", "NamespaceViolation", "classify", "describe_refusal",
    "assert_allowed_entry",
]


class NamespaceViolation(AgentRoomError):
    """A tracked path or mode the room protocol does not define.

    Fails closed on read as well as write: a branch carrying one is not a room
    whose contents can be trusted, whoever put it there.
    """


def classify(path: str) -> str | None:
    """"genesis", "message", or None for anything the protocol does not define."""
    if path == GENESIS_PATH:
        return "genesis"
    match = MESSAGE_PATH_RE.match(path)
    if match and THREAD_ID_RE.match(match.group(1)) and is_uuid7(match.group(2)):
        return "message"
    return None


def describe_refusal(path: str) -> str:
    if path in NOTABLY_FORBIDDEN:
        return (
            f"{path!r} is a Git metadata file. It changes how Git itself "
            "interprets tracked content, which is exactly what a verified "
            "message transport must not let anyone do"
        )
    if path == MESSAGES_DIR or path.startswith(f"{MESSAGES_DIR}/"):
        return (
            f"{path!r} is under {MESSAGES_DIR}/ but is not a canonical "
            "<thread_id>/<uuid7>.json message path"
        )
    return (
        f"{path!r} is not part of the room protocol. The branch holds exactly "
        f"{GENESIS_PATH} and {MESSAGES_DIR}/<thread_id>/<uuid7>.json"
    )


def assert_allowed_entry(mode: str, object_type: str, path: str) -> str:
    """Validate one tracked tree entry. Returns its classification."""
    kind = classify(path)
    if kind is None:
        raise NamespaceViolation(
            f"unexpected tracked path on the room branch: {describe_refusal(path)}"
        )
    if object_type != "blob":
        raise NamespaceViolation(
            f"{path!r} is a {object_type}, not a file; "
            f"{MODE_MEANINGS.get(mode, 'that')} has no place in the room namespace"
        )
    if mode != ALLOWED_BLOB_MODE:
        raise NamespaceViolation(
            f"{path!r} has mode {mode} ({MODE_MEANINGS.get(mode, 'unexpected')}); "
            f"room artifacts are plain non-executable files (mode "
            f"{ALLOWED_BLOB_MODE})"
        )
    return kind

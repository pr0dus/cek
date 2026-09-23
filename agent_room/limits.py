"""Hard resource bounds, checked before anything durable or expensive happens.

Every limit here exists because the alternative is unbounded: a message whose
body is a gigabyte still commits, a thread with a hundred thousand entries
still renders into a prompt, a proof that prints forever still fills the disk.
None of that requires an attacker — but an attacker is what makes it worth
failing closed rather than "probably fine in practice".

The numbers are deliberately generous for real traffic and deliberately finite.
They are policy, not physics: raising one is a decision, which is why they live
in one place with the reason attached rather than scattered as literals.

Where a limit is enforced matters as much as its value. Envelope limits are
checked before the Git commit, packet limits before the packet leaves the
process, and thread limits before a prompt is built — so an oversize input
fails without a durable write or a model invocation behind it.
"""

from .errors import AgentRoomError

#: One canonical envelope on disk. Large enough for a long review with
#: evidence; small enough that a room of them stays greppable.
MAX_ENVELOPE_BYTES = 256 * 1024

#: `body.text`, counted in characters before encoding.
MAX_BODY_TEXT_CHARS = 64 * 1024

#: Evidence entries on one message. Beyond this it is a dump, not a citation.
MAX_EVIDENCE_ITEMS = 64

#: Messages in one thread. A thread is one research question; this is a
#: ceiling on pathology, not on conversation.
MAX_THREAD_MESSAGES = 2000

#: The supervisor packet, serialised. It carries a whole thread, so its bound
#: is necessarily larger than one envelope's.
MAX_PACKET_BYTES = 8 * 1024 * 1024

#: Captured per stream from a proof. The digest always covers the complete
#: stream; this bounds what is *stored*.
MAX_PROOF_STREAM_BYTES = 4 * 1024 * 1024

#: One proof artifact on disk.
MAX_PROOF_ARTIFACT_BYTES = 12 * 1024 * 1024

__all__ = [
    "MAX_ENVELOPE_BYTES", "MAX_BODY_TEXT_CHARS", "MAX_EVIDENCE_ITEMS",
    "MAX_THREAD_MESSAGES", "MAX_PACKET_BYTES", "MAX_PROOF_STREAM_BYTES",
    "MAX_PROOF_ARTIFACT_BYTES", "LimitExceeded", "assert_within",
]


class LimitExceeded(AgentRoomError):
    """A hard resource bound was exceeded. Nothing was written or invoked."""


def assert_within(actual: int, limit: int, what: str, unit: str = "bytes") -> int:
    """Refuse `actual` if it exceeds `limit`, naming both."""
    if actual > limit:
        raise LimitExceeded(
            f"{what} is {actual} {unit}, over the {limit} {unit} limit; "
            "refusing before anything durable or expensive happens"
        )
    return actual

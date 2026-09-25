# C6 — bounded generic delivery recovery

Scope: the C5-V Medium in `GitMessageStore._reconcile_push`. No deployment,
credential, custody, release/CAS, protected-state or policy changes.

## Reproduced boundary

A real non-fast-forward signed participant post received 10,480,063 bytes from
`git ls-remote` before rejecting 40,000 hostile suffix-matching refs. Exact-ref
semantics were correct, but `subprocess.run(capture_output=True)` accumulated the
entire advertisement before checking it. C4 quarantine limits occur too late
to bound that recovery observation.

## Correction

The generic text Git wrapper's `ls-remote` operation now uses the existing
`process.run_bounded` streaming runner and the transport's authoritative
`remote_sync.MAX_GIT_OUTPUT_BYTES` cap (8 MiB per stdout/stderr stream).
The library's existing 60-second timeout, checked role-specific SSH binding,
sanitized environment and Git hardening are preserved. Other generic Git
operations are unchanged.

Reaching either stream's cap, or timing out, terminates the process group and
raises a controlled Agent Room error **before** parsing any returned prefix.
Per the existing runner contract, output strictly below the cap is admissible;
output equal to or greater than the cap is refused. A truncated empty or
apparently exact-ref prefix cannot become a delivery observation.

The exact OID/tab/authoritative-ref checks and verified-descendant recovery
remain unchanged. Output refusal means `pushed=null`, `pushed_known=false`, not
an assertion of non-delivery. Local commit identity/recovery information
remains available; callers retry delivery of that message, never repost it.

## Regression proof

`tests/test_agent_room_c6.py` covers:

- the actual 40,000-ref / ~10 MB advertisement through signed `AgentRoom.post`;
- bounded capture and no fallback fetch/rebase on output exhaustion;
- a later delivery retry preserving the same single message;
- real exact-ref output below/at/above the cap;
- stdout and stderr streaming boundaries (including valid stdout plus flooded
  stderr), timeout with a valid-looking prefix and controlled runner errors;
- recovery never falling back to unbounded `subprocess.run` capture.

Existing lost-acknowledgement tests inject their unavailable recovery query at
the new runner seam. Their uncertainty and CLI assertions are unchanged.
The C1–C5 security regressions remain required.

This correction is implementation/regression evidence, not independent S4
acceptance. The retained RuntimeMaxSec Low, passwordless-sudo activation
blocker and deployment-only cross-UID/credential/policy proofs are untouched.

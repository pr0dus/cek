# Process

## The principle

> The goal isn't to have humans design AGI, nor to have AI agents autonomously
> design AGI. The goal is to construct a persistent research and developmental
> process in which humans and AI systems can propose and challenge mechanisms,
> while the developing system increasingly discovers its own useful structure —
> and where **no participant's confidence substitutes for evidence**.

## Why this is the right shape

**It applies symmetrically.** The rule binds every participant: the human, the
AI collaborators, and the developing system itself. That is CEK's own
constitution — `USER_CONFIDENCE != TECHNICAL_VALIDATION`,
`LLM_OUTPUT != EVIDENCE` — extended to the research process that builds CEK.

**It names the actual research target.** "Increasingly discovers its own
useful structure" is precisely where current CEK stops: every mechanism
audited so far selects among a frozen, human-enumerated hypothesis space
(`docs/PRE_PHASE0_AUDIT.md`). Moving from *selecting among given hypotheses*
to *generating them from experience* is the concrete form of that sentence.

**It must survive its participants.** No participant persists. Claude sessions
end and their context is gone. Codex sessions end. Human memory reconstructs
rather than replays. Participants reason, propose and challenge; they do not
carry state. **The repository is the persistent research state** — the carrier
across participants, not a participant itself. That is not bookkeeping; it is
the mechanism by which the process continues at all.

## The gap: challenges need a record

The principle says participants propose *and challenge*. `CHARTER.md` defines
a promotion path for mechanisms, but nothing recorded the fate of **claims** —
so a challenge raised in one session was invisible to the next, and a
confidently-stated error could survive by being forgotten rather than by being
right.

The ledger exists for one purpose: **to stop unsupported conclusions from
silently becoming inherited assumptions.** It is not a process artifact to be
maintained for its own sake. Keep entries short.

### Fields

- **Status** — `proposed` · `challenged` · `supported` · `retracted`
- **Source** — human, Claude, Codex, or the system
- **Evidence** — what actually supports it, and by what method
- **Scope** — the bounds within which that support holds
- **Revision condition** — what would falsify it or require revision

### Rules

1. **`supported` is evidence-scoped, not true.** It means: this evidence
   supports this claim within this scope. A claim whose scope is unstated
   cannot be `supported`.
2. **Retractions stay.** A ledger that drops its errors cannot be audited.
3. **A claim with no revision condition is `proposed` at best.**
4. Any participant may challenge any claim, including their own.

## Ledger

### C1 — CEK's general `Observation` is unsuitable as the direct ARC interface
**Status:** `supported` · **Source:** Claude
**Evidence:** `model.py:93` — flat `(name, int)` features plus a required
integer `target`; `arcengine` 0.9.3 introspection confirms ARC supplies no
per-step target, only terminal `WIN`/`GAME_OVER`.
**Scope:** `model.Observation` specifically, as a *direct* interface, at commit
`40ffdf4`. Says nothing about other CEK entry points — see C2 — and nothing
about what real frames would show.
**Revision condition:** a non-supervised path into the same machinery, or a
target derivable without game-specific semantics.

### C2 — CEK is purely flat and supervised
**Status:** `retracted` · **Source:** Claude
**Evidence:** contradicted by `_composition_primitives.py:49`,
`PrimitiveRelationObservation` — a relational triple substrate requiring no
target.
**Cause:** asserted after reading four modules of 264.

### C3 — PoC 4's `GridAdapter` shows CEK can ground a grid
**Status:** `retracted` · **Source:** implied by prior framing
**Evidence:** `poc4_adapters.py:194` — `reconstruct` decodes a format the same
class's `project` wrote, hardcoding legend position and `len(rows) != 4`.
Sound as a representation-invariance test; not perception.

### C4 — Phase 0 is answered
**Status:** `retracted` · **Source:** Claude
**Evidence:** none available — source reading cannot settle an empirical
question. Retracted on external challenge.
**Cause:** conclusion stated at a confidence the method could not support.

### C5 — The missing layer is an object segmenter
**Status:** `retracted` · **Source:** Claude
**Evidence:** none — a premature ontology that would inject human semantics
into the experiment. Retracted on external challenge.
**Cause:** named a solution before the evidence that would constrain it.

### C6 — Every audited CEK mechanism selects among a frozen, human-enumerated hypothesis space
**Status:** `proposed` · **Source:** Claude
**Evidence:** PoC 3 spec ("frozen hypothesis space", four interpretations),
PoC 5 spec (four enumerated transition laws, one survivor required), PoC 8
spec (predeclared finite meta-grammar).
**Scope:** the four PoC specs read. Most of 264 modules unexamined, so
"every audited" must not be read as "every".
**Revision condition:** any CEK mechanism generating candidate hypotheses from
raw experience without a human-specified space.

### C7 — The PoC 5 / PoC 3 loop transfers to ARC; the enumerable-hypothesis assumption does not
**Status:** `proposed` · **Source:** Claude
**Evidence:** none yet. Structural reading of specs only.
**Scope:** untested. Requires real frames.
**Revision condition:** the loop failing on real transitions for reasons
unrelated to hypothesis-space size, or enumerable hypotheses proving
sufficient on real frames.

### C8 — A grounding/perception capability is missing or unproven in CEK
**Status:** `proposed` · **Source:** Claude, refined by human
**Evidence:** no module found that transforms a raw frame into persistent
entities or relations; filename-level sweep of 264 modules found no spatial,
topological or perceptual machinery.
**Scope:** filename-level sweep plus four specs read in full. Absence of
evidence at this depth, not demonstrated absence.
**Revision condition:** such a module in unread code, or existing machinery
handling real frames unmodified.

---

## Observations on this session

Eight claims were entered. Four were retracted — C2, C3, C4, C5 — two of those
on external challenge. All four failed the same way: **confidence exceeding
the evidence available to the method used.**

This is not an error rate and must not be used to estimate participant
reliability. One session is neither randomly sampled nor large enough to
support that inference, and treating it quantitatively would repeat the exact
failure it describes.

The defensible finding is narrower and sufficient: *multiple substantive
claims in a single research session required retraction after broader source
inspection or external challenge, and the failures repeatedly involved
confidence exceeding what the method could support.* That alone justifies
persistent claim tracking.

**The summary of this section was itself wrong on first writing** — it stated
six claims and three retractions against a ledger containing eight and four.
Caught in independent review, not by its author. The ledger demonstrated its
own necessity before it had been used once.

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
The system is held to the epistemics it is built to embody, and so is everyone
working on it.

**It names the actual research target.** "Increasingly discovers its own
useful structure" is precisely where current CEK stops: every mechanism
audited so far selects among a frozen, human-enumerated hypothesis space
(`docs/PRE_PHASE0_AUDIT.md`). Moving from *selecting among given hypotheses*
to *generating them from experience* is the concrete form of that sentence.

**It survives its participants.** No individual participant persists. Claude
sessions end and their context is gone. Codex sessions end. Human memory
degrades and reconstructs. So the process cannot live in any participant — it
has to live in artifacts: this repository, the charter, recorded findings,
and retained negative results. **The repository is the persistent
participant.** That is not bookkeeping; it is the mechanism.

## The gap: challenges need a record

The principle says participants propose *and challenge*. `CHARTER.md` defines
a promotion path for mechanisms, but nothing records the fate of **claims** —
so a challenge raised in one session is invisible to the next, and a
confidently-stated error survives by being forgotten rather than by being
right.

Every substantive claim about what the system is or does gets an entry:
what was claimed, who claimed it, what would falsify it, and its current
status.

**Status values:** `proposed` · `challenged` · `supported` · `retracted`

**Rules**

1. Retractions stay. A ledger that silently drops its errors cannot be
   audited, and the error rate is itself evidence about how much weight a
   participant's confidence deserves.
2. Source is recorded — human, Claude, Codex, or the system — not to assign
   blame but because a participant's track record is data.
3. A claim with no stated falsifier is `proposed` at best, never `supported`.
4. Any participant may challenge any claim, including their own.

## Ledger

### C1 — CEK's general `Observation` is unsuitable as the direct ARC interface
**Source:** Claude · **Status:** `supported`
Flat `(name, int)` features plus a required integer `target`; ARC supplies no
per-step target. Falsifier: a non-supervised path into the same machinery.

### C2 — CEK is purely flat and supervised
**Source:** Claude · **Status:** `retracted`
Missed `PrimitiveRelationObservation`, a relational triple substrate needing
no target. Retracted on reading `_composition_primitives.py`. **Cause:
asserted after reading 4 modules of 264.**

### C3 — PoC 4's `GridAdapter` shows CEK can ground a grid
**Source:** implied by prior framing · **Status:** `retracted`
Its `reconstruct` decodes a format its own `project` wrote. Sound as a
representation-invariance test; not perception.

### C4 — Phase 0 is answered
**Source:** Claude · **Status:** `retracted`
Source reading cannot settle an empirical question. Retracted on human
challenge. **Cause: conclusion stated at a confidence the method could not
support.**

### C5 — The missing layer is an object segmenter
**Source:** Claude · **Status:** `retracted`
Premature ontology; would inject human semantics into the experiment.
Retracted on human challenge. **Cause: named a solution before the evidence
that would constrain it.**

### C6 — Every audited CEK mechanism selects among a frozen, human-enumerated hypothesis space
**Source:** Claude · **Status:** `proposed`
PoC 3 ("frozen hypothesis space", four interpretations), PoC 5 (four
enumerated transition laws), PoC 8 (predeclared finite meta-grammar).
Falsifier: any CEK mechanism generating candidate hypotheses from raw
experience without a human-specified space. **Unaudited modules remain; this
is proposed, not supported.**

### C7 — The PoC 5 / PoC 3 loop transfers to ARC; the enumerable-hypothesis assumption does not
**Source:** Claude · **Status:** `proposed`
Falsifier: the loop failing on real transitions for reasons unrelated to
hypothesis-space size, or enumerable hypotheses proving sufficient on real
frames. **Requires real frames. Untested.**

### C8 — A grounding/perception capability is missing from CEK
**Source:** Claude, refined by human · **Status:** `proposed`
No module transforms a raw frame into persistent entities or relations.
Stated as missing *or unproven* — filename-level sweep only. Falsifier: such a
module in unread code, or existing machinery handling real frames unmodified.

---

**Observed so far:** of six claims this session, three were retracted, two
under human challenge. All three failures shared one cause — confidence
outrunning the evidence the method could supply. That rate is the reason this
ledger exists, and it is the concrete case for the principle above.

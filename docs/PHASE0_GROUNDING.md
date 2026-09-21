# Phase 0 — Grounding feasibility

**Date:** 2026-09-21
**Method:** Source reading of `pr0dus/concept-evolution-kernel` at `40ffdf4`,
and introspection of `arcengine` 0.9.3. No games were run — none were needed.

## Question

Can CEK's core represent an ARC-AGI-3 observation *without the adapter
encoding what the game is about?*

## Answer

**Not as it stands.** CEK assumes entities already exist; ARC-AGI-3 hands it
undifferentiated pixels. The missing piece is entity formation, not an
adapter — and not, as first suspected, a missing target or a purely flat
representation.

## Evidence

### 1. The general observation requires a supervised target

`src/concept_evolution_kernel/model.py:93`

```python
class Observation:
    features: tuple[tuple[str, int], ...]
    target: int
    family: str
    phase: str
```

CEK's fundamental input is a flat set of `(name, integer)` pairs plus **a
required integer `target`**. Feature names are deliberately non-semantic
(`q0`, `q1`, …), which is good discipline — but the shape is
supervised: features in, target out.

ARC-AGI-3 supplies no per-step target. Feedback is strictly binary and
terminal: `WIN` or `GAME_OVER`, with no shaping. Any value placed in `target`
would be invented by us, which is precisely the failure mode this branch
exists to avoid.

### 2. Flat scalar features cannot carry spatial structure — but a second substrate can

An ARC-AGI-3 frame is a stack of 64×64 integer grids. Flattening 4096 cells
into `q0…q4095` is mechanically possible and epistemically useless: adjacency
is destroyed. Cells `(3,4)` and `(3,5)` being neighbours — the single most
important fact about a grid — becomes unrepresentable.

**However, `model.Observation` is not CEK's only input type.**
`_composition_primitives.py:49` defines:

```python
class PrimitiveRelationObservation:
    subject_entity_token: str
    relation_token: str
    object_entity_token: str
    asserted: bool
```

A subject-relation-object triple with an assertion flag. This *can* carry
spatial structure — `(cell_3_4, right_of, cell_3_5)`, `(region_a, encloses,
region_b)` — and it needs no numeric target, which also sidesteps finding 1.

This is the honest place to build, and it is a better starting position than a
flat feature vector. But it relocates the problem rather than solving it,
which is finding 5.

### 3. No action in the representation

`Observation` models `features → target`. ARC-AGI-3 is a POMDP requiring
`(state, action) → next_state`. There is nowhere to record what was done, so
action-conditioned dynamics cannot be expressed at all.

### 4. PoC 4's grid is not a counterexample

`poc4_adapters.py:194` — `GridAdapter.reconstruct` decodes a format that the
same class's `project()` wrote. It knows row 0 is a legend, that rows 1/2/3
carry demand/capacity/blocked, and it hardcodes `len(rows) != 4`.

That is a hand-written decoder for a self-authored encoding. As a test of
representation invariance it is sound and the `18/18` result stands for what
it claims. It is not perception, and it does not indicate that CEK can ground
an unknown grid.

`CoreScene` (`poc4_core.py:14`) likewise hardcodes three named fields,
`demand`/`capacity`/`blocked`, with domain validation (`blocked > capacity`
raises).

### 5. The real gap is entity formation

A triple store requires **entity tokens**. Something must decide what the
entities *are* before any relation can be asserted.

For a 64×64 grid with unknown semantics, that decision is the grounding
problem itself:

- Individual cells? 4096 entities, ~16k adjacency triples per frame, and every
  interesting structure (a wall, a key, an agent) is spread across many of
  them with nothing marking which ones belong together.
- Regions or objects? Then something must segment the grid — group cells into
  objects, track them across frames, notice when one moves or changes. That is
  perception, and **CEK has no module for it**. Searching for
  spatial/grid/geometry/topology/adjacency/perception modules across all 264
  files returns nothing (`online_interactive_revision.py` and
  `revision_decision.py` match only because "re-vision" contains "vision").

So the gap is not "CEK lacks a target" or "CEK is flat". It is that CEK
assumes entities already exist, and ARC-AGI-3 hands it undifferentiated
pixels.

## What this does and does not mean

**Does not mean CEK is wrong or should be abandoned.** Per `CHARTER.md`, that
is not this branch's call, and nothing here bears on the main lineage. CEK was
built for evidence-gated concept induction over bounded structured state, and
by the evidence it is good at that.

**Does mean** the grounding layer is new work rather than adaptation. Anyone
estimating "wire CEK to ARC-AGI-3" as an integration task is off by a
foundation.

## The constructive part: PoC 5 is the likely bridge

The mechanism most likely to transfer is **PoC 5's precommitted prediction and
anomaly detection**, not PoC 0/4's induction from labelled examples.

Prediction needs no target label. It needs a next state, which the environment
supplies for free on every step. The learning signal becomes: predict the next
frame, be wrong, revise — which is falsification, native to CEK's philosophy,
and requires no invented supervision.

That reframes the missing piece. What is needed is not a target-generator but:

1. **Entity formation** — a mechanism that segments a raw grid into stable
   entities and tracks them across frames, so relation triples have something
   to refer to.
2. An **action-conditioned** transition representation.
3. A learning signal driven by **prediction error**, not target fitting.

Item 1 is the hard one and is the real Phase 0 deliverable. Items 2 and 3 are
mostly plumbing once 1 exists.

Note the ordering risk: entity formation is where ARC-specific hacks will be
most tempting and hardest to detect, because a segmenter tuned by looking at
`ls20` will look like general perception. `CHARTER.md`'s criterion 3 —
off-benchmark transfer — applies with full force here.

## Recommended next step

Do not wire CEK to the harness yet — there is nothing to wire it to until a
spatial observation type exists.

Instead:

1. Get the random baseline number on real games. It costs little, requires no
   architecture, and every later claim is stated against it.
2. Design the spatial observation type against *real frames* from `ft09`,
   `ls20`, `vc33` — not against assumptions about what a frame looks like.

Step 2 depends on step 1's data. Both are blocked only on network access to
`three.arcprize.org`, which this sandbox cannot reach.

## Caveat

Claims here cover `model.Observation`, `_composition_primitives`, the PoC 4
path, and a filename-level sweep of all 264 modules for spatial machinery.
A richer representation may still exist somewhere I did not read. If one
turns up, this document should be revised rather than defended — the claim is
about what was verified, not about what cannot exist.

Finding 2 was itself wrong on first pass: the relational substrate was missed,
and the flat-features objection stated more strongly than the code supports.
It is corrected above rather than quietly dropped.

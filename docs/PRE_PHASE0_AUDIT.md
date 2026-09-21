# Pre-Phase-0 representational audit

**Date:** 2026-09-21
**Method:** Source reading of `pr0dus/concept-evolution-kernel` at `40ffdf4`,
plus introspection of `arcengine` 0.9.3.
**Status:** Architectural audit. **Not** a grounding result.

## What this is and is not

This document records what source reading established. It does **not** answer
Phase 0.

Phase 0 is an empirical question and must be settled with real ARC-AGI-3
observations and transitions. No game has been run. Nothing here should be
cited as evidence about what CEK can or cannot do on real frames — only about
what its current machinery is shaped to accept.

An earlier version of this file claimed "Phase 0 is answered." That was an
overclaim and is retracted.

## Established

1. CEK has representational machinery that **may** consume relational
   structure.
2. The obvious supervised `Observation` type is unsuitable as the direct ARC
   interface.
3. PoC 4's `GridAdapter` is **not** evidence of bottom-up perceptual
   grounding.
4. No existing CEK mechanism has yet been demonstrated to transform an unknown
   raw ARC-AGI-3 frame into useful persistent entities or relations.
5. Therefore a grounding/perception capability appears **missing, or at least
   unproven**.

## Evidence

### The supervised observation type

`model.py:93`

```python
class Observation:
    features: tuple[tuple[str, int], ...]
    target: int
```

Flat `(name, integer)` pairs plus a **required** integer target. Feature names
are deliberately non-semantic (`q0`, `q1`, …), which is good discipline, but
the shape is supervised.

ARC-AGI-3 supplies no per-step target — feedback is binary and terminal. Any
value placed in `target` would be invented by us.

### A relational substrate also exists

`_composition_primitives.py:49`

```python
class PrimitiveRelationObservation:
    subject_entity_token: str
    relation_token: str
    object_entity_token: str
    asserted: bool
```

Subject-relation-object triples with an assertion flag. This can carry
structure and needs no numeric target. It is the more plausible interface.

But it requires **entity tokens** — something must already have decided what
the entities are. Nothing in CEK produces them from raw input. A filename-level
sweep of all 264 modules finds no spatial, geometry, topology, adjacency or
perception machinery (`online_interactive_revision.py` and
`revision_decision.py` match a "vision" search only because "re-vision"
contains the substring).

### PoC 4's grid adapter is not perception

`poc4_adapters.py:194` — `GridAdapter.reconstruct` decodes a format the same
class's `project()` wrote. It knows row 0 is a legend, that rows 1/2/3 carry
demand/capacity/blocked, and hardcodes `len(rows) != 4`. `CoreScene`
(`poc4_core.py:14`) hardcodes three named fields with domain validation.

As a representation-invariance test this is sound and its `18/18` stands for
what it claims. It is a hand-written decoder for a self-authored encoding, and
says nothing about grounding an unknown grid.

### The load-bearing pattern: frozen hypothesis spaces

This is the most important thing the audit found, and it recurs across every
mechanism examined:

| PoC | Mechanism | Hypothesis space |
|---|---|---|
| 3 | Active experiment selection | "**Frozen hypothesis space**" — four predeclared interpretations |
| 4 | Cross-representation identity | Three hand-written adapters over a 3-integer core |
| 5 | Shadow prediction / anomaly detection | "enumerates **four** bounded transition laws"; requires exactly one survivor |
| 8 | Proposal generation | "enumerate bounded proposals from a **predeclared finite meta-grammar**" |

CEK can *select among*, *falsify*, and *revise* hypotheses. In every examined
case a human enumerated the candidates first.

ARC-AGI-3's transition space is unbounded and unknown. Predeclaring the
candidate laws is not merely impractical — **it is the human-semantics
injection the charter forbids**.

So the gap may be less about perception narrowly than about **hypothesis
generation from raw experience**. That reframing is itself a hypothesis, and
belongs to Phase 0 to test rather than to this audit to assert.

## PoC 5 as candidate learning bridge

ARC supplies this loop for free:

```
observation_t → hypotheses → prediction → action
    → observation_t+1 → error/confirmation → revision
```

No invented supervised target is required.

**What PoC 5 contributes structurally:** precommitted prediction registered
before outcomes are visible, resolution against what actually happened,
anomaly detection, and a ledger that makes the whole thing auditable. That is
the loop's epistemic spine and it transfers.

**What PoC 5 lacks:**

- **No actions.** The spec is explicit: "No action or control record type
  exists in the shadow ledger." It is strictly passive observation. ARC is
  action-conditioned.
- **Enumerated laws.** Four predeclared candidates, exactly one survivor
  required.
- **Exact replay criterion.** A law is retained only if it "exactly replays
  every later calibration outcome." Whole-frame exactness on a 64×64 grid is a
  harsh early bar; partial and local prediction will likely be needed.

**PoC 3 supplies what PoC 5 lacks on the action side** — it represents
"bounded interventions as immutable actions" and selects the intervention that
best separates competing hypotheses. Combined, PoC 3 + PoC 5 have the loop's
full shape.

Both still stand on frozen hypothesis spaces. **Provisional reading: the loop
transfers; the hypothesis-space assumption does not.** To be tested, not
assumed.

## Grounding interface: design constraints

Do **not** define the missing layer as an object segmenter. ARC gives a 64×64
discrete observation; which decomposition is useful is unknown, and a
hardcoded object ontology injects human semantics into the experiment.

Instead, preserve the raw frame and generate **multiple low-assumption
candidate structures**, letting prediction and falsification determine which
carry information.

Candidate primitives — descriptions, not declared semantic objects:

- raw cells and values
- local adjacency / topology
- connected regions
- repeated structures
- frame-to-frame change regions
- persistence across transitions
- candidate grouping at multiple scales
- relations between candidate structures
- action-conditioned state deltas

**Reversibility:** every higher-level candidate structure must remain
traceable back to the raw cells and frames that produced it.

**Do not** optimise against one game. **Do not** inspect a game and encode its
apparent semantics into the grounding layer. This is where ARC-specific
contamination is most tempting and hardest to detect — a structure generator
tuned by staring at `ls20` is indistinguishable from general perception until
tested elsewhere. `CHARTER.md` criterion 3 applies with full force.

## Experimental sequence

1. Obtain real ARC frames and transition traces on the Ubuntu machine.
2. Record several episodes **without adding perception assumptions**.
3. Characterise what actually changes under each action.
4. Define the smallest generic candidate-structure representation capable of
   expressing those observations.
5. Connect that representation to existing CEK relational/predictive
   machinery.
6. Test whether CEK can make any prospective prediction that improves with
   experience.
7. Only then expand the grounding machinery.

## First success criterion

**Not** solving a game.

Evidence that, from previously unseen interactive observations, the system
acquires some **reusable predictive structure** that improves its prospective
prediction of subsequent observations or action consequences, **without
game-specific semantic information**.

## Caveat

Covers `model.Observation`, `_composition_primitives`, the PoC 3/4/5/8 specs,
and a filename-level sweep for spatial machinery. Other representations may
exist in unread modules. If one turns up, revise this rather than defend it.

Two corrections already applied in place rather than dropped: the original
claim that CEK is purely flat and supervised (it has a relational substrate),
and the framing of the missing layer as object segmentation (premature
ontology).

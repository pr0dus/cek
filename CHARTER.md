# Charter

## Status of this repository

This repository is a separate experimental branch derived from NEWI's Concept
Evolution Kernel (CEK).

It does not replace NEWI, redefine NEWI's architecture, or determine whether
CEK should continue to exist. The main NEWI/CEK project continues
independently on its existing developmental path.

Its purpose is to take a copy of CEK and expose it to ARC-AGI-3 as a demanding
interactive environment for testing grounding, concept formation, prediction,
revision, exploration, action efficiency, and eventually more advanced
adaptive behaviour.

This copy may be modified as necessary for ARC-AGI-3 work — instrumentation,
adapters, experimental mechanisms, alternative representations, new learning
machinery. **Divergence from the main CEK codebase is acceptable when the
experiment requires it.**

ARC-specific shortcuts, benchmark-specific hardcoding, hidden semantic
knowledge, and mechanisms that merely exploit particular games must never be
treated as improvements to NEWI.

## The questions this branch exists to answer

Not: *does ARC-AGI-3 prove CEK should survive?*

But:

- Which existing CEK mechanisms transfer successfully into a raw interactive
  environment?
- Where do those mechanisms fail or become insufficient?
- What new mechanisms are required for grounding, efficient exploration,
  prediction, learning, and adaptation?
- Which discovered mechanisms appear general rather than ARC-specific?
- Which of those survive independent testing and therefore deserve
  consideration for integration into NEWI?

## Promotion path

The main NEWI lineage remains the reference system. A mechanism discovered
here is promoted only after it is **isolated, characterised, ablated, and
tested independently**. Evidence of general usefulness comes before any port
or merge.

Benchmark performance alone is not sufficient evidence that a mechanism
belongs in NEWI. Generality, transfer, causal contribution, and independent
validation matter more than score.

## Objective

1. Develop this copy far enough to seriously attempt ARC-AGI-3, potentially
   targeting the 2027 competition.
2. Use that process as external pressure that may reveal missing general
   cognitive mechanisms useful to NEWI.

---

## Operationalising "general, not ARC-specific"

*This section is a working proposal, not part of the original charter. It
exists because the general-versus-specific judgment is the one most exposed to
motivated reasoning: we will want a mechanism to be general precisely when we
have just built it.*

"Isolate, characterise, ablate, test independently" is the right shape, but
"independently" needs teeth or it becomes a rubber stamp. Proposed standard —
a mechanism is **provisionally general** only when all four hold:

1. **Ablation.** Removing it measurably degrades performance on ARC-AGI-3. If
   removal changes nothing, there is nothing to promote.
2. **No privileged semantics.** Its implementation contains no game
   identifier, no mechanic name, no goal description, and no constant tuned by
   inspecting a specific game. Grep for game ids before claiming this.
3. **Off-benchmark transfer.** It improves behaviour on at least one domain
   outside ARC-AGI-3 *that it was not designed against*. This is the load-
   bearing criterion. Without it, "general" means "worked twice here."
4. **Stated failure mode.** We can describe conditions under which it would
   not help. A mechanism that allegedly helps everywhere has not been
   characterised.

Criterion 3 is the expensive one and the one we will be tempted to skip.
Skipping it converts this branch from a pressure test into a benchmark-chasing
exercise, which the charter above explicitly forbids.

### Recording

Every candidate mechanism gets an entry stating: what it does, its ablation
result, which of the four criteria it meets, and — when promotion is declined
— why. **Declined candidates are recorded too.** A branch that only remembers
its successes cannot be audited, and the discipline that makes NEWI worth
defending is precisely the willingness to keep the negative results.

# cek — ARC-AGI-3 experimental branch

An experimental copy of NEWI's Concept Evolution Kernel, exposed to ARC-AGI-3
as an external interactive environment.

**This repository does not decide NEWI's fate.** The main NEWI/CEK lineage
continues independently. See [`CHARTER.md`](./CHARTER.md) for what this branch
is for, what counts as a finding, and what must not be mistaken for one.

[`PROCESS.md`](./PROCESS.md) states how the work is conducted and carries the
claim ledger. Its governing rule: **no participant's confidence substitutes
for evidence** — human, AI, or the developing system. `supported` there means
evidence-scoped, never true.

## Why ARC-AGI-3

Every CEK result so far is measured on domains its author designed — PoC 4's
world is three integers. That is structurally a microworld, and microworld
success has historically not transferred.

ARC-AGI-3 is external, undesigned by us, and still discrete and turn-based. It
is the cheapest honest test of whether CEK's mechanisms survive contact with a
raw interactive environment.

## Current state

The harness exists and is measured; no reasoning core has been connected yet.

- 16 tests pass, 5 of them verifying the contract against `arcengine` 0.9.3
- The CLI runs correctly up to the first network call
- **No game has been run. No frame has been observed.**

A pre-Phase-0 representational audit is recorded in
[`docs/PRE_PHASE0_AUDIT.md`](./docs/PRE_PHASE0_AUDIT.md). It is an
architectural finding from source reading, **not** a grounding result —
Phase 0 is empirical and remains open.

## The contract (verified, not assumed)

Introspected from the installed engine rather than read from documentation,
and pinned by `tests/test_contract.py` so an engine upgrade cannot silently
invalidate grounding assumptions downstream.

- `frame: list[list[list[int]]]` — a stack of integer grids. Absent from the
  declared `FrameDataRaw` model but present at runtime, with layers arriving
  as numpy arrays rather than lists; `Observation.from_frame_data` normalises
  both.
- `state` — `NOT_PLAYED` | `NOT_FINISHED` | `WIN` | `GAME_OVER`
- Actions: `RESET`, `ACTION1-5`, `ACTION7` are bare. **Only `ACTION6` carries
  coordinates**, `x`/`y` in `[0, 63]`.

So the action space is six discrete actions plus one 64×64 point action.

## Scoring

RHAE — per-level actions against a human baseline, squared. Ten human actions
against a hundred of ours scores 1%. **Brute force that eventually wins still
scores near zero**, so actions-per-level is the number that matters, not levels
reached. `EpisodeResult.rhae()` returns `None` rather than `0.0` when no
completed level has a baseline, so an absent measurement never reads as a real
score.

## Layout

- `contract.py` — observation/action types, decoupled from the engine
- `core.py` — the `Core` protocol every architecture implements
- `runner.py` — the episode loop, identical for all cores
- `metrics.py` — per-level action accounting and RHAE
- `arc_env.py` — adapter to the real engine
- `run.py` — baseline CLI
- `trace.py` — lossless JSONL transition recording, no interpretation
- `analyze.py` — descriptive characterisation of traces, no decomposition
- `mock_env.py` — toy environment for testing wiring without a key
- `agents/random_core.py` — the baseline every result is stated against

## Running

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install arcengine==0.9.3 arc-agi==0.9.1 pytest
PYTHONPATH=. pytest tests/ -q
```

Python ≥3.12 is required by `arcengine`.

Against a real game, on a machine with network access:

```sh
export ARC_API_KEY=...            # never commit this
PYTHONPATH=. python -m newi_arc.run --list
PYTHONPATH=. python -m newi_arc.run --game ls20 --core random --episodes 5
```

`--mode offline` uses only a populated `environment_files/` directory and
needs no key.

### Recording traces

Step 2 of the experimental sequence needs episodes recorded *without*
perception assumptions, so record from the first run rather than re-running
later:

```sh
PYTHONPATH=. python -m newi_arc.run --game ls20 --core random \
    --episodes 5 --record traces/
```

Each episode writes one JSONL file: a header, one record per transition
(raw frame before, action, raw frame after), and a footer. Nothing is derived
and nothing is dropped — `tests/test_trace.py` pins that the only fields
written are the raw ones, so a derived field cannot quietly appear later.

### Characterising traces

Step 3 — what actually changes under each action:

```sh
PYTHONPATH=. python -m newi_arc.analyze traces/
PYTHONPATH=. python -m newi_arc.analyze traces/ --json > characterisation.json
```

Reports frame shapes, the value alphabet (across before *and* after frames),
per-action change counts, whether a clicked cell changed, and whether the same
action on the same frame ever gave different results — which would mean the
observed frame plus the recorded action is insufficient to uniquely predict
the next frame. The cause of that insufficiency is not inferred.

It performs **no** connected-component analysis, grouping, object tracking or
segmentation. Each of those is a choice of decomposition, and which
decomposition is useful is the open question; choosing one here would answer
it by assumption. Candidate structures belong to step 4, built against these
facts. `tests/test_analyze.py` pins the restraint.

## A warning about the mock

`mock_env.py` is a scaffold for testing wiring. Its mechanics are trivial and
known to its author — it is exactly the self-designed domain this whole branch
exists to escape. **No result measured on it means anything.**

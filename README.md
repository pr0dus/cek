# newi-arc

Architecture-agnostic harness for ARC-AGI-3.

Built so that CEK, a replacement architecture, and a random baseline can be
run on identical instrumentation — which turns "should we keep CEK?" from a
belief into a measurement.

## Why this exists first

Every CEK result to date is measured on domains its author designed. PoC 4's
world is three integers. That is structurally a microworld, and microworld
success historically does not transfer.

Phase 0 asks one question: can a reasoning core represent an ARC-AGI-3
observation *without the adapter encoding what the game is about?* This
harness is the apparatus for answering it, and it is needed whichever core
wins.

## The contract (verified, not assumed)

Introspected from `arcengine` 0.9.3 rather than read from documentation, and
pinned by `tests/test_contract.py` so an engine upgrade cannot silently
invalidate downstream grounding assumptions.

- `frame: list[list[list[int]]]` — a stack of integer grids
- `state` — `NOT_PLAYED` | `NOT_FINISHED` | `WIN` | `GAME_OVER`
- `levels_completed`, `win_levels`, `available_actions`
- Actions: `RESET`, `ACTION1-5`, `ACTION7` are bare; **only `ACTION6` carries
  coordinates**, `x`/`y` in `[0, 63]`

So the action space is six discrete actions plus one 64×64 point action.

## Scoring

RHAE — per-level actions against a human baseline, squared. Ten human actions
against a hundred of ours scores 1%. **Brute force that eventually wins still
scores near zero**, so actions-per-level is the number that matters, not
levels reached.

`EpisodeResult.rhae()` returns `None` rather than `0.0` when no completed
level has a baseline, so an absent measurement never reads as a real score.

## Layout

- `contract.py` — observation/action types, decoupled from the engine
- `core.py` — the `Core` protocol every architecture implements
- `runner.py` — the episode loop, identical for all cores
- `metrics.py` — per-level action accounting and RHAE
- `mock_env.py` — toy environment for testing without an API key
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

## Status

Harness and engine adapter work; 16 tests pass, 5 of them against the real
engine. The CLI runs correctly up to the first network call.

**Blocked on environment files.** Real games need either an `ARC_API_KEY` or a
populated `environment_files/` directory (the engine supports an `OFFLINE`
mode, and exposes an anonymous-key endpoint at `/api/games/anonkey`). Neither
is obtainable from this sandbox — `arcprize.org` and `three.arcprize.org` are
egress-blocked.

`mock_env.py` is a scaffold for testing wiring. It is trivial, its mechanics
are known to its author, and it is exactly the self-designed domain the real
benchmark exists to avoid. **No result measured on it means anything.**

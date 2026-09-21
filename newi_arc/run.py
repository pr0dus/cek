"""CLI: run a core against a real ARC-AGI-3 game.

    ARC_API_KEY=... python -m newi_arc.run --game ls20 --episodes 5

Reports actions per level. That is the Phase 1 baseline every later claim is
stated against, so it prints the raw per-episode numbers, not just a mean.
"""

import argparse
import statistics
import sys
from pathlib import Path

from .agents import RandomCore
from .runner import run_episode

CORES = {"random": RandomCore}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="newi_arc.run")
    parser.add_argument("--game", required=True)
    parser.add_argument("--core", default="random", choices=sorted(CORES))
    parser.add_argument("--episodes", type=int, default=1)
    parser.add_argument("--max-actions", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--mode", default="normal", choices=("normal", "online", "offline")
    )
    parser.add_argument("--list", action="store_true", help="list games and exit")
    parser.add_argument(
        "--record",
        metavar="DIR",
        help="write a lossless JSONL trace per episode into DIR",
    )
    args = parser.parse_args(argv)

    from .arc_env import ArcEnv

    if args.list:
        for game in ArcEnv.list_games(mode=args.mode):
            print(game)
        return 0

    results = []
    for i in range(args.episodes):
        seed = args.seed + i
        env = ArcEnv(args.game, seed=seed, mode=args.mode)
        core = CORES[args.core](seed=seed)
        recorder = None
        if args.record:
            from .trace import TraceRecorder

            recorder = TraceRecorder(
                Path(args.record) / f"{args.game}-{core.name}-ep{i:03d}.jsonl",
                game_id=args.game,
                core=core.name,
                seed=seed,
                extra={"max_actions": args.max_actions, "mode": args.mode},
            )
        result = run_episode(
            core, env, max_actions=args.max_actions, recorder=recorder
        )
        results.append(result)
        print(
            f"ep {i:>3}  actions={result.total_actions:>6}  "
            f"levels={result.levels_completed:>3}  "
            f"state={result.final_state:<13} "
            f"per_level={result.actions_per_completed_level or float('nan'):.1f}"
        )

    completed = [r.levels_completed for r in results]
    per_level = [
        r.actions_per_completed_level
        for r in results
        if r.actions_per_completed_level is not None
    ]
    print(f"\ncore={results[0].core} game={args.game} episodes={len(results)}")
    print(f"levels completed: total={sum(completed)} mean={statistics.mean(completed):.2f}")
    if per_level:
        print(f"actions per completed level: mean={statistics.mean(per_level):.1f}")
    else:
        print("actions per completed level: no level completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

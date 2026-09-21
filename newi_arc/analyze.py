"""Descriptive characterisation of recorded traces.

Step 3 of the experimental sequence: characterise what actually changes under
each action.

**Strictly descriptive.** This reports facts about raw cells — how many
changed, at which coordinates, whether the same action from the same frame
produces the same result. It performs no connected-component analysis, no
grouping, no object tracking, and no segmentation.

That restraint is deliberate. Any grouping decision is a choice of
decomposition, and which decomposition is useful is the open question Phase 0
exists to answer empirically. Choosing one here would answer it by assumption
and contaminate everything downstream. Candidate structures belong in step 4,
built against these facts.

Every number here is traceable to specific cells in specific frames.
"""

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .trace import read_trace

Grid = list[list[int]]
Frame = list[Grid]


def changed_cells(before: Frame, after: Frame) -> list[tuple[int, int, int]]:
    """Coordinates whose value differs, as (layer, row, col).

    Frames of differing shape are reported as fully changed rather than
    silently reconciled — a shape change is itself a finding.
    """
    changes: list[tuple[int, int, int]] = []
    for z in range(max(len(before), len(after))):
        b_layer = before[z] if z < len(before) else []
        a_layer = after[z] if z < len(after) else []
        for y in range(max(len(b_layer), len(a_layer))):
            b_row = b_layer[y] if y < len(b_layer) else []
            a_row = a_layer[y] if y < len(a_layer) else []
            for x in range(max(len(b_row), len(a_row))):
                b = b_row[x] if x < len(b_row) else None
                a = a_row[x] if x < len(a_row) else None
                if b != a:
                    changes.append((z, y, x))
    return changes


def frame_shape(frame: Frame) -> tuple[int, int, int]:
    depth = len(frame)
    rows = len(frame[0]) if depth else 0
    cols = len(frame[0][0]) if rows else 0
    return depth, rows, cols


def _values(frame: Frame) -> Counter:
    counter: Counter = Counter()
    for layer in frame:
        for row in layer:
            counter.update(row)
    return counter


@dataclass
class ActionStats:
    action: str
    transitions: int = 0
    no_change: int = 0
    change_counts: list[int] = field(default_factory=list)
    clicked_cell_changed: int = 0
    clicked_cell_total: int = 0

    def summary(self) -> dict[str, Any]:
        counts = sorted(self.change_counts)
        out: dict[str, Any] = {
            "action": self.action,
            "transitions": self.transitions,
            "no_change": self.no_change,
            "changed": self.transitions - self.no_change,
        }
        if counts:
            out["cells_changed"] = {
                "min": counts[0],
                "median": counts[len(counts) // 2],
                "max": counts[-1],
            }
        if self.clicked_cell_total:
            out["clicked_cell_changed"] = (
                f"{self.clicked_cell_changed}/{self.clicked_cell_total}"
            )
        return out


def analyze(transitions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    per_action: dict[str, ActionStats] = {}
    shapes: Counter = Counter()
    values: Counter = Counter()
    # (before-frame, action) -> set of resulting frames, to test determinism
    outcomes: dict[str, set[str]] = defaultdict(set)
    total = 0

    for record in transitions:
        total += 1
        before = record["before"]["frame"]
        after = record["after"]["frame"]
        action = record["action"]
        name = action["name"]

        stats = per_action.setdefault(name, ActionStats(name))
        stats.transitions += 1

        changes = changed_cells(before, after)
        if changes:
            stats.change_counts.append(len(changes))
        else:
            stats.no_change += 1

        if "x" in action and "y" in action:
            stats.clicked_cell_total += 1
            x, y = action["x"], action["y"]
            if any(cy == y and cx == x for _, cy, cx in changes):
                stats.clicked_cell_changed += 1

        shapes[frame_shape(before)] += 1
        values.update(_values(before))

        key = json.dumps([before, action], separators=(",", ":"), sort_keys=True)
        outcomes[key].add(json.dumps(after, separators=(",", ":")))

    ambiguous = sum(1 for v in outcomes.values() if len(v) > 1)

    return {
        "transitions": total,
        "frame_shapes": {str(k): v for k, v in shapes.most_common()},
        "value_alphabet": dict(values.most_common()),
        "actions": [s.summary() for s in per_action.values()],
        "determinism": {
            "distinct_before_action_pairs": len(outcomes),
            "pairs_with_conflicting_outcomes": ambiguous,
            "note": (
                "conflicting outcomes mean the same action on the same frame "
                "produced different results, so the frame is not the whole state"
            ),
        },
    }


def analyze_files(paths: Iterable[str | Path]) -> dict[str, Any]:
    all_transitions: list[dict[str, Any]] = []
    headers: list[dict[str, Any]] = []
    for path in paths:
        header, transitions = read_trace(path)
        headers.append(header)
        all_transitions.extend(transitions)
    report = analyze(all_transitions)
    report["episodes"] = len(headers)
    report["games"] = sorted({h.get("game_id", "?") for h in headers})
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="newi_arc.analyze")
    parser.add_argument("traces", nargs="+", help="trace .jsonl files")
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    args = parser.parse_args(argv)

    paths: list[Path] = []
    for item in args.traces:
        p = Path(item)
        paths.extend(sorted(p.glob("*.jsonl")) if p.is_dir() else [p])

    report = analyze_files(paths)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"episodes={report['episodes']} transitions={report['transitions']} "
          f"games={','.join(report['games'])}")
    print(f"frame shapes (depth,rows,cols): {report['frame_shapes']}")
    alphabet = report["value_alphabet"]
    print(f"value alphabet: {len(alphabet)} distinct -> {sorted(alphabet)[:20]}")
    print()
    print(f"{'action':<10}{'n':>6}{'changed':>9}{'no-change':>11}{'cells min/med/max':>22}{'clicked':>10}")
    for entry in report["actions"]:
        cells = entry.get("cells_changed")
        cells_s = f"{cells['min']}/{cells['median']}/{cells['max']}" if cells else "-"
        print(
            f"{entry['action']:<10}{entry['transitions']:>6}{entry['changed']:>9}"
            f"{entry['no_change']:>11}{cells_s:>22}"
            f"{entry.get('clicked_cell_changed', '-'):>10}"
        )
    det = report["determinism"]
    print()
    print(f"distinct (frame, action) pairs: {det['distinct_before_action_pairs']}")
    print(f"pairs with conflicting outcomes: {det['pairs_with_conflicting_outcomes']}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())

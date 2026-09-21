"""Lossless trace recording.

Writes what happened and nothing else: the raw frame exactly as received, the
action taken, and the frame that followed.

**No interpretation happens here.** No segmentation, no features, no derived
structure, no summary statistics. Any of those would embed a decision about
which decomposition matters — the decision Phase 0 exists to make empirically
rather than by assumption.

Traces are the raw material for steps 2 and 3 of the experimental sequence
(record episodes without perception assumptions; characterise what actually
changes under each action). Everything downstream must remain traceable back
to these records.

Format is JSON Lines: one header record, then one record per transition.
Append-only, flushed per line, so a crashed or interrupted run keeps whatever
it captured.
"""

import json
import time
from pathlib import Path
from typing import Any

from .contract import Action, Observation

SCHEMA_VERSION = 1


class TraceRecorder:
    """Records transitions to a JSONL file.

    Usable as a context manager. One file per episode keeps records
    independent, since concatenating episodes would imply continuity across
    resets that the environment does not promise.
    """

    def __init__(
        self,
        path: str | Path,
        game_id: str,
        core: str,
        seed: int,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w", encoding="utf-8")
        self._step = 0
        self._write(
            {
                "record": "header",
                "schema_version": SCHEMA_VERSION,
                "game_id": game_id,
                "core": core,
                "seed": seed,
                "started_at": time.time(),
                **(extra or {}),
            }
        )

    def _write(self, payload: dict[str, Any]) -> None:
        self._fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self._fh.flush()

    @staticmethod
    def _observation(obs: Observation) -> dict[str, Any]:
        return {
            "frame": obs.frame,
            "state": obs.state,
            "levels_completed": obs.levels_completed,
            "win_levels": obs.win_levels,
            "available_actions": list(obs.available_actions),
        }

    @staticmethod
    def _action(action: Action) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": action.name}
        if action.x is not None:
            payload["x"] = action.x
        if action.y is not None:
            payload["y"] = action.y
        return payload

    def record(
        self, before: Observation, action: Action, after: Observation
    ) -> None:
        self._write(
            {
                "record": "transition",
                "step": self._step,
                "before": self._observation(before),
                "action": self._action(action),
                "after": self._observation(after),
            }
        )
        self._step += 1

    def close(self, final_state: str = "", total_actions: int = 0) -> None:
        if self._fh.closed:
            return
        self._write(
            {
                "record": "footer",
                "steps": self._step,
                "final_state": final_state,
                "total_actions": total_actions,
                "ended_at": time.time(),
            }
        )
        self._fh.close()

    def __enter__(self) -> "TraceRecorder":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_trace(path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read a trace file, returning (header, transitions).

    The footer is absent when a run was interrupted; that is not an error, and
    a partial trace is still valid evidence for whatever it captured.
    """
    header: dict[str, Any] = {}
    transitions: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            kind = payload.get("record")
            if kind == "header":
                header = payload
            elif kind == "transition":
                transitions.append(payload)
    return header, transitions

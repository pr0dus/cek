"""The analyzer must stay descriptive.

These tests pin what it reports and — just as importantly — that it does not
group, segment, or otherwise choose a decomposition.
"""

from newi_arc.analyze import analyze, analyze_files, changed_cells, frame_shape
from newi_arc.contract import Action, Observation
from newi_arc.trace import TraceRecorder


def _t(before, after, action):
    def obs(frame):
        return {
            "frame": frame,
            "state": "NOT_FINISHED",
            "levels_completed": 0,
            "win_levels": 1,
            "available_actions": [1, 6],
        }

    return {"record": "transition", "before": obs(before), "after": obs(after),
            "action": action}


def test_changed_cells_reports_coordinates():
    before = [[[0, 0], [0, 0]]]
    after = [[[0, 1], [0, 0]]]
    assert changed_cells(before, after) == [(0, 0, 1)]


def test_no_change_reports_empty():
    frame = [[[1, 2], [3, 4]]]
    assert changed_cells(frame, frame) == []


def test_shape_change_is_reported_not_reconciled():
    before = [[[0, 0]]]
    after = [[[0, 0, 0]]]
    assert (0, 0, 2) in changed_cells(before, after)


def test_frame_shape():
    assert frame_shape([[[1, 2, 3], [4, 5, 6]]]) == (1, 2, 3)
    assert frame_shape([]) == (0, 0, 0)


def test_per_action_change_counts():
    report = analyze([
        _t([[[0, 0]]], [[[1, 0]]], {"name": "ACTION1"}),
        _t([[[0, 0]]], [[[0, 0]]], {"name": "ACTION1"}),
        _t([[[0, 0]]], [[[1, 1]]], {"name": "ACTION2"}),
    ])
    by_name = {a["action"]: a for a in report["actions"]}
    assert by_name["ACTION1"]["transitions"] == 2
    assert by_name["ACTION1"]["no_change"] == 1
    assert by_name["ACTION2"]["cells_changed"]["max"] == 2


def test_clicked_cell_tracked_for_complex_actions():
    report = analyze([
        _t([[[0, 0]]], [[[0, 1]]], {"name": "ACTION6", "x": 1, "y": 0}),
        _t([[[0, 0]]], [[[1, 0]]], {"name": "ACTION6", "x": 1, "y": 0}),
    ])
    by_name = {a["action"]: a for a in report["actions"]}
    assert by_name["ACTION6"]["clicked_cell_changed"] == "1/2"


def test_conflicting_outcomes_detected():
    """Same frame+action, different result: frame+action does not
    uniquely determine the next frame. No cause is inferred."""
    report = analyze([
        _t([[[0]]], [[[1]]], {"name": "ACTION1"}),
        _t([[[0]]], [[[2]]], {"name": "ACTION1"}),
    ])
    assert report["predictability"]["pairs_with_conflicting_outcomes"] == 1


def test_consistent_outcomes_not_flagged():
    report = analyze([
        _t([[[0]]], [[[1]]], {"name": "ACTION1"}),
        _t([[[0]]], [[[1]]], {"name": "ACTION1"}),
    ])
    assert report["predictability"]["pairs_with_conflicting_outcomes"] == 0


def test_value_alphabet_collected():
    report = analyze([_t([[[3, 7], [7, 0]]], [[[3, 7], [7, 0]]], {"name": "ACTION1"})])
    assert set(report["value_alphabet_before_and_after"]) == {0, 3, 7}


def _all_keys(node) -> set[str]:
    """Every dict key at every depth of the report."""
    keys: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            keys.add(key)
            keys |= _all_keys(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            keys |= _all_keys(item)
    return keys


def test_report_contains_no_derived_structure_at_any_depth():
    """Guards the no-decomposition rule across the whole report, not just its
    top level — a derived key could otherwise hide inside a nested section."""
    report = analyze([
        _t([[[0, 0]]], [[[1, 0]]], {"name": "ACTION1"}),
        _t([[[0, 0]]], [[[1, 1]]], {"name": "ACTION6", "x": 1, "y": 0}),
    ])
    forbidden = {
        "objects", "regions", "components", "segments", "entities", "groups",
        "shapes", "clusters", "blobs", "sprites", "connected", "adjacency",
        "neighbours", "neighbors", "tracked", "ontology",
    }
    assert forbidden.isdisjoint(_all_keys(report))


def test_nested_key_guard_would_catch_a_violation():
    """The guard itself must work, or it is decoration."""
    assert "regions" in _all_keys({"a": {"b": [{"regions": 1}]}})


def test_value_alphabet_includes_values_only_seen_after():
    """A value produced only by an action must not be missed."""
    report = analyze([_t([[[0]]], [[[9]]], {"name": "ACTION1"})])
    assert set(report["value_alphabet_before_and_after"]) == {0, 9}


def test_reads_real_trace_files(tmp_path):
    path = tmp_path / "t.jsonl"

    def obs(frame):
        return Observation("g", frame, "NOT_FINISHED", 0, 1, (1,))

    with TraceRecorder(path, game_id="g", core="c", seed=0) as rec:
        rec.record(obs([[[0, 0]]]), Action("ACTION1"), obs([[[1, 0]]]))

    report = analyze_files([path])
    assert report["episodes"] == 1
    assert report["transitions"] == 1
    assert report["games"] == ["g"]

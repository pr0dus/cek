"""Inspected-state manifests and independently observed proof (Issue #5 §2, §5).

The property under test throughout: what a reviewer looked at is *measured*,
never reported. A builder's list of changed files is not consulted anywhere in
this module, and neither is a builder's claim that tests passed.
"""

import hashlib
import json
import pathlib
import subprocess

import pytest

from agent_room.proof import ProofError, proof_evidence, run_proof, verify_proof
from agent_room.snapshot import (
    SnapshotError,
    manifest_digest,
    snapshot_manifest,
    verify_manifest,
)
from tests.conftest_agent_room import configure_identity, git


@pytest.fixture
def target(tmp_path):
    """A disposable checkout with one committed baseline."""
    repo = tmp_path / "target"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "work")
    configure_identity(repo)
    (repo / "kept.txt").write_text("baseline\n", encoding="utf-8")
    (repo / "removed.txt").write_text("doomed\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@localhost",
        "commit", "-q", "-m", "baseline")
    return repo


def base_of(repo) -> str:
    return git(repo, "rev-parse", "HEAD").strip()


def entry_for(manifest, path):
    for entry in manifest["entries"]:
        if entry["path"] == path:
            return entry
    return None


# -- 7. the manifest detects every class of change --------------------------

def test_a_clean_checkout_has_no_entries(target):
    manifest = snapshot_manifest(target, base_of(target))
    assert manifest["entries"] == []
    assert manifest["counts"]["changed_vs_base"] == 0
    verify_manifest(manifest)


def test_manifest_detects_tracked_staged_unstaged_deleted_and_untracked(target):
    base = base_of(target)
    # staged modification
    (target / "kept.txt").write_text("staged change\n", encoding="utf-8")
    git(target, "add", "kept.txt")
    # then edited again, so index and worktree disagree
    (target / "kept.txt").write_text("edited after staging\n", encoding="utf-8")
    # deletion
    (target / "removed.txt").unlink()
    # untracked
    (target / "new.txt").write_text("brand new\n", encoding="utf-8")

    manifest = snapshot_manifest(target, base)
    kept = entry_for(manifest, "kept.txt")
    assert kept["base_vs_index"] == "M", "staged change must be visible"
    assert kept["index_vs_worktree"] == "M", "later edit must be visible too"
    assert kept["base_vs_worktree"] == "M"
    assert kept["sha256"] == hashlib.sha256(b"edited after staging\n").hexdigest()

    removed = entry_for(manifest, "removed.txt")
    assert removed["base_vs_worktree"] == "D"
    assert removed["kind"] == "absent" and removed["sha256"] is None

    new = entry_for(manifest, "new.txt")
    assert new["tracked"] is False
    assert new["sha256"] == hashlib.sha256(b"brand new\n").hexdigest()

    assert manifest["counts"]["deleted"] == 1
    assert manifest["counts"]["untracked"] == 1
    verify_manifest(manifest)


def test_manifest_records_a_symlink_without_following_it(target, tmp_path):
    base = base_of(target)
    secret = tmp_path / "outside.txt"
    secret.write_text("must not be hashed\n", encoding="utf-8")
    (target / "link").symlink_to(secret)

    manifest = snapshot_manifest(target, base)
    link = entry_for(manifest, "link")
    assert link["kind"] == "symlink"
    assert link["sha256"] == hashlib.sha256(str(secret).encode()).hexdigest()
    assert link["sha256"] != hashlib.sha256(secret.read_bytes()).hexdigest()


def test_manifest_notices_a_mode_change_alone(target):
    """Content is unchanged, so only the diff digest can catch this."""
    base = base_of(target)
    before = snapshot_manifest(target, base)
    (target / "kept.txt").chmod(0o755)
    after = snapshot_manifest(target, base)
    assert after["manifest_sha256"] != before["manifest_sha256"]
    assert after["tracked_diff_sha256"] != before["tracked_diff_sha256"]


def test_a_builder_supplied_file_list_is_never_consulted(target):
    """Nothing in the API accepts one, which is the strongest form of this."""
    import inspect

    signature = inspect.signature(snapshot_manifest)
    assert list(signature.parameters) == ["workdir", "base_commit"]


# -- 8. a change after inspection invalidates the inspection ----------------

def test_any_later_edit_moves_the_manifest_digest(target):
    base = base_of(target)
    reviewed = snapshot_manifest(target, base)
    (target / "kept.txt").write_text("changed after review\n", encoding="utf-8")
    now = snapshot_manifest(target, base)

    assert now["manifest_sha256"] != reviewed["manifest_sha256"], (
        "a review bound to the earlier digest must not cover this state"
    )


def test_an_untracked_file_added_after_inspection_also_invalidates_it(target):
    base = base_of(target)
    reviewed = snapshot_manifest(target, base)
    (target / "sneaked-in.py").write_text("print('hi')\n", encoding="utf-8")
    assert snapshot_manifest(target, base)["manifest_sha256"] != \
        reviewed["manifest_sha256"]


def test_the_same_state_measured_twice_is_identical(target):
    """Otherwise every re-measurement would look like tampering."""
    base = base_of(target)
    (target / "kept.txt").write_text("stable\n", encoding="utf-8")
    first = snapshot_manifest(target, base)
    second = snapshot_manifest(target, base)
    assert first["manifest_sha256"] == second["manifest_sha256"]


def test_a_tampered_manifest_fails_verification(target):
    manifest = snapshot_manifest(target, base_of(target))
    manifest["counts"]["untracked"] = 99
    with pytest.raises(SnapshotError, match="digest mismatch"):
        verify_manifest(manifest)


def test_manifest_digest_ignores_only_the_digest_field(target):
    manifest = snapshot_manifest(target, base_of(target))
    assert manifest_digest(manifest) == manifest["manifest_sha256"]


def test_an_abbreviated_base_commit_is_refused(target):
    with pytest.raises(SnapshotError, match="full Git object id"):
        snapshot_manifest(target, base_of(target)[:8])


def test_a_base_that_is_not_a_commit_is_refused(target):
    blob = git(target, "rev-parse", "HEAD:kept.txt").strip()
    with pytest.raises(SnapshotError, match="is not a commit"):
        snapshot_manifest(target, blob)


# -- 11. proof is observed by the harness, not reported by the builder ------

def test_proof_records_command_status_and_output_digests(target, tmp_path):
    record = run_proof(
        ["python3", "-c", "import sys; print('ok'); sys.exit(0)"],
        cwd=target, run_dir=tmp_path / "runs", proof_id="p1",
        repo_commit=base_of(target),
    )
    assert record["status"] == "completed"
    assert record["exit_status"] == 0
    assert record["command"] == ["python3", "-c",
                                 "import sys; print('ok'); sys.exit(0)"]
    assert record["stdout_sha256"] == hashlib.sha256(b"ok\n").hexdigest()
    assert "ok" in record["stdout_tail"]
    verify_proof(record)


def test_a_failing_proof_is_a_result_not_a_harness_error(target, tmp_path):
    record = run_proof(
        ["python3", "-c", "import sys; sys.exit(3)"],
        cwd=target, run_dir=tmp_path / "runs", proof_id="p-fail",
    )
    assert record["status"] == "completed"
    assert record["exit_status"] == 3
    verify_proof(record)


def test_a_denied_command_is_recorded_as_evidence_not_worked_around(
        target, tmp_path):
    record = run_proof(
        [str(tmp_path / "does-not-exist")],
        cwd=target, run_dir=tmp_path / "runs", proof_id="p-denied",
    )
    assert record["status"] == "denied"
    assert record["exit_status"] is None
    assert "FileNotFoundError" in record["error"]
    verify_proof(record)


def test_a_proof_artifact_is_written_outside_the_checkout(target, tmp_path):
    record = run_proof(
        ["python3", "-c", "print('x')"],
        cwd=target, run_dir=tmp_path / "runs", proof_id="p-art",
    )
    path = pathlib.Path(record["artifact_path"])
    # Content-addressed: the filename carries the proof digest, which is what
    # makes a second run of the same id a second artifact, never a rewrite.
    assert path.parent == (tmp_path / "runs").resolve()
    assert path.name == f"p-art-{record['proof_sha256'][:16]}.json"

    artifact = json.loads(path.read_text())
    assert artifact["proof_sha256"] == record["proof_sha256"]
    assert artifact["stdout"] == "x\n"
    assert not str(tmp_path / "runs").startswith(str(target))
    assert record["artifact_sha256"] == hashlib.sha256(
        path.read_bytes()).hexdigest()


def test_artifacts_inside_the_inspected_checkout_are_refused(target):
    with pytest.raises(ProofError, match="outside the inspected checkout"):
        run_proof(["python3", "-c", "pass"], cwd=target,
                  run_dir=target / "runs", proof_id="p-inside")


def test_a_tampered_proof_record_fails_verification(target, tmp_path):
    record = run_proof(["python3", "-c", "import sys; sys.exit(1)"],
                       cwd=target, run_dir=tmp_path / "runs", proof_id="p-t")
    record["exit_status"] = 0
    with pytest.raises(ProofError, match="digest mismatch"):
        verify_proof(record)


def test_proof_evidence_names_the_observation_not_a_file(target, tmp_path):
    record = run_proof(["python3", "-c", "pass"], cwd=target,
                       run_dir=tmp_path / "runs", proof_id="p-ev")
    evidence = proof_evidence(record, commit=base_of(target))
    assert evidence["kind"] == "run"
    assert evidence["run_id"] == record["proof_sha256"]
    assert "path" not in evidence

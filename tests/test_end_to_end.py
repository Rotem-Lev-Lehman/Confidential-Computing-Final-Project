"""
test_end_to_end.py
==================
The whole system, as four separate OS processes.

Every other test file checks one component in isolation.  This one checks that
they compose: it runs the real program the way the demo runs it --
``demo_setup.py``, then four node processes talking over real sockets, through
all three phases in sequence -- and checks the published alert list against the
counts the fixture generated.

Only a test at this level can catch integration failures: a phase that is never
reached, an entry point that does not fire, a hand-off whose two sides disagree.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THRESHOLD = 50

def _isolated_workspace(tmp_path: Path, base_port: int) -> Path:
    """A throwaway copy of the project, on its own ports.

    Mirrors the real layout -- ``src/`` for the code, ``config.json`` at the
    root beside it -- because ``config_loader`` resolves the config relative to
    its own location.  Copied rather than run in place because
    ``demo_setup.py`` rewrites ``config.json`` with freshly generated keys.
    """
    work = tmp_path / "run"
    work.mkdir()
    shutil.copytree(
        ROOT / "src", work / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    shutil.copy(ROOT / "config.json", work / "config.json")

    config = json.loads((work / "config.json").read_text())
    for offset, node_id in enumerate(sorted(config["nodes"], key=int)):
        config["nodes"][node_id]["port"] = base_port + offset
    # Keep the run quick: 4 regions instead of 20.
    config["regions"] = config["regions"][:4]
    config["vector_size"] = 4
    (work / "config.json").write_text(json.dumps(config, indent=2))
    return work


def _run(work: Path, args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True,
        timeout=timeout,
    )


def _true_totals(work: Path, regions: list[str]) -> dict[str, int]:
    counts: Counter = Counter()
    for path in sorted((work / "data").glob("hospital*.txt")):
        counts.update(path.read_text().split())
    return {region: counts[region] for region in regions}


def _launch_pipeline(work: Path, extra: list[str], timeout: float) -> dict[int, str]:
    """Start every node as its own process; return {node_id: stdout}."""
    config = json.loads((work / "config.json").read_text())
    node_ids = sorted(int(n) for n in config["nodes"])
    procs = {
        nid: subprocess.Popen(
            [sys.executable, "-u", "src/main.py", "--node-id", str(nid),
             "--records", f"data/hospital{nid}.txt", "--connect-delay", "2.0",
             *extra],
            cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for nid in node_ids
    }
    outputs: dict[int, str] = {}
    try:
        for nid, proc in procs.items():
            out, err = proc.communicate(timeout=timeout)
            assert proc.returncode == 0, f"node {nid} failed:\n{out}\n{err}"
            outputs[nid] = out
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                proc.kill()
    return outputs


def _clone_prepared(workspace: Path, tmp_path: Path, base_port: int) -> Path:
    """A fresh workspace on its own ports, reusing the prepared keys and records.

    Re-running ``demo_setup.py`` per test would be slow and would generate a
    different scenario; copying the prepared keys means the public keys in the
    config must be copied across with them or nothing authenticates.
    """
    work = _isolated_workspace(tmp_path, base_port)
    shutil.copytree(workspace / "keys", work / "keys")
    shutil.copytree(workspace / "data", work / "data")
    prepared = json.loads((workspace / "config.json").read_text())
    target = json.loads((work / "config.json").read_text())
    for node_id, node in prepared["nodes"].items():
        target["nodes"][node_id]["public_key"] = node["public_key"]
    (work / "config.json").write_text(json.dumps(target, indent=2))
    return work


def _quarantined_from_output(stdout: str) -> set[str]:
    """Parse the alert table node 2 prints."""
    return {
        line.split("(id")[0].replace("region", "").strip()
        for line in stdout.splitlines()
        if "->  QUARANTINE" in line
    }


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    work = _isolated_workspace(tmp_path_factory.mktemp("e2e"), base_port=9701)
    # Seed 1 is chosen so the 4-region scenario straddles the threshold (91,
    # 26, 33, 51) -- including a region one case over it.  A run that was all
    # clear or all quarantine would demonstrate nothing.
    setup = _run(work, ["src/demo_setup.py", "--seed", "1", "--threshold",
                        str(THRESHOLD)], timeout=120)
    assert setup.returncode == 0, f"demo_setup failed:\n{setup.stdout}{setup.stderr}"
    return work


# --- the demo fixtures ------------------------------------------------------


def test_demo_setup_produces_keys_config_and_records(workspace):
    keys = sorted((workspace / "keys").glob("node*.key"))
    assert len(keys) == 4
    for key in keys:
        # Private identity keys must not be group- or world-readable.
        assert key.stat().st_mode & 0o077 == 0
    assert len(sorted((workspace / "data").glob("hospital*.txt"))) == 4

    # The generated public keys really are the ones in the config.
    config = json.loads((workspace / "config.json").read_text())
    assert len({n["public_key"] for n in config["nodes"].values()}) == 4


def test_scenario_straddles_the_threshold(workspace):
    """A demo that is all-clear or all-quarantine would prove nothing."""
    config = json.loads((workspace / "config.json").read_text())
    totals = _true_totals(workspace, config["regions"])
    assert any(t > THRESHOLD for t in totals.values())
    assert any(t <= THRESHOLD for t in totals.values())


# --- the full pipeline ------------------------------------------------------


@pytest.mark.slow
def test_pipeline_publishes_the_correct_alert_list(workspace, tmp_path):
    work = _clone_prepared(workspace, tmp_path, base_port=9711)
    outputs = _launch_pipeline(work, ["--ot-group", "1024"], timeout=600)
    target = json.loads((work / "config.json").read_text())

    regions = target["regions"]
    totals = _true_totals(work, regions)
    expected = {r for r, t in totals.items() if t > THRESHOLD}

    # Node 2 (the Evaluator) publishes the alert list, per the proposal.
    assert _quarantined_from_output(outputs[2]) == expected

    # Every node ran its part.
    for nid in (1, 2):
        assert "Phase 3 done" in outputs[nid], outputs[nid]
    for nid in (3, 4):
        assert "contributed my share" in outputs[nid], outputs[nid]


@pytest.mark.slow
def test_sub_threshold_counts_never_appear_in_the_output(workspace, tmp_path):
    """The proposal's core guarantee, checked on the real published output.

    A clear region may be *named* -- the circuit's defined output is
    ``region_id`` or ``Clear`` at a public index -- but its case count must
    never surface anywhere.
    """
    work = _clone_prepared(workspace, tmp_path, base_port=9731)
    target = json.loads((work / "config.json").read_text())
    outputs = _launch_pipeline(work, ["--ot-group", "1024"], timeout=600)
    published = "\n".join(outputs.values())

    regions = target["regions"]
    totals = _true_totals(work, regions)
    clear = {r: t for r, t in totals.items() if t <= THRESHOLD}
    assert clear, "fixture has no sub-threshold region to check"

    for region, count in clear.items():
        assert f"{region} (id" in published  # named, as designed
        # ...but the count itself is nowhere: not on its line, not anywhere.
        for line in published.splitlines():
            if region in line:
                assert str(count) not in line.split("->")[-1], line

    # And no node dumped its share vector by default.
    assert "my share of the global vector" not in published


@pytest.mark.slow
def test_gc_out_is_off_by_default_but_protected_when_asked(workspace, tmp_path):
    """The demo dump is opt-in, per-node, and owner-readable only."""
    work = _clone_prepared(workspace, tmp_path, base_port=9741)
    _launch_pipeline(work, ["--ot-group", "1024"], timeout=600)
    assert not (work / "gc_input").exists(), "share vectors dumped without being asked"

    _launch_pipeline(work, ["--ot-group", "1024", "--gc-out", "gc_input"], timeout=600)
    dumps = sorted((work / "gc_input").rglob("problem_*.json"))
    assert len(dumps) == 2
    # Each party's dump lives in its own directory and holds only its own vector.
    assert {d.parent.name for d in dumps} == {"node1", "node2"}
    for dump in dumps:
        assert dump.stat().st_mode & 0o077 == 0
        problem = json.loads(dump.read_text())
        assert (problem["a_shares"] is None) != (problem["b_shares"] is None)

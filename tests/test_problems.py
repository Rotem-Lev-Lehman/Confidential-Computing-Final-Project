"""Run every problem in ``problems/`` and check it against the expected solution.

Each ``problems/<n>/`` directory holds the two per-party input files
(``problem_A.json`` for party 0, ``problem_B.json`` for party 1) and the
expected public outcome (``solution.json``).

Two levels are covered:

* **local simulation** — every problem, in-process;
* **genuine two-process 2PC** — the CLI is launched twice, each process holding
  only its own share file, and both parties' revealed outputs must match the
  solution.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from smpc_gc import evaluate_threshold
from smpc_gc.mock import load_problem_dir
from smpc_gc.yao.ot import GROUP_1024

PROBLEMS_DIR = Path(__file__).resolve().parent.parent / "problems"
PROBLEM_DIRS = sorted(
    (p for p in PROBLEMS_DIR.iterdir() if p.is_dir()), key=lambda p: int(p.name)
)


def _solution(problem_dir: Path) -> dict:
    return json.loads((problem_dir / "solution.json").read_text())


def _assert_matches_solution(results, solution: dict) -> None:
    expected = solution["results"]
    assert [r.revealed for r in results] == [e["revealed"] for e in expected]
    assert [r.crossed for r in results] == [e["crossed"] for e in expected]
    quarantined = [r.region_id for r in results if r.crossed]
    assert quarantined == solution["quarantined_region_ids"]


# --- local simulation: every problem ----------------------------------------


@pytest.mark.parametrize("problem_dir", PROBLEM_DIRS, ids=lambda p: f"problem{p.name}")
def test_problem_matches_solution(problem_dir):
    # The OT group size only affects speed, never correctness; the fast
    # 1024-bit group keeps this ten-run matrix quick.  The default (2048-bit)
    # path is exercised by test_cli_two_process_run below and by the OT and
    # protocol tests in test_yao.py.
    problem = load_problem_dir(problem_dir)
    results = evaluate_threshold(problem, group=GROUP_1024)
    _assert_matches_solution(results, _solution(problem_dir))


# --- genuine two-process run via the CLI ------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.slow
@pytest.mark.parametrize(
    "problem_dir", [PROBLEMS_DIR / "1"], ids=lambda p: f"problem{p.name}"
)
def test_cli_two_process_run(problem_dir):
    """Two separate processes, each holding only its own share vector."""
    port = _free_port()

    def _cli(party: int) -> list[str]:
        return [
            sys.executable,
            "-m",
            "smpc_gc.cli",
            "--input", str(problem_dir / f"problem_{'AB'[party]}.json"),
            "--party", str(party),
            "--port", str(port),
            "--json",
        ]

    p0 = subprocess.Popen(
        _cli(0), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        p1 = subprocess.run(_cli(1), capture_output=True, text=True, timeout=300)
        out0, err0 = p0.communicate(timeout=300)
    finally:
        p0.kill()

    assert p1.returncode == 0, f"party 1 failed:\n{p1.stdout}\n{p1.stderr}"
    assert p0.returncode == 0, f"party 0 failed:\n{out0}\n{err0}"

    solution = _solution(problem_dir)
    expected_revealed = [e["revealed"] for e in solution["results"]]
    for label, stdout in (("party0", out0), ("party1", p1.stdout)):
        payload = json.loads(stdout)
        assert [r["revealed"] for r in payload["results"]] == expected_revealed, label

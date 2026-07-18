"""Run every problem in ``problems/`` on every backend and check the solution.

Each ``problems/<n>/`` directory holds the two per-party input files
(``problem_A.json`` for party 0, ``problem_B.json`` for party 1) and the
expected public outcome (``solution.json``).  These tests prove the backends
are interchangeable: the same problems, the same expected results, only the
backend name changes.

Two levels are covered:

* **local simulation** — every problem × every backend, in-process;
* **genuine two-process 2PC** — the CLI is launched twice per backend with
  *identical* flags except ``--party``, each process holding only its own
  share file, and both parties' revealed outputs must match the solution.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from smpc_gc import get_backend
from smpc_gc.mock import load_problem_dir

PROBLEMS_DIR = Path(__file__).resolve().parent.parent / "problems"
PROBLEM_DIRS = sorted(
    (p for p in PROBLEMS_DIR.iterdir() if p.is_dir()), key=lambda p: int(p.name)
)
BACKENDS = ["yao", "mpyc"]


def _solution(problem_dir: Path) -> dict:
    return json.loads((problem_dir / "solution.json").read_text())


def _assert_matches_solution(results, solution: dict) -> None:
    expected = solution["results"]
    assert [r.revealed for r in results] == [e["revealed"] for e in expected]
    assert [r.crossed for r in results] == [e["crossed"] for e in expected]
    quarantined = [r.region_id for r in results if r.crossed]
    assert quarantined == solution["quarantined_region_ids"]


# --- local simulation: every problem on every backend -----------------------


def _make_backend(name: str):
    if name == "yao":
        from smpc_gc.backends.yao_backend import YaoBackend
        from smpc_gc.yao.ot import GROUP_1024

        # The OT group size only affects speed, never correctness; the fast
        # 1024-bit group keeps this 20-run matrix quick.  The default
        # (2048-bit) path is exercised by test_cli_two_process_run below and
        # by the OT/protocol tests in test_yao.py.
        return YaoBackend(group=GROUP_1024)
    return get_backend(name)


@pytest.mark.parametrize("backend_name", BACKENDS)
@pytest.mark.parametrize("problem_dir", PROBLEM_DIRS, ids=lambda p: f"problem{p.name}")
def test_problem_matches_solution(backend_name, problem_dir):
    problem = load_problem_dir(problem_dir)
    results = _make_backend(backend_name).evaluate(problem)
    _assert_matches_solution(results, _solution(problem_dir))


# --- genuine two-process run via the CLI: same flags, any backend -----------


def _free_port_pair() -> int:
    """A port ``p`` with both ``p`` and ``p+1`` free (mpyc uses two ports)."""
    for _ in range(50):
        with socket.socket() as s0:
            s0.bind(("127.0.0.1", 0))
            port = s0.getsockname()[1]
            try:
                with socket.socket() as s1:
                    s1.bind(("127.0.0.1", port + 1))
                    return port
            except OSError:
                continue
    raise RuntimeError("could not find two consecutive free ports")


@pytest.mark.parametrize("backend_name", BACKENDS)
@pytest.mark.parametrize(
    "problem_dir", [PROBLEMS_DIR / "1"], ids=lambda p: f"problem{p.name}"
)
def test_cli_two_process_run(backend_name, problem_dir):
    port = _free_port_pair()

    def _cli(party: int) -> list[str]:
        # Identical flags for every backend; only --backend selects the engine.
        return [
            sys.executable,
            "-m",
            "smpc_gc.cli",
            "--backend", backend_name,
            "--input", str(problem_dir / f"problem_{'AB'[party]}.json"),
            "--party", str(party),
            "--port", str(port),
            "--json",
        ]

    p0 = subprocess.Popen(
        _cli(0), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        p1 = subprocess.run(
            _cli(1), capture_output=True, text=True, timeout=120
        )
        out0, err0 = p0.communicate(timeout=120)
    finally:
        p0.kill()

    assert p1.returncode == 0, f"party 1 failed:\n{p1.stdout}\n{p1.stderr}"
    assert p0.returncode == 0, f"party 0 failed:\n{out0}\n{err0}"

    solution = _solution(problem_dir)
    expected_revealed = [e["revealed"] for e in solution["results"]]
    for label, stdout in (("party0", out0), ("party1", p1.stdout)):
        payload = json.loads(stdout)
        assert payload["backend"] == backend_name, label
        assert [r["revealed"] for r in payload["results"]] == expected_revealed, label

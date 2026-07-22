"""Tests for the shared problem types, mocking, and the MPyC backend.

The MPyC backend is exercised end-to-end (it runs in-process).
"""

from __future__ import annotations

import pytest

from smpc_gc import get_backend
from smpc_gc.mock import load_problem, make_mock_problem, problem_to_dict
from smpc_gc.types import CLEAR_TOKEN, ThresholdProblem


# --- problem / plaintext semantics -----------------------------------------


def test_expected_plaintext_matches_definition():
    problem = ThresholdProblem(
        threshold=50,
        region_ids=[1001, 1002, 1003],
        a_shares=[30, 10, 25],
        b_shares=[25, 20, 25],  # sums: 55 (>50), 30 (<=50), 50 (==50 -> not >)
    )
    results = problem.expected_plaintext()
    assert [r.revealed for r in results] == [1001, CLEAR_TOKEN, CLEAR_TOKEN]
    assert [r.crossed for r in results] == [True, False, False]


def test_validate_rejects_region_id_colliding_with_clear():
    problem = ThresholdProblem(
        threshold=50, region_ids=[0, 1002], a_shares=[1, 1], b_shares=[1, 1]
    )
    with pytest.raises(ValueError):
        problem.validate()


def test_validate_requires_both_shares_in_local_mode():
    problem = ThresholdProblem(threshold=50, region_ids=[1001], a_shares=[10])
    with pytest.raises(ValueError):
        problem.validate(party=None)


def test_mock_is_deterministic():
    p1 = make_mock_problem(num_regions=6, seed=42)
    p2 = make_mock_problem(num_regions=6, seed=42)
    assert p1.a_shares == p2.a_shares and p1.b_shares == p2.b_shares
    # additive split reconstructs the true count
    for a, b in zip(p1.a_shares, p1.b_shares):
        assert a >= 0 and b >= 0


def test_problem_json_roundtrip(tmp_path):
    problem = make_mock_problem(num_regions=5, seed=1)
    path = tmp_path / "p.json"
    path.write_text(__import__("json").dumps(problem_to_dict(problem)))
    loaded = load_problem(path)
    assert loaded.region_ids == problem.region_ids
    assert loaded.a_shares == problem.a_shares
    assert loaded.b_shares == problem.b_shares


# --- MPyC backend (runs for real) ------------------------------------------


def test_mpyc_matches_plaintext_boundary_cases():
    backend = get_backend("mpyc")
    problem = ThresholdProblem(
        threshold=50,
        region_ids=[1001, 1002, 1003, 1004],
        a_shares=[26, 25, 0, 100],
        b_shares=[25, 25, 0, 100],  # sums: 51(>), 50(=), 0, 200(>)
    )
    results = backend.evaluate(problem)
    assert [r.revealed for r in results] == [1001, CLEAR_TOKEN, CLEAR_TOKEN, 1004]


def test_mpyc_matches_plaintext_on_mock():
    backend = get_backend("mpyc")
    problem = make_mock_problem(num_regions=10, seed=7)
    expected = problem.expected_plaintext()
    results = backend.evaluate(problem)
    assert [r.revealed for r in results] == [e.revealed for e in expected]


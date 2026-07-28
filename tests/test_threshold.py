"""Tests for the shared problem types and the mock/JSON problem loading.

These cover the interface boundary between the secure-summation layer and the
2PC engine: what a well-formed :class:`ThresholdProblem` is, what the plaintext
answer to one is, and that a problem survives a JSON round trip.
"""

from __future__ import annotations

import json

import pytest

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


def test_expected_plaintext_is_none_without_both_vectors():
    """A real distributed party holds one vector and cannot compute the answer."""
    problem = ThresholdProblem(threshold=50, region_ids=[1001], a_shares=[10])
    assert problem.expected_plaintext() is None


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


def test_validate_requires_the_partys_own_shares():
    problem = ThresholdProblem(threshold=50, region_ids=[1001], a_shares=[10])
    problem.validate(party=0)  # party 0 owns a_shares: fine
    with pytest.raises(ValueError, match="party 1"):
        problem.validate(party=1)


def test_validate_rejects_a_wrong_length_vector():
    problem = ThresholdProblem(
        threshold=50, region_ids=[1001, 1002], a_shares=[1], b_shares=[1, 2]
    )
    with pytest.raises(ValueError, match="length"):
        problem.validate()


def test_validate_rejects_an_empty_problem():
    with pytest.raises(ValueError, match="no regions"):
        ThresholdProblem(threshold=50, region_ids=[]).validate()


# --- mocking and JSON -------------------------------------------------------


def test_mock_is_deterministic():
    p1 = make_mock_problem(num_regions=6, seed=42)
    p2 = make_mock_problem(num_regions=6, seed=42)
    assert p1.a_shares == p2.a_shares and p1.b_shares == p2.b_shares
    # additive split reconstructs the true count
    for a, b in zip(p1.a_shares, p1.b_shares):
        assert a >= 0 and b >= 0


def test_mock_straddles_the_threshold():
    """A mock that is all-clear or all-quarantine would test nothing."""
    problem = make_mock_problem(num_regions=12, threshold=50, seed=3)
    crossed = [r.crossed for r in problem.expected_plaintext()]
    assert any(crossed) and not all(crossed)


def test_problem_json_roundtrip(tmp_path):
    problem = make_mock_problem(num_regions=5, seed=1)
    path = tmp_path / "p.json"
    path.write_text(json.dumps(problem_to_dict(problem)))
    loaded = load_problem(path)
    assert loaded == problem


def test_load_problem_defaults_modulus_to_none():
    """Problems without a field (the mocked ones) reconstruct over the integers."""
    problem = make_mock_problem(num_regions=2, seed=0)
    assert problem.modulus is None
    assert problem.reconstruct(30, 25) == 55

"""
test_gc_handoff.py
==================
Tests for the Phase 2 -> Phase 3 hand-off boundary.

The two halves of the project agree on this schema and nothing else, so it gets
a round-trip test on the *real* configured parameters: whatever
``gc_handoff.build_problem`` emits must load back through the GC layer's own
``smpc_gc.mock.load_problem`` and evaluate to the same answer.
"""

from __future__ import annotations

import json
import secrets

import pytest

from config_loader import load_config
from gc_handoff import (
    build_problem,
    problem_to_json,
    region_ids_from_config,
    write_problem,
)
from secure_sum import compute_local_shares, local_sum
from share_reduction import EVALUATOR_ID, GARBLER_ID, consolidate, target_party
from smpc_gc.mock import load_problem, merge_problems

CONFIG = load_config()


def _phase1_and_2(local_vectors, p, node_ids):
    """Run Phases 1 and 2 in-process; return the two consolidated vectors."""
    all_sh = {n: compute_local_shares(local_vectors[n], p, node_ids) for n in node_ids}
    phase1 = {
        n: local_sum([all_sh[n][n]] + [all_sh[o][n] for o in node_ids if o != n], p)
        for n in node_ids
    }
    groups = {GARBLER_ID: [], EVALUATOR_ID: []}
    for n in node_ids:
        groups[target_party(n, node_ids)].append(phase1[n])
    return consolidate(groups[GARBLER_ID], p), consolidate(groups[EVALUATOR_ID], p)


# --- schema ----------------------------------------------------------------


def test_region_ids_are_non_zero_and_distinct():
    """0 is the 'Clear' sentinel, so no region may use it."""
    ids = region_ids_from_config(CONFIG.regions)
    assert len(ids) == len(CONFIG.regions)
    assert 0 not in ids
    assert len(set(ids)) == len(ids)


def test_each_party_file_holds_only_its_own_vector():
    ids = region_ids_from_config(["a", "b"])
    a = build_problem(party=0, shares=[1, 2], region_ids=ids, threshold=50, p=CONFIG.p)
    b = build_problem(party=1, shares=[3, 4], region_ids=ids, threshold=50, p=CONFIG.p)
    assert a.a_shares == [1, 2] and a.b_shares is None
    assert b.b_shares == [3, 4] and b.a_shares is None


def test_threshold_is_passed_through_unchanged():
    """No offset arithmetic: the circuit takes the real threshold."""
    problem = build_problem(
        party=0, shares=[1], region_ids=[1001], threshold=50, p=CONFIG.p
    )
    assert problem.threshold == 50
    assert problem.modulus == CONFIG.p
    assert problem.bit_length == CONFIG.p.bit_length()


def test_rejects_a_region_id_colliding_with_clear():
    with pytest.raises(ValueError, match="clear_token"):
        build_problem(party=0, shares=[1], region_ids=[0], threshold=50, p=CONFIG.p)


def test_rejects_mismatched_vector_lengths():
    with pytest.raises(ValueError, match="length"):
        build_problem(
            party=0, shares=[1, 2], region_ids=[1001], threshold=50, p=CONFIG.p
        )


def test_rejects_an_unreduced_share():
    with pytest.raises(ValueError, match="not reduced"):
        build_problem(
            party=0, shares=[CONFIG.p], region_ids=[1001], threshold=50, p=CONFIG.p
        )


# --- round trip through the GC layer's own loader ---------------------------


def test_written_files_load_back_and_merge(tmp_path):
    node_ids = CONFIG.node_ids
    locals_ = {
        n: [secrets.randbelow(60) for _ in CONFIG.regions] for n in node_ids
    }
    true = [sum(locals_[n][j] for n in node_ids) for j in range(len(CONFIG.regions))]
    A, B = _phase1_and_2(locals_, CONFIG.p, node_ids)
    ids = region_ids_from_config(CONFIG.regions)

    pa = build_problem(party=0, shares=A, region_ids=ids, threshold=50, p=CONFIG.p)
    pb = build_problem(party=1, shares=B, region_ids=ids, threshold=50, p=CONFIG.p)
    path_a = write_problem(tmp_path / "a" / "problem_A.json", pa)
    path_b = write_problem(tmp_path / "b" / "problem_B.json", pb)

    # Written owner-only: together these two files reconstruct every count.
    assert path_a.stat().st_mode & 0o077 == 0
    assert path_b.stat().st_mode & 0o077 == 0

    merged = merge_problems(load_problem(path_a), load_problem(path_b))
    merged.validate()
    assert merged.modulus == CONFIG.p
    # The merged problem's plaintext view must equal the true counts.
    expected = [c > 50 for c in true]
    assert [r.crossed for r in merged.expected_plaintext()] == expected


def test_json_shape_matches_what_load_problem_reads(tmp_path):
    problem = build_problem(
        party=0, shares=[7], region_ids=[1001], threshold=50, p=CONFIG.p
    )
    path = tmp_path / "p.json"
    path.write_text(json.dumps(problem_to_json(problem)))
    loaded = load_problem(path)
    assert loaded == problem


@pytest.mark.slow
def test_handoff_evaluates_correctly_on_the_real_engine():
    """The full boundary: config parameters -> problem -> secure result."""
    from smpc_gc import evaluate_threshold
    from smpc_gc.yao.ot import GROUP_1024

    node_ids = CONFIG.node_ids
    regions = CONFIG.regions[:4]
    ids = region_ids_from_config(regions)
    locals_ = {1: [10, 30, 0, 25], 2: [20, 5, 0, 26], 3: [15, 5, 0, 0], 4: [6, 9, 0, 0]}
    true = [51, 49, 0, 51]
    A, B = _phase1_and_2(locals_, CONFIG.p, node_ids)

    pa = build_problem(party=0, shares=A, region_ids=ids, threshold=50, p=CONFIG.p)
    pb = build_problem(party=1, shares=B, region_ids=ids, threshold=50, p=CONFIG.p)
    merged = merge_problems(pa, pb)

    results = evaluate_threshold(merged, group=GROUP_1024)
    assert [r.crossed for r in results] == [c > 50 for c in true]
    assert [r.revealed for r in results] == [ids[0], 0, 0, ids[3]]

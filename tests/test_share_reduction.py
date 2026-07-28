"""
test_share_reduction.py
=======================
Tests for Phase 2: migrating the Phase 1 shares to the two 2PC parties.

The property that matters is that Phase 2 is a *pure regrouping* of Phase 1's
shares -- it must not re-derive anything from the raw local vectors, and the
consolidated pair must reconstruct the same global vector, mod p.
"""

import secrets

import pytest

from secure_sum import compute_local_shares, local_sum
from share_reduction import (
    EVALUATOR_ID,
    GARBLER_ID,
    consolidate,
    expected_contributors,
    required_bit_length,
    target_party,
    verify_against_phase1,
)

P = 1048573
NODE_IDS = [1, 2, 3, 4]


def _phase1(local_vectors, node_ids=NODE_IDS, p=P):
    """Run Phase 1 in-process; return {node_id: its share of the global vector}."""
    all_shares = {
        n: compute_local_shares(local_vectors[n], p, node_ids) for n in node_ids
    }
    return {
        n: local_sum(
            [all_shares[n][n]] + [all_shares[o][n] for o in node_ids if o != n], p
        )
        for n in node_ids
    }


def _reduce(phase1_shares, node_ids=NODE_IDS, p=P):
    """Consolidate Phase 1's shares into the two parties' vectors (A, B)."""
    groups = {GARBLER_ID: [], EVALUATOR_ID: []}
    for n in node_ids:
        groups[target_party(n, node_ids)].append(phase1_shares[n])
    return consolidate(groups[GARBLER_ID], p), consolidate(groups[EVALUATOR_ID], p)


# --- routing ---------------------------------------------------------------


def test_the_two_parties_keep_their_own_share():
    assert target_party(GARBLER_ID, NODE_IDS) == GARBLER_ID
    assert target_party(EVALUATOR_ID, NODE_IDS) == EVALUATOR_ID


def test_extra_nodes_are_split_between_the_parties():
    """The proposal's routing: node 3 -> node 1, node 4 -> node 2."""
    assert target_party(3, NODE_IDS) == GARBLER_ID
    assert target_party(4, NODE_IDS) == EVALUATOR_ID


def test_every_node_contributes_exactly_once():
    targets = [target_party(n, NODE_IDS) for n in NODE_IDS]
    assert len(targets) == len(NODE_IDS)
    assert set(targets) <= {GARBLER_ID, EVALUATOR_ID}
    contributors = (
        expected_contributors(GARBLER_ID, NODE_IDS)
        + expected_contributors(EVALUATOR_ID, NODE_IDS)
    )
    # Everyone but the two parties themselves shows up exactly once.
    assert sorted(contributors) == [3, 4]


def test_routing_generalises_beyond_four_nodes():
    ids = [1, 2, 3, 4, 5, 6]
    assert expected_contributors(GARBLER_ID, ids) == [3, 5]
    assert expected_contributors(EVALUATOR_ID, ids) == [4, 6]


# --- reconstruction --------------------------------------------------------


def test_consolidated_pair_reconstructs_the_true_totals():
    for _ in range(100):
        locals_ = {n: [secrets.randbelow(300) for _ in range(5)] for n in NODE_IDS}
        true = [sum(locals_[n][j] for n in NODE_IDS) for j in range(5)]
        A, B = _reduce(_phase1(locals_))
        assert [(a + b) % P for a, b in zip(A, B)] == true


def test_agrees_with_phase1():
    """Phase 2 must be a regrouping of Phase 1, not a fresh computation."""
    locals_ = {n: [secrets.randbelow(200) for _ in range(4)] for n in NODE_IDS}
    phase1 = _phase1(locals_)
    phase1_global = local_sum(list(phase1.values()), P)
    A, B = _reduce(phase1)
    assert verify_against_phase1(A, B, phase1_global, P)


def test_threshold_decisions_preserved():
    """The real threshold is used unchanged -- no offset arithmetic."""
    thr = 50
    for _ in range(100):
        locals_ = {n: [secrets.randbelow(30) for _ in range(6)] for n in NODE_IDS}
        true = [sum(locals_[n][j] for n in NODE_IDS) for j in range(6)]
        A, B = _reduce(_phase1(locals_))
        got = [((a + b) % P) > thr for a, b in zip(A, B)]
        assert got == [t > thr for t in true]


def test_boundary_exactly_at_threshold():
    """50 -> clear, 51 -> crossed (the proposal says *more than* 50)."""
    thr = 50
    for total, expect in ((49, False), (50, False), (51, True), (52, True)):
        per = [total // 4] * 4
        per[0] += total - sum(per)
        locals_ = {n: [per[i]] for i, n in enumerate(NODE_IDS)}
        A, B = _reduce(_phase1(locals_))
        assert (((A[0] + B[0]) % P) > thr) == expect, f"total={total}"


# --- privacy ---------------------------------------------------------------


def test_each_consolidated_vector_alone_is_uniform():
    """Neither party's vector leaks anything: it stays uniform over F_p.

    The same true count, shared many times, must scatter A across the field
    rather than clustering near the count -- that is the information-theoretic
    hiding Phase 1's field arithmetic buys us.
    """
    samples = []
    for _ in range(500):
        locals_ = {n: [10] for n in NODE_IDS}  # identical inputs every time
        A, _ = _reduce(_phase1(locals_))
        samples.append(A[0])
    assert len(set(samples)) > 450, "A is not varying -- masking is broken"
    assert abs(sum(samples) / len(samples) - P / 2) < P * 0.1


# --- parameters ------------------------------------------------------------


def test_required_bit_length_fits_every_share():
    bits = required_bit_length(P)
    assert bits == P.bit_length()
    for _ in range(200):
        locals_ = {n: [secrets.randbelow(1000)] for n in NODE_IDS}
        A, B = _reduce(_phase1(locals_))
        assert A[0] < (1 << bits) and B[0] < (1 << bits)


def test_consolidate_rejects_mismatched_lengths():
    """A dropped/duplicated message must fail loudly, not silently zero-pad."""
    with pytest.raises(ValueError):
        consolidate([[1, 2, 3], [1, 2]], P)


def test_consolidate_rejects_empty_input():
    with pytest.raises(ValueError):
        consolidate([], P)

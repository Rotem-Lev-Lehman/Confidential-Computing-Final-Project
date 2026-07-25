"""
test_share_reduction.py
=======================
Tests for Phase 2 (share reduction to two parties).

Run with:  python3 test_share_reduction.py
"""

import secrets

from share_reduction import (
    MASK_BITS,
    add_vectors,
    offset,
    required_bit_length,
    shifted_threshold,
    split_for_two,
    split_vector_for_two,
    verify_against_phase1,
)
from secure_sum import compute_local_shares, local_sum

P = 1048573
NODE_IDS = [1, 2, 3, 4]


def test_split_reconstructs_exactly():
    """a + b == value + M, exactly, over the integers (no modulus)."""
    M = 1 << MASK_BITS
    for v in (0, 1, 50, 51, 999, 65535):
        a, b = split_for_two(v)
        assert a + b == v + M, f"v={v}: {a}+{b} != {v}+{M}"
    print("PASS: test_split_reconstructs_exactly")


def test_shares_non_negative():
    """Both halves stay non-negative -- the GC circuit takes unsigned inputs."""
    for _ in range(2000):
        v = secrets.randbelow(70000)
        a, b = split_for_two(v)
        assert a >= 0 and b >= 0, f"negative share for v={v}: ({a}, {b})"
    print("PASS: test_shares_non_negative")


def test_mask_independent_of_value():
    """`a` is uniform in [0, M) regardless of the value it hides."""
    M = 1 << MASK_BITS
    for v in (0, 42, 65535):
        for _ in range(200):
            a, _ = split_for_two(v)
            assert 0 <= a < M, f"a={a} outside [0,{M})"
    print("PASS: test_mask_independent_of_value")


def test_four_node_reconstruction():
    """A + B - offset == the true totals, for many random scenarios."""
    for _ in range(200):
        locals_ = {n: [secrets.randbelow(300) for _ in range(5)] for n in NODE_IDS}
        true = [sum(locals_[n][j] for n in NODE_IDS) for j in range(5)]

        a_parts, b_parts = [], []
        for n in NODE_IDS:
            av, bv = split_vector_for_two(locals_[n])
            a_parts.append(av)
            b_parts.append(bv)
        A, B = add_vectors(a_parts), add_vectors(b_parts)

        off = offset(len(NODE_IDS))
        assert [a + b - off for a, b in zip(A, B)] == true
    print("PASS: test_four_node_reconstruction (200 scenarios)")


def test_threshold_decisions_preserved():
    """The shifted threshold gives the same verdicts as plaintext comparison."""
    thr = 50
    sthr = shifted_threshold(thr, len(NODE_IDS))
    for _ in range(200):
        # bias counts to straddle the threshold
        locals_ = {n: [secrets.randbelow(30) for _ in range(6)] for n in NODE_IDS}
        true = [sum(locals_[n][j] for n in NODE_IDS) for j in range(6)]
        a_parts, b_parts = [], []
        for n in NODE_IDS:
            av, bv = split_vector_for_two(locals_[n])
            a_parts.append(av)
            b_parts.append(bv)
        A, B = add_vectors(a_parts), add_vectors(b_parts)
        got = [(a + b) > sthr for a, b in zip(A, B)]
        want = [t > thr for t in true]
        assert got == want, f"verdicts diverged: {got} vs {want}"
    print("PASS: test_threshold_decisions_preserved (200 scenarios)")


def test_boundary_exactly_at_threshold():
    """50 -> clear, 51 -> crossed (proposal says *more than* 50)."""
    thr = 50
    sthr = shifted_threshold(thr, len(NODE_IDS))
    for total, expect in ((49, False), (50, False), (51, True), (52, True)):
        # spread `total` across the 4 nodes
        per = [total // 4] * 4
        per[0] += total - sum(per)
        a_parts, b_parts = [], []
        for v in per:
            av, bv = split_vector_for_two([v])
            a_parts.append(av)
            b_parts.append(bv)
        A, B = add_vectors(a_parts), add_vectors(b_parts)
        crossed = (A[0] + B[0]) > sthr
        assert crossed == expect, f"total={total}: crossed={crossed}, expected {expect}"
    print("PASS: test_boundary_exactly_at_threshold")


def test_agrees_with_phase1():
    """Phase 2's result cross-checks against Phase 1's mod-p secure sum."""
    locals_ = {n: [secrets.randbelow(200) for _ in range(4)] for n in NODE_IDS}

    # Phase 1
    all_sh = {n: compute_local_shares(locals_[n], P, NODE_IDS) for n in NODE_IDS}
    local_results = [
        local_sum([all_sh[n][n]] + [all_sh[o][n] for o in NODE_IDS if o != n], P)
        for n in NODE_IDS
    ]
    phase1_global = local_sum(local_results, P)

    # Phase 2
    a_parts, b_parts = [], []
    for n in NODE_IDS:
        av, bv = split_vector_for_two(locals_[n])
        a_parts.append(av)
        b_parts.append(bv)
    A, B = add_vectors(a_parts), add_vectors(b_parts)

    assert verify_against_phase1(A, B, phase1_global, P, len(NODE_IDS))
    print("PASS: test_agrees_with_phase1")


def test_bit_length_sufficient():
    """The advertised bit_length actually fits the largest possible share."""
    bl = required_bit_length(len(NODE_IDS))
    locals_ = {n: [65535] * 3 for n in NODE_IDS}
    a_parts, b_parts = [], []
    for n in NODE_IDS:
        av, bv = split_vector_for_two(locals_[n])
        a_parts.append(av)
        b_parts.append(bv)
    A, B = add_vectors(a_parts), add_vectors(b_parts)
    assert all(x < (1 << bl) for x in A + B), "share exceeds advertised bit_length"
    print(f"PASS: test_bit_length_sufficient (bit_length={bl})")


def test_mismatched_lengths_rejected():
    """A dropped/duplicated message must fail loudly, not silently zero-pad."""
    try:
        add_vectors([[1, 2, 3], [1, 2]])
        assert False, "expected ValueError on mismatched lengths"
    except ValueError:
        print("PASS: test_mismatched_lengths_rejected")


if __name__ == "__main__":
    test_split_reconstructs_exactly()
    test_shares_non_negative()
    test_mask_independent_of_value()
    test_four_node_reconstruction()
    test_threshold_decisions_preserved()
    test_boundary_exactly_at_threshold()
    test_agrees_with_phase1()
    test_bit_length_sufficient()
    test_mismatched_lengths_rejected()
    print("\nAll share_reduction tests passed.")

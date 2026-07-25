"""Tests for Phase 1: vectorization, secret sharing and the secure sum."""

import secrets

import pytest

from secret_sharing import reconstruct, split_into_shares
from secure_sum import (
    compute_local_shares,
    distribute_shares,
    local_sum,
    reconstruct_global,
)
from vectorize import UnknownRegionError, build_region_index, vectorize

P = 1048573
NODE_IDS = [1, 2, 3, 4]
REGIONS = ["72701", "72703", "72704", "72712"]


# --- vectorize -------------------------------------------------------------


def test_build_region_index_maps_positions():
    assert build_region_index(REGIONS) == {
        "72701": 0, "72703": 1, "72704": 2, "72712": 3
    }


def test_vectorize_counts_per_region():
    records = ["72701", "72701", "72703", "72712", "72712", "72712"]
    assert vectorize(records, REGIONS, P) == [2, 1, 0, 3]


def test_vectorize_empty_records_gives_zero_vector():
    assert vectorize([], REGIONS, P) == [0, 0, 0, 0]


def test_vectorize_length_is_always_m():
    assert len(vectorize(["72701"], REGIONS, P)) == len(REGIONS)


def test_vectorize_unknown_region_raises():
    with pytest.raises(UnknownRegionError):
        vectorize(["72701", "99999"], REGIONS, P)


def test_vectorize_reduces_mod_p():
    """A count exceeding p must come back reduced, not raw."""
    assert vectorize(["72701"] * (P + 5), REGIONS, P)[0] == 5


# --- secret sharing --------------------------------------------------------


def test_split_roundtrip():
    for _ in range(500):
        v = secrets.randbelow(P)
        assert reconstruct(split_into_shares(v, P, 4), P) == v


def test_split_returns_requested_count():
    for n in (2, 3, 4, 7):
        assert len(split_into_shares(100, P, n)) == n


def test_split_defaults_to_four_shares():
    assert len(split_into_shares(100, P)) == 4


def test_split_shares_within_field():
    for _ in range(500):
        assert all(0 <= s < P for s in split_into_shares(500, P, 4))


def test_split_zero_value():
    assert reconstruct(split_into_shares(0, P, 4), P) == 0


def test_split_is_randomised():
    """Two splits of the same value must differ, or the RNG is broken."""
    assert split_into_shares(42, P, 4) != split_into_shares(42, P, 4)


@pytest.mark.parametrize("value", [-1, P, P + 10])
def test_split_rejects_unreduced_value(value):
    with pytest.raises(ValueError):
        split_into_shares(value, P, 4)


def test_split_rejects_too_few_shares():
    with pytest.raises(ValueError):
        split_into_shares(10, P, 1)


# --- the secure sum --------------------------------------------------------


def _simulate_secure_sum(local_vectors):
    """Run Phase 1 in-process across all nodes; return the global vector."""
    all_shares = {
        nid: compute_local_shares(local_vectors[nid], P, NODE_IDS)
        for nid in NODE_IDS
    }
    local_results = []
    for nid in NODE_IDS:
        received = [all_shares[other][nid] for other in NODE_IDS if other != nid]
        local_results.append(local_sum([all_shares[nid][nid]] + received, P))
    return reconstruct_global(local_results, P)


def test_secure_sum_matches_plaintext_totals():
    local_vectors = {1: [10, 5], 2: [3, 20], 3: [0, 1], 4: [7, 4]}
    assert _simulate_secure_sum(local_vectors) == [20, 30]


def test_secure_sum_over_random_inputs():
    for _ in range(50):
        local_vectors = {
            nid: [secrets.randbelow(500) for _ in range(6)] for nid in NODE_IDS
        }
        expected = [
            sum(local_vectors[nid][j] for nid in NODE_IDS) % P for j in range(6)
        ]
        assert _simulate_secure_sum(local_vectors) == expected


def test_compute_local_shares_gives_one_share_per_region():
    V = [1, 2, 3]
    shares = compute_local_shares(V, P, NODE_IDS)
    assert set(shares) == set(NODE_IDS)
    assert all(len(vec) == len(V) for vec in shares.values())


def test_distribute_shares_keeps_own_and_sends_rest():
    shares = compute_local_shares([1, 2], P, NODE_IDS)
    sent = []
    mine = distribute_shares(1, shares, lambda pid, msg: sent.append((pid, msg)))
    assert mine == shares[1]
    assert sorted(pid for pid, _ in sent) == [2, 3, 4]
    assert all("shares" in msg for _, msg in sent)


def test_local_sum_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        local_sum([[1, 2, 3], [1, 2]], P)


def test_local_sum_rejects_empty_input():
    with pytest.raises(ValueError):
        local_sum([], P)

"""
vectorize.py
============
Turn a hospital's local records into a fixed-length histogram vector.

Each hospital maps its local records into a vector of length M = len(regions),
where V[j] is the number of positive cases in regions[j] at this hospital.

The index -> region mapping comes from the `regions` list in the public config,
so it is identical across all 4 nodes. That is what makes the Secure Sum
meaningful: every node agrees that index j refers to the same region. If one
node built a different mapping, the sums would be silently wrong.
"""

from typing import Iterable


class UnknownRegionError(ValueError):
    """
    Raised when a record references a region that is not in the config.

    We fail fast rather than silently dropping the record: dropping health data
    would corrupt the global sum with no trace, and someone would see a wrong
    result without knowing records were lost. An explicit error forces fixing
    the source (dirty data or an out-of-sync config).
    """


def build_region_index(regions: list[str]) -> dict[str, int]:
    """
    Build a region -> index lookup from the ordered config list.

    Built once and reused, so vectorization is O(N) over the number of records
    instead of O(N*M) (a linear scan of the list per record).
    """
    return {region: idx for idx, region in enumerate(regions)}


def vectorize(records: Iterable[str], regions: list[str], p: int) -> list[int]:
    """
    Convert an iterable of region labels (one per positive case) into the
    histogram vector V of length M, reduced mod p.

    Args:
        records: iterable of region labels, one per positive case.
        regions: the public, ordered region list from config (length M).
        p:       the public prime modulus.

    Returns:
        V: list[int] of length M, where V[j] = (local count for regions[j]) % p.

    Raises:
        UnknownRegionError: if a record references a region not in `regions`.
    """
    region_to_idx = build_region_index(regions)
    V = [0] * len(regions)

    for rec in records:
        idx = region_to_idx.get(rec)
        if idx is None:
            raise UnknownRegionError(f"unknown region {rec!r}")
        V[idx] += 1

    # Reduce mod p so every element is in [0, p) before it reaches
    # split_into_shares. Cheap, idempotent, and keeps the invariant that
    # share reduction later relies on.
    return [count % p for count in V]

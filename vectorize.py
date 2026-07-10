"""
vectorize.py
============
Task 2: Turn a hospital's local DB into a fixed-length histogram vector of size M.

Each hospital maps its local records into a vector of length M = len(regions).
V[j] = number of positive cases in regions[j] at this hospital.

** Why this is critical: ** the index -> region mapping is derived from the
`regions` list in the config, which is identical across all 4 nodes. This is
what makes the Secure Sum meaningful -- every node agrees that index j refers
to the exact same region. If one node built a different mapping, we'd sum
apples with oranges and the result would be silently wrong.
"""

from typing import Iterable


class UnknownRegionError(ValueError):
    """
    Raised when a record references a region that is not in the config.

    We fail fast rather than silently dropping the record: silently dropping
    health data would corrupt the global sum with no trace -- someone would
    see a wrong result without knowing records were lost. An explicit error
    forces fixing the source (dirty data or an out-of-sync config).
    """


def build_region_index(regions: list[str]) -> dict[str, int]:
    """
    Build a region -> index lookup from the ordered config list.

    We build the dict once and reuse it, so vectorization is O(N) over the
    number of records instead of O(N*M) (a linear scan of the list per record).

    TODO 1: Return a dict mapping each region to its index.
            Hint: enumerate(regions) yields (idx, region) pairs.
            {region: idx for idx, region in enumerate(regions)}
    """
    reg_ind = {}

    for i, val in enumerate(regions):
        reg_ind[val] = i

    return reg_ind


def vectorize(records: Iterable[str], regions: list[str], p: int) -> list[int]:
    """
    Convert an iterable of region labels (one per positive case) into the
    histogram vector V of length M, reduced mod p.

    Args:
        records: iterable of region labels -- one per positive case.
                 (Each element is the region of a single patient.)
        regions: the public, ordered region list from config (length M).
        p:       the public prime modulus.

    Returns:
        V: list[int] of length M, where V[j] = (local count for regions[j]) % p.

    Raises:
        UnknownRegionError: if a record references a region not in `regions`.

    -------------------------------------------------------------------
    TODO 2: Build the lookup.
    TODO 3: Initialize vector.
    TODO 4: Iterate over records.
    TODO 5: EDGE CASE / invariant: reduce every element mod p before returning.
    
              Cheap, idempotent, and guarantees every element is in [0, p)
              before it reaches split_into_shares. Especially important for
              the upcoming share reduction, which works with full random
              values in [0, p).
    -------------------------------------------------------------------
    """
    region_to_idx = build_region_index(regions)
    M = len(regions)
    V = [0] * M

    for rec in records:
        idx = region_to_idx.get(rec)
        if idx is None:
            raise UnknownRegionError(f"Unknown Region {rec!r}")
        V[idx] += 1
        
    V = [count % p for count in V]

    return V

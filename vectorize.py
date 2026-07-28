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


class CountOverflowError(ValueError):
    """
    Raised when a local count is too large for the configured field.

    Reducing such a count mod p would wrap it to a small number, and the global
    sum would then be quietly wrong -- a region with a genuine outbreak could
    report as clear. The field is sized for this in config.json
    (``p > num_nodes * max_local_count``), so hitting this means either the data
    or the configuration is wrong, and both deserve a loud failure.
    """


def build_region_index(regions: list[str]) -> dict[str, int]:
    """
    Build a region -> index lookup from the ordered config list.

    Built once and reused, so vectorization is O(N) over the number of records
    instead of O(N*M) (a linear scan of the list per record).
    """
    return {region: idx for idx, region in enumerate(regions)}


def vectorize(
    records: Iterable[str],
    regions: list[str],
    p: int,
    max_local_count: int | None = None,
) -> list[int]:
    """
    Convert an iterable of region labels (one per positive case) into the
    histogram vector V of length M.

    Args:
        records: iterable of region labels, one per positive case.
        regions: the public, ordered region list from config (length M).
        p:       the public prime modulus.
        max_local_count: the largest per-region count this deployment is sized
            for (``config.json``). Counts above it are rejected rather than
            wrapped. Defaults to ``p - 1``, i.e. reject only true overflow.

    Returns:
        V: list[int] of length M, where V[j] is the local count for regions[j],
        guaranteed to be in [0, p) so it is a valid input to split_into_shares.

    Raises:
        UnknownRegionError: if a record references a region not in `regions`.
        CountOverflowError: if a count exceeds what the field is sized for.
    """
    region_to_idx = build_region_index(regions)
    V = [0] * len(regions)

    for rec in records:
        idx = region_to_idx.get(rec)
        if idx is None:
            raise UnknownRegionError(f"unknown region {rec!r}")
        V[idx] += 1

    # Never wrap silently: a count that does not fit the field would come back
    # as a small number and corrupt the global sum with no trace.
    limit = p - 1 if max_local_count is None else min(max_local_count, p - 1)
    for j, count in enumerate(V):
        if count > limit:
            raise CountOverflowError(
                f"region {regions[j]!r} has {count} local cases, over the "
                f"configured limit of {limit}; widen p / max_local_count in "
                "config.json"
            )
    return V

"""
gc_handoff.py
=============
The hand-off boundary from Phase 2 to the Garbled Circuit layer.

Writes the problem file the GC engine (``smpc_gc``) consumes.  Its
``load_problem`` expects exactly these keys::

    {"threshold": int, "region_ids": [int, ...],
     "a_shares": [int, ...] | null, "b_shares": [int, ...] | null,
     "bit_length": int, "clear_token": int}

Party 0 (Garbler / Node 1) supplies ``a_shares`` and leaves ``b_shares`` null;
party 1 (Evaluator / Node 2) does the reverse.  Neither file ever contains both
vectors, so neither party can reconstruct the counts locally.

Two public parameters are derived from Phase 2's offset (see
:mod:`share_reduction`):

* ``threshold`` is shifted by ``n * 2**mask_bits`` so the unchanged circuit
  still decides ``T > threshold``;
* ``bit_length`` is widened to fit the offset shares.

``clear_token`` stays 0, and region ids must therefore be non-zero — the GC
layer's own ``validate()`` enforces this.
"""

from __future__ import annotations

import json
from pathlib import Path

from share_reduction import MASK_BITS, required_bit_length, shifted_threshold


def build_problem(
    party: int,
    shares: list[int],
    region_ids: list[int],
    threshold: int,
    num_nodes: int,
    mask_bits: int = MASK_BITS,
    clear_token: int = 0,
) -> dict:
    """Build the GC problem dict for one party.

    Args:
        party: 0 for the Garbler (supplies A), 1 for the Evaluator (supplies B).
        shares: this party's share vector from Phase 2.
        region_ids: public, non-zero region identifiers (one per index).
        threshold: the *real* threshold (e.g. 50); shifting is handled here.
        num_nodes: how many nodes contributed, for the offset.
    """
    if party not in (0, 1):
        raise ValueError(f"party must be 0 or 1, got {party!r}")
    if len(shares) != len(region_ids):
        raise ValueError(
            f"shares length {len(shares)} != region_ids length {len(region_ids)}"
        )
    if clear_token in region_ids:
        raise ValueError(
            f"clear_token {clear_token} collides with a region id; "
            "region ids must be non-zero"
        )
    return {
        "threshold": shifted_threshold(threshold, num_nodes, mask_bits),
        "region_ids": list(region_ids),
        "a_shares": list(shares) if party == 0 else None,
        "b_shares": list(shares) if party == 1 else None,
        "bit_length": required_bit_length(num_nodes, mask_bits),
        "clear_token": clear_token,
    }


def write_problem(path: str | Path, **kwargs) -> Path:
    """Write :func:`build_problem` output to ``path`` as JSON."""
    problem = build_problem(**kwargs)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(problem, indent=2) + "\n")
    return path


def region_ids_from_config(regions: list[str], base: int = 1001) -> list[int]:
    """Map the config's region labels to non-zero integer ids for the circuit.

    The GC layer works with integer ids and reserves 0 as the 'Clear' sentinel,
    so index ``j`` becomes ``base + j``.  Deterministic, so every party derives
    the same mapping from the same public config.
    """
    return [base + j for j in range(len(regions))]

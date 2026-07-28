"""
gc_handoff.py
=============
The hand-off boundary from Phase 2 to the Garbled Circuit layer.

Builds the :class:`smpc_gc.types.ThresholdProblem` (or the equivalent JSON) that
the GC engine consumes from one party's consolidated share vector.  The keys
are exactly what ``smpc_gc.mock.load_problem`` expects::

    {"threshold": int, "region_ids": [int, ...],
     "a_shares": [int, ...] | null, "b_shares": [int, ...] | null,
     "bit_length": int, "clear_token": int, "modulus": int}

Party 0 (Garbler / Node 1) supplies ``a_shares`` and leaves ``b_shares`` null;
party 1 (Evaluator / Node 2) does the reverse.  Neither side ever holds both
vectors, so neither can reconstruct the counts locally.

THE PUBLIC PARAMETERS
---------------------
``modulus`` is the field the Phase 1 / Phase 2 shares live in.  Passing it
tells the circuit to reduce ``A + B`` mod ``p`` before comparing, which is what
lets the *real* threshold (50) be used unchanged -- no offset arithmetic
anywhere.  ``bit_length`` is just wide enough for a reduced share.

``clear_token`` stays 0, so region ids must be non-zero; both this module and
the GC layer's own ``validate()`` enforce that.

WRITING THE PROBLEM TO DISK IS OPTIONAL AND FOR DEMOS ONLY
----------------------------------------------------------
In a real run nodes 1 and 2 keep their vectors in memory and hand them straight
to the 2PC engine -- see ``main.py``.  :func:`write_problem` exists so a demo
can show the hand-off, and it writes ``0600`` into a per-node directory: the two
files together reconstruct every regional count, so they are as sensitive as the
raw data.  See ``THREAT_MODEL.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

from share_reduction import required_bit_length
from smpc_gc.types import ThresholdProblem


def build_problem(
    party: int,
    shares: list[int],
    region_ids: list[int],
    threshold: int,
    p: int,
    clear_token: int = 0,
) -> ThresholdProblem:
    """Build the GC problem for one party from its Phase 2 share vector.

    Args:
        party: 0 for the Garbler (supplies A), 1 for the Evaluator (supplies B).
        shares: this party's consolidated share vector, reduced mod ``p``.
        region_ids: public, non-zero region identifiers (one per index).
        threshold: the real quarantine threshold (e.g. 50) -- used as-is.
        p: the public prime modulus the shares live in.
        clear_token: public sentinel for a sub-threshold region.
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
    problem = ThresholdProblem(
        threshold=threshold,
        region_ids=list(region_ids),
        a_shares=list(shares) if party == 0 else None,
        b_shares=list(shares) if party == 1 else None,
        bit_length=required_bit_length(p),
        clear_token=clear_token,
        modulus=p,
    )
    problem.validate(party=party)
    return problem


def problem_to_json(problem: ThresholdProblem) -> dict:
    """Serialize a problem into the JSON shape ``load_problem`` reads back."""
    return {
        "threshold": problem.threshold,
        "region_ids": list(problem.region_ids),
        "a_shares": problem.a_shares,
        "b_shares": problem.b_shares,
        "bit_length": problem.bit_length,
        "clear_token": problem.clear_token,
        "modulus": problem.modulus,
    }


def write_problem(path: str | Path, problem: ThresholdProblem) -> Path:
    """Write a problem to ``path`` as JSON, owner-readable only.

    Demo/debug aid -- see the module docstring.  The file holds one party's
    share vector; combined with the other party's it reconstructs every count.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(problem_to_json(problem), indent=2) + "\n")
    path.chmod(0o600)
    return path


def region_ids_from_config(regions: list[str], base: int = 1001) -> list[int]:
    """Map the config's region labels to non-zero integer ids for the circuit.

    The GC layer works with integer ids and reserves 0 as the 'Clear' sentinel,
    so index ``j`` becomes ``base + j``.  Deterministic, so every party derives
    the same mapping from the same public config.
    """
    return [base + j for j in range(len(regions))]

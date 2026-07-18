"""Mock input generation for isolated development.

The threshold engine does *not* need a live 4-node network: it can be developed
and tested against locally mocked shares ``A`` and ``B``.  This module fabricates
a realistic scenario — a mix of regions above
and below the quarantine threshold — and splits each region's true count into
two additive shares ``A_j + B_j == true_count_j`` (without field wraparound, per
the mocking assumption documented on :class:`ThresholdProblem`).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from smpc_gc.types import ThresholdProblem


def make_mock_problem(
    *,
    num_regions: int = 8,
    threshold: int = 50,
    seed: int = 0,
    max_count: int | None = None,
    bit_length: int = 32,
    region_id_base: int = 1001,
) -> ThresholdProblem:
    """Build a deterministic mock :class:`ThresholdProblem`.

    Region ids are ``region_id_base, region_id_base+1, ...`` (kept distinct from
    the zero 'Clear' sentinel).  True counts are drawn to straddle ``threshold``
    so results contain both QUARANTINE and clear outcomes.
    """
    rng = random.Random(seed)
    hi = max_count if max_count is not None else threshold * 2
    if hi <= 0:
        raise ValueError("max_count/threshold produce an empty count range")

    region_ids: list[int] = []
    a_shares: list[int] = []
    b_shares: list[int] = []
    for j in range(num_regions):
        region_ids.append(region_id_base + j)
        true_count = rng.randint(0, hi)
        a = rng.randint(0, true_count)  # non-negative additive split
        b = true_count - a
        a_shares.append(a)
        b_shares.append(b)

    return ThresholdProblem(
        threshold=threshold,
        region_ids=region_ids,
        a_shares=a_shares,
        b_shares=b_shares,
        bit_length=bit_length,
    )


def load_problem(path: str | Path) -> ThresholdProblem:
    """Load a :class:`ThresholdProblem` from a JSON file.

    Expected keys: ``threshold``, ``region_ids`` and any of ``a_shares``,
    ``b_shares`` (omit one for a genuine distributed party), plus optional
    ``bit_length`` and ``clear_token``.
    """
    data = json.loads(Path(path).read_text())
    return ThresholdProblem(
        threshold=data["threshold"],
        region_ids=list(data["region_ids"]),
        a_shares=data.get("a_shares"),
        b_shares=data.get("b_shares"),
        bit_length=data.get("bit_length", 32),
        clear_token=data.get("clear_token", 0),
    )


def merge_problems(
    problem_a: ThresholdProblem, problem_b: ThresholdProblem
) -> ThresholdProblem:
    """Combine party 0's and party 1's problem files into one local problem.

    The public parameters (threshold, region ids, bit length, clear token) must
    agree; the merged problem holds both share vectors, which is what the
    local-simulation mode (``party=None``) and the plaintext cross-check need.
    """
    for attr in ("threshold", "region_ids", "bit_length", "clear_token"):
        va, vb = getattr(problem_a, attr), getattr(problem_b, attr)
        if va != vb:
            raise ValueError(
                f"problem files disagree on public parameter {attr!r}: {va!r} != {vb!r}"
            )
    return ThresholdProblem(
        threshold=problem_a.threshold,
        region_ids=problem_a.region_ids,
        a_shares=problem_a.a_shares if problem_a.a_shares is not None else problem_b.a_shares,
        b_shares=problem_b.b_shares if problem_b.b_shares is not None else problem_a.b_shares,
        bit_length=problem_a.bit_length,
        clear_token=problem_a.clear_token,
    )


def load_problem_dir(path: str | Path) -> ThresholdProblem:
    """Load a ``problems/<n>/`` directory (``problem_A.json`` + ``problem_B.json``)
    into one merged, locally runnable :class:`ThresholdProblem`."""
    path = Path(path)
    return merge_problems(
        load_problem(path / "problem_A.json"),
        load_problem(path / "problem_B.json"),
    )


def problem_to_dict(problem: ThresholdProblem) -> dict:
    return {
        "threshold": problem.threshold,
        "region_ids": list(problem.region_ids),
        "a_shares": problem.a_shares,
        "b_shares": problem.b_shares,
        "bit_length": problem.bit_length,
        "clear_token": problem.clear_token,
    }

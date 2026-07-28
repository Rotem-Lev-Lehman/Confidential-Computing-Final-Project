"""
test_modulus.py
===============
Tests for modular reconstruction inside the secure computation.

Phase 1's shares live in 𝔽ₚ, so ``A + B`` over the integers is either the true
count or the true count plus ``p``.  The circuit resolves that with one
conditional subtraction.  Getting this wrong is silent and catastrophic -- an
over-threshold region would report as clear -- so both branches are tested
directly, and both backends are checked to agree.
"""

from __future__ import annotations

import random

import pytest

from smpc_gc import get_backend
from smpc_gc.backends.yao_backend import YaoBackend
from smpc_gc.types import ThresholdProblem
from smpc_gc.yao import build_threshold_circuit, evaluate, garble
from smpc_gc.yao.ot import GROUP_1024

P = 1048573  # the configured modulus, 2**20 - 3
BITS = P.bit_length()


def _bits(value: int, wires) -> dict[int, int]:
    return {w: (value >> i) & 1 for i, w in enumerate(wires)}


def _to_int(bits: list[int]) -> int:
    return sum(b << i for i, b in enumerate(bits))


def _garble_eval(circuit, a_val: int, b_val: int) -> int:
    """Drive garbling/evaluation directly, isolating the circuit from the OT."""
    garbled, pairs = garble(circuit, _bits(a_val, circuit.garbler_input_wires))
    ev = _bits(b_val, circuit.evaluator_input_wires)
    labels = {w: pairs[w][ev[w]] for w in circuit.evaluator_input_wires}
    return _to_int(evaluate(garbled, labels))


# --- the circuit ------------------------------------------------------------


def test_circuit_rejects_a_modulus_too_wide_for_the_shares():
    with pytest.raises(ValueError, match="modulus"):
        build_threshold_circuit(
            bit_length=8, threshold=50, region_id=1001, clear_token=0, modulus=1000
        )


def _share_pairs(true_count: int, rng: random.Random, n: int = 5):
    """Share pairs for ``true_count``, half wrapping the field and half not.

    Which branch you land in is decided by whether ``a <= true_count``:  then
    ``b = T - a`` and the integer sum is ``T``; otherwise ``b = T - a + p`` and
    the sum is ``T + p``.  Picking ``a`` uniformly would almost always give the
    wrapping branch (the counts are tiny next to ``p``), so both are constructed
    explicitly -- the conditional subtraction is exactly what is under test.
    """
    no_wrap = [(a, true_count - a) for a in
               sorted({rng.randint(0, true_count) for _ in range(n)} | {0, true_count})]
    wrap = [(a, true_count - a + P) for a in
            {rng.randrange(true_count + 1, P) for _ in range(n)} | {P - 1}]
    return no_wrap, wrap


@pytest.mark.parametrize("true_count", [0, 1, 49, 50, 51, 52, 1000, P - 2])
def test_boundary_counts_under_both_wrap_branches(true_count):
    """Every boundary count is tested with shares that wrap and shares that don't."""
    circuit = build_threshold_circuit(
        bit_length=BITS, threshold=50, region_id=1001, clear_token=0, modulus=P
    )
    expected = 1001 if true_count > 50 else 0
    no_wrap, wrap = _share_pairs(true_count, random.Random(true_count))
    assert no_wrap and wrap, "did not construct both branches"

    for a, b in no_wrap:
        assert a + b == true_count  # no wrap: integer sum is already the count
        assert _garble_eval(circuit, a, b) == expected, f"no-wrap a={a} b={b}"
    for a, b in wrap:
        assert a + b == true_count + P  # wrap: needs the conditional subtraction
        assert _garble_eval(circuit, a, b) == expected, f"wrap a={a} b={b}"


def test_modular_circuit_is_cheaper_than_integer_masking():
    """The redesign is not just more private -- it is smaller and does less OT.

    An integer-masking scheme would need 40 mask bits plus room for four nodes'
    contributions; modular reduction keeps the shares at p's width.
    """
    modular = build_threshold_circuit(
        bit_length=BITS, threshold=50, region_id=1001, clear_token=0, modulus=P
    )
    masked = build_threshold_circuit(
        bit_length=47, threshold=50 + 4 * (1 << 40), region_id=1001, clear_token=0
    )
    ands = lambda c: sum(1 for g in c.gates if g.op == "AND")  # noqa: E731
    assert ands(modular) < ands(masked)
    # The dominant cost is one base OT per evaluator input bit.
    assert len(modular.evaluator_input_wires) < len(masked.evaluator_input_wires)


# --- the problem type -------------------------------------------------------


def test_expected_plaintext_reduces_mod_p():
    problem = ThresholdProblem(
        threshold=50,
        region_ids=[1001, 1002],
        a_shares=[P - 10, P - 10],
        b_shares=[61, 60],  # true counts: 51 (crossed), 50 (not)
        bit_length=BITS,
        modulus=P,
    )
    assert [r.crossed for r in problem.expected_plaintext()] == [True, False]


def test_validate_rejects_an_unreduced_share():
    problem = ThresholdProblem(
        threshold=50, region_ids=[1001], a_shares=[P], b_shares=[0],
        bit_length=BITS, modulus=P,
    )
    with pytest.raises(ValueError, match="not reduced"):
        problem.validate()


def test_validate_rejects_a_modulus_wider_than_bit_length():
    problem = ThresholdProblem(
        threshold=50, region_ids=[1001], a_shares=[1], b_shares=[1],
        bit_length=8, modulus=P,
    )
    with pytest.raises(ValueError, match="modulus"):
        problem.validate()


# --- both backends ----------------------------------------------------------


def _modular_problem(seed: int, num_regions: int = 4) -> ThresholdProblem:
    rng = random.Random(seed)
    ids, a, b = [], [], []
    for j in range(num_regions):
        ids.append(1001 + j)
        true_count = rng.choice([0, 30, 50, 51, 80, 120])
        share_a = rng.randrange(P)
        a.append(share_a)
        b.append((true_count - share_a) % P)
    return ThresholdProblem(
        threshold=50, region_ids=ids, a_shares=a, b_shares=b,
        bit_length=BITS, modulus=P,
    )


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_yao_matches_plaintext_on_modular_shares(seed):
    problem = _modular_problem(seed)
    results = YaoBackend(group=GROUP_1024).evaluate(problem)
    expected = problem.expected_plaintext()
    assert [r.revealed for r in results] == [e.revealed for e in expected]


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_mpyc_matches_plaintext_on_modular_shares(seed):
    problem = _modular_problem(seed)
    results = get_backend("mpyc").evaluate(problem)
    expected = problem.expected_plaintext()
    assert [r.revealed for r in results] == [e.revealed for e in expected]


def test_both_backends_agree_on_modular_shares():
    """The swappable-engine claim, on the parameters the system actually uses."""
    problem = _modular_problem(seed=7, num_regions=6)
    yao = YaoBackend(group=GROUP_1024).evaluate(problem)
    mpyc = get_backend("mpyc").evaluate(problem)
    assert [r.revealed for r in yao] == [r.revealed for r in mpyc]
    assert [r.crossed for r in yao] == [r.crossed for r in mpyc]

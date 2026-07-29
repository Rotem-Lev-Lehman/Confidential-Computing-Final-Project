"""Securely evaluate the quarantine-threshold problem with Yao's Garbled Circuits.

This is the entry point to the 2PC layer.  Given a :class:`ThresholdProblem` it
runs, for each region, one independent garbled-circuit instance computing

    (A + B mod p) > threshold ? region_id : Clear

using the garbling, Oblivious Transfer and protocol code in :mod:`smpc_gc.yao`.
Nothing else is involved: the cryptography is ours, end to end.

RUN MODES (``party``)
---------------------
``None`` -- **local simulation.**  One process holds both share vectors and
    drives the garbler and evaluator against each other over an in-process
    socket pair (see :func:`~smpc_gc.yao.protocol.run_yao_2pc`).  Handy for
    demos and the plaintext cross-check; even here no single call holds both
    parties' secret bits.

``0`` / ``1`` -- **genuine two-process run.**  Two separate processes each hold
    only their own share vector and talk over a :class:`~smpc_gc.channel.Channel`:

        party 0 (garbler)   binds ``host:port`` and waits for the evaluator;
        party 1 (evaluator) connects to it.

    Pass a ``channel_factory`` (any :data:`~smpc_gc.channel.ChannelFactory`) to
    carry the protocol over a different transport -- the system uses this to run
    the whole 2PC over the SIGMA-authenticated, AES-GCM-encrypted mesh instead
    of a bare socket, without the crypto layer knowing.

WHY THERE IS NO BACKEND ABSTRACTION HERE
----------------------------------------
An earlier version put this behind a pluggable ``ThresholdBackend`` interface so
a second engine (MPyC) could be swapped in.  MPyC turned out not to implement
Yao's Garbled Circuits at all -- it is honest-majority Shamir secret sharing,
which in a two-party setting degenerates to no input privacy whatsoever -- so it
was dropped, and with only one engine the indirection was pure overhead.  See
``README.md`` for the full account.
"""

from __future__ import annotations

from smpc_gc.channel import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    Channel,
    ChannelFactory,
    open_channel,
)
from smpc_gc.types import RegionResult, ThresholdProblem
from smpc_gc.yao import (
    build_threshold_circuit,
    run_evaluator,
    run_garbler,
    run_yao_2pc,
)
from smpc_gc.yao.ot import DEFAULT_GROUP, DHGroup

#: Human-readable name of the technique, for CLI banners and reports.
TECHNIQUE = "Yao's Garbled Circuits + Oblivious Transfer (from scratch)"


def evaluate_threshold(
    problem: ThresholdProblem,
    *,
    party: int | None = None,
    group: DHGroup = DEFAULT_GROUP,
    channel_factory: ChannelFactory | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> list[RegionResult]:
    """Securely evaluate ``problem`` and return the revealed results.

    Args:
        problem: the fully specified problem (see :class:`ThresholdProblem`).
        party: ``None`` for a single-process local simulation holding both share
            vectors; ``0`` or ``1`` to act as that party in a distributed run.
        group: the Diffie-Hellman group the Oblivious Transfer runs in.
        channel_factory: transport for a distributed run; defaults to the
            built-in socket rendezvous on ``host:port``.
        host: rendezvous host for the default transport.
        port: rendezvous port for the default transport.

    Returns:
        One :class:`RegionResult` per region, in region order.  The revealed
        output is identical for both parties -- the threshold outcome is a
        public result broadcast to all.
    """
    problem.validate(party=party)
    if party is None:
        return _run_local(problem, group)

    factory = channel_factory or (lambda p: open_channel(p, host, port))
    return _run_distributed(problem, party, group, factory)


# --- local simulation (both shares held here) -------------------------------


def _run_local(problem: ThresholdProblem, group: DHGroup) -> list[RegionResult]:
    results: list[RegionResult] = []
    for j, region_id in enumerate(problem.region_ids):
        a_val = problem.a_shares[j]
        b_val = problem.b_shares[j]
        _check_fits(a_val, problem.bit_length, "A", j)
        _check_fits(b_val, problem.bit_length, "B", j)

        circuit = _region_circuit(problem, region_id)
        output_bits = run_yao_2pc(
            circuit,
            _bits_on_wires(a_val, circuit.garbler_input_wires),
            _bits_on_wires(b_val, circuit.evaluator_input_wires),
            group,
        )
        results.append(_region_result(problem, j, region_id, output_bits))
    return results


# --- genuine two-process run (each party holds only its own share) ----------


def _run_distributed(
    problem: ThresholdProblem,
    party: int,
    group: DHGroup,
    channel_factory: ChannelFactory,
) -> list[RegionResult]:
    channel = channel_factory(party)
    try:
        results: list[RegionResult] = []
        for j, region_id in enumerate(problem.region_ids):
            circuit = _region_circuit(problem, region_id)
            output_bits = _run_region_party(problem, j, circuit, party, channel, group)
            results.append(_region_result(problem, j, region_id, output_bits))
        return results
    finally:
        channel.close()


def _run_region_party(
    problem: ThresholdProblem,
    j: int,
    circuit,
    party: int,
    channel: Channel,
    group: DHGroup,
) -> list[int]:
    if party == 0:
        a_val = problem.a_shares[j]
        _check_fits(a_val, problem.bit_length, "A", j)
        bits = _bits_on_wires(a_val, circuit.garbler_input_wires)
        return run_garbler(circuit, bits, channel, group)

    b_val = problem.b_shares[j]
    _check_fits(b_val, problem.bit_length, "B", j)
    bits = _bits_on_wires(b_val, circuit.evaluator_input_wires)
    return run_evaluator(circuit, bits, channel, group)


# --- helpers ----------------------------------------------------------------


def _region_circuit(problem: ThresholdProblem, region_id: int):
    """The public circuit for one region -- built identically by both parties."""
    return build_threshold_circuit(
        bit_length=problem.bit_length,
        threshold=problem.threshold,
        region_id=region_id,
        clear_token=problem.clear_token,
        modulus=problem.modulus,
    )


def _region_result(
    problem: ThresholdProblem, j: int, region_id: int, output_bits: list[int]
) -> RegionResult:
    revealed = _bits_to_int(output_bits)
    return RegionResult(
        region_index=j,
        region_id=region_id,
        revealed=revealed,
        crossed=revealed != problem.clear_token,
    )


def _bits_on_wires(value: int, wires: tuple[int, ...]) -> dict[int, int]:
    """Map each wire to bit ``i`` of ``value`` (little-endian)."""
    return {w: (value >> i) & 1 for i, w in enumerate(wires)}


def _bits_to_int(bits: list[int]) -> int:
    out = 0
    for i, bit in enumerate(bits):
        out |= (bit & 1) << i
    return out


def _check_fits(value: int, bit_length: int, name: str, region: int) -> None:
    if value < 0 or value >= (1 << bit_length):
        raise ValueError(
            f"{name} share {value} for region {region} does not fit in "
            f"{bit_length} bits; increase --bit-length"
        )

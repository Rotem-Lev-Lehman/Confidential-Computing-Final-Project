"""Backend that runs the from-scratch Yao's Garbled Circuits engine.

Unlike the MPyC backend (which delegates to an existing SMPC framework), this
backend uses the garbling, Oblivious Transfer and protocol code implemented in
:mod:`smpc_gc.yao`.  It is the actual cryptographic realization of the
threshold check.

For each region it runs one independent 2PC instance: the garbler holds that
region's ``A`` share, the evaluator holds ``B``, and together they reveal
``region_id`` iff ``A + B > threshold`` (else the ``Clear`` sentinel).

Run modes (``party``):

* ``None`` — **local simulation.** One process holds both share vectors and
  drives the garbler and evaluator against each other over an in-process socket
  pair (see :func:`~smpc_gc.yao.protocol.run_yao_2pc`).  Handy for demos and the
  plaintext cross-check; still never lets one call hold both parties' secrets.
* ``0`` / ``1`` — **genuine two-process run.**  Two separate processes each hold
  only their own share vector and talk over the shared
  :mod:`smpc_gc.channel` transport:

      party 0 (garbler)   binds ``host:port`` and waits for the evaluator;
      party 1 (evaluator) connects to it.

  Pass a custom ``channel_factory`` (any :data:`~smpc_gc.channel.ChannelFactory`)
  to carry the protocol over a different transport — e.g. Student A's
  networking layer — without touching the crypto.
"""

from __future__ import annotations

from smpc_gc.channel import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    Channel,
    ChannelFactory,
    open_channel,
)
from smpc_gc.interface import ThresholdBackend
from smpc_gc.types import RegionResult, ThresholdProblem
from smpc_gc.yao import (
    build_threshold_circuit,
    run_evaluator,
    run_garbler,
    run_yao_2pc,
)
from smpc_gc.yao.ot import DEFAULT_GROUP, DHGroup


class YaoBackend(ThresholdBackend):
    name = "yao"
    technique = "Yao's Garbled Circuits + Oblivious Transfer (from scratch)"

    def __init__(
        self,
        group: DHGroup = DEFAULT_GROUP,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        channel_factory: ChannelFactory | None = None,
    ) -> None:
        self.group = group
        self.host = host
        self.port = port
        # The transport swap point: defaults to the built-in socket stub.
        self.channel_factory: ChannelFactory = channel_factory or (
            lambda party: open_channel(party, self.host, self.port)
        )

    def availability(self) -> tuple[bool, str]:
        # Pure Python (hashlib + secrets + sockets); always runnable.
        return True, ""

    def evaluate(
        self, problem: ThresholdProblem, *, party: int | None = None
    ) -> list[RegionResult]:
        problem.validate(party=party)
        if party is None:
            return self._run_local(problem)
        return self._run_distributed(problem, party)

    # --- local simulation (both shares held here) ---------------------------

    def _run_local(self, problem: ThresholdProblem) -> list[RegionResult]:
        results: list[RegionResult] = []
        for j, region_id in enumerate(problem.region_ids):
            a_val = problem.a_shares[j]
            b_val = problem.b_shares[j]
            _check_fits(a_val, problem.bit_length, "A", j)
            _check_fits(b_val, problem.bit_length, "B", j)

            circuit = _region_circuit(problem, region_id)
            garbler_bits = _bits_on_wires(a_val, circuit.garbler_input_wires)
            evaluator_bits = _bits_on_wires(b_val, circuit.evaluator_input_wires)

            output_bits = run_yao_2pc(
                circuit, garbler_bits, evaluator_bits, self.group
            )
            results.append(_region_result(problem, j, region_id, output_bits))
        return results

    # --- genuine two-process run (each party holds only its own share) ------

    def _run_distributed(
        self, problem: ThresholdProblem, party: int
    ) -> list[RegionResult]:
        channel = self.channel_factory(party)
        try:
            results: list[RegionResult] = []
            for j, region_id in enumerate(problem.region_ids):
                circuit = _region_circuit(problem, region_id)
                output_bits = self._run_region_party(
                    problem, j, region_id, circuit, party, channel
                )
                results.append(_region_result(problem, j, region_id, output_bits))
            return results
        finally:
            channel.close()

    def _run_region_party(
        self,
        problem: ThresholdProblem,
        j: int,
        region_id: int,
        circuit,
        party: int,
        channel: Channel,
    ) -> list[int]:
        if party == 0:
            a_val = problem.a_shares[j]
            _check_fits(a_val, problem.bit_length, "A", j)
            bits = _bits_on_wires(a_val, circuit.garbler_input_wires)
            return run_garbler(circuit, bits, channel, self.group)

        b_val = problem.b_shares[j]
        _check_fits(b_val, problem.bit_length, "B", j)
        bits = _bits_on_wires(b_val, circuit.evaluator_input_wires)
        return run_evaluator(circuit, bits, channel, self.group)


def _region_circuit(problem: ThresholdProblem, region_id: int):
    """The public circuit for one region — built identically by both parties."""
    return build_threshold_circuit(
        bit_length=problem.bit_length,
        threshold=problem.threshold,
        region_id=region_id,
        clear_token=problem.clear_token,
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

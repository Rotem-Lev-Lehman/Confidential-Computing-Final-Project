"""Yao's garbling scheme: free-XOR + point-and-permute.

Each wire carries two 128-bit *labels*, one per truth value.  We use the two
standard optimizations:

* **Free-XOR** — a single global secret offset ``R`` (with ``lsb(R) = 1``) is
  fixed for the whole circuit and every wire satisfies ``label1 = label0 XOR R``.
  An XOR gate then needs no garbled table at all: the evaluator just XORs the two
  input labels it holds.
* **Point-and-permute** — the least-significant bit of a label is its public
  *select bit*.  The two labels of a wire have complementary select bits (because
  ``lsb(R) = 1``), so the evaluator can index directly into the 4-row AND table
  without learning the underlying truth value.

Only the garbler ever knows ``R`` or the ``label0`` values, so the evaluator can
decrypt exactly one row per AND gate and nothing more.  NOT/OR were compiled
away into XOR+AND in :mod:`smpc_gc.yao.circuit`, so the evaluator only needs to
XOR labels or decrypt an AND row — never anything requiring ``R``.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from smpc_gc.yao.circuit import AND, XOR, Circuit

LABEL_BITS = 128
LABEL_BYTES = LABEL_BITS // 8


def _rand_label() -> int:
    return secrets.randbits(LABEL_BITS)


def _H(gate_id: int, label_a: int, label_b: int) -> int:
    """Gate-encryption hash H(gid, Wa, Wb) -> 128-bit label mask.

    Keyed by a per-gate id so identical input labels in different gates give
    independent masks (a tweakable-hash style construction).
    """
    data = (
        gate_id.to_bytes(4, "big")
        + label_a.to_bytes(LABEL_BYTES, "big")
        + label_b.to_bytes(LABEL_BYTES, "big")
    )
    return int.from_bytes(hashlib.sha256(data).digest()[:LABEL_BYTES], "big")


@dataclass
class GarbledCircuit:
    """Everything the garbler sends to the evaluator (public transcript).

    It deliberately contains no ``label0`` values and not ``R``: the evaluator's
    own input labels arrive separately via Oblivious Transfer, so this message
    leaks nothing about either party's inputs.
    """

    circuit: Circuit
    and_tables: dict[int, list[int]]  # gate index -> 4 ciphertext labels
    garbler_input_labels: dict[int, int]  # wire -> active label for A's bit
    constant_labels: dict[int, int]  # wire -> active label for the fixed bit
    output_decoding: dict[int, int]  # output wire -> select bit of its 0-label


def garble(
    circuit: Circuit, garbler_bits: dict[int, int]
) -> tuple[GarbledCircuit, dict[int, tuple[int, int]]]:
    """Garble ``circuit`` given the garbler's private input bits.

    Args:
        circuit: the (public) boolean circuit.
        garbler_bits: wire -> bit for each ``garbler_input_wires`` entry.

    Returns:
        ``(garbled, evaluator_label_pairs)`` where ``garbled`` is the message for
        the evaluator and ``evaluator_label_pairs`` maps each evaluator input
        wire to its ``(label_for_0, label_for_1)`` pair — the garbler's private
        OT inputs, never sent directly.
    """
    delta = _rand_label() | 1  # global free-XOR offset, lsb = 1
    zero_label: dict[int, int] = {}  # wire -> label representing bit 0

    # Garbler's own inputs: reveal only the active label for the known bit.
    garbler_input_labels: dict[int, int] = {}
    for w in circuit.garbler_input_wires:
        zero_label[w] = _rand_label()
        bit = garbler_bits[w]
        garbler_input_labels[w] = zero_label[w] ^ (delta if bit else 0)

    # Constant wires: the active label for the fixed public bit.
    constant_labels: dict[int, int] = {}
    for w, value in circuit.constant_wires.items():
        zero_label[w] = _rand_label()
        constant_labels[w] = zero_label[w] ^ (delta if value else 0)

    # Evaluator's inputs: both labels; the evaluator picks one by OT.
    evaluator_label_pairs: dict[int, tuple[int, int]] = {}
    for w in circuit.evaluator_input_wires:
        zero_label[w] = _rand_label()
        evaluator_label_pairs[w] = (zero_label[w], zero_label[w] ^ delta)

    # Gates in topological order.
    and_tables: dict[int, list[int]] = {}
    for gid, gate in enumerate(circuit.gates):
        a0 = zero_label[gate.in0]
        b0 = zero_label[gate.in1]
        if gate.op == XOR:
            zero_label[gate.out] = a0 ^ b0  # free
        elif gate.op == AND:
            out0 = _rand_label()
            zero_label[gate.out] = out0
            table = [0, 0, 0, 0]
            for av in (0, 1):
                for bv in (0, 1):
                    a_lbl = a0 ^ (delta if av else 0)
                    b_lbl = b0 ^ (delta if bv else 0)
                    row = ((a_lbl & 1) << 1) | (b_lbl & 1)  # point-and-permute
                    out_val = av & bv
                    out_lbl = out0 ^ (delta if out_val else 0)
                    table[row] = _H(gid, a_lbl, b_lbl) ^ out_lbl
            and_tables[gid] = table
        else:  # pragma: no cover - circuit only emits XOR/AND
            raise ValueError(f"unknown gate op {gate.op!r}")

    output_decoding = {w: zero_label[w] & 1 for w in circuit.output_wires}

    garbled = GarbledCircuit(
        circuit=circuit,
        and_tables=and_tables,
        garbler_input_labels=garbler_input_labels,
        constant_labels=constant_labels,
        output_decoding=output_decoding,
    )
    return garbled, evaluator_label_pairs


def evaluate(
    garbled: GarbledCircuit, evaluator_input_labels: dict[int, int]
) -> list[int]:
    """Evaluate a garbled circuit and return the output bits (little-endian).

    The evaluator holds one active label per wire and never learns ``R`` or any
    inactive label.
    """
    circuit = garbled.circuit
    active: dict[int, int] = {}
    active.update(garbled.garbler_input_labels)
    active.update(garbled.constant_labels)
    active.update(evaluator_input_labels)

    for gid, gate in enumerate(circuit.gates):
        a = active[gate.in0]
        b = active[gate.in1]
        if gate.op == XOR:
            active[gate.out] = a ^ b  # free-XOR: just combine labels
        else:  # AND: decrypt the row selected by the two select bits
            row = ((a & 1) << 1) | (b & 1)
            ciphertext = garbled.and_tables[gid][row]
            active[gate.out] = ciphertext ^ _H(gid, a, b)

    # Decode: recover each output bit from its label's select bit.
    return [
        (active[w] & 1) ^ garbled.output_decoding[w] for w in circuit.output_wires
    ]

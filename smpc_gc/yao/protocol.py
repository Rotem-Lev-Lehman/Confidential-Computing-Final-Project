"""The two-party protocol: Garbler (party 0) and Evaluator (party 1).

Each party runs in its **own process** and holds only its own secret bits.  They
exchange messages exclusively through the shared, swappable
:class:`~smpc_gc.channel.Channel`; neither ever sees the other's input.  The
cryptography is what keeps the inputs private:

    * the garbled circuit reveals nothing on its own (random labels only);
    * the garbler's input labels look random to the evaluator;
    * Oblivious Transfer hides the evaluator's bits from the garbler and hides
      the unchosen labels from the evaluator.

The message exchange, per region:

    1. garbler -> evaluator : the garbled circuit (tables + garbler/const labels
                              + output decoding)
    2. garbler -> evaluator : the OT sender's public key ``A``
    3. evaluator -> garbler : the OT choice values ``B`` (encode B's bits)
    4. garbler -> evaluator : the OT ciphertexts (encrypted label pairs)
    5. evaluator -> garbler : the decoded output bits (public result, broadcast)

Both parties build the *same* public circuit independently from the public
parameters (bit length, threshold, region id, clear token), so only the
secret-dependent garbled material has to cross the wire — never the circuit
topology.

:func:`run_yao_2pc` keeps the single-call convenience API for tests and the
local simulation: it spins the garbler up on a background thread connected to
the evaluator by a real socket pair, so even there no single call ever holds
both parties' secret bits.
"""

from __future__ import annotations

import threading

from smpc_gc.channel import Channel, local_pair
from smpc_gc.yao.circuit import Circuit
from smpc_gc.yao.garbling import (
    LABEL_BYTES,
    GarbledCircuit,
    evaluate,
    garble,
)
from smpc_gc.yao.ot import DEFAULT_GROUP, DHGroup, OTReceiver, OTSender


def _label_to_bytes(label: int) -> bytes:
    return label.to_bytes(LABEL_BYTES, "big")


def _bytes_to_label(data: bytes) -> int:
    return int.from_bytes(data, "big")


# --- (de)serialization of the messages that cross the channel ---------------
#
# The channel carries JSON, so int-keyed dicts become string-keyed and byte
# strings become hex.  These helpers translate at the boundary; both parties
# agree on the shapes.


def _serialize_garbled(garbled: GarbledCircuit) -> dict:
    """Pack the secret-dependent garbled material (not the public circuit)."""
    return {
        "and_tables": {str(k): v for k, v in garbled.and_tables.items()},
        "garbler_input_labels": {
            str(k): v for k, v in garbled.garbler_input_labels.items()
        },
        "constant_labels": {str(k): v for k, v in garbled.constant_labels.items()},
        "output_decoding": {str(k): v for k, v in garbled.output_decoding.items()},
    }


def _deserialize_garbled(circuit: Circuit, msg: dict) -> GarbledCircuit:
    """Rebuild the garbled circuit around the evaluator's own copy of ``circuit``."""

    def _int_keys(d: dict) -> dict:
        return {int(k): v for k, v in d.items()}

    return GarbledCircuit(
        circuit=circuit,
        and_tables=_int_keys(msg["and_tables"]),
        garbler_input_labels=_int_keys(msg["garbler_input_labels"]),
        constant_labels=_int_keys(msg["constant_labels"]),
        output_decoding=_int_keys(msg["output_decoding"]),
    )


def _serialize_ciphertexts(cts: list[tuple[bytes, bytes]]) -> list[list[str]]:
    return [[c0.hex(), c1.hex()] for c0, c1 in cts]


def _deserialize_ciphertexts(raw: list[list[str]]) -> list[tuple[bytes, bytes]]:
    return [(bytes.fromhex(c0), bytes.fromhex(c1)) for c0, c1 in raw]


# --- the two party halves ---------------------------------------------------


def run_garbler(
    circuit: Circuit,
    garbler_bits: dict[int, int],
    channel: Channel,
    group: DHGroup = DEFAULT_GROUP,
) -> list[int]:
    """Play the garbler (party 0) for one circuit over ``channel``.

    Holds only the garbler's bits (A); learns the evaluator's bits never.
    Returns the public output bits (little-endian), received back from the
    evaluator.
    """
    # Garble with the private A bits; keep the evaluator's label pairs local.
    garbled, evaluator_label_pairs = garble(circuit, garbler_bits)
    channel.send({"type": "garbled", **_serialize_garbled(garbled)})  # msg 1

    ev_wires = circuit.evaluator_input_wires
    ot_messages = [
        (
            _label_to_bytes(evaluator_label_pairs[w][0]),
            _label_to_bytes(evaluator_label_pairs[w][1]),
        )
        for w in ev_wires
    ]

    sender = OTSender(group)
    channel.send({"type": "ot_pubkey", "A": sender.public_key()})  # msg 2
    B_values = channel.recv()["B"]  # msg 3
    ciphertexts = sender.respond(B_values, ot_messages)
    channel.send(  # msg 4
        {"type": "ot_ciphertexts", "ct": _serialize_ciphertexts(ciphertexts)}
    )

    return channel.recv()["output"]  # msg 5 (evaluator broadcasts the result)


def run_evaluator(
    circuit: Circuit,
    evaluator_bits: dict[int, int],
    channel: Channel,
    group: DHGroup = DEFAULT_GROUP,
) -> list[int]:
    """Play the evaluator (party 1) for one circuit over ``channel``.

    Holds only the evaluator's bits (B); fetches its input-wire labels by OT so
    those bits stay private.  Returns the public output bits (little-endian).
    """
    garbled = _deserialize_garbled(circuit, channel.recv())  # msg 1
    ev_wires = circuit.evaluator_input_wires

    A = channel.recv()["A"]  # msg 2
    receiver = OTReceiver(A, group)
    ot_choices = [evaluator_bits[w] for w in ev_wires]
    B_values = receiver.choose(ot_choices)
    channel.send({"type": "ot_choice", "B": B_values})  # msg 3

    ciphertexts = _deserialize_ciphertexts(channel.recv()["ct"])  # msg 4
    chosen_labels = receiver.finalize(ciphertexts)
    evaluator_input_labels = {
        w: _bytes_to_label(chosen_labels[i]) for i, w in enumerate(ev_wires)
    }

    output_bits = evaluate(garbled, evaluator_input_labels)
    channel.send({"type": "output", "output": output_bits})  # msg 5
    return output_bits


def run_yao_2pc(
    circuit: Circuit,
    garbler_bits: dict[int, int],
    evaluator_bits: dict[int, int],
    group: DHGroup = DEFAULT_GROUP,
) -> list[int]:
    """Run both halves locally over a socket pair and return the output bits.

    Convenience wrapper for tests and the local simulation: the garbler runs on
    a background thread with *only* ``garbler_bits``, the evaluator runs here
    with *only* ``evaluator_bits``, and they talk over a real socket — a
    faithful rehearsal of the two-process protocol inside one process.

    Args:
        circuit: the public boolean circuit.
        garbler_bits: wire -> bit for the garbler's input wires (A).
        evaluator_bits: wire -> bit for the evaluator's input wires (B).
        group: the DH group used by the Oblivious Transfer.
    """
    garbler_side, evaluator_side = local_pair()
    error: list[BaseException] = []

    def _garble() -> None:
        try:
            run_garbler(circuit, garbler_bits, garbler_side, group)
        except BaseException as exc:  # re-raised on the caller's thread below
            error.append(exc)
        finally:
            garbler_side.close()

    thread = threading.Thread(target=_garble, name="yao-garbler")
    thread.start()
    try:
        with evaluator_side:
            output_bits = run_evaluator(circuit, evaluator_bits, evaluator_side, group)
    finally:
        thread.join()

    if error:
        raise error[0]
    return output_bits

"""Tests for the from-scratch Yao's Garbled Circuits + OT engine."""

from __future__ import annotations

import threading

import pytest

from smpc_gc import get_backend
from smpc_gc.backends.yao_backend import YaoBackend
from smpc_gc.channel import Listener, local_pair
from smpc_gc.types import CLEAR_TOKEN, ThresholdProblem
from smpc_gc.yao import (
    build_threshold_circuit,
    evaluate,
    garble,
    run_evaluator,
    run_garbler,
    run_yao_2pc,
)
from smpc_gc.yao.ot import GROUP_1024, GROUP_2048, OTReceiver, OTSender


# --- Oblivious Transfer -----------------------------------------------------


@pytest.mark.parametrize("group", [GROUP_1024, GROUP_2048])
def test_ot_receiver_gets_only_chosen_message(group):
    m = [(b"m0_______aaaa___", b"m1_______bbbb___"),
         (b"zero000000000000", b"one_111111111111")]
    for choices in ([0, 1], [1, 0], [0, 0], [1, 1]):
        sender = OTSender(group)
        receiver = OTReceiver(sender.public_key(), group)
        B = receiver.choose(choices)
        ct = sender.respond(B, m)
        got = receiver.finalize(ct)
        assert got == [m[i][c] for i, c in enumerate(choices)]


def test_ot_choice_bit_is_hidden_from_the_senders_view():
    """The sender sees only ``B``, which is uniform in <g> either way.

    ``B`` is ``g^b`` for c=0 and ``A*g^b`` for c=1; with ``b`` uniform, both are
    uniform over the subgroup, so the sender's view is independent of the choice
    bit.  Sampled here: the two distributions must be statistically
    indistinguishable, which we check by comparing how the values split around
    the midpoint of the group -- a real (if coarse) distinguishing test rather
    than a range check.
    """
    group = GROUP_1024
    sender = OTSender(group)
    trials = 400
    halves = {}
    for c in (0, 1):
        receiver = OTReceiver(sender.public_key(), group)
        values = receiver.choose([c] * trials)
        assert all(1 < B < group.p - 1 for B in values), "B left the valid range"
        assert len(set(values)) == trials, "B repeated -- b is not fresh per instance"
        halves[c] = sum(1 for B in values if B < group.p // 2) / trials
    # Both should sit near 0.5; a bit that leaked would skew one of them.
    assert abs(halves[0] - halves[1]) < 0.12, halves


def test_ot_rejects_a_sender_key_outside_the_subgroup():
    """S9: a bogus ``A`` could otherwise leak the receiver's choice bit."""
    group = GROUP_1024
    for bad in (1, group.p - 1, group.p, 0, group.g + 1):
        with pytest.raises(ValueError):
            OTReceiver(bad, group)


def test_ot_rejects_a_receiver_value_outside_the_subgroup():
    group = GROUP_1024
    sender = OTSender(group)
    with pytest.raises(ValueError):
        sender.respond([group.p - 1], [(b"0" * 16, b"1" * 16)])


def test_ot_rejects_a_truncated_ciphertext():
    """A short ciphertext must fail, not silently yield a short wire label."""
    group = GROUP_1024
    sender = OTSender(group)
    receiver = OTReceiver(sender.public_key(), group)
    B = receiver.choose([0])
    (ct0, ct1) = sender.respond(B, [(b"m0" * 8, b"m1" * 8)])[0]
    with pytest.raises(ValueError, match="length mismatch"):
        receiver.finalize([(ct0[:8], ct1)])


def test_ot_rejects_a_wrong_sized_batch():
    group = GROUP_1024
    sender = OTSender(group)
    receiver = OTReceiver(sender.public_key(), group)
    receiver.choose([0, 1])
    with pytest.raises(ValueError, match="expected 2"):
        receiver.finalize([(b"a" * 16, b"b" * 16)])


# --- garbling ---------------------------------------------------------------


def _bits(value: int, wires) -> dict[int, int]:
    return {w: (value >> i) & 1 for i, w in enumerate(wires)}


def _to_int(bits: list[int]) -> int:
    return sum(b << i for i, b in enumerate(bits))


def test_garble_evaluate_without_ot_matches_plaintext():
    # Drive garbling/evaluation directly (evaluator labels handed over in the
    # clear) to isolate the garbling scheme from the OT layer.
    circuit = build_threshold_circuit(bit_length=8, threshold=50, region_id=1007,
                                      clear_token=0)
    for a_val, b_val in [(30, 25), (25, 25), (0, 0), (100, 100), (49, 1), (49, 2)]:
        garbler_bits = _bits(a_val, circuit.garbler_input_wires)
        garbled, pairs = garble(circuit, garbler_bits)
        ev_bits = _bits(b_val, circuit.evaluator_input_wires)
        ev_labels = {w: pairs[w][ev_bits[w]] for w in circuit.evaluator_input_wires}
        out = _to_int(evaluate(garbled, ev_labels))
        assert out == (1007 if a_val + b_val > 50 else 0)


# --- full protocol ----------------------------------------------------------


def test_run_yao_2pc_boundary_cases():
    circuit = build_threshold_circuit(bit_length=8, threshold=50, region_id=42,
                                      clear_token=0)
    cases = {(26, 25): 42, (25, 25): 0, (25, 26): 42, (0, 0): 0, (60, 40): 42}
    for (a_val, b_val), expected in cases.items():
        out = run_yao_2pc(
            circuit,
            _bits(a_val, circuit.garbler_input_wires),
            _bits(b_val, circuit.evaluator_input_wires),
        )
        assert _to_int(out) == expected


# --- backend integration ----------------------------------------------------


def test_yao_backend_matches_plaintext():
    backend = get_backend("yao")
    problem = ThresholdProblem(
        threshold=50,
        region_ids=[1001, 1002, 1003, 1004],
        a_shares=[26, 25, 0, 100],
        b_shares=[25, 25, 0, 100],  # sums: 51(>), 50(=), 0, 200(>)
        bit_length=8,
    )
    results = backend.evaluate(problem)
    assert [r.revealed for r in results] == [1001, CLEAR_TOKEN, CLEAR_TOKEN, 1004]
    assert [r.crossed for r in results] == [True, False, False, True]


def test_yao_backend_rejects_share_overflow():
    backend = get_backend("yao")
    problem = ThresholdProblem(
        threshold=50, region_ids=[1001], a_shares=[999], b_shares=[1], bit_length=4
    )
    with pytest.raises(ValueError):
        backend.evaluate(problem)


# --- split garbler / evaluator over a channel -------------------------------


def test_protocol_rejects_an_out_of_sequence_message():
    """C5: the halves check the message type instead of reading a missing key."""
    from smpc_gc.yao.protocol import _expect

    class _Canned:
        def __init__(self, msg):
            self._msg = msg

        def recv(self):
            return self._msg

    assert _expect(_Canned({"type": "garbled", "x": 1}), "garbled")["x"] == 1
    with pytest.raises(ValueError, match="desynchronized"):
        _expect(_Canned({"type": "output"}), "garbled")
    with pytest.raises(ValueError, match="desynchronized"):
        _expect(_Canned("not a dict"), "garbled")


def test_garbler_and_evaluator_run_over_a_channel():
    # Each half sees only its own party's bits; they agree via the channel only.
    circuit = build_threshold_circuit(bit_length=8, threshold=50, region_id=42,
                                      clear_token=0)
    garbler_side, evaluator_side = local_pair()
    box: dict[str, list[int]] = {}

    def _garble():
        with garbler_side:
            box["g"] = run_garbler(
                circuit, _bits(26, circuit.garbler_input_wires), garbler_side
            )

    t = threading.Thread(target=_garble)
    t.start()
    with evaluator_side:
        ev_out = run_evaluator(
            circuit, _bits(25, circuit.evaluator_input_wires), evaluator_side
        )
    t.join()

    assert _to_int(ev_out) == 42  # 26 + 25 = 51 > 50
    assert box["g"] == ev_out  # both parties learn the same public result


def test_yao_backend_two_process_distributed_run():
    # Party 0 (garbler) holds only A, party 1 (evaluator) holds only B; they
    # meet on a real socket on an ephemeral port.
    region_ids = [1001, 1002, 1003, 1004]
    a_shares = [26, 25, 0, 100]
    b_shares = [25, 25, 0, 100]  # sums: 51(>), 50(=), 0, 200(>)
    # Bind up front so the evaluator can connect without a startup race.
    listener = Listener("127.0.0.1", 0)
    port = listener.port
    box: dict[str, list] = {}

    def _garbler():
        # Reuse the already-bound listener so the client can connect immediately.
        channel = listener.accept()
        try:
            results = []
            for j, rid in enumerate(region_ids):
                circuit = build_threshold_circuit(
                    bit_length=8, threshold=50, region_id=rid, clear_token=0
                )
                bits = _bits(a_shares[j], circuit.garbler_input_wires)
                results.append(_to_int(run_garbler(circuit, bits, channel)))
            box["g"] = results
        finally:
            channel.close()
            listener.close()

    t = threading.Thread(target=_garbler)
    t.start()
    try:
        evaluator = YaoBackend(port=port)
        evaluator_problem = ThresholdProblem(
            threshold=50, region_ids=region_ids, b_shares=b_shares, bit_length=8
        )
        results = evaluator._run_distributed(evaluator_problem, party=1)
    finally:
        t.join()

    assert [r.revealed for r in results] == [1001, CLEAR_TOKEN, CLEAR_TOKEN, 1004]
    assert box["g"] == [1001, CLEAR_TOKEN, CLEAR_TOKEN, 1004]

"""
test_gc_channel.py
==================
Integration test: run the partner's Yao Garbled Circuit engine over OUR
SIGMA-encrypted node transport, replacing its built-in socket stub.

Requires the GC layer on the path, e.g.:
    PYTHONPATH=/path/to/Confidential-Computing-Final-Project-feat-yaos_garbled_circuits:. \
        python3 test_gc_channel.py
"""

import queue
import threading
import time

from gc_channel import GC_KEY, NodeChannel, make_channel_factory


# --- unit tests for the adapter (no GC layer needed) -----------------------


class _FakeNode:
    """Minimal Node stand-in: records sends, exposes an inbox."""

    def __init__(self, node_id=1):
        self.node_id = node_id
        self.inbox = queue.Queue()
        self.sent = []

    def send(self, peer_id, message):
        self.sent.append((peer_id, message))


def test_send_wraps_with_gc_key():
    node = _FakeNode(node_id=1)
    ch = NodeChannel(node, peer_id=2)
    ch.send({"type": "garbled"})
    peer_id, msg = node.sent[0]
    assert peer_id == 2, f"sent to {peer_id}"
    assert msg[GC_KEY] == {"type": "garbled"}, msg
    assert msg["from"] == 1
    print("PASS: test_send_wraps_with_gc_key")


def test_recv_returns_unwrapped():
    node = _FakeNode()
    node.inbox.put({GC_KEY: {"A": 12345}, "from": 2})
    ch = NodeChannel(node, peer_id=2)
    assert ch.recv() == {"A": 12345}
    print("PASS: test_recv_returns_unwrapped")


def test_non_gc_messages_are_not_dropped():
    """The bug that deadlocked a node in a real run: foreign messages must survive."""
    node = _FakeNode()
    node.inbox.put({"shares": [1, 2, 3]})        # Phase 1 traffic
    node.inbox.put({"reduce": [4, 5, 6]})        # Phase 2 traffic
    node.inbox.put({GC_KEY: "mine", "from": 2})  # ours
    ch = NodeChannel(node, peer_id=2)

    assert ch.recv() == "mine"
    assert node.inbox.empty(), "holdover should not be back yet"
    ch.close()

    survivors = []
    while not node.inbox.empty():
        survivors.append(node.inbox.get())
    assert {"shares": [1, 2, 3]} in survivors, survivors
    assert {"reduce": [4, 5, 6]} in survivors, survivors
    print("PASS: test_non_gc_messages_are_not_dropped")


def test_recv_timeout_raises_clean_error():
    """A dead peer must raise, not hang forever."""
    node = _FakeNode()
    ch = NodeChannel(node, peer_id=2, recv_timeout=0.3)
    t0 = time.monotonic()
    try:
        ch.recv()
        assert False, "expected ConnectionError"
    except ConnectionError as exc:
        assert "died mid-session" in str(exc), str(exc)
    assert time.monotonic() - t0 < 3, "timeout did not fire promptly"
    print("PASS: test_recv_timeout_raises_clean_error")


def test_closed_channel_rejects_use():
    node = _FakeNode()
    ch = NodeChannel(node, peer_id=2)
    ch.close()
    for op in (lambda: ch.send({}), ch.recv):
        try:
            op()
            assert False, "expected ConnectionError on closed channel"
        except ConnectionError:
            pass
    print("PASS: test_closed_channel_rejects_use")


# --- end-to-end: real GC engine over the real encrypted transport ----------


def test_yao_over_encrypted_transport():
    """Run the partner's YaoBackend across two real SIGMA-encrypted nodes."""
    from node import Node
    from share_reduction import add_vectors, split_vector_for_two
    from gc_handoff import build_problem
    from smpc_gc.types import ThresholdProblem
    from smpc_gc.backends.yao_backend import YaoBackend
    from smpc_gc.yao.ot import GROUP_1024

    PSK = b"integration-test-psk"
    config = {1: {"host": "127.0.0.1", "port": 9401},
              2: {"host": "127.0.0.1", "port": 9402}}

    n1 = Node(1, config, PSK, num_nodes=2)
    n2 = Node(2, config, PSK, num_nodes=2)
    n1.start_listener()
    n2.start_listener()
    time.sleep(0.4)

    t = threading.Thread(target=lambda: n2.connect_to_peer(1), daemon=True)
    t.start()
    n1.connect_to_peer(2)
    t.join()
    time.sleep(0.4)

    # Two nodes contribute local counts; region totals: 62 (cross) and 40 (clear)
    locals_ = {1: [40, 25], 2: [22, 15]}
    true_counts = [62, 40]
    a_parts, b_parts = [], []
    for nid in (1, 2):
        av, bv = split_vector_for_two(locals_[nid])
        a_parts.append(av)
        b_parts.append(bv)
    A, B = add_vectors(a_parts), add_vectors(b_parts)

    region_ids = [1001, 1002]
    pa = build_problem(party=0, shares=A, region_ids=region_ids,
                       threshold=50, num_nodes=2)

    results = {}
    errors = []

    def run(node, peer_id, party, shares):
        try:
            prob = ThresholdProblem(
                threshold=pa["threshold"], region_ids=region_ids,
                a_shares=shares if party == 0 else None,
                b_shares=shares if party == 1 else None,
                bit_length=pa["bit_length"],
            )
            backend = YaoBackend(
                group=GROUP_1024,
                channel_factory=make_channel_factory(node, peer_id),
            )
            results[party] = backend.evaluate(prob, party=party)
        except BaseException as exc:  # surfaced on the main thread below
            errors.append(exc)

    th = threading.Thread(target=run, args=(n1, 2, 0, A), daemon=True)
    th.start()
    run(n2, 1, 1, B)
    th.join(timeout=600)

    if errors:
        raise errors[0]

    assert 0 in results and 1 in results, f"missing party results: {sorted(results)}"
    for party in (0, 1):
        for r, t_count in zip(results[party], true_counts):
            expected = t_count > 50
            assert r.crossed == expected, (
                f"party {party} region {r.region_id}: true={t_count} "
                f"crossed={r.crossed}, expected {expected}"
            )
    assert [r.revealed for r in results[0]] == [r.revealed for r in results[1]], \
        "the two parties disagree on the public result"

    print("PASS: test_yao_over_encrypted_transport")
    for r, t_count in zip(results[0], true_counts):
        print(f"      region {r.region_id}: true={t_count:3d} -> "
              f"revealed={r.revealed:5d} ({r.status})")


if __name__ == "__main__":
    test_send_wraps_with_gc_key()
    test_recv_returns_unwrapped()
    test_non_gc_messages_are_not_dropped()
    test_recv_timeout_raises_clean_error()
    test_closed_channel_rejects_use()
    test_yao_over_encrypted_transport()
    print("\nAll gc_channel tests passed.")

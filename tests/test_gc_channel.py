"""
test_gc_channel.py
==================
Integration: run the Yao Garbled Circuit engine over OUR SIGMA-encrypted node
transport, replacing its built-in socket stub.

This is the seam between the two halves of the project (see ``division.md``):
Student A's networking layer carrying Student B's 2PC protocol, with neither
side modified.
"""

from __future__ import annotations

import queue
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gc_channel import GC_PHASE, NodeChannel, make_channel_factory
from node import TransportError
from sigma_handshake import generate_identity_keypair


# --- unit tests for the adapter (no real network needed) --------------------


class _FakeNode:
    """Minimal Node stand-in: records sends, serves canned receives."""

    def __init__(self, node_id: int = 1) -> None:
        self.node_id = node_id
        self.sent: list[tuple[int, str, object]] = []
        self._incoming: queue.Queue = queue.Queue()

    def send(self, peer_id, phase, payload):
        self.sent.append((peer_id, phase, payload))

    def offer(self, sender, payload):
        self._incoming.put((sender, payload))

    def recv(self, phase, timeout=None, sender=None):
        assert phase == GC_PHASE
        try:
            return self._incoming.get(timeout=0.2)
        except queue.Empty:
            raise TransportError("timed out waiting for an expected message") from None


def test_send_is_tagged_with_the_gc_phase():
    node = _FakeNode(node_id=1)
    NodeChannel(node, peer_id=2).send({"type": "garbled"})
    assert node.sent == [(2, GC_PHASE, {"type": "garbled"})]


def test_recv_unwraps_the_payload():
    node = _FakeNode()
    node.offer(2, {"A": 12345})
    assert NodeChannel(node, peer_id=2).recv() == {"A": 12345}


def test_recv_translates_a_transport_timeout_into_connectionerror():
    """The GC backend only knows about ConnectionError, so we translate."""
    channel = NodeChannel(_FakeNode(), peer_id=2)
    with pytest.raises(ConnectionError):
        channel.recv()


def test_closed_channel_rejects_use():
    channel = NodeChannel(_FakeNode(), peer_id=2)
    channel.close()
    with pytest.raises(ConnectionError):
        channel.send({})
    with pytest.raises(ConnectionError):
        channel.recv()


def test_factory_ignores_the_party_argument():
    node = _FakeNode()
    factory = make_channel_factory(node, peer_id=2)
    assert isinstance(factory(0), NodeChannel)
    assert isinstance(factory(1), NodeChannel)


# --- end-to-end: real GC engine over the real encrypted transport ----------


def test_yao_over_encrypted_transport():
    """Run the YaoBackend across two real SIGMA-authenticated nodes."""
    from gc_handoff import build_problem
    from node import Node
    from secure_sum import compute_local_shares, local_sum
    from share_reduction import consolidate
    from smpc_gc.backends.yao_backend import YaoBackend
    from smpc_gc.yao.ot import GROUP_1024

    p = 1048573
    node_ids = [1, 2]

    # Per-node identity keys: no shared secret anywhere.
    keys, config = {}, {}
    for nid, port in ((1, 9401), (2, 9402)):
        priv_raw, pub_raw = generate_identity_keypair()
        keys[nid] = Ed25519PrivateKey.from_private_bytes(priv_raw)
        config[nid] = {"host": "127.0.0.1", "port": port, "public_key": pub_raw.hex()}

    n1 = Node(1, config, keys[1], num_nodes=2, log=lambda _m: None)
    n2 = Node(2, config, keys[2], num_nodes=2, log=lambda _m: None)
    try:
        n1.start_listener()
        n2.start_listener()
        time.sleep(0.4)
        t = threading.Thread(target=lambda: n2.connect_to_peer(1), daemon=True)
        t.start()
        n1.connect_to_peer(2)
        t.join(timeout=30)
        time.sleep(0.3)

        # Phase 1 + Phase 2, in-process (the transport is what's under test).
        locals_ = {1: [40, 25], 2: [22, 15]}  # region totals: 62 (cross), 40 (clear)
        true_counts = [62, 40]
        all_sh = {n: compute_local_shares(locals_[n], p, node_ids) for n in node_ids}
        phase1 = {
            n: local_sum([all_sh[n][n]] + [all_sh[o][n] for o in node_ids if o != n], p)
            for n in node_ids
        }
        A, B = consolidate([phase1[1]], p), consolidate([phase1[2]], p)

        region_ids = [1001, 1002]
        results, errors = {}, []

        def run(node, peer_id, party, shares):
            try:
                problem = build_problem(
                    party=party, shares=shares, region_ids=region_ids,
                    threshold=50, p=p,
                )
                backend = YaoBackend(
                    group=GROUP_1024,
                    channel_factory=make_channel_factory(node, peer_id),
                )
                results[party] = backend.evaluate(problem, party=party)
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
            for r, count in zip(results[party], true_counts):
                assert r.crossed == (count > 50), (
                    f"party {party} region {r.region_id}: true={count}, "
                    f"crossed={r.crossed}"
                )
        assert [r.revealed for r in results[0]] == [r.revealed for r in results[1]], (
            "the two parties disagree on the public result"
        )
        # The sub-threshold region reveals the sentinel, never its count.
        assert results[0][1].revealed == 0
    finally:
        n1.close()
        n2.close()

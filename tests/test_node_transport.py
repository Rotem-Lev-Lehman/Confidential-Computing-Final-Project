"""
test_node_transport.py
======================
Security regression tests for the node-to-node transport.

These cover the properties the protocol *relies on* but that a happy-path test
would never notice: that a replayed message is rejected, that a peer cannot
contribute twice, that an oversized frame is refused before it is allocated,
and that a dead peer produces an error rather than a permanent hang.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from node import (
    MAX_FRAME_BYTES,
    Node,
    ProtocolError,
    TransportError,
    _recv_frame,
    _send_frame,
)
from secure_channel import ReplayError, decrypt_message, encrypt_message
from sigma_handshake import generate_identity_keypair

PHASE = "shares"


# --- AEAD: replay, reorder and cross-link rejection -------------------------


def test_roundtrip_at_the_right_position():
    key = bytes(range(32))
    wrapped = encrypt_message(key, b"hello", sender=1, receiver=2, seq=7)
    assert decrypt_message(key, wrapped, sender=1, receiver=2, seq=7) == b"hello"


def test_replay_at_a_different_position_is_rejected():
    """The core of S5: a captured message re-injected later must not authenticate."""
    key = bytes(range(32))
    wrapped = encrypt_message(key, b"shares", sender=1, receiver=2, seq=0)
    with pytest.raises(ReplayError):
        decrypt_message(key, wrapped, sender=1, receiver=2, seq=1)


def test_message_from_another_link_is_rejected():
    key = bytes(range(32))
    wrapped = encrypt_message(key, b"shares", sender=1, receiver=2, seq=0)
    with pytest.raises(ReplayError):
        decrypt_message(key, wrapped, sender=3, receiver=2, seq=0)
    with pytest.raises(ReplayError):
        decrypt_message(key, wrapped, sender=1, receiver=4, seq=0)


def test_tampered_ciphertext_is_rejected():
    key = bytes(range(32))
    wrapped = encrypt_message(key, b"shares", sender=1, receiver=2, seq=0)
    raw = bytearray(bytes.fromhex(wrapped["ct"]))
    raw[0] ^= 0x01
    with pytest.raises(ReplayError):
        decrypt_message(key, {"ct": raw.hex()}, sender=1, receiver=2, seq=0)


def test_malformed_wrapper_is_rejected():
    with pytest.raises(ReplayError):
        decrypt_message(bytes(32), {"nope": "x"}, sender=1, receiver=2, seq=0)


# --- framing ----------------------------------------------------------------


def test_oversized_frame_is_refused_before_allocation():
    """S6: an unbounded length prefix must not become a memory allocation."""
    a, b = socket.socketpair()
    try:
        # Announce a huge frame but send no body; the reader must refuse on the
        # header alone rather than block waiting for gigabytes.
        a.sendall((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
        b.settimeout(5)
        with pytest.raises(TransportError, match="over the"):
            _recv_frame(b)
    finally:
        a.close()
        b.close()


def test_frame_roundtrip():
    a, b = socket.socketpair()
    try:
        _send_frame(a, b"payload")
        assert _recv_frame(b) == b"payload"
    finally:
        a.close()
        b.close()


def test_closed_peer_reads_as_end_of_stream():
    a, b = socket.socketpair()
    a.close()
    try:
        assert _recv_frame(b) is None
    finally:
        b.close()


# --- a real two-node mesh ---------------------------------------------------


def _free_ports(count):
    """Reserve ``count`` currently-free localhost ports.

    Nodes dial each other by the port in their shared config, so an ephemeral
    bind is not enough -- the numbers have to be known up front.  Probing beats
    hardcoding: a fixed port left in TIME_WAIT by the previous test makes the
    next one fail to bind.
    """
    socks = []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _make_nodes(node_ids):
    keys, config = {}, {}
    ports = _free_ports(len(node_ids))
    for offset, nid in enumerate(node_ids):
        priv_raw, pub_raw = generate_identity_keypair()
        keys[nid] = Ed25519PrivateKey.from_private_bytes(priv_raw)
        config[nid] = {
            "host": "127.0.0.1",
            "port": ports[offset],
            "public_key": pub_raw.hex(),
        }
    nodes = {
        nid: Node(nid, config, keys[nid], len(node_ids), recv_timeout=20.0, log=lambda _m: None)
        for nid in node_ids
    }
    for n in nodes.values():
        n.start_listener()
    time.sleep(0.3)

    threads = [
        threading.Thread(target=n.connect_to_peer, args=(peer,), daemon=True)
        for n in nodes.values()
        for peer in n.peers
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    time.sleep(0.3)
    return nodes


@pytest.fixture
def two_nodes():
    nodes = _make_nodes([1, 2])
    yield nodes
    for n in nodes.values():
        n.close()


def test_messages_arrive_with_the_authenticated_sender(two_nodes):
    """S4: the receiver learns who really sent it, not a self-declared field."""
    n1, n2 = two_nodes[1], two_nodes[2]
    n1.send(2, PHASE, {"shares": [1, 2, 3]})
    sender, payload = n2.recv(PHASE, timeout=15)
    assert sender == 1
    assert payload == {"shares": [1, 2, 3]}


def test_phases_never_consume_each_other(two_nodes):
    """A message for another phase is held aside, never dropped."""
    n1, n2 = two_nodes[1], two_nodes[2]
    n1.send(2, "gc", {"type": "garbled"})
    n1.send(2, PHASE, {"shares": [7]})

    # Ask for the *second* phase first; the first message must survive.
    sender, payload = n2.recv(PHASE, timeout=15)
    assert (sender, payload) == (1, {"shares": [7]})
    sender, payload = n2.recv("gc", timeout=15)
    assert (sender, payload) == (1, {"type": "garbled"})


def test_collect_rejects_a_peer_contributing_twice(two_nodes):
    """S4: one contribution per authenticated peer, enforced."""
    n1, n2 = two_nodes[1], two_nodes[2]
    n1.send(2, PHASE, {"shares": [1]})
    n1.send(2, PHASE, {"shares": [2]})
    time.sleep(0.5)
    with pytest.raises(ProtocolError, match="two"):
        n2.collect(PHASE, [1, 3], timeout=5)


def test_collect_times_out_instead_of_hanging(two_nodes):
    """S7: a peer that never answers must raise, not block forever."""
    started = time.monotonic()
    with pytest.raises(TransportError, match="timed out"):
        two_nodes[2].collect(PHASE, [1], timeout=1.0)
    assert time.monotonic() - started < 15


def test_sending_without_a_session_is_refused(two_nodes):
    with pytest.raises(TransportError, match="no authenticated link"):
        two_nodes[1].send(99, PHASE, {"shares": []})


def test_unauthenticated_peer_cannot_inject_messages(two_nodes):
    """A stranger who can reach the port still gets nowhere without a key."""
    n2 = two_nodes[2]
    s = socket.create_connection(("127.0.0.1", n2.port), timeout=5)
    try:
        _send_frame(s, b'{"phase": "shares", "payload": {"shares": [666]}}')
        time.sleep(0.5)
    finally:
        s.close()
    # Nothing was accepted: the handshake never completed.
    with pytest.raises(TransportError):
        n2.recv(PHASE, timeout=1.0)

"""
gc_channel.py
=============
Adapter that lets the Garbled Circuit layer run over our SIGMA-encrypted
node-to-node transport instead of its own plain-socket stub.

WHY AN ADAPTER
--------------
The GC layer (``smpc_gc.channel.Channel``) expects a point-to-point object::

    send(obj) -> None      # one JSON-serializable message to *the* peer
    recv()    -> obj       # block until one message arrives
    close()   -> None

Our :class:`node.Node` has a different shape: it is a mesh endpoint, so its
``send`` names a peer and a protocol phase, and its receive side is keyed by the
*authenticated* sender.  :class:`NodeChannel` binds one peer and presents the
point-to-point view the GC layer wants, so ``smpc_gc``'s ``open_channel`` can be
swapped out with nothing else changing.

WHAT THIS BUYS THE GC LAYER
---------------------------
Everything sent through here inherits the transport's guarantees, so Phase 3
traffic (garbled tables, OT values) is protected exactly like Phase 1/2 traffic:

* AES-256-GCM under the SIGMA session key -- confidentiality and integrity;
* counter nonces + associated data -- replay and reordering are rejected;
* delivery keyed by the SIGMA-authenticated peer id, so the evaluator cannot be
  fed a garbled circuit by anyone other than the garbler it handshook with;
* phase tagging, so Phase 3 traffic can never be consumed by a Phase 1 or
  Phase 2 collector (and vice versa) -- a bug that really did deadlock a node
  during development.

Message routing, hold-aside and timeouts all live in :class:`node.Node` now, so
this adapter is a thin binding rather than a second inbox implementation.
"""

from __future__ import annotations

from node import TransportError

#: Phase tag for Phase 3 (Garbled Circuit) traffic.  Distinct from Phase 1's
#: ``"shares"`` and Phase 2's ``"reduce"`` so no phase can consume another's.
GC_PHASE = "gc"


class NodeChannel:
    """A GC-layer :class:`Channel` backed by one peer link of a :class:`Node`.

    Args:
        node: the local :class:`node.Node` (already connected and
            SIGMA-handshaken with ``peer_id``).
        peer_id: the node id of the other party in this 2PC session.
        recv_timeout: seconds to block in :meth:`recv` before raising; ``None``
            uses the node's default.
    """

    def __init__(self, node, peer_id: int, recv_timeout: float | None = None) -> None:
        self._node = node
        self._peer_id = peer_id
        self._timeout = recv_timeout
        self._closed = False

    # --- Channel protocol ---------------------------------------------------

    def send(self, obj) -> None:
        """Send one message to the bound peer."""
        if self._closed:
            raise ConnectionError("channel is closed")
        self._node.send(self._peer_id, GC_PHASE, obj)

    def recv(self):
        """Block until a Phase 3 message arrives from the bound peer.

        Raises:
            ConnectionError: if nothing arrives in time -- the peer most likely
                died mid-session.  This matches the error the GC layer's own
                socket channel raises, so the backend needs no special case.
        """
        if self._closed:
            raise ConnectionError("channel is closed")
        try:
            _sender, payload = self._node.recv(
                GC_PHASE, timeout=self._timeout, sender=self._peer_id
            )
        except TransportError as exc:
            raise ConnectionError(str(exc)) from None
        return payload

    def close(self) -> None:
        """Mark the channel closed.

        The underlying sockets are owned by the :class:`Node` and stay open --
        other phases and peers may still be using them.
        """
        self._closed = True

    # --- context manager convenience ---------------------------------------

    def __enter__(self) -> "NodeChannel":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def make_channel_factory(node, peer_id: int, recv_timeout: float | None = None):
    """Build a ``ChannelFactory`` for the GC backend.

    ``smpc_gc``'s backends call ``channel_factory(party)`` to obtain their
    channel.  Our channel does not depend on the party number -- the peer is
    already fixed by ``peer_id`` -- so the argument is accepted and ignored.

    Usage::

        backend = YaoBackend(channel_factory=make_channel_factory(node, peer_id))
        results = backend.evaluate(problem, party=party)
    """

    def factory(_party: int) -> NodeChannel:
        return NodeChannel(node, peer_id, recv_timeout)

    return factory

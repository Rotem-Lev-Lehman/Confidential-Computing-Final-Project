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

Our :class:`node.Node` has a different shape: ``send(peer_id, obj)`` (it talks
to three peers, not one) and a single shared ``inbox`` queue fed by every peer
and every protocol phase.  :class:`NodeChannel` binds one peer id and presents
the point-to-point view the GC layer wants, so ``smpc_gc``'s ``open_channel``
can be swapped out with nothing else changing.

Everything sent through here inherits the transport's AES-GCM encryption under
the SIGMA session key, so the Phase 3 traffic (garbled tables, OT values) is
protected exactly like the Phase 1/2 traffic.

TWO PROBLEMS THIS SOLVES
------------------------
1. **Message tagging.**  The inbox is shared across peers and phases.  A Phase 1
   collector that sees a message it does not recognize and simply drops it will
   silently destroy another phase's traffic -- we hit exactly this bug in a real
   4-process run (a Phase 2 message was swallowed by the Phase 1 collector and
   the node deadlocked).  Phase 3 traffic therefore carries its own key,
   :data:`GC_KEY`, and anything else this channel pulls off the inbox is held
   aside and put back rather than discarded.

2. **Mid-session drop.**  ``queue.Queue.get()`` blocks forever, so if the peer
   process dies mid-protocol the run hangs with no diagnostic.  :meth:`recv`
   takes a timeout and raises :class:`ConnectionError` instead, matching the
   error the GC layer's own socket channel raises when a peer disappears.
"""

from __future__ import annotations

import queue

#: Inbox key for Phase 3 (Garbled Circuit) traffic.  Distinct from Phase 1's
#: ``"shares"`` and Phase 2's ``"reduce"`` so no phase can consume another's.
GC_KEY = "gc"

#: Seconds to wait for a message before declaring the peer gone.  Generous by
#: default: a garbled circuit for a wide `bit_length` takes a while to build and
#: transmit, and base OT does a modular exponentiation per input bit.
DEFAULT_RECV_TIMEOUT = 300.0


class NodeChannel:
    """A GC-layer :class:`Channel` backed by one peer link of a :class:`Node`.

    Args:
        node: the local :class:`node.Node` (already connected and
            SIGMA-handshaken with ``peer_id``).
        peer_id: the node id of the other party in this 2PC session.
        recv_timeout: seconds to block in :meth:`recv` before raising.
    """

    def __init__(self, node, peer_id: int, recv_timeout: float = DEFAULT_RECV_TIMEOUT):
        self._node = node
        self._peer_id = peer_id
        self._timeout = recv_timeout
        # Messages pulled off the shared inbox that are not ours. Kept here and
        # returned to the inbox on close() so no other phase loses traffic.
        self._holdover: list = []
        self._closed = False

    # --- Channel protocol ---------------------------------------------------

    def send(self, obj) -> None:
        """Send one message to the bound peer, wrapped so it is identifiable."""
        if self._closed:
            raise ConnectionError("channel is closed")
        self._node.send(self._peer_id, {GC_KEY: obj, "from": self._node.node_id})

    def recv(self):
        """Block until a Phase 3 message arrives from the peer, and return it.

        Non-GC messages are held aside (see :attr:`_holdover`), never dropped.

        Raises:
            ConnectionError: if nothing arrives within ``recv_timeout`` -- the
                peer most likely died mid-session.
        """
        if self._closed:
            raise ConnectionError("channel is closed")
        while True:
            try:
                msg = self._node.inbox.get(timeout=self._timeout)
            except queue.Empty:
                raise ConnectionError(
                    f"no message from peer {self._peer_id} within "
                    f"{self._timeout:.0f}s; the peer appears to have died mid-session"
                ) from None
            if isinstance(msg, dict) and GC_KEY in msg:
                return msg[GC_KEY]
            self._holdover.append(msg)

    def close(self) -> None:
        """Return any held-aside messages to the inbox and mark closed.

        The underlying socket is owned by the :class:`Node` and stays open --
        other phases and peers may still be using it.
        """
        if self._closed:
            return
        self._closed = True
        for msg in self._holdover:
            self._node.inbox.put(msg)
        self._holdover.clear()

    # --- context manager convenience ---------------------------------------

    def __enter__(self) -> "NodeChannel":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def make_channel_factory(node, peer_id: int, recv_timeout: float = DEFAULT_RECV_TIMEOUT):
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

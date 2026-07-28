"""The shared message-passing transport between the two parties.

The 2PC protocol never touches sockets directly: everything that moves between
party 0 and party 1 goes through the :class:`Channel` protocol defined here.
The two parties run in **separate processes** and never share memory; every
value one needs from the other crosses a ``Channel``.

This module ships a simple, self-contained socket implementation so the two
parties can talk out of the box.  It is deliberately a thin placeholder: the
project's networking layer (Student A's P2P / secure-summation transport) can
replace it by providing any object with the same ``send(obj)`` / ``recv()`` /
``close()`` interface — nothing else in the project has to change.
:func:`open_channel` is the single integration point: swap its body (or inject
a different factory to ``evaluate_threshold``) to run the whole engine on
another transport -- which is exactly how the system carries 2PC traffic over
its SIGMA-authenticated, AES-GCM-encrypted mesh.

Wire format: each message is a JSON object, length-prefixed with a 4-byte
big-endian byte count.  JSON keeps the transcript human-inspectable and handles
Python's arbitrary-precision integers (DH group elements, 128-bit wire labels)
without loss; ``bytes`` payloads are hex-encoded by the protocol layer before
they get here.
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any, Callable, Protocol, runtime_checkable

_LENGTH_BYTES = 4

#: Default rendezvous address for a two-process run (party 0 binds, party 1
#: connects).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000


@runtime_checkable
class Channel(Protocol):
    """The transport contract the 2PC protocol depends on.

    Any object implementing these three methods can carry the protocol — the
    socket channel below, an in-memory pipe, or an external networking layer.
    """

    def send(self, obj: Any) -> None:
        """Send one JSON-serializable message to the peer."""

    def recv(self) -> Any:
        """Block until one message arrives from the peer and return it."""

    def close(self) -> None:
        """Release the underlying transport."""


class SocketChannel:
    """A :class:`Channel` over a connected stream socket (length-prefixed JSON)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def send(self, obj: Any) -> None:
        data = json.dumps(obj).encode("utf-8")
        self._sock.sendall(len(data).to_bytes(_LENGTH_BYTES, "big") + data)

    def recv(self) -> Any:
        header = self._recv_exactly(_LENGTH_BYTES)
        length = int.from_bytes(header, "big")
        return json.loads(self._recv_exactly(length).decode("utf-8"))

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def _recv_exactly(self, n: int) -> bytes:
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise ConnectionError(
                    "peer closed the connection mid-message "
                    f"(wanted {n} bytes, got {n - remaining})"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def __enter__(self) -> "SocketChannel":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class Listener:
    """A one-shot server socket: bind now, hand out a channel on ``accept``.

    Binding is separate from accepting so a caller can read :attr:`port` (useful
    with an ephemeral port ``0``) and hand it to the peer before blocking on the
    incoming connection.
    """

    def __init__(self, host: str, port: int) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(1)

    @property
    def port(self) -> int:
        return self._srv.getsockname()[1]

    def accept(self) -> SocketChannel:
        conn, _addr = self._srv.accept()
        return SocketChannel(conn)

    def close(self) -> None:
        try:
            self._srv.close()
        except OSError:
            pass


def connect(host: str, port: int, retry_timeout: float = 10.0) -> SocketChannel:
    """Open a channel to a :class:`Listener` at ``host:port``.

    Retries for up to ``retry_timeout`` seconds while the peer is not yet
    listening, so the two parties do not have to be started in a strict order.
    """
    deadline = time.monotonic() + retry_timeout
    while True:
        try:
            return SocketChannel(socket.create_connection((host, port)))
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


#: Anything that maps a party id (0 or 1) to a connected :class:`Channel`.
#: Backends take one of these; supply your own to run on a different transport.
ChannelFactory = Callable[[int], "Channel"]


def open_channel(
    party: int, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT
) -> Channel:
    """Open the party-to-party channel for a two-process run.

    Party 0 binds ``host:port`` and waits for the peer; party 1 connects to it.
    This is the **single swap point** for the transport: replace this factory
    (or pass a custom :data:`ChannelFactory` to ``evaluate_threshold``) to carry the
    protocol over the project's real networking layer instead of the built-in
    socket stub.
    """
    if party == 0:
        listener = Listener(host, port)
        try:
            return listener.accept()
        finally:
            listener.close()  # one-shot: the accepted connection stays alive
    if party == 1:
        return connect(host, port)
    raise ValueError(f"party must be 0 or 1, got {party!r}")


def local_pair() -> tuple[SocketChannel, SocketChannel]:
    """Two connected channels backed by an OS socket pair.

    Used to drive the garbler and evaluator over a real socket while they live
    in one process (each on its own thread) — a faithful in-process rehearsal of
    the genuine two-process run.
    """
    a, b = socket.socketpair()
    return SocketChannel(a), SocketChannel(b)

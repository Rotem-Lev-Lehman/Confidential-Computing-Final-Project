"""
node.py
=======
The P2P transport every protocol phase runs on: authenticated, encrypted,
replay-protected point-to-point links between the hospital nodes.

TOPOLOGY
--------
Static full mesh, hardcoded in ``config.json`` (per ``proposal.md`` §3).  Each
ordered pair of nodes gets its **own** link: node A's outbound connection to
node B is a separate socket, a separate SIGMA handshake and a separate session
key from B's outbound connection to A.  Keeping the two directions independent
is what lets the AEAD use a simple per-link counter (see
:mod:`secure_channel`).

WHAT ARRIVES ON THE INBOX
-------------------------
``(sender_id, phase, payload)`` triples, where ``sender_id`` is the id SIGMA
*authenticated* -- not a self-declared field in the message.  Every consumer
therefore knows who really sent what, and :meth:`Node.collect` can require
exactly one contribution per expected peer and reject duplicates.  An earlier
design dropped the authenticated id and counted messages instead, which meant
one node could supply several vectors and displace another's.

PHASES
------
Every message carries an explicit phase tag (``"shares"``, ``"reduce"``,
``"gc"``).  A message that does not match what the current caller is waiting for
is held aside on the node and re-offered later, never dropped -- a phase can
legitimately arrive early when a fast peer runs ahead.

DEFENSIVE LIMITS
----------------
The network is untrusted, so the pre-authentication surface is kept small:
length-prefixed frames with a hard size cap (an unbounded read is a one-line
memory-exhaustion DoS), socket timeouts, a cap on concurrent connections, and a
rule that each peer gets exactly one inbound session.  Failures close the
connection and log, rather than killing a thread silently and leaving every
other node blocked forever.
"""

from __future__ import annotations

import json
import queue
import socket
import sys
import threading
import time
from typing import Any, Callable

import sigma_handshake as sigma
from sigma_handshake import HandshakeError, load_public_key
from secure_channel import ReplayError, decrypt_message, encrypt_message

#: Largest accepted frame.  Comfortably above a garbled circuit for a wide
#: bit_length, far below anything that threatens memory.
MAX_FRAME_BYTES = 8 * 1024 * 1024

#: Width of the frame length prefix.
_LENGTH_BYTES = 4

#: Seconds a socket may block on a single read before the peer is declared gone.
SOCKET_TIMEOUT = 300.0

#: Default seconds :meth:`Node.recv` / :meth:`Node.collect` wait for a peer.
#: Generous: garbling and base OT for a wide circuit take a while.
DEFAULT_RECV_TIMEOUT = 600.0


class TransportError(Exception):
    """Raised when the transport cannot deliver what the protocol asked for."""


class ProtocolError(TransportError):
    """Raised when a peer's traffic violates the protocol (e.g. a duplicate)."""


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise TransportError(
            f"outgoing frame of {len(payload)} bytes exceeds the "
            f"{MAX_FRAME_BYTES}-byte limit"
        )
    sock.sendall(len(payload).to_bytes(_LENGTH_BYTES, "big") + payload)


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None  # peer closed cleanly
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> bytes | None:
    """Read one length-prefixed frame, or ``None`` if the peer closed.

    Raises:
        TransportError: if the declared length exceeds :data:`MAX_FRAME_BYTES`.
            Checking *before* allocating is the point -- it is what stops a
            single hostile header from exhausting memory.
    """
    header = _recv_exactly(sock, _LENGTH_BYTES)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    if length > MAX_FRAME_BYTES:
        raise TransportError(
            f"peer announced a {length}-byte frame, over the "
            f"{MAX_FRAME_BYTES}-byte limit; refusing to read it"
        )
    return _recv_exactly(sock, length)


def _send_json(sock: socket.socket, obj: Any) -> None:
    _send_frame(sock, json.dumps(obj).encode("utf-8"))


def _recv_json(sock: socket.socket) -> Any | None:
    frame = _recv_frame(sock)
    if frame is None:
        return None
    return json.loads(frame.decode("utf-8"))


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class Node:
    """One hospital node's view of the mesh.

    Args:
        node_id: this node's id.
        config: ``{node_id: {"host", "port", "public_key"}}`` -- public config.
        signing_key: this node's PRIVATE Ed25519 key (see ``keygen.py``).
        num_nodes: how many nodes participate.
        recv_timeout: default seconds to wait for an expected message.
        log: where to report dropped connections; ``None`` silences it.
    """

    def __init__(
        self,
        node_id: int,
        config: dict[int, dict],
        signing_key,
        num_nodes: int,
        *,
        recv_timeout: float = DEFAULT_RECV_TIMEOUT,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.node_id = node_id
        self.peers = {nid: addr for nid, addr in config.items() if nid != node_id}
        self.host = config[node_id]["host"]
        self.port = config[node_id]["port"]
        self.num_nodes = num_nodes
        self.signing_key = signing_key  # our long-term identity key (secret)
        self.recv_timeout = recv_timeout
        self._log = log if log is not None else (
            lambda msg: print(f"[node {node_id}] {msg}", file=sys.stderr)
        )

        # Every peer's public key, so we can verify who we are talking to.
        self.peer_public_keys = {
            nid: load_public_key(entry["public_key"]) for nid, entry in config.items()
        }

        # Inbound: (authenticated_sender_id, phase, payload)
        self.inbox: queue.Queue = queue.Queue()
        # Messages pulled off the inbox that some other caller is waiting for.
        self._holdover: list[tuple[int, str, Any]] = []
        self._holdover_lock = threading.Lock()

        # Outbound state, one entry per peer.
        self.connections: dict[int, socket.socket] = {}
        self.session_keys: dict[int, bytes] = {}
        self._send_seq: dict[int, int] = {}
        self._out_lock = threading.Lock()

        # Inbound state: which peers already have a session (one each).
        self._inbound_peers: set[int] = set()
        self._inbound_lock = threading.Lock()

        self._server: socket.socket | None = None
        self._closed = threading.Event()

    # ------------------------------------------------------------------
    # Listener
    # ------------------------------------------------------------------

    def start_listener(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(self.num_nodes - 1)
        srv.settimeout(1.0)  # so the accept loop can notice close()
        self._server = srv
        if self.port == 0:  # ephemeral port, used by the tests
            self.port = srv.getsockname()[1]

        def accept_loop() -> None:
            live: list[threading.Thread] = []
            while not self._closed.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return  # socket closed underneath us
                live = [t for t in live if t.is_alive()]
                if len(live) >= self.num_nodes - 1:
                    # A static mesh needs exactly num_nodes-1 inbound links.
                    # Anything beyond that is a misconfiguration or a flood.
                    self._log("refusing connection: inbound link limit reached")
                    conn.close()
                    continue
                t = threading.Thread(
                    target=self._handle_connection, args=(conn,), daemon=True
                )
                t.start()
                live.append(t)

        threading.Thread(target=accept_loop, daemon=True).start()

    # ------------------------------------------------------------------
    # Inbound: SIGMA as RESPONDER, then authenticated application messages
    # ------------------------------------------------------------------

    def _handle_connection(self, conn: socket.socket) -> None:
        """Serve one inbound link. Never raises -- it logs and closes instead.

        A handler that dies on an exception used to take its diagnostic with it
        and leave every peer blocked on a message that would never come.
        """
        peer_id: int | None = None
        try:
            conn.settimeout(SOCKET_TIMEOUT)
            peer_id, session_key = self._responder_handshake(conn)
            self._read_messages(conn, peer_id, session_key)
        except (HandshakeError, ProtocolError, ReplayError, TransportError) as exc:
            self._log(f"dropping inbound connection: {exc}")
        except (OSError, ValueError, KeyError) as exc:
            self._log(f"dropping inbound connection: malformed traffic ({exc})")
        finally:
            if peer_id is not None:
                with self._inbound_lock:
                    self._inbound_peers.discard(peer_id)
            try:
                conn.close()
            except OSError:
                pass

    def _responder_handshake(self, conn: socket.socket) -> tuple[int, bytes]:
        """Run SIGMA as responder; return the authenticated peer id and key."""
        msg1 = _recv_json(conn)
        if msg1 is None:
            raise HandshakeError("peer closed before the handshake started")
        state, msg2 = sigma.responder_handle_msg1(msg1, self.node_id, self.signing_key)
        _send_json(conn, msg2)

        msg3 = _recv_json(conn)
        if msg3 is None:
            raise HandshakeError("peer closed mid-handshake")
        # Authenticates WHICH node the peer is, via its Ed25519 signature.
        session_key, peer_id = sigma.responder_handle_msg3(
            msg3, state, self.peer_public_keys
        )

        if peer_id == self.node_id:
            raise HandshakeError("peer authenticated as this node itself")
        if peer_id not in self.peers:
            raise HandshakeError(f"node {peer_id} is not a configured peer")
        with self._inbound_lock:
            if peer_id in self._inbound_peers:
                raise ProtocolError(
                    f"node {peer_id} already has an inbound session; "
                    "the mesh allows exactly one per peer"
                )
            self._inbound_peers.add(peer_id)
        return peer_id, session_key

    def _read_messages(
        self, conn: socket.socket, peer_id: int, session_key: bytes
    ) -> None:
        """Decrypt and enqueue every application message on this link.

        ``seq`` is the receiver's own counter: it is never taken from the wire,
        so a replayed or reordered frame authenticates against the wrong
        position and is rejected (see :mod:`secure_channel`).
        """
        seq = 0
        while not self._closed.is_set():
            try:
                wrapped = _recv_json(conn)
            except socket.timeout:
                raise TransportError(
                    f"no traffic from node {peer_id} for {SOCKET_TIMEOUT:.0f}s"
                ) from None
            if wrapped is None:
                return  # peer closed cleanly
            plaintext = decrypt_message(
                session_key, wrapped, sender=peer_id, receiver=self.node_id, seq=seq
            )
            seq += 1
            envelope = json.loads(plaintext.decode("utf-8"))
            if not isinstance(envelope, dict) or "phase" not in envelope:
                raise ProtocolError(f"node {peer_id} sent a message with no phase tag")
            self.inbox.put((peer_id, envelope["phase"], envelope.get("payload")))

    # ------------------------------------------------------------------
    # Outbound: connect, then SIGMA as INITIATOR
    # ------------------------------------------------------------------

    def connect_to_peer(self, peer_id: int, retries: int = 20, delay: float = 0.5) -> None:
        peer_addr = self.peers[peer_id]
        last_error: Exception | None = None
        for _ in range(retries):
            try:
                s = socket.create_connection(
                    (peer_addr["host"], peer_addr["port"]), timeout=SOCKET_TIMEOUT
                )
            except (ConnectionRefusedError, socket.timeout, OSError) as exc:
                last_error = exc
                time.sleep(delay)
                continue
            try:
                session_key = self._initiator_handshake(peer_id, s)
            except Exception:
                s.close()
                raise
            with self._out_lock:
                self.connections[peer_id] = s
                self.session_keys[peer_id] = session_key
                self._send_seq[peer_id] = 0
            return
        raise ConnectionError(f"could not connect to peer {peer_id}: {last_error}")

    def _initiator_handshake(self, peer_id: int, s: socket.socket) -> bytes:
        """Run the SIGMA initiator side over an already-connected socket."""
        state, msg1 = sigma.initiator_start(self.node_id)
        _send_json(s, msg1)

        msg2 = _recv_json(s)
        if msg2 is None:
            raise HandshakeError(f"peer {peer_id} closed mid-handshake")
        # Verifies the responder really is `peer_id` before we send anything.
        session_key, msg3 = sigma.initiator_handle_msg2(
            msg2, state, peer_id, self.peer_public_keys[peer_id], self.signing_key
        )
        _send_json(s, msg3)
        return session_key

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send(self, peer_id: int, phase: str, payload: Any) -> None:
        """Encrypt and send one phase-tagged message to ``peer_id``."""
        with self._out_lock:
            sock = self.connections.get(peer_id)
            key = self.session_keys.get(peer_id)
            if sock is None or key is None:
                raise TransportError(
                    f"no authenticated link to peer {peer_id} (handshake not done)"
                )
            seq = self._send_seq[peer_id]
            self._send_seq[peer_id] = seq + 1
            plaintext = json.dumps({"phase": phase, "payload": payload}).encode("utf-8")
            wrapped = encrypt_message(
                key, plaintext, sender=self.node_id, receiver=peer_id, seq=seq
            )
            _send_json(sock, wrapped)

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    def _take(
        self, matches: Callable[[tuple[int, str, Any]], bool], timeout: float
    ) -> tuple[int, str, Any]:
        """Return the first message satisfying ``matches``, holding the rest.

        Messages for another phase (a fast peer running ahead) are kept on the
        node and re-offered to later callers, so no traffic is ever lost between
        phases.
        """
        deadline = time.monotonic() + timeout
        with self._holdover_lock:
            for i, item in enumerate(self._holdover):
                if matches(item):
                    return self._holdover.pop(i)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(
                    f"timed out after {timeout:.0f}s waiting for an expected "
                    "message; a peer appears to have died"
                )
            try:
                item = self.inbox.get(timeout=remaining)
            except queue.Empty:
                continue
            if matches(item):
                return item
            with self._holdover_lock:
                self._holdover.append(item)

    def recv(
        self, phase: str, timeout: float | None = None, sender: int | None = None
    ) -> tuple[int, Any]:
        """Block for one message of ``phase``; return ``(sender_id, payload)``.

        Pass ``sender`` to accept traffic only from that authenticated peer;
        anything else is left on the inbox for whoever is waiting for it.
        """
        got, _, payload = self._take(
            lambda item: item[1] == phase and (sender is None or item[0] == sender),
            self.recv_timeout if timeout is None else timeout,
        )
        return got, payload

    def collect(
        self, phase: str, senders: list[int], timeout: float | None = None
    ) -> dict[int, Any]:
        """Collect exactly one ``phase`` message from each of ``senders``.

        The sender ids are the ones SIGMA authenticated, so this is a real
        one-contribution-per-peer rule rather than a message count.  A peer that
        sends twice is rejected instead of silently displacing another peer's
        contribution.

        Raises:
            ProtocolError: if a peer contributes more than once.
            TransportError: if a peer does not contribute in time.
        """
        wanted = set(senders)
        collected: dict[int, Any] = {}
        limit = self.recv_timeout if timeout is None else timeout
        while len(collected) < len(wanted):
            sender, _, payload = self._take(
                lambda item: item[1] == phase and item[0] in wanted, limit
            )
            if sender in collected:
                raise ProtocolError(
                    f"node {sender} sent two '{phase}' messages; exactly one "
                    "contribution per peer is allowed"
                )
            collected[sender] = payload
        return collected

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Stop the listener and close every socket this node owns."""
        self._closed.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        with self._out_lock:
            for sock in self.connections.values():
                try:
                    sock.close()
                except OSError:
                    pass
            self.connections.clear()
            self.session_keys.clear()
            self._send_seq.clear()

    def __enter__(self) -> "Node":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

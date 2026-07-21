# confidential_computing

import time
import json
import socket
import threading
import queue

import sigma_handshake as sigma
from secure_channel import encrypt_message, decrypt_message


class Node:
    def __init__(self, node_id, config, psk: bytes, num_nodes: int):
        self.node_id = node_id
        self.num_nodes = num_nodes
        self.peers = {nid: addr for nid, addr in config.items() if nid != node_id}
        self.inbox = queue.Queue()
        self.host = config[node_id]['host']
        self.port = config[node_id]['port']
        self.connections = {}       # peer_id -> socket (outbound, for sending)
        self.session_keys = {}      # peer_id -> 32-byte SIGMA session key
        self.psk = psk              # pre-shared key, same for all nodes (from config/env)
        self._keys_lock = threading.Lock()  # session_keys is touched by multiple threads

    # ------------------------------------------------------------------
    # Listener
    # ------------------------------------------------------------------
    def start_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(self.num_nodes - 1)

        def accept_loop():
            while True:
                conn, _ = s.accept()
                t = threading.Thread(target=self._handle_connection, args=(conn,), daemon=True)
                t.start()

        threading.Thread(target=accept_loop, daemon=True).start()

    # ------------------------------------------------------------------
    # Inbound connection handler: first runs SIGMA as RESPONDER, then reads
    # encrypted application messages.
    # ------------------------------------------------------------------
    def _handle_connection(self, conn):
        f = conn.makefile('r')

        # --- SIGMA responder handshake (runs once, before any app traffic) ---
        line = f.readline()
        if not line:
            return
        msg1 = json.loads(line)
        peer_id = msg1["from"]
        state, msg2 = sigma.responder_handle_msg1(msg1, self.psk)
        conn.sendall((json.dumps({"from": self.node_id, **msg2}) + "\n").encode("utf-8"))

        line = f.readline()
        if not line:
            return
        msg3 = json.loads(line)
        session_key = sigma.responder_handle_msg3(msg3, state, self.psk)
        # NOTE: this key belongs to THIS inbound socket only. The outbound
        # socket to the same peer (opened by connect_to_peer) runs its own
        # separate handshake with its own key. We deliberately do NOT store
        # this under self.session_keys[peer_id] -- that map is for the
        # OUTBOUND direction (used by send()). This key is local to the
        # decrypt loop below.

        # --- from here on: every line is an AES-GCM wrapped application message ---
        while True:
            line = f.readline()
            if not line:
                break
            wrapped = json.loads(line)
            plaintext = decrypt_message(session_key, wrapped)
            message = json.loads(plaintext.decode("utf-8"))
            self.inbox.put(message)

    # ------------------------------------------------------------------
    # Outbound connection: connect, then run SIGMA as INITIATOR.
    # ------------------------------------------------------------------
    def connect_to_peer(self, peer_id, retries=10, delay=0.5):
        peer_addr = self.peers[peer_id]
        for _ in range(retries):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((peer_addr['host'], peer_addr['port']))
                self.connections[peer_id] = s
                self._do_initiator_handshake(peer_id, s)
                return
            except ConnectionRefusedError:
                time.sleep(delay)
        raise ConnectionError(f"Could not connect to peer {peer_id}")

    def _do_initiator_handshake(self, peer_id, s):
        """Run the SIGMA initiator side over an already-connected socket."""
        f = s.makefile('r')

        state, msg1 = sigma.initiator_start()
        s.sendall((json.dumps({"from": self.node_id, **msg1}) + "\n").encode("utf-8"))

        line = f.readline()
        msg2 = json.loads(line)
        session_key, msg3 = sigma.initiator_handle_msg2(msg2, state, self.psk)
        s.sendall((json.dumps({"from": self.node_id, **msg3}) + "\n").encode("utf-8"))

        with self._keys_lock:
            self.session_keys[peer_id] = session_key

    # ------------------------------------------------------------------
    # Send: AES-GCM encrypt under the peer's session key, then frame + send.
    # ------------------------------------------------------------------
    def send(self, peer_id, message: dict):
        peer_s = self.connections.get(peer_id)
        if peer_s is None:
            raise ValueError(f"No connection to peer {peer_id}")

        with self._keys_lock:
            key = self.session_keys.get(peer_id)
        if key is None:
            raise ValueError(f"No SIGMA session key for peer {peer_id} (handshake not done)")

        plaintext = json.dumps(message).encode("utf-8")
        wrapped = encrypt_message(key, plaintext)
        peer_s.sendall((json.dumps(wrapped) + "\n").encode("utf-8"))

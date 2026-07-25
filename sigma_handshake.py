"""
sigma_handshake.py
==================
SIGMA authenticated key exchange with **per-node identity keys**.

WHERE THIS FITS
---------------
Runs ONCE per directed connection, right after connect_to_peer() succeeds and
BEFORE any application traffic. It produces a per-session symmetric key that
the transport then uses to encrypt every subsequent message. The Secure Sum /
share-reduction / GC layers never see it.

THE PROTOCOL (SIGMA "sign-and-MAC", Krawczyk 2003)
--------------------------------------------------
Ephemeral X25519 Diffie-Hellman gives a fresh shared secret, and each party
proves its identity by **signing the DH transcript** with its long-term Ed25519
key. A MAC over the signer's identity, keyed from the DH secret, binds that
identity to this specific session -- the "MAC" half of sign-and-MAC, which is
what prevents identity-misbinding attacks.

    Initiator A                                Responder B
       |  msg1:  g_a, id_A  ------------------->  |
       |  <---- msg2:  g_b, id_B, SIG_B, MAC_B    |
       |  msg3:  id_A, SIG_A, MAC_A ----------->  |

        SIG_B = Sign_B("SIGMA-responder" || g_a || g_b)
        SIG_A = Sign_A("SIGMA-initiator" || g_a || g_b)
        MAC_X = HMAC(mac_key, "id" || id_X)
        mac_key     = KDF(g_ab, "sigma-mac-key")
        session_key = KDF(g_ab, "sigma-session-key" || g_a || g_b)

The two signature labels differ, so a message from one direction can never be
replayed as the other (reflection attack).

WHAT THIS GIVES
---------------
* **Per-node authentication.** Each node holds its own private signing key; the
  four public keys are public config. A valid signature proves *which* node is
  on the other end, not merely that it belongs to a group. There is no shared
  secret anywhere in the system.
* **Forward secrecy.** DH keys are ephemeral and discarded after the handshake,
  so compromising a long-term signing key later does not decrypt past sessions.
* **Replay resistance.** Fresh ephemeral keys per session mean a recorded msg2
  or msg3 fails signature verification against the new transcript.

KEY MANAGEMENT
--------------
Private signing keys live in per-node files (see keygen.py) and must never be
committed. Public keys ship in config.json alongside each node's address.
"""

from __future__ import annotations

import hmac
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# Domain-separation labels. Distinct per direction to stop reflection attacks.
_LABEL_INITIATOR = b"SIGMA-initiator"
_LABEL_RESPONDER = b"SIGMA-responder"


class HandshakeError(Exception):
    """Raised when authentication fails; the session key must not be used."""


# ---------------------------------------------------------------------------
# Long-term identity keys (Ed25519)
# ---------------------------------------------------------------------------

def generate_identity_keypair() -> tuple[bytes, bytes]:
    """Create a long-term Ed25519 identity keypair.

    Returns:
        ``(private_bytes, public_bytes)`` -- 32 raw bytes each.
    """
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def load_signing_key(path: str | Path) -> Ed25519PrivateKey:
    """Load a node's private signing key from a hex file."""
    raw = bytes.fromhex(Path(path).read_text().strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(hex_str: str) -> Ed25519PublicKey:
    """Load a peer's public key from its hex representation in the config."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


# ---------------------------------------------------------------------------
# Ephemeral DH + key derivation
# ---------------------------------------------------------------------------

def generate_ephemeral_keypair():
    """Fresh ephemeral X25519 keypair for ONE handshake (forward secrecy)."""
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def compute_shared_secret(my_priv, peer_pub_bytes: bytes) -> bytes:
    """Raw DH secret; both sides compute the same g^ab."""
    return my_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))


def build_transcript(g_initiator: bytes, g_responder: bytes) -> bytes:
    """Canonical transcript: initiator's DH key first, responder's second.

    Both parties must build byte-identical transcripts or nothing verifies.
    """
    return g_initiator + g_responder


def derive_mac_key(shared_secret: bytes) -> bytes:
    """Key for the identity MACs (kept separate from the session key)."""
    return hmac.new(shared_secret, b"sigma-mac-key", hashlib.sha256).digest()


def derive_session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """The 32-byte AES-GCM session key, bound to this handshake's transcript."""
    return hmac.new(
        shared_secret, b"sigma-session-key" + transcript, hashlib.sha256
    ).digest()


def _identity_mac(mac_key: bytes, node_id: int) -> bytes:
    return hmac.new(mac_key, b"id" + str(node_id).encode(), hashlib.sha256).digest()


def _signed_payload(label: bytes, transcript: bytes) -> bytes:
    return label + transcript


# ---------------------------------------------------------------------------
# The three messages
# ---------------------------------------------------------------------------

def initiator_start(my_id: int):
    """Initiator step 1: fresh ephemeral key. Returns ``(state, msg1)``."""
    priv, g_a = generate_ephemeral_keypair()
    state = {"priv": priv, "g_a": g_a, "my_id": my_id}
    return state, {"g": g_a.hex(), "from": my_id}


def responder_handle_msg1(msg1: dict, my_id: int, my_signing_key):
    """Responder: derive keys, sign the transcript, MAC our identity.

    Returns ``(state, msg2)``. The initiator's claimed id is recorded but not
    yet trusted -- it is authenticated in :func:`responder_handle_msg3`.
    """
    g_a = bytes.fromhex(msg1["g"])
    claimed_initiator = msg1["from"]

    priv, g_b = generate_ephemeral_keypair()
    shared = compute_shared_secret(priv, g_a)
    transcript = build_transcript(g_a, g_b)
    mac_key = derive_mac_key(shared)

    signature = my_signing_key.sign(_signed_payload(_LABEL_RESPONDER, transcript))
    msg2 = {
        "g": g_b.hex(),
        "from": my_id,
        "sig": signature.hex(),
        "mac": _identity_mac(mac_key, my_id).hex(),
    }
    state = {
        "session_key": derive_session_key(shared, transcript),
        "mac_key": mac_key,
        "transcript": transcript,
        "claimed_initiator": claimed_initiator,
    }
    return state, msg2


def initiator_handle_msg2(
    msg2: dict, state: dict, expected_peer_id: int, peer_public_key, my_signing_key
):
    """Initiator: authenticate the responder, then prove our own identity.

    Verifies, in order: that the responder is the node we dialled, that its
    signature over the transcript is valid, and that its identity MAC binds it
    to this session.

    Returns ``(session_key, msg3)``.

    Raises:
        HandshakeError: on any verification failure. The session key is
            discarded and no application traffic may be sent.
    """
    if msg2["from"] != expected_peer_id:
        raise HandshakeError(
            f"expected to reach node {expected_peer_id} but peer claims to be "
            f"node {msg2['from']}"
        )

    g_b = bytes.fromhex(msg2["g"])
    shared = compute_shared_secret(state["priv"], g_b)
    transcript = build_transcript(state["g_a"], g_b)
    mac_key = derive_mac_key(shared)

    try:
        peer_public_key.verify(
            bytes.fromhex(msg2["sig"]),
            _signed_payload(_LABEL_RESPONDER, transcript),
        )
    except InvalidSignature:
        raise HandshakeError(
            f"responder {expected_peer_id} signature invalid -- possible MITM "
            "or wrong public key in config"
        ) from None

    expected_mac = _identity_mac(mac_key, msg2["from"])
    if not hmac.compare_digest(expected_mac, bytes.fromhex(msg2["mac"])):
        raise HandshakeError(f"responder {expected_peer_id} identity MAC invalid")

    my_id = state["my_id"]
    signature = my_signing_key.sign(_signed_payload(_LABEL_INITIATOR, transcript))
    msg3 = {
        "from": my_id,
        "sig": signature.hex(),
        "mac": _identity_mac(mac_key, my_id).hex(),
    }
    return derive_session_key(shared, transcript), msg3


def responder_handle_msg3(msg3: dict, state: dict, peer_public_keys: dict):
    """Responder: authenticate the initiator and activate the session.

    Args:
        peer_public_keys: ``{node_id: Ed25519PublicKey}`` from public config.

    Returns:
        ``(session_key, initiator_id)`` -- the id is now authenticated.

    Raises:
        HandshakeError: on any verification failure.
    """
    initiator_id = msg3["from"]
    if initiator_id != state["claimed_initiator"]:
        raise HandshakeError(
            f"initiator identity changed mid-handshake: claimed "
            f"{state['claimed_initiator']} in msg1, {initiator_id} in msg3"
        )

    public_key = peer_public_keys.get(initiator_id)
    if public_key is None:
        raise HandshakeError(f"no public key configured for node {initiator_id}")

    try:
        public_key.verify(
            bytes.fromhex(msg3["sig"]),
            _signed_payload(_LABEL_INITIATOR, state["transcript"]),
        )
    except InvalidSignature:
        raise HandshakeError(
            f"initiator {initiator_id} signature invalid -- possible MITM or "
            "wrong public key in config"
        ) from None

    expected_mac = _identity_mac(state["mac_key"], initiator_id)
    if not hmac.compare_digest(expected_mac, bytes.fromhex(msg3["mac"])):
        raise HandshakeError(f"initiator {initiator_id} identity MAC invalid")

    return state["session_key"], initiator_id

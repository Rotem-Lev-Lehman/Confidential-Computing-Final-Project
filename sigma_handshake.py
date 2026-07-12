"""
sigma_handshake.py
==================
PSK-authenticated Diffie-Hellman handshake between two nodes, following the
SIGMA 3-message structure (msg1 / msg2 / msg3).

WHERE THIS FITS
---------------
Runs ONCE per pair of nodes, right after connect_to_peer() succeeds and BEFORE
any Secure Sum shares are exchanged. It produces a per-session symmetric key
that the transport layer then uses to authenticate/encrypt every subsequent
message. The Secure Sum layer (vectorize / split / distribute / collect) does
not need to know SIGMA exists.

WHAT "SIGMA" MEANS HERE
-----------------------
Classic SIGMA authenticates the ephemeral DH keys with SIGNATURES + a MAC over
the identity ("sign-and-mac"). We use a pre-shared key (PSK) known to all 4
nodes to HMAC the transcript. This gives mutual authentication (only PSK
holders produce a valid tag), a fresh session key (ephemeral DH per
handshake), and forward secrecy (DH secret discarded after key derivation).
We keep the SIGMA msg1/msg2/msg3 shape so the mapping is explicit.

THREAT MODEL NOTE
-----------------
A single shared PSK across all nodes authenticates "member of the group" but
NOT "which specific node". For pairwise identity you'd want per-pair PSKs
(psk[frozenset({i, j})]) or per-node signing keys. Documented as a known
limitation for this fixed-topology, honest-but-curious project.
"""

import hmac
import hashlib

# X25519: modern, fast, fixed-size (32-byte) elliptic-curve Diffie-Hellman.
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


# ---------------------------------------------------------------------------
# Cryptographic primitives
# ---------------------------------------------------------------------------

def generate_ephemeral_keypair():
    """
    Generate a fresh ephemeral X25519 keypair for ONE handshake.

    Returns:
        (private_key_obj, public_bytes) where public_bytes is 32 raw bytes.

    Ephemeral = new pair every handshake -> forward secrecy: once the private
    key is discarded, a later PSK compromise cannot decrypt past sessions.
    """
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()  # 32 bytes
    return priv, pub_bytes


def compute_shared_secret(my_priv, peer_pub_bytes: bytes) -> bytes:
    """
    Compute the raw DH shared secret. Both sides get the same value:
    DH(a, g^b) == DH(b, g^a) == g^ab.
    """
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return my_priv.exchange(peer_pub)  # raw shared secret (32 bytes)


def derive_session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """
    Derive the symmetric session key from the DH shared secret, bound to the
    handshake transcript (both public keys). Binding to the transcript stops an
    attacker from mixing keys across handshakes.
    """
    return hmac.new(
        shared_secret, b"session-key" + transcript, hashlib.sha256
    ).digest()  # 32-byte key


def make_auth_tag(psk: bytes, transcript: bytes) -> bytes:
    """
    HMAC authenticator over the transcript using the PSK. Only a party holding
    the PSK can produce a tag that verifies, so a valid tag proves the peer is
    a legitimate group member and that the DH keys in the transcript are real.
    """
    return hmac.new(psk, transcript, hashlib.sha256).digest()


def verify_auth_tag(psk: bytes, transcript: bytes, tag: bytes) -> bool:
    """
    Verify a received auth tag using a CONSTANT-TIME comparison
    (hmac.compare_digest) to avoid timing side channels. Never use `==` on MACs.
    """
    expected = make_auth_tag(psk, transcript)
    return hmac.compare_digest(expected, tag)


def build_transcript(g_initiator: bytes, g_responder: bytes) -> bytes:
    """
    Canonical transcript both sides agree on: the two DH public keys in a FIXED
    order (initiator first, responder second), regardless of who is sending.
    Both parties must build byte-identical transcripts or the tags won't match.
    """
    return g_initiator + g_responder


# ---------------------------------------------------------------------------
# Handshake orchestration (SIGMA 3-message flow)
# ---------------------------------------------------------------------------
#
# Initiator                          Responder
#    | ---- msg1: g_a ------------------> |
#    | <--- msg2: g_b, tag_b ------------ |     tag_b = HMAC(psk, transcript)
#    | ---- msg3: tag_a ----------------> |     tag_a = HMAC(psk, transcript)
#    |                                    |
#  both derive session_key = KDF(g_ab, transcript)


def initiator_start():
    """
    Initiator step 1: generate ephemeral keypair, return (state, msg1).
    msg1 = {"g": hex(g_a)}
    """
    priv, g_a = generate_ephemeral_keypair()
    state = {"priv": priv, "g_a": g_a}
    msg1 = {"g": g_a.hex()}
    return state, msg1


def responder_handle_msg1(msg1: dict, psk: bytes):
    """
    Responder: receive msg1, generate own keypair, compute shared secret,
    build transcript, produce tag_b. Return (state, msg2).
    msg2 = {"g": hex(g_b), "tag": hex(tag_b)}
    """
    g_a = bytes.fromhex(msg1["g"])
    priv, g_b = generate_ephemeral_keypair()
    shared = compute_shared_secret(priv, g_a)
    transcript = build_transcript(g_a, g_b)  # initiator first
    tag_b = make_auth_tag(psk, transcript)
    session_key = derive_session_key(shared, transcript)
    state = {
        "session_key": session_key,
        "transcript": transcript,
        "g_a": g_a,
        "g_b": g_b,
    }
    msg2 = {"g": g_b.hex(), "tag": tag_b.hex()}
    return state, msg2


def initiator_handle_msg2(msg2: dict, state: dict, psk: bytes):
    """
    Initiator: receive msg2, compute shared secret, verify responder's tag_b,
    derive session key, produce tag_a. Return (session_key, msg3).
    On tag failure -> raise (abort; do NOT proceed).
    msg3 = {"tag": hex(tag_a)}
    """
    g_b = bytes.fromhex(msg2["g"])
    tag_b = bytes.fromhex(msg2["tag"])
    shared = compute_shared_secret(state["priv"], g_b)
    transcript = build_transcript(state["g_a"], g_b)
    if not verify_auth_tag(psk, transcript, tag_b):
        raise ValueError("SIGMA: responder auth tag verification failed")
    session_key = derive_session_key(shared, transcript)
    tag_a = make_auth_tag(psk, transcript)
    msg3 = {"tag": tag_a.hex()}
    return session_key, msg3


def responder_handle_msg3(msg3: dict, state: dict, psk: bytes) -> bytes:
    """
    Responder: receive msg3, verify initiator's tag_a. On success return the
    session key (now active). On failure raise.
    """
    tag_a = bytes.fromhex(msg3["tag"])
    if not verify_auth_tag(psk, state["transcript"], tag_a):
        raise ValueError("SIGMA: initiator auth tag verification failed")
    return state["session_key"]


if __name__ == "__main__":
    # Manual smoke test: run the whole handshake in-process (no sockets) and
    # confirm BOTH sides derive the SAME session key.
    psk = b"shared-secret-across-all-hospitals"  # in reality: from config
    st_i, msg1 = initiator_start()
    st_r, msg2 = responder_handle_msg1(msg1, psk)
    key_i, msg3 = initiator_handle_msg2(msg2, st_i, psk)
    key_r = responder_handle_msg3(msg3, st_r, psk)
    assert key_i == key_r, "session keys differ!"
    print("handshake OK, shared session key:", key_i.hex()[:16], "...")

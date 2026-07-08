"""
secure_channel.py
=================
AES-GCM authenticated encryption for messages sent over the (untrusted)
network, keyed by the per-session key produced by the SIGMA handshake.

WHERE THIS FITS
---------------
After sigma_handshake gives node A and node B a shared 32-byte session key,
every application message between them is wrapped with encrypt_message()
before hitting the socket and unwrapped with decrypt_message() on arrival.
This mirrors the "Secure Communication After AKE" phase from the SGX Ex3:
AES-GCM for confidentiality + integrity, a fresh random IV per message, and
the ciphertext authenticated so a tampering host is detected.

The session key from SIGMA is 32 bytes -> AES-256-GCM.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(session_key: bytes, plaintext: bytes) -> dict:
    """
    Encrypt plaintext under the session key with AES-GCM.

    Returns a JSON-serializable dict {"iv": hex, "ct": hex} where ct is the
    ciphertext with the GCM tag appended (the `cryptography` AESGCM API returns
    ciphertext||tag together).

    A fresh 12-byte (96-bit) IV is generated per call. IV reuse under the same
    key breaks GCM, so this must never be a fixed value.
    """
    aesgcm = AESGCM(session_key)
    iv = os.urandom(12)  # 96-bit nonce, the GCM standard size
    ct = aesgcm.encrypt(iv, plaintext, None)  # associated_data=None
    return {"iv": iv.hex(), "ct": ct.hex()}


def decrypt_message(session_key: bytes, wrapped: dict) -> bytes:
    """
    Decrypt a {"iv": hex, "ct": hex} dict produced by encrypt_message.

    Raises cryptography.exceptions.InvalidTag if the ciphertext or tag was
    modified in transit (the host tampered), or if the wrong key is used.
    """
    aesgcm = AESGCM(session_key)
    iv = bytes.fromhex(wrapped["iv"])
    ct = bytes.fromhex(wrapped["ct"])
    return aesgcm.decrypt(iv, ct, None)

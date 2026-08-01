"""
secure_channel.py
=================
AES-256-GCM authenticated encryption for messages sent over the (untrusted)
network, keyed by the per-session key produced by the SIGMA handshake.

WHERE THIS FITS
---------------
After sigma_handshake gives a directed link its own 32-byte session key, every
application message on that link is wrapped with :func:`encrypt_message` before
hitting the socket and unwrapped with :func:`decrypt_message` on arrival.

WHAT THE AEAD BINDS
-------------------
Confidentiality and integrity alone are not enough on an untrusted network: an
attacker who cannot forge a message can still *replay* one it captured, and a
duplicate share vector silently corrupts the secure sum.  Two mechanisms stop
that, and both are free:

* **Counter nonces.**  The nonce is the message sequence number, not a random
  value.  Each direction of each link has its own session key (initiator and
  responder run separate handshakes), and each key starts its counter at 0, so a
  nonce is never reused under a key -- the one thing that would break GCM.
* **Associated data.**  Each message authenticates ``sender -> receiver # seq``
  as associated data.  The receiver derives the same sequence number from its
  own counter, so a replayed, reordered, reflected or cross-link message
  authenticates against the wrong value and fails with ``InvalidTag``.

Both counters advance in lockstep, which relies on the underlying stream
delivering every message exactly once and in order.  That is what TCP provides,
and it is a deliberate dependency: over a lossy datagram transport the counters
would desynchronise on the first dropped message and every later message would
fail to authenticate.

Note that the sequence number is *never transmitted*: both sides derive it from
their own counters.  An attacker therefore cannot renumber a captured message to
make it fit.  The message's phase tag travels inside the ciphertext, so it is
covered by the same authentication.

The session key from SIGMA is 32 bytes -> AES-256-GCM.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: GCM's standard nonce width.  Also the counter width -- 96 bits of sequence
#: number is far more than any run will ever use.
NONCE_BYTES = 12

#: AES-256 key width.  ``AESGCM`` silently accepts 16- and 24-byte keys too
#: (AES-128 / AES-192), so a shortened KDF output would downgrade the cipher
#: without any error.  We check explicitly instead.
KEY_BYTES = 32


class ReplayError(ValueError):
    """Raised when a message fails to authenticate at its expected position."""


def _check_key(session_key: bytes) -> None:
    if len(session_key) != KEY_BYTES:
        raise ValueError(
            f"session key must be {KEY_BYTES} bytes for AES-256-GCM, "
            f"got {len(session_key)}"
        )


def _nonce(seq: int) -> bytes:
    if seq < 0 or seq >= (1 << (NONCE_BYTES * 8)):
        raise ValueError(f"sequence number {seq} out of range")
    return seq.to_bytes(NONCE_BYTES, "big")


def _aad(sender: int, receiver: int, seq: int) -> bytes:
    """Bind the message to its link and its position in the stream."""
    return f"{sender}->{receiver}#{seq}".encode("utf-8")


def encrypt_message(
    session_key: bytes, plaintext: bytes, *, sender: int, receiver: int, seq: int
) -> dict:
    """Encrypt one message for position ``seq`` of the ``sender -> receiver`` link.

    Returns a JSON-serializable ``{"ct": hex}``; the GCM tag is appended to the
    ciphertext by the ``cryptography`` API.  Neither the nonce nor the sequence
    number is transmitted -- the receiver derives both.
    """
    _check_key(session_key)
    ct = AESGCM(session_key).encrypt(
        _nonce(seq), plaintext, _aad(sender, receiver, seq)
    )
    return {"ct": ct.hex()}


def decrypt_message(
    session_key: bytes, wrapped: dict, *, sender: int, receiver: int, seq: int
) -> bytes:
    """Decrypt a message expected at position ``seq`` of the given link.

    Raises:
        ReplayError: if the message does not authenticate at this position --
            it was tampered with, replayed, reordered, or came from a different
            link than it claims.
    """
    _check_key(session_key)
    try:
        ct = bytes.fromhex(wrapped["ct"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReplayError(f"malformed encrypted message: {exc}") from None
    try:
        return AESGCM(session_key).decrypt(
            _nonce(seq), ct, _aad(sender, receiver, seq)
        )
    except InvalidTag:
        raise ReplayError(
            f"message {seq} on link {sender}->{receiver} failed authentication "
            "(tampered, replayed or out of order)"
        ) from None

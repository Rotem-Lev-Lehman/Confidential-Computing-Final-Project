"""1-out-of-2 Oblivious Transfer — the Chou-Orlandi protocol (2015).

OT lets the evaluator fetch, for each of its input bits, exactly the wire label
matching that bit — without revealing the bit to the garbler, and without
learning the other label.  It is the piece that makes the input transfer in
Yao's protocol private.

We implement the "simplest OT" of Chou and Orlandi over a prime-order subgroup
of Z*_p (a Diffie-Hellman group).  For a choice bit ``c`` and sender messages
``m0, m1``:

    sender:    a <- Z_q,  A = g^a                      (sent once, reused)
    receiver:  b <- Z_q,  B = g^b        if c = 0
                          B = A * g^b     if c = 1      (sent to sender)
               key k_c = Hash(i, A^b)
    sender:    k_0 = Hash(i, B^a),  k_1 = Hash(i, (B / A)^a)
               ct_e = m_e XOR k_e                        (both sent to receiver)
    receiver:  m_c = ct_c XOR k_c

Correctness: ``A^b = g^{ab}`` equals ``B^a`` when ``c = 0`` and ``(B/A)^a`` when
``c = 1``, so the receiver reconstructs exactly the key for its chosen bit.
Security (semi-honest): the sender never sees ``c`` (``B`` is uniform either
way), and the receiver cannot form the other key without ``g^{ab}`` for the
unchosen branch (the Computational Diffie-Hellman assumption).

Two standard MODP groups are provided: a 2048-bit group (RFC 3526, the default —
the modern recommended strength) and a 1024-bit group (RFC 2409, ~5x faster
here because every OT is a full-width modular exponentiation — handy for quick
demos, but below today's recommended key size).  Pick with ``--ot-group``.
This is textbook base OT — one public-key operation per bit — not OT extension.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# RFC 3526 MODP Group 14 (2048-bit safe prime, p = 2q + 1 with q prime).
_RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# RFC 2409 MODP Group 2 (1024-bit safe prime, p = 2q + 1 with q prime).
_RFC2409_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16,
)


@dataclass(frozen=True)
class DHGroup:
    """A prime-order Diffie-Hellman group ``<g>`` of order ``q`` in Z*_p."""

    p: int
    q: int
    g: int

    @property
    def elem_bytes(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def rand_exponent(self) -> int:
        return 1 + secrets.randbelow(self.q - 1)

    def pow(self, base: int, exp: int) -> int:
        return pow(base, exp, self.p)

    def inv(self, x: int) -> int:
        return pow(x, -1, self.p)

    def check_element(self, x: int, name: str) -> int:
        """Reject anything that is not a real element of the order-q subgroup.

        Both sides validate what they receive.  A value outside ``<g>`` -- say
        the small-order element ``p - 1`` -- would collapse the key space and
        let the party that sent it learn the other's secret.  This is beyond the
        semi-honest model the project assumes, but the check costs one
        exponentiation against a protocol break, so it is always on.
        """
        if not isinstance(x, int):
            raise ValueError(f"OT {name} must be an integer, got {type(x).__name__}")
        if not 1 < x < self.p - 1:
            raise ValueError(f"OT {name} is outside the valid range for this group")
        if pow(x, self.q, self.p) != 1:
            raise ValueError(f"OT {name} is not in the order-q subgroup")
        return x


def _modp_group(p: int) -> DHGroup:
    # g = 4 = 2^2 is a quadratic residue, hence a generator of the order-q
    # subgroup; working inside it keeps every transmitted element in <g>.
    return DHGroup(p=p, q=(p - 1) // 2, g=4)


GROUP_1024 = _modp_group(_RFC2409_P)
GROUP_2048 = _modp_group(_RFC3526_P)

# Default to the 2048-bit group (the modern recommended strength).  Base OT
# does a full modular exponentiation per input bit, so the 1024-bit group is
# ~5x faster — override with --ot-group 1024 for quick demos.
DEFAULT_GROUP = GROUP_2048

GROUPS: dict[str, DHGroup] = {"1024": GROUP_1024, "2048": GROUP_2048}


def _kdf(
    group: DHGroup, index: int, A: int, B: int, group_elem: int, n_bytes: int
) -> bytes:
    """Derive a one-time pad key from a shared group element.

    The whole transcript goes into the hash -- the instance index and both
    public values ``A`` and ``B``, not just the shared element -- as in the
    Chou-Orlandi paper.  Hashing the transcript is what the security proof
    assumes, and it domain-separates instances and sessions that might otherwise
    share a group element.
    """
    data = (
        index.to_bytes(4, "big")
        + A.to_bytes(group.elem_bytes, "big")
        + B.to_bytes(group.elem_bytes, "big")
        + group_elem.to_bytes(group.elem_bytes, "big")
    )
    return hashlib.sha512(data).digest()[:n_bytes]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    # Strict: zip() would silently truncate to the shorter operand, turning a
    # corrupted ciphertext into a short (and wrong) wire label instead of an
    # error.
    if len(a) != len(b):
        raise ValueError(f"length mismatch in OT one-time pad: {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


class OTSender:
    """OT sender (the garbler): offers a pair of messages per instance."""

    def __init__(self, group: DHGroup = DEFAULT_GROUP) -> None:
        self.group = group
        self._a = group.rand_exponent()
        self.A = group.pow(group.g, self._a)  # public, reused across instances
        self._inv_A = group.inv(self.A)

    def public_key(self) -> int:
        return self.A

    def respond(
        self, receiver_B: list[int], messages: list[tuple[bytes, bytes]]
    ) -> list[tuple[bytes, bytes]]:
        """Encrypt each ``(m0, m1)`` pair against the receiver's ``B`` values."""
        if len(receiver_B) != len(messages):
            raise ValueError("mismatched OT batch sizes")
        out: list[tuple[bytes, bytes]] = []
        for i, (B, (m0, m1)) in enumerate(zip(receiver_B, messages)):
            self.group.check_element(B, f"B[{i}]")
            if len(m0) != len(m1):
                raise ValueError("OT message pair must have equal lengths")
            n = len(m0)
            k0 = _kdf(self.group, i, self.A, B, self.group.pow(B, self._a), n)
            b_over_a = (B * self._inv_A) % self.group.p
            k1 = _kdf(self.group, i, self.A, B, self.group.pow(b_over_a, self._a), n)
            out.append((_xor_bytes(m0, k0), _xor_bytes(m1, k1)))
        return out


class OTReceiver:
    """OT receiver (the evaluator): learns only the message for its choice bit."""

    def __init__(self, sender_A: int, group: DHGroup = DEFAULT_GROUP) -> None:
        self.group = group
        # Validate before use: a sender's A outside the subgroup could otherwise
        # leak the choice bit.
        self.A = group.check_element(sender_A, "A")
        self._choices: list[int] = []
        self._B: list[int] = []
        self._keys: list[int] = []  # shared element A^b per instance

    def choose(self, choice_bits: list[int]) -> list[int]:
        """Produce the ``B`` values that encode the private choice bits."""
        self._choices = list(choice_bits)
        self._keys = []
        B_list: list[int] = []
        for c in choice_bits:
            b = self.group.rand_exponent()
            gb = self.group.pow(self.group.g, b)
            B = gb if c == 0 else (self.A * gb) % self.group.p
            self._keys.append(self.group.pow(self.A, b))  # A^b = g^{ab}
            B_list.append(B)
        self._B = B_list
        return B_list

    def finalize(
        self, ciphertexts: list[tuple[bytes, bytes]], expected_len: int | None = None
    ) -> list[bytes]:
        """Decrypt exactly the chosen message from each ciphertext pair.

        Args:
            ciphertexts: the sender's ``(ct0, ct1)`` pairs.
            expected_len: length every recovered message must have. The one-time
                pad is derived at the ciphertext's own length, so without this a
                truncated ciphertext would decrypt "successfully" into a short
                wire label instead of failing -- pass the caller's known label
                size to close that off.
        """
        if len(ciphertexts) != len(self._choices):
            raise ValueError(
                f"expected {len(self._choices)} OT ciphertext pairs, "
                f"got {len(ciphertexts)}"
            )
        out: list[bytes] = []
        for i, (c, (ct0, ct1)) in enumerate(zip(self._choices, ciphertexts)):
            if len(ct0) != len(ct1):
                raise ValueError(
                    f"length mismatch in OT ciphertext pair {i}: "
                    f"{len(ct0)} != {len(ct1)}"
                )
            if expected_len is not None and len(ct0) != expected_len:
                raise ValueError(
                    f"length mismatch in OT ciphertext {i}: expected "
                    f"{expected_len} bytes, got {len(ct0)}"
                )
            chosen_ct = ct0 if c == 0 else ct1
            key = _kdf(
                self.group, i, self.A, self._B[i], self._keys[i], len(chosen_ct)
            )
            out.append(_xor_bytes(chosen_ct, key))
        return out

"""
secret_sharing.py
=================
Additive secret sharing over F_p.

A secret value v is split into num_shares random pieces such that

    (share_1 + share_2 + ... + share_n) mod p == v

Each individual share looks uniformly random and leaks nothing about v; only
someone holding ALL shares can reconstruct it. This is the privacy guarantee
of the Phase 1 secure sum.
"""

import secrets


def split_into_shares(value: int, p: int, num_shares: int = 4) -> list[int]:
    """
    Split `value` into num_shares additive shares over F_p, such that
    sum(shares) % p == value.

    Draws (num_shares - 1) shares uniformly at random from [0, p), then
    computes the last share so the total closes exactly on `value`.

    Uses `secrets` (CSPRNG) rather than `random`: these shares ARE the privacy
    guarantee. random.Random is a deterministic PRNG whose internal state can
    be recovered, which would let a curious node compute the shares sent to
    others and break secrecy.

    Args:
        value:      the value to split. Must satisfy 0 <= value < p.
        p:          the prime modulus.
        num_shares: number of shares (>= 2).

    Returns:
        list[int] of length num_shares, each in [0, p), summing mod p to value.

    Raises:
        ValueError: if `value` is not reduced mod p, or num_shares < 2.

    The guards are explicit `raise`, not `assert`: `python -O` strips asserts,
    which would silently disable exactly the checks that stop this function
    producing broken shares.
    """
    if not 0 <= value < p:
        raise ValueError(f"value {value} not reduced mod p={p}")
    if num_shares < 2:
        raise ValueError(
            f"need at least 2 shares for secret sharing, got {num_shares}"
        )

    shares = [secrets.randbelow(p) for _ in range(num_shares - 1)]
    shares.append((value - sum(shares)) % p)
    return shares


def reconstruct(shares: list[int], p: int) -> int:
    """
    Reconstruct the original value from all shares: sum(shares) mod p.

    In the real protocol no single node ever holds every share -- that is what
    keeps the inputs private. This exists for round-trip verification.
    """
    return sum(shares) % p

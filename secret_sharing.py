"""
secret_sharing.py
=================
Task 4: Additive secret sharing over F_p.

The idea: split a secret value v into num_shares random pieces such that:
    (share_1 + share_2 + ... + share_n) mod p == v

Each individual share looks completely random and leaks nothing about v.
Only someone who collects ALL shares can reconstruct it. This is the
privacy guarantee of the entire protocol.
"""

import secrets


def split_into_shares(value: int, p: int, num_shares: int = 4) -> list[int]:
    """
    Split `value` into num_shares additive shares over F_p, such that
    sum(shares) % p == value.

    Method: draw (num_shares - 1) shares uniformly at random from [0, p),
    then compute the last share so the total closes exactly on `value`.

    ** Why secrets and not random: ** these shares ARE the whole privacy
    guarantee. random.Random is a deterministic PRNG (Mersenne Twister)
    that can be reconstructed from its internal state -- a curious node
    that recovers the seed could compute the shares sent to others and
    break secrecy. secrets is a CSPRNG. Under the honest-but-curious
    model, this is exactly the protection we need.

    Args:
        value:      the value to split. Must be reduced: 0 <= value < p.
        num_shares: number of shares (>= 2).
        p:          the prime modulus.

    Returns:
        list[int] of length num_shares, each in [0, p), summing mod p to value.

    -------------------------------------------------------------------
    The two asserts below are a safety net -- they catch a logic bug (an
    unreduced value, or a wrong num_shares) early, instead of silently
    producing broken shares.

    TODO 1: Draw (num_shares - 1) random shares in [0, p).
            Hint: secrets.randbelow(p) returns a number in [0, p).

    TODO 2: Compute the last share so everything closes on value.

    TODO 3: Append last to the list and return.
            
    -------------------------------------------------------------------
    """
    assert 0 <= value < p, f"value {value} not reduced mod p={p}"
    assert num_shares >= 2, "need at least 2 shares for secret sharing"

    shares = []

    for _ in range(num_shares - 1):
        shares.append(secrets.randbelow(p))

    shares.append( (value - sum(shares)) % p)

    return shares


def reconstruct(shares: list[int], p: int) -> int:
    """
    Reconstruct the original value from all shares: sum(shares) mod p.

    Helper for tests and the verification step. In the real system no single
    node should ever hold all shares -- otherwise there is no privacy. This
    is used only for round-trip checks.

    """
    return (sum(shares) % p)

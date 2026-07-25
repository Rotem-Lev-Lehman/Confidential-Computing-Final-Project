"""
share_reduction.py
==================
Phase 2: reduce the 4-node network to the 2 parties the Garbled Circuit needs.

WHY THIS EXISTS
---------------
Phase 3 (Yao's Garbled Circuit) is a *two-party* protocol: Node 1 (Garbler)
holds ``A``, Node 2 (Evaluator) holds ``B``, and the circuit checks
``A + B > threshold``.  The circuit adds ``A`` and ``B`` as plain integers.

Phase 1's secure sum works modulo ``p``.  Naively handing the GC engine two
consolidated mod-p shares does NOT work: if ``s_i`` are the four mod-p shares of
the true count ``T``, then

    A = (s1 + s3) mod p,   B = (s2 + s4) mod p
    =>  A + B == T   OR   A + B == T + p     (as integers)

and in practice it is almost always ``T + p`` (measured: 100% of random trials),
which silently flips the threshold result.  Resolving *which* case holds would
itself require a secure comparison — exactly the thing the GC is there to do.

THE FIX IMPLEMENTED HERE (option "b" agreed with the GC layer's author)
-----------------------------------------------------------------------
Phase 2 does a fresh **2-party additive re-sharing over the integers**, so
reconstruction is exact and the GC circuit needs no modular reduction at all.

For each region, every node ``i`` splits its own local count ``v_i`` into

    a_i = uniform random in [0, M)          -> sent to Node 1
    b_i = v_i - a_i + M                     -> sent to Node 2

Both parts are non-negative (``a_i < M``, so ``b_i >= v_i > -1``), and summing
over all ``n`` nodes gives

    A + B = sum(v_i) + n*M = T + n*M

i.e. an *exact* integer reconstruction, offset by the public constant ``n*M``.

THE OFFSET IS FREE
------------------
The GC circuit takes ``threshold`` as a **public** parameter, so we simply hand
it ``threshold + n*M``:

    (A + B) > (threshold + n*M)   <=>   T > threshold

The circuit source is untouched — only a public number changes.

PRIVACY
-------
* Node 1 sees only the ``a_i`` values, each drawn uniformly from ``[0, M)``
  independently of ``v_i`` — they carry zero information about the counts.
* Node 2 sees only ``b_i = v_i - a_i + M``, uniform over ``(v_i, v_i + M]``.
  Its statistical distance from uniform over ``(0, M]`` is ``v_i / M``; with the
  default ``MASK_BITS = 40`` and realistic counts (< 2^16) that is about 2^-24.
  This is *statistical* hiding rather than the information-theoretic hiding of
  Phase 1's mod-p sharing — the standard, documented trade for exact integer
  reconstruction.  Raise ``mask_bits`` to shrink it further.
* Neither party alone can reconstruct ``T``; only ``A + B`` reveals it, and that
  sum is never formed outside the garbled circuit.

RELATIONSHIP TO PHASE 1
-----------------------
Phase 1's mod-p secure sum is still run and still meaningful: it is the 4-party
additive-secret-sharing deliverable, and :func:`verify_against_phase1` uses its
result to cross-check this phase.  Phase 2 re-shares from the local vectors
because, as shown above, exact integer shares cannot be derived from mod-p
shares without a secure comparison.
"""

from __future__ import annotations

import secrets

#: Bits of randomness masking each local count.  The per-share statistical
#: leakage is about ``max_count / 2**MASK_BITS``.
MASK_BITS = 40

#: Node ids of the two parties the Garbled Circuit runs between.
GARBLER_ID = 1  # holds A (party 0)
EVALUATOR_ID = 2  # holds B (party 1)


def offset(num_nodes: int, mask_bits: int = MASK_BITS) -> int:
    """The public constant by which ``A + B`` exceeds the true count."""
    return num_nodes * (1 << mask_bits)


def shifted_threshold(threshold: int, num_nodes: int, mask_bits: int = MASK_BITS) -> int:
    """Public threshold to hand the GC engine, accounting for the offset."""
    return threshold + offset(num_nodes, mask_bits)


def required_bit_length(num_nodes: int, mask_bits: int = MASK_BITS, headroom: int = 4) -> int:
    """Smallest safe ``bit_length`` for the GC circuit given the offset."""
    return (num_nodes << mask_bits).bit_length() + headroom


def split_for_two(value: int, mask_bits: int = MASK_BITS) -> tuple[int, int]:
    """Split one non-negative ``value`` into two non-negative integer shares.

    Returns ``(a, b)`` with ``a + b == value + 2**mask_bits``.  ``a`` is uniform
    in ``[0, 2**mask_bits)`` and independent of ``value``; ``b`` absorbs the
    remainder plus the mask so it stays non-negative.

    Uses :mod:`secrets` (CSPRNG), not :mod:`random`: these shares are the
    privacy guarantee, and a predictable PRNG would let a party recover the
    other's inputs.
    """
    if value < 0:
        raise ValueError(f"cannot split negative value {value}")
    M = 1 << mask_bits
    a = secrets.randbelow(M)
    b = value - a + M
    return a, b


def split_vector_for_two(
    V: list[int], mask_bits: int = MASK_BITS
) -> tuple[list[int], list[int]]:
    """Apply :func:`split_for_two` element-wise to a whole region vector."""
    pairs = [split_for_two(v, mask_bits) for v in V]
    a_vec = [a for a, _ in pairs]
    b_vec = [b for _, b in pairs]
    return a_vec, b_vec


def add_vectors(vectors: list[list[int]]) -> list[int]:
    """Element-wise integer sum of equal-length vectors (no modulus)."""
    if not vectors:
        raise ValueError("add_vectors got no vectors")
    M = len(vectors[0])
    if not all(len(v) == M for v in vectors):
        raise ValueError(
            "vectors have mismatched lengths -- a message was dropped or duplicated"
        )
    return [sum(vec[j] for vec in vectors) for j in range(M)]


# ---------------------------------------------------------------------------
# Networked protocol
# ---------------------------------------------------------------------------

#: Message key for Phase 2 traffic, kept distinct from Phase 1's ``"shares"``
#: so the two phases never consume each other's messages from the shared inbox.
REDUCE_KEY = "reduce"


def collect_tagged(inbox, key: str, num_expected: int) -> list:
    """Pull ``num_expected`` messages carrying ``key`` from the inbox.

    Messages that do not carry ``key`` (e.g. a fast peer's Phase 2 message
    arriving while we are still finishing Phase 1) are held aside and put back
    afterwards, so no message is ever lost between phases.
    """
    collected: list = []
    holdover: list = []
    while len(collected) < num_expected:
        msg = inbox.get()
        if isinstance(msg, dict) and key in msg:
            collected.append(msg[key])
        else:
            holdover.append(msg)
    for msg in holdover:
        inbox.put(msg)
    return collected


def run_share_reduction(
    node_id: int,
    node,
    V: list[int],
    node_ids: list[int],
    mask_bits: int = MASK_BITS,
) -> list[int] | None:
    """Run Phase 2 for this node.

    Every node splits its local vector and sends one half to the Garbler and the
    other to the Evaluator.  Nodes 1 and 2 additionally collect and sum what
    they receive.

    Args:
        node_id: this node's id.
        node: the transport (needs ``.send(peer_id, dict)`` and ``.inbox``).
        V: this node's local region vector (non-negative counts).
        node_ids: all participating node ids.
        mask_bits: masking strength (see :data:`MASK_BITS`).

    Returns:
        ``A`` on the Garbler, ``B`` on the Evaluator, ``None`` on other nodes
        (they only contribute and then drop out of the protocol).
    """
    a_vec, b_vec = split_vector_for_two(V, mask_bits)

    # Send each half to its destination; keep our own half locally.
    own_parts: list[list[int]] = []
    for target, vec in ((GARBLER_ID, a_vec), (EVALUATOR_ID, b_vec)):
        if target == node_id:
            own_parts.append(vec)
        else:
            node.send(target, {REDUCE_KEY: vec, "from": node_id})

    if node_id not in (GARBLER_ID, EVALUATOR_ID):
        return None

    # Nodes 1 and 2 gather one vector from every *other* node.
    received = collect_tagged(node.inbox, REDUCE_KEY, num_expected=len(node_ids) - 1)
    return add_vectors(own_parts + received)


def verify_against_phase1(
    A: list[int], B: list[int], phase1_global: list[int], p: int, num_nodes: int,
    mask_bits: int = MASK_BITS,
) -> bool:
    """Cross-check Phase 2 against Phase 1's mod-p result.

    ``A + B - offset`` should equal Phase 1's reconstructed global vector
    (mod ``p``).  Only usable in tests/simulation, where both are available —
    in the real protocol no single party holds both ``A`` and ``B``.
    """
    off = offset(num_nodes, mask_bits)
    return all(
        (a + b - off) % p == g for a, b, g in zip(A, B, phase1_global)
    )

"""
share_reduction.py
==================
Phase 2: reduce the 4-node network to the 2 parties the Garbled Circuit needs.

WHERE THIS FITS
---------------
Phase 1 leaves every node holding one additive share, over 𝔽ₚ, of the Global
Region Vector.  Phase 3 (Yao's Garbled Circuit) is a *two-party* protocol.  This
module is the bridge the proposal calls "Protocol Switching & Share Migration":

    Nodes 3 and 4 mathematically mask and send their algebraic shares to
    Nodes 1 and 2.  This leaves Node 1 holding a single consolidated value (A)
    and Node 2 holding a single consolidated value (B), such that
    A + B = True Regional Case Count (mod p).

That is exactly what :func:`run_share_reduction` does, and it consumes Phase 1's
output rather than re-deriving anything from the raw local vectors.

WHY THE SHARES ARE ALREADY MASKED
---------------------------------
A Phase 1 share ``G_i`` is uniform over 𝔽ₚ on its own -- that is the whole point
of additive secret sharing -- so node 3 does not need to add anything before
sending ``G_3`` to node 1.  Node 1 learns a uniformly random field element and
nothing else; the masking the proposal asks for is already inherent in the
share.  Consolidation is then a single modular addition:

    A = (G_1 + G_3) mod p        (held by Node 1, the Garbler,   party 0)
    B = (G_2 + G_4) mod p        (held by Node 2, the Evaluator, party 1)
    A + B ≡ T  (mod p)

PRIVACY
-------
Information-theoretic, inherited unchanged from Phase 1.  Each of ``A`` and
``B`` is uniform over 𝔽ₚ taken alone, so neither party learns anything about the
counts; only their sum carries information, and that sum is never formed outside
the garbled circuit.  This is strictly stronger than a statistical masking
scheme, and it is available precisely because the reduction stays in the field.

See ``THREAT_MODEL.md`` §3 for the full statement of what this phase hides.

THE MODULAR RECONSTRUCTION, AND WHERE IT IS RESOLVED
----------------------------------------------------
Because the field wraps, ``A + B`` over the *integers* is either ``T`` or
``T + p``:

    A, B ∈ [0, p)  =>  A + B ∈ [0, 2p)  and  A + B ≡ T (mod p)

Deciding which case holds is itself a comparison on secret data, so it cannot be
done in the clear here.  It is done *inside* the garbled circuit instead: the
circuit takes ``modulus=p`` as a public parameter and performs one conditional
subtraction (``S >= p ? S - p : S``) between its adder and its comparator.  See
:func:`smpc_gc.yao.circuit.build_threshold_circuit`.

The cost is small and is repaid immediately: the shares are ``p.bit_length()``
bits wide (20 for the configured p) instead of the 47 an integer-masking scheme
would need, and base OT cost is linear in that width.
"""

from __future__ import annotations

#: Node ids of the two parties the Garbled Circuit runs between.
GARBLER_ID = 1  # holds A (party 0)
EVALUATOR_ID = 2  # holds B (party 1)

#: Message phase tag for Phase 2 traffic, kept distinct from Phase 1's so the
#: two phases can never consume each other's messages from the shared inbox.
REDUCE_PHASE = "reduce"


def target_party(node_id: int, node_ids: list[int]) -> int:
    """Which of the two parties a node contributes its Phase 1 share to.

    Nodes 1 and 2 keep their own share.  The remaining nodes are dealt
    alternately to the Garbler and the Evaluator, so the two parties stay
    balanced for any node count (with the proposal's four nodes this is
    exactly "node 3 -> node 1, node 4 -> node 2").
    """
    if node_id in (GARBLER_ID, EVALUATOR_ID):
        return node_id
    extras = [n for n in sorted(node_ids) if n not in (GARBLER_ID, EVALUATOR_ID)]
    return GARBLER_ID if extras.index(node_id) % 2 == 0 else EVALUATOR_ID


def expected_contributors(party_id: int, node_ids: list[int]) -> list[int]:
    """The node ids whose shares ``party_id`` must receive (excluding itself)."""
    return [
        n for n in sorted(node_ids)
        if n != party_id and target_party(n, node_ids) == party_id
    ]


def consolidate(share_vectors: list[list[int]], p: int) -> list[int]:
    """Element-wise modular sum of the share vectors one party ends up holding.

    Raises:
        ValueError: on empty input or mismatched lengths, which would mean a
            message was dropped or duplicated upstream.
    """
    if not share_vectors:
        raise ValueError("consolidate got no share vectors")
    width = len(share_vectors[0])
    if not all(len(v) == width for v in share_vectors):
        raise ValueError(
            "share vectors have mismatched lengths -- "
            "a message was dropped or duplicated upstream"
        )
    return [
        sum(vec[j] for vec in share_vectors) % p for j in range(width)
    ]


def required_bit_length(p: int) -> int:
    """Share width the GC circuit needs for shares reduced mod ``p``."""
    return p.bit_length()


# ---------------------------------------------------------------------------
# Networked protocol
# ---------------------------------------------------------------------------


def run_share_reduction(
    node_id: int,
    node,
    phase1_share: list[int],
    node_ids: list[int],
    p: int,
    timeout: float | None = None,
) -> list[int] | None:
    """Run Phase 2 for this node, consuming its Phase 1 output.

    Args:
        node_id: this node's id.
        node: the transport (needs ``.send(peer_id, phase, payload)`` and
            ``.collect(phase, senders, timeout)``).
        phase1_share: this node's share of the Global Region Vector from Phase 1.
        node_ids: all participating node ids.
        p: the public prime modulus.
        timeout: seconds to wait for each expected peer.

    Returns:
        ``A`` on the Garbler, ``B`` on the Evaluator, ``None`` on every other
        node -- they contribute their share and then drop out of the protocol.
    """
    destination = target_party(node_id, node_ids)
    if destination != node_id:
        node.send(destination, REDUCE_PHASE, {"share": list(phase1_share)})
        return None

    contributors = expected_contributors(node_id, node_ids)
    received = node.collect(REDUCE_PHASE, contributors, timeout=timeout)
    return consolidate(
        [phase1_share] + [received[peer]["share"] for peer in contributors], p
    )


def verify_against_phase1(
    A: list[int], B: list[int], phase1_global: list[int], p: int
) -> bool:
    """Cross-check that ``A + B`` reconstructs Phase 1's global vector mod ``p``.

    Only usable in tests/simulation, where both consolidated vectors are
    available -- in the real protocol no single party holds both.
    """
    return all((a + b) % p == g for a, b, g in zip(A, B, phase1_global))

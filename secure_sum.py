"""
secure_sum.py
=============
Phase 1: the 4-node secure sum (vectorize -> secret-share -> exchange -> sum).

Each node computes its local region vector V, additively secret-shares every
element across the other nodes, and locally sums the shares it receives. No
node ever learns another node's raw V; each ends up holding one share of the
Global Region Vector.

Each node is launched separately (see main.py) with its node id, the path to
its local records file, and the path to its own Ed25519 private signing key
(keys/node<N>.key, never committed). The matching public keys are published in
config.json, so SIGMA authenticates which specific node each peer is.

Transport contract (node.py):
    node.send(peer_id, message: dict)   -- sends a JSON-able dict to peer_id
    node.inbox                          -- queue.Queue of incoming messages;
                                           .get() blocks until one arrives
"""

from secret_sharing import split_into_shares


def compute_local_shares(
    V: list[int], p: int, node_ids: list[int]
) -> dict[int, list[int]]:
    """
    Secret-share every element of the local vector V across all nodes.

    Args:
        V:        this node's local histogram vector, already reduced mod p.
        p:        the public prime modulus.
        node_ids: all participating node ids; len(node_ids) == num_shares.

    Returns:
        node_id -> that node's list of M shares (one per region, in order).

    The position of a share in the list returned by split_into_shares maps to
    node_ids[i] by index. That mapping must be identical on every node, or one
    node's share for a peer lands in the wrong bucket; node_ids is sorted by
    the caller to guarantee it.
    """
    result: dict[int, list[int]] = {node_id: [] for node_id in node_ids}

    for value in V:
        shares = split_into_shares(value, p, len(node_ids))
        for node_id, share in zip(node_ids, shares):
            result[node_id].append(share)

    return result


def distribute_shares(
    my_node_id: int,
    shares_by_peer: dict[int, list[int]],
    send_fn,
) -> list[int]:
    """
    Send each peer its share vector and keep this node's own share locally.

    Args:
        my_node_id:     this node's id.
        shares_by_peer: output of compute_local_shares().
        send_fn:        callable(peer_id, message_dict) -- node.send in practice.

    Returns:
        This node's own share vector, which is never sent over the network.
    """
    my_share = None

    for peer_id, share_vector in shares_by_peer.items():
        if peer_id == my_node_id:
            my_share = share_vector
            continue
        send_fn(peer_id, {"shares": share_vector})

    if my_share is None:
        raise ValueError(f"node {my_node_id} has no share of its own vector")

    return my_share


def collect_shares(inbox, num_expected: int) -> list[list[int]]:
    """
    Block until this node has received share vectors from all other peers.

    Args:
        inbox:        the node's inbox queue.
        num_expected: how many share vectors to wait for (num_nodes - 1).

    Returns:
        The received share vectors, each of length M.

    The inbox is shared across protocol phases, so a message that is not a
    Phase 1 share (a peer that finished early and already sent its Phase 2
    message) is held aside and put back before returning. Discarding it would
    lose that peer's contribution permanently and deadlock the next phase.
    """
    result = []
    holdover = []

    while len(result) < num_expected:
        msg = inbox.get()
        if "shares" in msg:
            result.append(msg["shares"])
        else:
            holdover.append(msg)

    for msg in holdover:
        inbox.put(msg)

    return result


def local_sum(all_share_vectors: list[list[int]], p: int) -> list[int]:
    """
    Element-wise modular sum of this node's own share and every share received.

    This is the homomorphic step: additive shares add without any further
    communication, so each node computes its part of the Global Region Vector
    locally.

    Args:
        all_share_vectors: this node's own share plus every received share.
        p: the public prime modulus.

    Returns:
        list[int] of length M -- this node's share of the Global Region Vector.

    Raises:
        ValueError: on empty input or mismatched lengths, which would mean a
            message was dropped or duplicated upstream.
    """
    if not all_share_vectors:
        raise ValueError("local_sum got no share vectors")

    M = len(all_share_vectors[0])
    if not all(len(v) == M for v in all_share_vectors):
        raise ValueError(
            "share vectors have mismatched lengths -- "
            "a message was dropped or duplicated upstream"
        )

    result = [0] * M
    for share_vector in all_share_vectors:
        for j in range(M):
            result[j] = (result[j] + share_vector[j]) % p
    return result


def run_secure_sum(
    node_id: int, node, V: list[int], p: int, node_ids: list[int]
) -> list[int]:
    """
    Run one node's part of Phase 1 and return its share of the global vector.
    """
    shares_by_peer = compute_local_shares(V, p, node_ids)
    my_share = distribute_shares(node_id, shares_by_peer, node.send)
    received = collect_shares(node.inbox, num_expected=len(node_ids) - 1)
    return local_sum([my_share] + received, p)


def reconstruct_global(local_results: list[list[int]], p: int) -> list[int]:
    """
    Reconstruct the true Global Region Vector from every node's local result.

    Not part of the protocol -- no single node holds all the local results.
    Used to verify Phase 1 correctness in tests.
    """
    return local_sum(local_results, p)

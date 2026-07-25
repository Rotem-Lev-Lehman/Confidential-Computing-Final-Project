"""
secure_sum.py
=============
Task 6: Wire together vectorize -> split_into_shares -> network -> local sum.

This is the orchestration layer for Phase 1 of the protocol (see proposal.md):
each of the 4 nodes computes its local vector V, secret-shares every element
of V across the other 3 nodes, and then locally sums whatever shares it
receives. No node ever learns another node's raw V -- only the final
per-index sum is ever reconstructed (and only in Phase 3, by 2 nodes, via
the Garbled Circuit).

ASSUMPTIONS ABOUT node.py:
  - Node(node_id, config) or similar constructor
  - node.start_listener()                    -- begins listening for peers
  - node.connect_to_peer(peer_id)            -- opens a connection to peer_id
  - node.send(peer_id, message: dict)        -- sends a JSON-able dict to peer_id
  - node.inbox                               -- a queue.Queue() of incoming
                                                 messages; node.inbox.get()
                                                 blocks until a message arrives
  - split_into_shares(value, p, num_shares)  -- from secret_sharing.py
                                                 
"""
# Each node is launched separately (main.py) with: its node_id, a path to
# its local records file, and the shared PSK (loaded from env/file, NOT
# committed to git). Authentication uses a PSK + HMAC SIGMA variant, so there
# are no per-node private/public key pairs.
from secret_sharing import split_into_shares


def compute_local_shares(V: list[int], p: int, node_ids: list[int]) -> dict[int, list[int]]:
    """
    Secret-share every element of the local vector V across all nodes.

    Args:
        V:        this node's local histogram vector (length M), already
                   reduced mod p by vectorize().
        p:        the public prime modulus.
        node_ids: the full list of participating node ids, e.g. [1, 2, 3, 4].
                   len(node_ids) == num_shares.

    Returns:
        A dict mapping each node_id -> that node's list of M shares
        (one share per region/index in V).

        Example shape (M=3, 4 nodes):
        {
          1: [s0_for_node1, s1_for_node1, s2_for_node1],
          2: [s0_for_node2, s1_for_node2, s2_for_node2],
          3: [...],
          4: [...],
        }

    -------------------------------------------------------------------
    TODO 1: For each index j in V (0..M-1):
              - call split_into_shares(V[j], p, num_shares=len(node_ids))
                -> this returns a list of len(node_ids) shares for V[j]
              - shares[k] is the share destined for node_ids[k]
              - append shares[k] into result[node_ids[k]]

            EDGE CASE: the mapping between "position in the returned
            shares list" and "which node_id it goes to" must be
            consistent across all 4 hospitals -- otherwise you'll add
            node A's share for node B's slot into the wrong bucket.
            Pin it down explicitly: shares[i] always goes to node_ids[i]
            (sorted node_ids, e.g. [1,2,3,4]), not any other order.
    -------------------------------------------------------------------
    """
    result = {}
    for id_ in node_ids:
        result[id_] = []

    for val in V:
        shares = split_into_shares(val, p)
        for id_, share in zip(node_ids, shares):
            result[id_].append(share)

    return result


def distribute_shares(
    my_node_id: int,
    shares_by_peer: dict[int, list[int]],
    send_fn,
) -> list[int]:
    """
    Send each peer its share vector, and keep this node's own share locally.

    Args:
        my_node_id:     this node's own id.
        shares_by_peer: output of compute_local_shares() -- node_id -> shares.
        send_fn:        callable(peer_id: int, message: dict) -> None.
                         In the real system this is node.send.

    Returns:
        This node's own share vector (the one it does NOT send over the
        network, because it's already local).

    -------------------------------------------------------------------
    TODO 2: For each (peer_id, share_vector) in shares_by_peer.items():
              - EDGE CASE: if peer_id == my_node_id, do NOT send it over
                the network -- this is this node's own share, keep it
                and return it separately (no self-message).
              - else: call send_fn(peer_id, {"shares": share_vector})
                (wrap in a dict so it round-trips cleanly as JSON --
                match whatever message framing node.py expects)
    TODO 3: Return the local share vector for my_node_id.
    -------------------------------------------------------------------
    """
    my_shareVec = None

    for peer_id, share_vector in shares_by_peer.items():
        if peer_id == my_node_id:
            my_shareVec = share_vector
            continue

        send_fn(peer_id, {"shares": share_vector})
    
    if my_shareVec is None:
        raise ValueError(f"my_node_id {my_node_id} not found in shares_by_peer")

    return my_shareVec


def collect_shares(inbox, num_expected: int) -> list[list[int]]:
    """
    Block until this node has received share vectors from all other peers.

    Args:
        inbox:        the node's inbox (e.g. a queue.Queue()).
        num_expected: how many incoming share vectors to wait for
                       (num_nodes - 1, since we don't message ourselves).

    Returns:
        A list of received share vectors (each itself a list[int] of length M).

    -------------------------------------------------------------------
    TODO 4: Loop num_expected times:
              - msg = inbox.get()   (this blocks until something arrives --
                that's *why* Queue was chosen over a manual wait/Event)
              - extract the share vector from msg (msg["shares"], matching
                the wrapping used in distribute_shares)
              - append it to the results list

            EDGE CASE: what if a message arrives that ISN'T a share
            message (e.g. some other protocol message got mixed into the
            same inbox)? Decide now: either assume the inbox is
            phase-scoped (only share messages arrive during this call),
            or check a "type" field and skip/requeue anything else.
            Document whichever assumption you pick as a comment --
            don't leave it implicit.
    -------------------------------------------------------------------

    ASSUMPTION: the inbox is shared across protocol phases, so a message that
    is not a Phase 1 share (e.g. a fast peer's Phase 2 message arriving while we
    are still collecting here) must NOT be dropped -- it is held aside and put
    back before returning.  Discarding it instead would lose that peer's Phase 2
    contribution permanently and deadlock the next phase.
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
    Sum this node's own share vector together with all received share
    vectors, element-wise, mod p. This is the homomorphic step: no
    network communication needed, because addition of shares commutes
    with the secret sharing.

    Args:
        all_share_vectors: list of share vectors (this node's own local
                            share, plus every received share) -- all the
                            same length M.
        p: the public prime modulus.

    Returns:
        list[int] of length M -- this node's contribution to the Global
        Region Vector G (see proposal.md Phase 1, step 3).

    -------------------------------------------------------------------
    TODO 5: EDGE CASE: guard against empty input or mismatched lengths
            before summing -- a length mismatch here means a bug
            upstream (dropped or duplicated message) and should be
            caught loudly, not silently zero-padded.
            assert all(len(v) == len(all_share_vectors[0]) for v in all_share_vectors)

    TODO 6: M = len(all_share_vectors[0])
            result = [0] * M
            for share_vector in all_share_vectors:
                for j in range(M):
                    result[j] = (result[j] + share_vector[j]) % p
            return result
    -------------------------------------------------------------------
    """
    if not all_share_vectors:
        raise ValueError("local_sum got no share vectors")

    M = len(all_share_vectors[0])
    if not all(len(v) == M for v in all_share_vectors):
        raise ValueError("share vectors have mismatched lengths -- dropped/duplicated message upstream")

    result = [0] * M
    for share_vector in all_share_vectors:
        for j in range(M):
            result[j] = (result[j] + share_vector[j]) % p
    return result


def run_secure_sum(node_id: int, node, V: list[int], p: int, node_ids: list[int]) -> list[int]:
    """
    Top-level orchestration for one node's participation in Phase 1.

    This ties together every function above in order. Fill in the TODOs
    above first -- this function should need little to no editing once
    they're done, it's just the call sequence.

    -------------------------------------------------------------------
    TODO 7: shares_by_peer = compute_local_shares(V, p, node_ids)
    TODO 8: my_share = distribute_shares(node_id, shares_by_peer, node.send)
    TODO 9: received = collect_shares(node.inbox, num_expected=len(node_ids) - 1)
    TODO 10: return local_sum([my_share] + received, p)
    -------------------------------------------------------------------
    """
    shares_by_peer = compute_local_shares(V, p, node_ids)
    my_share = distribute_shares(node_id, shares_by_peer, node.send)
    received = collect_shares(node.inbox, num_expected=len(node_ids) - 1)
    return local_sum([my_share] + received, p)


def reconstruct_global(local_results: list[list[int]], p: int) -> list[int]:
    """
    Reconstruct the true Global Region Vector from every node's local_sum
    result. In the real protocol this is NOT done by any single node (Phase 3
    does the threshold check on secret shares) -- this helper exists only to
    verify Phase 1's correctness in tests.
    """
    return local_sum(local_results, p)


if __name__ == "__main__":
    # In-process 4-node simulation (no networking) -- verifies Phase 1 math.
    p = 1048573
    node_ids = [1, 2, 3, 4]

    local_vectors = {
        1: [10, 5],
        2: [3, 20],
        3: [0, 1],
        4: [7, 4],
    }
    true_sum = [20, 30]  # [10+3+0+7, 5+20+1+4]

    # 1. every node splits its vector into shares for each peer
    all_shares = {nid: compute_local_shares(local_vectors[nid], p, node_ids)
                  for nid in node_ids}

    # 2. simulate delivery: node nid "receives" all_shares[other][nid]
    local_results = []
    for nid in node_ids:
        my_share = all_shares[nid][nid]
        received = [all_shares[other][nid] for other in node_ids if other != nid]
        local_results.append(local_sum([my_share] + received, p))

    # 3. reconstruct and compare
    G = reconstruct_global(local_results, p)
    print("Reconstructed global vector:", G)
    print("Expected:                   ", true_sum)
    assert G == true_sum, f"MISMATCH: got {G}, expected {true_sum}"
    print("PASS: Phase 1 secure-sum math is correct end-to-end.")

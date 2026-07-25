"""
main.py
=======
Per-node entry point for the Secure COVID-19 Alert System (Phase 1: Secure Sum).

Each of the 4 hospital nodes runs this file as its own process:

    python main.py --node-id 1 --records data/hospital1.txt
    python main.py --node-id 2 --records data/hospital2.txt
    ...

Each node authenticates with its OWN Ed25519 identity key, read from
keys/node<N>.key (never committed). The matching public keys live in
config.json. There is no shared secret.

Flow per node:
  1. load config (public: p, regions, node addresses)
  2. build a Node with this node's private identity key
  3. start listening, then SIGMA-handshake-connect to every peer
  4. read local records -> vectorize into V
  5. run the secure sum -> this node's share of the Global Region Vector
  6. print the local result (Phase 2/3 will consume the shares later)
"""

import sys
import time
import argparse
from pathlib import Path

from config_loader import load_config
from sigma_handshake import load_signing_key
from vectorize import vectorize
from secure_sum import run_secure_sum
from share_reduction import GARBLER_ID, EVALUATOR_ID, run_share_reduction
from gc_handoff import region_ids_from_config, write_problem
from node import Node


def config_to_node_dict(config) -> dict[int, dict]:
    """
    Bridge the config_loader dataclass to the plain dict shape node.py expects.

    config_loader returns Config(nodes={id: NodeConfig(...)}), but Node indexes
    config[node_id]['host']. This adapter keeps both layers unchanged and
    converts between them in one place.
    """
    return {
        nid: {"host": nc.host, "port": nc.port, "public_key": nc.public_key}
        for nid, nc in config.nodes.items()
    }


def load_records(path: str) -> list[str]:
    """
    Load this hospital's local records: one region label per line (one line
    per positive case). Blank lines are ignored.
    """
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def load_identity_key(node_id: int, key_path: str | None):
    """Load this node's PRIVATE Ed25519 signing key.

    Each node has its own key -- there is no shared secret. Generate them with
    keygen.py; the matching public keys live in config.json.
    """
    path = Path(key_path) if key_path else Path("keys") / f"node{node_id}.key"
    if not path.exists():
        print(
            f"ERROR: signing key not found at {path}\n"
            "Generate the identity keys first:\n"
            "  python3 keygen.py\n"
            "then paste the printed public keys into config.json.",
            file=sys.stderr,
        )
        sys.exit(1)
    return load_signing_key(path)


def main():
    parser = argparse.ArgumentParser(description="Secure Sum hospital node")
    parser.add_argument("--node-id", type=int, required=True, help="this node's id (1..4)")
    parser.add_argument("--records", type=str, required=True, help="path to local records file")
    parser.add_argument("--key", type=str, default=None,
                        help="path to this node's private signing key "
                             "(default: keys/node<ID>.key)")
    parser.add_argument("--connect-delay", type=float, default=1.0,
                        help="seconds to wait for peers' listeners before connecting")
    parser.add_argument("--threshold", type=int, default=50,
                        help="quarantine threshold (a region crosses when count > threshold)")
    parser.add_argument("--gc-out", type=str, default="gc_input",
                        help="directory for the Garbled Circuit problem file (nodes 1 and 2)")
    args = parser.parse_args()

    config = load_config()
    p = config.p
    regions = config.regions
    node_ids = sorted(config.nodes.keys())
    num_nodes = len(node_ids)
    signing_key = load_identity_key(args.node_id, args.key)

    if args.node_id not in node_ids:
        print(f"ERROR: node-id {args.node_id} not in config nodes {node_ids}", file=sys.stderr)
        sys.exit(1)

    # 1-2. build the node
    node = Node(args.node_id, config_to_node_dict(config), signing_key, num_nodes)

    # 3. start listening, give peers a moment to come up, then connect to all
    node.start_listener()
    print(f"[node {args.node_id}] listening on {node.host}:{node.port}")
    time.sleep(args.connect_delay)

    for peer_id in sorted(node.peers):
        node.connect_to_peer(peer_id)
    print(f"[node {args.node_id}] connected + SIGMA handshake done with all peers")

    # 4. read local records and vectorize
    records = load_records(args.records)
    V = vectorize(records, regions, p)
    print(f"[node {args.node_id}] local vector (len {len(V)}) computed from {len(records)} records")

    # 5. run the secure sum
    local_result = run_secure_sum(args.node_id, node, V, p, node_ids)

    # 6. output this node's share of the Global Region Vector
    print(f"[node {args.node_id}] local share of global vector: {local_result}")

    # 7. Phase 2: reduce the 4 nodes to the 2 parties the Garbled Circuit needs.
    #    Every node contributes; only nodes 1 and 2 end up holding a vector.
    reduced = run_share_reduction(args.node_id, node, V, node_ids)
    if reduced is None:
        print(f"[node {args.node_id}] contributed to share reduction; done")
        return

    # 8. Write the problem file for the GC layer.  Node 1 is the Garbler
    #    (party 0, holds A); Node 2 is the Evaluator (party 1, holds B).
    party = 0 if args.node_id == GARBLER_ID else 1
    letter = "A" if party == 0 else "B"
    out_path = f"{args.gc_out}/problem_{letter}.json"
    write_problem(
        out_path,
        party=party,
        shares=reduced,
        region_ids=region_ids_from_config(regions),
        threshold=args.threshold,
        num_nodes=num_nodes,
    )
    print(f"[node {args.node_id}] party {party} holds {letter}; wrote {out_path}")


if __name__ == "__main__":
    main()

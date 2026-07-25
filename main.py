"""
main.py
=======
Per-node entry point for the Secure COVID-19 Alert System (Phase 1: Secure Sum).

Each of the 4 hospital nodes runs this file as its own process:

    python main.py --node-id 1 --records data/hospital1.txt
    python main.py --node-id 2 --records data/hospital2.txt
    ...

The shared PSK is read from the HOSPITAL_PSK environment variable (never
committed to git). All 4 nodes must use the same PSK.

Flow per node:
  1. load config (public: p, regions, node addresses)
  2. build a Node with the shared PSK
  3. start listening, then SIGMA-handshake-connect to every peer
  4. read local records -> vectorize into V
  5. run the secure sum -> this node's share of the Global Region Vector
  6. print the local result (Phase 2/3 will consume the shares later)
"""

import os
import sys
import time
import argparse

from config_loader import load_config
from vectorize import vectorize
from secure_sum import run_secure_sum
from share_reduction import GARBLER_ID, EVALUATOR_ID, run_share_reduction
from gc_handoff import region_ids_from_config, write_problem
from node import Node


def config_to_node_dict(config) -> dict[int, dict]:
    """
    Bridge the config_loader dataclass to the plain dict shape node.py expects.

    config_loader returns Config(nodes={id: NodeConfig(host, port)}), but
    Node indexes config[node_id]['host']. This adapter keeps both layers
    unchanged and converts between them in one place.
    """
    return {nid: {"host": nc.host, "port": nc.port} for nid, nc in config.nodes.items()}


def load_records(path: str) -> list[str]:
    """
    Load this hospital's local records: one region label per line (one line
    per positive case). Blank lines are ignored.
    """
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def load_psk() -> bytes:
    """Read the shared PSK from the environment. Fail loudly if missing."""
    psk = os.environ.get("HOSPITAL_PSK")
    if not psk:
        print(
            "ERROR: HOSPITAL_PSK environment variable not set.\n"
            "All nodes must share the same PSK, e.g.:\n"
            "  export HOSPITAL_PSK='some-long-shared-secret'",
            file=sys.stderr,
        )
        sys.exit(1)
    return psk.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Secure Sum hospital node")
    parser.add_argument("--node-id", type=int, required=True, help="this node's id (1..4)")
    parser.add_argument("--records", type=str, required=True, help="path to local records file")
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
    psk = load_psk()

    if args.node_id not in node_ids:
        print(f"ERROR: node-id {args.node_id} not in config nodes {node_ids}", file=sys.stderr)
        sys.exit(1)

    # 1-2. build the node
    node = Node(args.node_id, config_to_node_dict(config), psk, num_nodes)

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

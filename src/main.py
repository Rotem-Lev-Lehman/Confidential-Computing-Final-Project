"""
main.py
=======
Per-node entry point for the Secure COVID-19 Regional Quarantine Alert System.

Each of the hospital nodes runs this file as its own process::

    uv run python src/main.py --node-id 1 --records data/hospital1.txt
    uv run python src/main.py --node-id 2 --records data/hospital2.txt
    ...

or all of them at once with ``./run_all.sh``.

Each node authenticates with its OWN Ed25519 identity key, read from
``keys/node<N>.key`` (never committed).  The matching public keys live in
``config.json``.  There is no shared secret anywhere in the system.

THE THREE PHASES, END TO END
----------------------------
Phase 1 -- Secure Sum (all nodes).  Each node vectorizes its local records into
    a histogram over the public region list, additively secret-shares every
    element over 𝔽ₚ, and locally sums the shares it receives.  Each node ends up
    holding one share of the Global Region Vector; nobody holds the vector.

Phase 2 -- Share Migration (all nodes).  The extra nodes send their Phase 1
    shares to the two parties the garbled circuit runs between, which
    consolidate them into A (Node 1, Garbler) and B (Node 2, Evaluator) with
    A + B ≡ true count (mod p).

Phase 3 -- Garbled Circuit (nodes 1 and 2).  The two parties run Yao's 2PC over
    the same SIGMA-encrypted link they already share, evaluating for each region

        (A + B mod p) > threshold ? region_id : "Clear"

    Node 2 broadcasts the resulting quarantine alert list.  Sub-threshold
    regions reveal only "Clear" -- never their count.

DEMO NOTE
---------
Run locally, all nodes print to one console, so the transcript shows more than
any single hospital would see in production (where the four nodes run on four
machines under four organizations).  That is deliberate -- it is how the
protocol is demonstrated.  See THREAT_MODEL.md.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from config_loader import CONFIG_PATH, load_config
from gc_channel import make_channel_factory
from gc_handoff import build_problem, region_ids_from_config, write_problem
from node import Node
from secure_sum import run_secure_sum
from share_reduction import EVALUATOR_ID, GARBLER_ID, run_share_reduction
from sigma_handshake import load_signing_key
from vectorize import vectorize


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
    demo_setup.py (or keygen.py); the matching public keys live in config.json.
    """
    path = Path(key_path) if key_path else Path("keys") / f"node{node_id}.key"
    if not path.exists():
        print(
            f"ERROR: signing key not found at {path}\n"
            "Generate the identity keys and matching config first:\n"
            "  uv run python src/demo_setup.py",
            file=sys.stderr,
        )
        sys.exit(1)
    return load_signing_key(path)


def run_phase3(problem, party: int, node: Node, peer_id: int, ot_group: str):
    """Run the 2PC threshold evaluation over *our* encrypted transport.

    The GC engine is handed a ``channel_factory`` and never learns it is talking
    over SIGMA + AES-GCM rather than a bare socket, so Phase 3's garbled tables
    and OT values get exactly the same protection as Phase 1 and Phase 2 traffic.
    """
    from smpc_gc.threshold import evaluate_threshold
    from smpc_gc.yao.ot import GROUPS

    return evaluate_threshold(
        problem,
        party=party,
        group=GROUPS[ot_group],
        channel_factory=make_channel_factory(node, peer_id),
    )


def print_alerts(results, regions: list[str], region_ids: list[int], threshold: int) -> None:
    """Print the public output: the quarantine alert list.

    Sub-threshold regions appear as 'Clear'.  That is the entire public result
    -- their case counts never leave the circuit.
    """
    id_to_label = dict(zip(region_ids, regions))
    print()
    print("=" * 58)
    print(f"  QUARANTINE ALERT  (threshold: more than {threshold} cases)")
    print("=" * 58)
    for r in results:
        label = id_to_label.get(r.region_id, str(r.region_id))
        marker = "QUARANTINE" if r.crossed else "clear"
        print(f"  region {label:>8} (id {r.region_id})  ->  {marker}")
    crossed = [id_to_label.get(r.region_id, r.region_id) for r in results if r.crossed]
    print("-" * 58)
    if crossed:
        print(f"  {len(crossed)} region(s) must be locked down: {', '.join(map(str, crossed))}")
    else:
        print("  No region crossed the threshold.")
    print("=" * 58)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure quarantine-alert hospital node")
    parser.add_argument("--node-id", type=int, required=True, help="this node's id (1..N)")
    parser.add_argument("--records", type=str, required=True, help="path to local records file")
    parser.add_argument("--config", type=str, default=str(CONFIG_PATH),
                        help="path to the public config file")
    parser.add_argument("--key", type=str, default=None,
                        help="path to this node's private signing key "
                             "(default: keys/node<ID>.key)")
    parser.add_argument("--connect-delay", type=float, default=1.0,
                        help="seconds to wait for peers' listeners before connecting")
    parser.add_argument("--threshold", type=int, default=None,
                        help="quarantine threshold (default: the config's)")
    parser.add_argument("--ot-group", choices=("1024", "2048"), default="2048",
                        help="MODP group for the Oblivious Transfer "
                             "(default: 2048; 1024 is ~5x faster but weaker)")
    parser.add_argument("--show-shares", action="store_true",
                        help="DEMO ONLY: print this node's raw share of the global "
                             "vector. Individually meaningless (a share is uniform "
                             "noise), but all nodes' shares together reconstruct "
                             "the true counts -- so only do this on a single-machine "
                             "demo. See THREAT_MODEL.md")
    parser.add_argument("--gc-out", type=str, default=None,
                        help="DEMO ONLY: also dump this party's Phase 2 share vector "
                             "to a JSON file. The two parties' files together "
                             "reconstruct every region's exact count -- see "
                             "THREAT_MODEL.md")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    config = load_config(args.config)
    p = config.p
    regions = config.regions
    node_ids = config.node_ids
    threshold = config.threshold if args.threshold is None else args.threshold
    me = args.node_id

    if me not in node_ids:
        print(f"ERROR: node-id {me} not in config nodes {node_ids}", file=sys.stderr)
        return 1

    signing_key = load_identity_key(me, args.key)
    node = Node(me, config_to_node_dict(config), signing_key, len(node_ids))

    try:
        # --- connect the mesh -------------------------------------------------
        node.start_listener()
        print(f"[node {me}] listening on {node.host}:{node.port}")
        time.sleep(args.connect_delay)
        for peer_id in sorted(node.peers):
            node.connect_to_peer(peer_id)
        print(f"[node {me}] SIGMA handshake done with all {len(node.peers)} peers")

        # --- Phase 1: vectorize, secret-share, sum ---------------------------
        records = load_records(args.records)
        V = vectorize(records, regions, p, config.max_local_count)
        print(f"[node {me}] vectorized {len(records)} records into {len(V)} regions")

        phase1_share = run_secure_sum(me, node, V, p, node_ids)
        print(f"[node {me}] Phase 1 done: holding one share of the global vector")
        if args.show_shares:
            # Uniform over F_p and independent of the counts -- this is what
            # "the node learns nothing" looks like in practice.
            print(f"[node {me}] (demo) my share of the global vector: {phase1_share}")

        # --- Phase 2: migrate the shares to the two 2PC parties --------------
        consolidated = run_share_reduction(me, node, phase1_share, node_ids, p)
        if consolidated is None:
            print(f"[node {me}] Phase 2 done: contributed my share; leaving the protocol")
            return 0

        party = 0 if me == GARBLER_ID else 1
        role = "Garbler (A)" if party == 0 else "Evaluator (B)"
        peer_id = EVALUATOR_ID if party == 0 else GARBLER_ID
        print(f"[node {me}] Phase 2 done: party {party}, {role}")

        # --- Phase 3: the garbled circuit ------------------------------------
        region_ids = region_ids_from_config(regions)
        problem = build_problem(
            party=party,
            shares=consolidated,
            region_ids=region_ids,
            threshold=threshold,
            p=p,
        )
        if args.gc_out:
            out = write_problem(Path(args.gc_out) / f"node{me}" / f"problem_{'AB'[party]}.json", problem)
            print(f"[node {me}] WARNING (demo): wrote my share vector to {out}")

        print(
            f"[node {me}] Phase 3: Yao's garbled circuits with node {peer_id} "
            f"over our SIGMA-encrypted link ({len(region_ids)} regions, "
            f"{problem.bit_length}-bit shares)..."
        )
        results = run_phase3(problem, party, node, peer_id, args.ot_group)
        print(f"[node {me}] Phase 3 done")

        if me == EVALUATOR_ID:
            # The proposal's Phase 3 step 3: Node 2 collects the active hot spot
            # ids and broadcasts the quarantine alert list.
            print_alerts(results, regions, region_ids, threshold)
        return 0
    finally:
        node.close()


if __name__ == "__main__":
    raise SystemExit(main())

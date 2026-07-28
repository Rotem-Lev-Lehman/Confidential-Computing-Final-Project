"""
demo_setup.py
=============
One-shot preparation for a local demo run of the 4-node system.

Three things have to line up before ``main.py`` can run, and all three are
deliberately kept out of git (see ``.gitignore``):

1. **Identity keys.** Each node needs its own Ed25519 private key in
   ``keys/node<N>.key``.  The public halves must be in ``config.json``, or the
   SIGMA handshake correctly refuses to authenticate anybody.
2. **Matching public keys in the config.**  The committed ``config.json`` ships
   placeholder public keys whose private halves nobody has -- that is the point.
   This script regenerates the pair and writes the public halves back.
3. **Hospital records.**  Synthetic per-node record files, one region label per
   line, one line per positive case.

Usage::

    uv run python demo_setup.py                 # keys + config + data
    uv run python demo_setup.py --seed 7        # a different case distribution
    uv run python demo_setup.py --keep-keys     # regenerate data only

The generated case counts are deterministic for a given ``--seed``, so a demo
can be rehearsed and reproduced exactly.  They straddle the quarantine
threshold on purpose, so the run shows both QUARANTINE and clear outcomes.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from keygen import write_keypair

CONFIG_PATH = Path(__file__).parent / "config.json"


def generate_keys(config: dict, out_dir: Path) -> dict[str, str]:
    """Generate one keypair per configured node; return ``{node_id: public_hex}``."""
    return {
        node_id: write_keypair(int(node_id), out_dir)
        for node_id in sorted(config["nodes"], key=int)
    }


def generate_records(
    config: dict, data_dir: Path, seed: int, threshold: int
) -> dict[str, int]:
    """Write one synthetic record file per node; return the true regional totals.

    Per-region totals are drawn to straddle ``threshold`` (some clearly above,
    some clearly below, a few near the boundary) and then split across the
    nodes, so the demo exercises both branches of the circuit.
    """
    rng = random.Random(seed)
    regions: list[str] = config["regions"]
    node_ids = sorted(config["nodes"], key=int)

    totals: dict[str, int] = {}
    per_node: dict[str, list[str]] = {nid: [] for nid in node_ids}
    for region in regions:
        # A third clearly over, a third clearly under, a third near the line.
        bucket = rng.randrange(3)
        if bucket == 0:
            total = rng.randint(threshold + 5, threshold * 2)
        elif bucket == 1:
            total = rng.randint(0, threshold - 10)
        else:
            total = rng.randint(threshold - 3, threshold + 3)
        totals[region] = total

        # Split the total across the nodes at random.
        for _ in range(total):
            per_node[rng.choice(node_ids)].append(region)

    data_dir.mkdir(parents=True, exist_ok=True)
    for nid in node_ids:
        rng.shuffle(per_node[nid])
        path = data_dir / f"hospital{nid}.txt"
        path.write_text("\n".join(per_node[nid]) + "\n")
        path.chmod(0o600)  # stands in for patient data
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a local 4-node demo")
    parser.add_argument("--config", type=str, default=str(CONFIG_PATH))
    parser.add_argument("--key-dir", type=str, default="keys")
    parser.add_argument("--data-dir", type=str, default="data")
    parser.add_argument("--seed", type=int, default=2024,
                        help="RNG seed; same seed -> same case counts")
    parser.add_argument("--threshold", type=int, default=50,
                        help="counts are drawn to straddle this value")
    parser.add_argument("--keep-keys", action="store_true",
                        help="regenerate records only, leave keys/config alone")
    args = parser.parse_args()

    config_path = Path(args.config)
    config = json.loads(config_path.read_text())

    if not args.keep_keys:
        public = generate_keys(config, Path(args.key_dir))
        for node_id, public_hex in public.items():
            config["nodes"][node_id]["public_key"] = public_hex
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        print(f"wrote {len(public)} private keys to {args.key_dir}/ (mode 0600)")
        print(f"wrote the matching public keys into {config_path}")

    totals = generate_records(config, Path(args.data_dir), args.seed, args.threshold)
    print(f"wrote {len(config['nodes'])} record files to {args.data_dir}/")

    crossed = sorted(r for r, t in totals.items() if t > args.threshold)
    print(
        f"\nDemo scenario (seed {args.seed}): {len(crossed)} of {len(totals)} "
        f"regions are over the threshold of {args.threshold}."
    )
    print(f"Expected quarantine regions: {crossed}")


if __name__ == "__main__":
    main()

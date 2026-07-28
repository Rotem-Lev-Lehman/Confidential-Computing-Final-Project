"""
keygen.py
=========
Generate the long-term Ed25519 identity keys used by the SIGMA handshake.

Each hospital node gets its own keypair:

* the **private** key is written to ``keys/node<N>.key`` (hex).  These files are
  secret -- ``keys/`` is gitignored and must never be committed.
* the **public** keys are printed as a JSON block to paste into
  ``config.json``.  They are public by design: every node needs every peer's
  public key to verify its signatures.

Usage::

    uv run python src/keygen.py                 # nodes 1..4 from config.json
    uv run python src/keygen.py --nodes 1 2     # just these nodes
    uv run python src/keygen.py --out-dir keys  # where the private keys go

Most of the time you want ``src/demo_setup.py`` instead: it calls this and
also writes the matching public keys into ``config.json``.

Re-running overwrites existing keys, which invalidates every peer's copy of the
corresponding public key -- so regenerate for all nodes together and update
``config.json`` in the same step.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sigma_handshake import generate_identity_keypair


def write_keypair(node_id: int, out_dir: Path) -> str:
    """Generate one node's keypair; write the private half, return the public."""
    private_bytes, public_bytes = generate_identity_keypair()
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / f"node{node_id}.key"
    key_path.write_text(private_bytes.hex() + "\n")
    key_path.chmod(0o600)  # owner-only, like an SSH private key
    return public_bytes.hex()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SIGMA identity keys")
    parser.add_argument("--nodes", type=int, nargs="*", default=None,
                        help="node ids (default: every node in config.json)")
    parser.add_argument("--out-dir", type=str, default="keys",
                        help="directory for the private key files")
    parser.add_argument("--config", type=str, default="config.json")
    args = parser.parse_args()

    node_ids = args.nodes
    if node_ids is None:
        raw = json.loads(Path(args.config).read_text())
        node_ids = sorted(int(k) for k in raw["nodes"])

    out_dir = Path(args.out_dir)
    public = {str(nid): write_keypair(nid, out_dir) for nid in node_ids}

    print(f"Private keys written to {out_dir}/ (keep secret, do not commit)\n")
    print("Paste each public_key into the matching node in config.json:\n")
    print(json.dumps(public, indent=2))


if __name__ == "__main__":
    main()

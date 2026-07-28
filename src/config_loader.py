"""
config_loader.py
================
Load and validate the public system configuration.

Everything in ``config.json`` is public by design: the field modulus, the region
list, and each node's address and Ed25519 *public* key.  The private keys live
in ``keys/`` and never appear here.

WHY THE VALIDATION IS STRICT
----------------------------
A misconfigured field or a malformed public key is not a cosmetic problem.  If
``p`` is too small the global sum wraps and a region with an outbreak can report
as clear; if a public key is the wrong length the failure used to surface deep
inside the handshake, on another node, as an unexplained authentication error.
Every invariant the protocol depends on is therefore checked once, here, at
startup -- before any node opens a socket.
"""

import json
from dataclasses import dataclass
from pathlib import Path

# The code lives in src/; the config is deployment data and stays at the repo
# root, where an operator expects to find and edit it.
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

#: Length of a raw Ed25519 public key, in hex characters.
_PUBLIC_KEY_HEX_LEN = 64

#: Per-region case count the deployment is sized for, if config.json omits it.
DEFAULT_MAX_LOCAL_COUNT = 65536


@dataclass
class NodeConfig:
    host: str
    port: int
    public_key: str   # hex Ed25519 identity key - public by design


@dataclass
class Config:
    p: int
    vector_size: int
    regions: list[str]
    nodes: dict[int, NodeConfig]
    #: Largest per-region, per-node case count the field is sized for.
    max_local_count: int = DEFAULT_MAX_LOCAL_COUNT
    #: Quarantine threshold; a region crosses when its total is strictly above.
    threshold: int = 50

    @property
    def num_nodes(self) -> int:
        return len(self.nodes)

    @property
    def node_ids(self) -> list[int]:
        return sorted(self.nodes)


def _is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin for every 64-bit n (and correct beyond it).

    The listed bases are a known-complete witness set for n < 3.3e24, which
    covers any modulus this project would use.
    """
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _load_node(node_id: int, node_data: dict) -> NodeConfig:
    for name in ("host", "port", "public_key"):
        _require(
            name in node_data,
            f"Node {node_id} missing {name!r} "
            "(run keygen.py, then paste the public keys into config.json)",
        )

    host = node_data["host"]
    port = node_data["port"]
    public_key = node_data["public_key"]

    _require(isinstance(host, str) and host, f"Node {node_id} has an empty host")
    _require(
        isinstance(port, int) and 1 <= port <= 65535,
        f"Node {node_id} has an invalid port {port!r} (expected 1..65535)",
    )
    _require(
        isinstance(public_key, str) and len(public_key) == _PUBLIC_KEY_HEX_LEN,
        f"Node {node_id} public_key must be {_PUBLIC_KEY_HEX_LEN} hex chars "
        f"(a raw Ed25519 key), got {len(str(public_key))}",
    )
    try:
        bytes.fromhex(public_key)
    except ValueError:
        raise ValueError(f"Node {node_id} public_key is not valid hex") from None

    return NodeConfig(host=host, port=port, public_key=public_key)


def load_config(path: str | Path = CONFIG_PATH) -> Config:
    """
    Load and validate system configuration.

    Args:
        path: Path to config.json

    Returns:
        Config object with validated values.

    Raises:
        ValueError: If configuration invariants are violated.
        FileNotFoundError: If config file does not exist.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = json.loads(config_path.read_text())

    for name in ("p", "vector_size", "regions", "nodes"):
        _require(name in raw, f"Missing required config field: {name}")

    p = raw["p"]
    vector_size = raw["vector_size"]
    regions = raw["regions"]
    max_local_count = raw.get("max_local_count", DEFAULT_MAX_LOCAL_COUNT)
    threshold = raw.get("threshold", 50)

    # --- regions ---
    _require(
        isinstance(regions, list) and all(isinstance(r, str) for r in regions),
        "regions must be a list of strings",
    )
    _require(
        len(regions) == vector_size,
        f"vector_size ({vector_size}) does not match regions count ({len(regions)})",
    )
    _require(len(set(regions)) == len(regions), "Duplicate regions found in configuration")

    # --- nodes ---
    nodes: dict[int, NodeConfig] = {}
    for node_id, node_data in raw["nodes"].items():
        try:
            node_id = int(node_id)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid node id: {node_id}") from None
        nodes[node_id] = _load_node(node_id, node_data)

    expected_ids = set(range(1, len(nodes) + 1))
    _require(
        set(nodes) == expected_ids,
        f"Node ids must be {sorted(expected_ids)}, got {sorted(nodes)}",
    )
    _require(
        len(nodes) >= 2,
        f"Need at least 2 nodes for secret sharing, got {len(nodes)}",
    )

    addresses = [(n.host, n.port) for n in nodes.values()]
    _require(len(set(addresses)) == len(addresses), "Two nodes share a host:port")

    public_keys = [n.public_key for n in nodes.values()]
    _require(
        len(set(public_keys)) == len(public_keys),
        "Two nodes share a public key -- each node needs its own identity",
    )

    # --- field ---
    _require(isinstance(p, int) and p > 2, f"p must be an integer > 2, got {p!r}")
    _require(_is_prime(p), f"p ({p}) is not prime; F_p would not be a field")
    _require(
        isinstance(max_local_count, int) and max_local_count > 0,
        f"max_local_count must be a positive integer, got {max_local_count!r}",
    )
    # The global sum must not wrap: every node can contribute up to
    # max_local_count cases to a region, and the sum is taken mod p.
    _require(
        p > len(nodes) * max_local_count,
        f"p ({p}) is too small: {len(nodes)} nodes x max_local_count "
        f"({max_local_count}) can reach {len(nodes) * max_local_count}, which "
        "would wrap around the field and silently corrupt the global sum",
    )
    _require(
        isinstance(threshold, int) and 0 <= threshold < p,
        f"threshold must be an integer in [0, p), got {threshold!r}",
    )

    return Config(
        p=p,
        vector_size=vector_size,
        regions=regions,
        nodes=nodes,
        max_local_count=max_local_count,
        threshold=threshold,
    )

import json
from dataclasses import dataclass
from pathlib import Path
CONFIG_PATH = Path(__file__).parent / "config.json"

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


def load_config(path: str = CONFIG_PATH) -> Config:
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
        raise FileNotFoundError(
            f"Config file not found: {path}"
        )

    with open(config_path, "r") as f:
        raw = json.load(f)

    # required fields
    required_fields = [
        "p",
        "vector_size",
        "regions",
        "nodes"
    ]

    for field in required_fields:
        if field not in raw:
            raise ValueError(
                f"Missing required config field: {field}"
            )

    p = raw["p"]
    vector_size = raw["vector_size"]
    regions = raw["regions"]

    # validate vector size
    if len(regions) != vector_size:
        raise ValueError(
            f"vector_size ({vector_size}) "
            f"does not match regions count ({len(regions)})"
        )

    # validate duplicate regions
    if len(set(regions)) != len(regions):
        raise ValueError(
            "Duplicate regions found in configuration"
        )

    # convert node ids from JSON strings to integers
    nodes = {}

    for node_id, node_data in raw["nodes"].items():

        try:
            node_id = int(node_id)
        except ValueError:
            raise ValueError(
                f"Invalid node id: {node_id}"
            )

        for field in ("host", "port", "public_key"):
            if field not in node_data:
                raise ValueError(
                    f"Node {node_id} missing {field!r} "
                    "(run keygen.py, then paste the public keys into config.json)"
                )

        nodes[node_id] = NodeConfig(
            host=node_data["host"],
            port=node_data["port"],
            public_key=node_data["public_key"]
        )

    # validate number of nodes
    expected_nodes = 4

    if len(nodes) != expected_nodes:
        raise ValueError(
            f"Expected {expected_nodes} nodes, "
            f"got {len(nodes)}"
        )

    # validate node ids
    expected_ids = set(range(1, expected_nodes + 1))

    if set(nodes.keys()) != expected_ids:
        raise ValueError(
            f"Node ids must be {expected_ids}, "
            f"got {set(nodes.keys())}"
        )

    return Config(
        p=p,
        vector_size=vector_size,
        regions=regions,
        nodes=nodes
    )

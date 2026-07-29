"""
test_config_loader.py
=====================
Tests for the public-configuration validation.

Every invariant checked here is one the protocol silently depends on: a field
that is too small wraps the global sum, a malformed public key breaks
authentication on a *different* node, and duplicated addresses or keys break the
one-session-per-peer rule. They must all fail at startup, loudly.
"""

from __future__ import annotations

import json

import pytest

from config_loader import _is_prime, load_config

BASE = {
    "p": 1048573,
    "max_local_count": 1000,
    "threshold": 50,
    "vector_size": 2,
    "regions": ["A", "B"],
    "nodes": {
        "1": {"host": "127.0.0.1", "port": 9001, "public_key": "aa" * 32},
        "2": {"host": "127.0.0.1", "port": 9002, "public_key": "bb" * 32},
    },
}


def _write(tmp_path, **overrides):
    data = json.loads(json.dumps(BASE))
    for key, value in overrides.items():
        data[key] = value
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return path


def test_loads_a_valid_config(tmp_path):
    config = load_config(_write(tmp_path))
    assert config.p == 1048573
    assert config.node_ids == [1, 2]
    assert config.num_nodes == 2
    assert config.threshold == 50


def test_the_shipped_config_is_valid():
    """The committed config.json must itself pass every check."""
    config = load_config()
    assert config.num_nodes == 4
    assert len(config.regions) == config.vector_size


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.json")


@pytest.mark.parametrize("missing", ["p", "vector_size", "regions", "nodes"])
def test_missing_required_field(tmp_path, missing):
    data = json.loads(json.dumps(BASE))
    del data[missing]
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Missing required"):
        load_config(path)


def test_vector_size_must_match_regions(tmp_path):
    with pytest.raises(ValueError, match="does not match"):
        load_config(_write(tmp_path, vector_size=3))


def test_duplicate_regions_rejected(tmp_path):
    with pytest.raises(ValueError, match="Duplicate"):
        load_config(_write(tmp_path, regions=["A", "A"]))


# --- the field --------------------------------------------------------------


def test_is_prime_agrees_with_known_values():
    assert _is_prime(1048573)  # 2**20 - 3, the configured modulus
    assert _is_prime(2)
    assert not _is_prime(1)
    assert not _is_prime(1048575)
    assert not _is_prime(561)  # a Carmichael number: fools naive tests


def test_composite_p_rejected(tmp_path):
    with pytest.raises(ValueError, match="not prime"):
        load_config(_write(tmp_path, p=1048575))


def test_p_too_small_for_the_node_count_rejected(tmp_path):
    """S15/C1: p must exceed num_nodes * max_local_count or the sum wraps."""
    with pytest.raises(ValueError, match="too small"):
        load_config(_write(tmp_path, p=1048573, max_local_count=600000))


def test_threshold_must_be_in_the_field(tmp_path):
    with pytest.raises(ValueError, match="threshold"):
        load_config(_write(tmp_path, threshold=-1))


# --- nodes ------------------------------------------------------------------


def test_short_public_key_rejected(tmp_path):
    nodes = json.loads(json.dumps(BASE["nodes"]))
    nodes["2"]["public_key"] = "aa" * 16
    with pytest.raises(ValueError, match="hex chars"):
        load_config(_write(tmp_path, nodes=nodes))


def test_non_hex_public_key_rejected(tmp_path):
    nodes = json.loads(json.dumps(BASE["nodes"]))
    nodes["2"]["public_key"] = "zz" * 32
    with pytest.raises(ValueError, match="not valid hex"):
        load_config(_write(tmp_path, nodes=nodes))


def test_shared_public_key_rejected(tmp_path):
    """Two nodes with one identity would defeat per-node authentication."""
    nodes = json.loads(json.dumps(BASE["nodes"]))
    nodes["2"]["public_key"] = nodes["1"]["public_key"]
    with pytest.raises(ValueError, match="share a public key"):
        load_config(_write(tmp_path, nodes=nodes))


def test_duplicate_address_rejected(tmp_path):
    nodes = json.loads(json.dumps(BASE["nodes"]))
    nodes["2"]["port"] = nodes["1"]["port"]
    with pytest.raises(ValueError, match="host:port"):
        load_config(_write(tmp_path, nodes=nodes))


@pytest.mark.parametrize("port", [0, 70000, "9001"])
def test_invalid_port_rejected(tmp_path, port):
    nodes = json.loads(json.dumps(BASE["nodes"]))
    nodes["2"]["port"] = port
    with pytest.raises(ValueError, match="invalid port"):
        load_config(_write(tmp_path, nodes=nodes))


def test_missing_public_key_points_at_keygen(tmp_path):
    nodes = json.loads(json.dumps(BASE["nodes"]))
    del nodes["2"]["public_key"]
    with pytest.raises(ValueError, match="keygen"):
        load_config(_write(tmp_path, nodes=nodes))


def test_non_contiguous_node_ids_rejected(tmp_path):
    nodes = {"1": BASE["nodes"]["1"], "5": BASE["nodes"]["2"]}
    with pytest.raises(ValueError, match="Node ids"):
        load_config(_write(tmp_path, nodes=nodes))


def test_single_node_rejected(tmp_path):
    nodes = {"1": BASE["nodes"]["1"]}
    with pytest.raises(ValueError, match="at least 2 nodes"):
        load_config(_write(tmp_path, nodes=nodes))

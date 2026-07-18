"""Garbled Circuit / 2-Party Threshold Evaluation Layer.

This package implements the non-linear threshold sub-protocol of the
Privacy-Preserving COVID-19 Regional Quarantine Alert System.

Given, for every monitored region, two consolidated additive shares held by
two parties:

    * ``A``  — held by Node 1 (the Garbler / party 0)
    * ``B``  — held by Node 2 (the Evaluator / party 1)

the parties jointly and securely evaluate, for each region ``j``::

    output_j = (A_j + B_j) > threshold ? region_id_j : "Clear"

so that a region's identity is revealed **only** when the combined case count
crosses the quarantine threshold, and nothing leaks about sub-threshold
regions.

The secure computation is done by a pluggable backend, selected with a single
CLI flag (``--backend``):

    * :mod:`smpc_gc.yao`                   — our from-scratch implementation of
      Yao's Garbled Circuits + Oblivious Transfer (the default backend and the
      core cryptographic deliverable)
    * :mod:`smpc_gc.backends.mpyc_backend` — the MPyC framework

The MPyC backend exists to demonstrate the same computation running on an
established library and to satisfy the "swappable library" requirement; the
real garbling/OT protocol lives in :mod:`smpc_gc.yao`.

Shared, backend-agnostic resources (also the integration points with the
networking / secure-summation layer):

    * :mod:`smpc_gc.types`     — the ``ThresholdProblem`` / ``RegionResult``
      interface boundary
    * :mod:`smpc_gc.channel`   — the swappable party-to-party transport
    * :mod:`smpc_gc.interface` — the backend ABC + registry
    * :mod:`smpc_gc.mock`      — mock/JSON problem loading
"""

from smpc_gc.types import CLEAR_TOKEN, RegionResult, ThresholdProblem
from smpc_gc.channel import (
    Channel,
    ChannelFactory,
    Listener,
    SocketChannel,
    connect,
    local_pair,
    open_channel,
)
from smpc_gc.interface import (
    ThresholdBackend,
    available_backends,
    get_backend,
    register_backend,
)

__all__ = [
    "CLEAR_TOKEN",
    "RegionResult",
    "ThresholdProblem",
    "Channel",
    "ChannelFactory",
    "SocketChannel",
    "Listener",
    "connect",
    "local_pair",
    "open_channel",
    "ThresholdBackend",
    "available_backends",
    "get_backend",
    "register_backend",
]

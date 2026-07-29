"""Garbled Circuit / 2-Party Threshold Evaluation Layer.

This package implements the non-linear threshold sub-protocol of the
Privacy-Preserving COVID-19 Regional Quarantine Alert System.

Given, for every monitored region, two consolidated additive shares held by
two parties:

    * ``A``  — held by Node 1 (the Garbler / party 0)
    * ``B``  — held by Node 2 (the Evaluator / party 1)

the parties jointly and securely evaluate, for each region ``j``::

    output_j = (A_j + B_j mod p) > threshold ? region_id_j : "Clear"

so that a region's identity is revealed **only** when the combined case count
crosses the quarantine threshold, and nothing leaks about sub-threshold
regions — a region with 0 cases and one with 49 produce identical transcripts.

The secure computation is Yao's Garbled Circuits and Oblivious Transfer,
implemented from scratch in :mod:`smpc_gc.yao`.  No SMPC library is involved;
see ``README.md`` for why the one we evaluated (MPyC) was dropped.

Layout:

    * :mod:`smpc_gc.yao`       — the protocol itself: the boolean circuit,
      garbling, Oblivious Transfer, and the two party halves
    * :mod:`smpc_gc.threshold` — ``evaluate()``, the entry point that runs one
      circuit instance per region
    * :mod:`smpc_gc.types`     — the ``ThresholdProblem`` / ``RegionResult``
      interface boundary with the secure-summation layer
    * :mod:`smpc_gc.channel`   — the swappable party-to-party transport
    * :mod:`smpc_gc.mock`      — mock generation and JSON problem loading
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
from smpc_gc.threshold import TECHNIQUE, evaluate_threshold

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
    "TECHNIQUE",
    "evaluate_threshold",
]

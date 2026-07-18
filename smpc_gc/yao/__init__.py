"""A from-scratch implementation of Yao's Garbled Circuits and Oblivious Transfer.

Nothing in this sub-package delegates the cryptography to an SMPC library: the
boolean circuit, the garbling scheme (free-XOR + point-and-permute), the
1-out-of-2 Oblivious Transfer (Chou-Orlandi), and the two-party Garbler/Evaluator
protocol are all implemented here.  This is the real cryptographic core of the
threshold check; the MPyC backend exists only to show the same computation
running on an established framework.

This package is crypto only — the transport the two parties talk over is the
shared, backend-agnostic :mod:`smpc_gc.channel`.
"""

from smpc_gc.yao.circuit import Circuit, build_threshold_circuit
from smpc_gc.yao.garbling import GarbledCircuit, evaluate, garble
from smpc_gc.yao.ot import (
    DEFAULT_GROUP,
    GROUP_1024,
    GROUP_2048,
    GROUPS,
    DHGroup,
    OTReceiver,
    OTSender,
)
from smpc_gc.yao.protocol import run_evaluator, run_garbler, run_yao_2pc

__all__ = [
    "Circuit",
    "build_threshold_circuit",
    "GarbledCircuit",
    "garble",
    "evaluate",
    "DHGroup",
    "DEFAULT_GROUP",
    "GROUP_1024",
    "GROUP_2048",
    "GROUPS",
    "OTSender",
    "OTReceiver",
    "run_garbler",
    "run_evaluator",
    "run_yao_2pc",
]

"""A from-scratch implementation of Yao's Garbled Circuits and Oblivious Transfer.

Nothing here delegates the cryptography to an SMPC library: the boolean circuit,
the garbling scheme (free-XOR + point-and-permute), the 1-out-of-2 Oblivious
Transfer (Chou-Orlandi), and the two-party Garbler/Evaluator protocol are all
implemented in this sub-package.  It is the cryptographic core of the project.

This package is crypto only — the transport the two parties talk over is the
swappable :mod:`smpc_gc.channel`, and :mod:`smpc_gc.threshold` is what drives one
circuit instance per region.
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

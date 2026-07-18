"""Command-line entry point for the threshold engine.

One command, one set of flags, two interchangeable engines.  The default
backend, ``yao``, is our from-scratch implementation of Yao's Garbled Circuits
and Oblivious Transfer; ``mpyc`` runs the identical problem on the MPyC
framework.  **Only** ``--backend`` **changes between them** — every other flag
(problem input, ``--party``, ``--host``, ``--port``, output format) means the
same thing for both, and each backend internally converts them to whatever its
engine needs (e.g. MPyC's native ``-M/-I/-P`` flags).

    # from-scratch Garbled Circuits + OT (default), mocked A/B, threshold 50
    uv run smpc-gc

    # the same problem on the MPyC framework — nothing else changes
    uv run smpc-gc --backend mpyc

A genuine two-process 2PC run: each party loads a JSON problem holding **only
its own** share vector and the parties rendezvous on ``host:port`` (start
party 0 first — it waits for party 1).  Identical flags for every backend::

    uv run smpc-gc --backend yao  --input problem_A.json --party 0   # holds A
    uv run smpc-gc --backend yao  --input problem_B.json --party 1   # holds B

    uv run smpc-gc --backend mpyc --input problem_A.json --party 0   # holds A
    uv run smpc-gc --backend mpyc --input problem_B.json --party 1   # holds B
"""

from __future__ import annotations

import argparse
import json
import sys

from smpc_gc.channel import DEFAULT_HOST, DEFAULT_PORT
from smpc_gc.interface import available_backends, get_backend
from smpc_gc.mock import load_problem, make_mock_problem
from smpc_gc.types import RegionResult, ThresholdProblem


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smpc-gc",
        description=(
            "Securely evaluate the quarantine-threshold circuit "
            "(A + B > threshold ? region_id : Clear) on a pluggable SMPC backend."
        ),
    )
    parser.add_argument(
        "-b",
        "--backend",
        default="yao",
        choices=available_backends(),
        help=(
            "engine to evaluate on: 'yao' (from-scratch Garbled Circuits + OT) "
            "or 'mpyc' (default: yao); all other flags are backend-agnostic"
        ),
    )
    parser.add_argument(
        "--list-backends",
        action="store_true",
        help="list backends with their availability and exit",
    )

    src = parser.add_argument_group("problem input")
    src.add_argument(
        "-i",
        "--input",
        metavar="FILE.json",
        help="load the problem (region ids + shares) from a JSON file",
    )
    src.add_argument(
        "-t", "--threshold", type=int, default=50, help="quarantine threshold (mock mode)"
    )
    src.add_argument(
        "-m", "--regions", type=int, default=8, help="number of mock regions"
    )
    src.add_argument("--seed", type=int, default=0, help="mock RNG seed")
    src.add_argument(
        "--max-count", type=int, default=None, help="max mock per-region case count"
    )
    src.add_argument(
        "--bit-length", type=int, default=16, help="secure integer bit width"
    )

    run = parser.add_argument_group(
        "run mode (identical for every backend)"
    )
    run.add_argument(
        "--party",
        type=int,
        choices=(0, 1),
        default=None,
        help="act as this party in a distributed run (default: local simulation)",
    )
    run.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=(
            "rendezvous host for the two-process run (--party): party 0 binds "
            f"it, party 1 connects to it (default: {DEFAULT_HOST})"
        ),
    )
    run.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=(
            "rendezvous TCP port for the two-process run (--party) "
            f"(default: {DEFAULT_PORT}; mpyc also uses port+1)"
        ),
    )
    run.add_argument(
        "--json", action="store_true", help="emit results as JSON instead of a table"
    )

    yao = parser.add_argument_group("yao backend options")
    yao.add_argument(
        "--ot-group",
        choices=("1024", "2048"),
        default="2048",
        help=(
            "MODP group size for the Oblivious Transfer "
            "(default: 2048; 1024 is ~5x faster but weaker)"
        ),
    )
    return parser


def _load_problem(args: argparse.Namespace) -> ThresholdProblem:
    if args.input:
        return load_problem(args.input)
    return make_mock_problem(
        num_regions=args.regions,
        threshold=args.threshold,
        seed=args.seed,
        max_count=args.max_count,
        bit_length=args.bit_length,
    )


def _make_backend(args: argparse.Namespace):
    """Instantiate the chosen backend from the *shared* CLI flags.

    Every backend receives the same host/port rendezvous parameters and does
    its own translation, so ``--backend`` is the only flag that differs
    between engines.
    """
    if args.backend == "yao":
        from smpc_gc.backends.yao_backend import YaoBackend
        from smpc_gc.yao.ot import GROUPS

        return YaoBackend(group=GROUPS[args.ot_group], host=args.host, port=args.port)
    if args.backend == "mpyc":
        from smpc_gc.backends.mpyc_backend import MPyCBackend

        return MPyCBackend(host=args.host, port=args.port)
    return get_backend(args.backend)


def _print_backends() -> None:
    print("Available backends:")
    for name in available_backends():
        print(f"  {get_backend(name).describe()}")


def _render_table(
    problem: ThresholdProblem, results: list[RegionResult], party: int | None
) -> str:
    lines = []
    lines.append(f"{'region':>7}  {'id':>6}  {'output':>8}  status")
    lines.append("-" * 34)
    for r in results:
        out = r.region_id if r.crossed else "Clear"
        lines.append(f"{r.region_index:>7}  {r.region_id:>6}  {str(out):>8}  {r.status}")

    quarantined = [r.region_id for r in results if r.crossed]
    lines.append("-" * 34)
    lines.append(
        f"Quarantine alert: {len(quarantined)} region(s) crossed threshold "
        f"{problem.threshold}: {quarantined if quarantined else '(none)'}"
    )

    # Correctness self-check when both shares are known locally.
    expected = problem.expected_plaintext()
    if expected is not None and party is None:
        match = all(
            e.revealed == r.revealed for e, r in zip(expected, results)
        )
        lines.append(
            "Plaintext cross-check: "
            + ("OK (secure result == cleartext)" if match else "MISMATCH!")
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_backends:
        _print_backends()
        return 0

    problem = _load_problem(args)
    backend = _make_backend(args)

    ok, reason = backend.availability()
    if not ok:
        print(f"error: backend {args.backend!r} unavailable: {reason}", file=sys.stderr)
        return 2

    results = backend.evaluate(problem, party=args.party)

    if args.json:
        print(
            json.dumps(
                {
                    "backend": backend.name,
                    "technique": backend.technique,
                    "threshold": problem.threshold,
                    "party": args.party,
                    "results": [r.as_dict() for r in results],
                },
                indent=2,
            )
        )
    else:
        print(f"Backend: {backend.name} — {backend.technique}")
        if args.party is not None:
            print(f"Running as party {args.party}")
        print(_render_table(problem, results, args.party))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

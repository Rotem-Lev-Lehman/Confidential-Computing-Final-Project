"""Command-line entry point for the threshold engine.

Evaluates the quarantine-threshold circuit
``(A + B > threshold) ? region_id : Clear`` with Yao's Garbled Circuits and
Oblivious Transfer, on mocked or file-loaded shares.  This exercises the 2PC
layer on its own; ``main.py`` is what runs the complete four-node system.

    # mocked A/B, threshold 50, local simulation
    uv run smpc-gc
    uv run smpc-gc --seed 3 --regions 12 --threshold 50

    # faster (weaker) OT group, for a quick demo
    uv run smpc-gc --ot-group 1024

A genuine two-process 2PC run: each party loads a JSON problem holding **only
its own** share vector and the parties rendezvous on ``host:port`` (start
party 0 first — it waits for party 1)::

    uv run smpc-gc --input problems/1/problem_A.json --party 0   # holds A
    uv run smpc-gc --input problems/1/problem_B.json --party 1   # holds B
"""

from __future__ import annotations

import argparse
import json

from smpc_gc.channel import DEFAULT_HOST, DEFAULT_PORT
from smpc_gc.mock import load_problem, make_mock_problem
from smpc_gc.threshold import TECHNIQUE, evaluate_threshold
from smpc_gc.types import RegionResult, ThresholdProblem
from smpc_gc.yao.ot import GROUPS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smpc-gc",
        description=(
            "Securely evaluate the quarantine-threshold circuit "
            "(A + B > threshold ? region_id : Clear) with Yao's Garbled "
            "Circuits and Oblivious Transfer."
        ),
    )

    src = parser.add_argument_group("problem input")
    src.add_argument(
        "-i",
        "--input",
        metavar="FILE.json",
        help="load the problem (region ids + shares) from a JSON file",
    )
    src.add_argument(
        "-t", "--threshold", type=int, default=50,
        help="quarantine threshold (mock mode)",
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

    run = parser.add_argument_group("run mode")
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
        help=f"rendezvous TCP port for the two-process run (default: {DEFAULT_PORT})",
    )
    run.add_argument(
        "--ot-group",
        choices=("1024", "2048"),
        default="2048",
        help=(
            "MODP group size for the Oblivious Transfer "
            "(default: 2048; 1024 is ~5x faster but weaker)"
        ),
    )
    run.add_argument(
        "--json", action="store_true", help="emit results as JSON instead of a table"
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
        match = all(e.revealed == r.revealed for e, r in zip(expected, results))
        lines.append(
            "Plaintext cross-check: "
            + ("OK (secure result == cleartext)" if match else "MISMATCH!")
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    problem = _load_problem(args)
    results = evaluate_threshold(
        problem,
        party=args.party,
        group=GROUPS[args.ot_group],
        host=args.host,
        port=args.port,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "technique": TECHNIQUE,
                    "threshold": problem.threshold,
                    "party": args.party,
                    "results": [r.as_dict() for r in results],
                },
                indent=2,
            )
        )
    else:
        print(f"Engine: {TECHNIQUE}")
        if args.party is not None:
            print(f"Running as party {args.party}")
        print(_render_table(problem, results, args.party))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

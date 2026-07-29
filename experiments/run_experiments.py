"""Experiment harness for the from-scratch Yao's Garbled Circuits engine.

Runs a battery of measurements and writes everything needed for the report:

    experiments/results.json      raw measurements (machine-readable)
    experiments/measurements.md   the generated tables (human-readable)

The project-wide write-up that cites these numbers is ``report.md`` at the
repo root; this harness only produces the measurements it quotes.

**Every timed run is a genuine two-process 2PC session**: party 0 and party 1
are spawned as separate OS processes via the CLI, each holding only its own
share file, rendezvousing over real sockets — exactly how the system runs in the
real world.  Local simulation mode is never used for measurements.

Dimensions covered:

    * results     — does the engine reveal the expected output on every problem
                    in ``problems/``, matching ``solution.json``?
    * speed       — distributed wall time per problem; scaling with number of
                    regions, share bit-width and OT group; the fixed protocol
                    overhead floor (smallest possible run).
    * bandwidth   — bytes crossing the wire, measured exactly on the channel.
    * footprint   — implementation size and dependency count.

Usage:

    uv run python experiments/run_experiments.py                # full (~3 min)
    uv run python experiments/run_experiments.py --quick        # subset (~1 min)
    uv run python experiments/run_experiments.py --render-only  # tables only
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))  # allow running without an editable install

from smpc_gc.channel import local_pair  # noqa: E402
from smpc_gc.mock import load_problem_dir, make_mock_problem, problem_to_dict  # noqa: E402
from smpc_gc.yao import build_threshold_circuit, run_evaluator, run_garbler  # noqa: E402
from smpc_gc.yao.ot import GROUP_1024, GROUP_2048  # noqa: E402

PROBLEMS_DIR = ROOT / "problems"
OUT_DIR = ROOT / "experiments"

# The engine configurations under test.  Only the OT group differs: it is the
# one knob with a real security/performance trade-off.
CONFIGS: list[tuple[str, list[str]]] = [
    ("ot-2048", ["--ot-group", "2048"]),
    ("ot-1024", ["--ot-group", "1024"]),
]


def _configs(quick: bool) -> list[tuple[str, list[str]]]:
    return [c for c in CONFIGS if not (quick and c[0] == "ot-2048")]


def _problem_dirs(quick: bool) -> list[Path]:
    dirs = sorted(
        (p for p in PROBLEMS_DIR.iterdir() if p.is_dir()), key=lambda p: int(p.name)
    )
    if quick:
        dirs = [d for d in dirs if d.name in ("1", "7", "9")]
    return dirs


# --- running one genuine two-process session --------------------------------


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_distributed(flags: list[str], files_dir: Path) -> dict:
    """One genuine 2PC session: two processes, identical flags except --party.

    Returns wall time (spawn -> both parties done, i.e. what a user actually
    waits) and the revealed outputs.
    """
    port = _free_port()
    env = {**_os_environ(), "PYTHONPATH": str(ROOT / "src")}

    def _cli(party: int) -> list[str]:
        return [
            sys.executable, "-m", "smpc_gc.cli",
            *flags,
            "--input", str(files_dir / f"problem_{'AB'[party]}.json"),
            "--party", str(party),
            "--port", str(port),
            "--json",
        ]

    t0 = time.perf_counter()
    p0 = subprocess.Popen(_cli(0), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, cwd=ROOT, env=env)
    p1 = subprocess.Popen(_cli(1), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, cwd=ROOT, env=env)
    out0, err0 = p0.communicate(timeout=600)
    out1, err1 = p1.communicate(timeout=600)
    wall = time.perf_counter() - t0
    assert p0.returncode == 0, f"party0 failed: {out0}\n{err0}"
    assert p1.returncode == 0, f"party1 failed: {out1}\n{err1}"

    return {
        "seconds_wall": round(wall, 3),
        "revealed": [r["revealed"] for r in json.loads(out1)["results"]],
    }


def _os_environ() -> dict:
    import os

    return dict(os.environ)


def _write_party_files(problem, files_dir: Path) -> None:
    """Split a mock problem into the two per-party input files."""
    d = problem_to_dict(problem)
    (files_dir / "problem_A.json").write_text(json.dumps({**d, "b_shares": None}))
    (files_dir / "problem_B.json").write_text(json.dumps({**d, "a_shares": None}))


# --- experiment 1: correctness + speed on problems/ (distributed) -----------


def exp_problems(quick: bool) -> dict:
    """Every problem in every configuration, each run as two real processes."""
    rows = []
    for pdir in _problem_dirs(quick):
        problem = load_problem_dir(pdir)
        solution = json.loads((pdir / "solution.json").read_text())
        expected = [r["revealed"] for r in solution["results"]]

        row = {
            "problem": pdir.name,
            "regions": problem.num_regions,
            "bit_length": problem.bit_length,
            "runs": {},
        }
        for label, flags in _configs(quick):
            out = run_distributed(flags, pdir)
            out["matches_solution"] = out["revealed"] == expected
            row["runs"][label] = out
        rows.append(row)
        print("  problems/{}: {}".format(
            pdir.name,
            ", ".join(f"{k} {v['seconds_wall']:.2f}s" for k, v in row["runs"].items()),
        ))
    return {"rows": rows}


# --- experiment 2: scaling --------------------------------------------------


def exp_scaling(quick: bool) -> dict:
    import tempfile

    def _sweep(cases: list[tuple[int, int]]) -> list[dict]:
        out = []
        for m, bits in cases:
            problem = make_mock_problem(num_regions=m, bit_length=bits, seed=1)
            with tempfile.TemporaryDirectory() as tmp:
                _write_party_files(problem, Path(tmp))
                entry = {"regions": m, "bit_length": bits, "seconds": {}}
                for label, flags in _configs(quick):
                    entry["seconds"][label] = run_distributed(flags, Path(tmp))[
                        "seconds_wall"
                    ]
            out.append(entry)
            print("  regions={} bits={}: {}".format(
                m, bits,
                ", ".join(f"{k} {v:.2f}s" for k, v in entry["seconds"].items()),
            ))
        return out

    regions_list = [1, 2, 4] if quick else [1, 2, 4, 8]
    bits_list = [8, 16] if quick else [8, 16, 24, 32]
    return {
        "by_regions": _sweep([(m, 16) for m in regions_list]),
        "by_bit_length": _sweep([(4, b) for b in bits_list]),
    }


# --- experiment 3: fixed protocol overhead ----------------------------------


def exp_overhead(quick: bool) -> dict:
    """The floor: the smallest possible run, i.e. what the protocol costs empty."""
    import tempfile

    problem = make_mock_problem(num_regions=1, bit_length=8, seed=2)
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        _write_party_files(problem, Path(tmp))
        for label, flags in _configs(quick):
            out[label] = run_distributed(flags, Path(tmp))["seconds_wall"]
            print(f"  {label}: {out[label]:.2f}s")
    return {"seconds": out, "note": "1 region, 8-bit shares, two processes"}


# --- experiment 4: communication cost ---------------------------------------


class _CountingChannel:
    """Wraps a channel and counts the JSON bytes crossing it in each direction."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.sent_bytes = 0
        self.recv_bytes = 0
        self.messages = 0

    def send(self, obj) -> None:
        self.sent_bytes += len(json.dumps(obj).encode())
        self.messages += 1
        self._inner.send(obj)

    def recv(self):
        obj = self._inner.recv()
        self.recv_bytes += len(json.dumps(obj).encode())
        return obj

    def close(self) -> None:
        self._inner.close()


def exp_communication(quick: bool, problem_name: str = "1") -> dict:
    """Exact bytes on the wire, measured on the channel itself."""
    problem = load_problem_dir(PROBLEMS_DIR / problem_name)
    groups = [("ot-1024", GROUP_1024)]
    if not quick:
        groups.insert(0, ("ot-2048", GROUP_2048))

    rows = {}
    for label, group in groups:
        garbler_side, evaluator_side = local_pair()
        counted_g = _CountingChannel(garbler_side)
        counted_e = _CountingChannel(evaluator_side)

        def _bits(value, wires):
            return {w: (value >> i) & 1 for i, w in enumerate(wires)}

        def _garbler() -> None:
            for j, rid in enumerate(problem.region_ids):
                circuit = build_threshold_circuit(
                    bit_length=problem.bit_length, threshold=problem.threshold,
                    region_id=rid, clear_token=problem.clear_token,
                    modulus=problem.modulus,
                )
                run_garbler(
                    circuit,
                    _bits(problem.a_shares[j], circuit.garbler_input_wires),
                    counted_g, group,
                )

        thread = threading.Thread(target=_garbler)
        thread.start()
        try:
            for j, rid in enumerate(problem.region_ids):
                circuit = build_threshold_circuit(
                    bit_length=problem.bit_length, threshold=problem.threshold,
                    region_id=rid, clear_token=problem.clear_token,
                    modulus=problem.modulus,
                )
                run_evaluator(
                    circuit,
                    _bits(problem.b_shares[j], circuit.evaluator_input_wires),
                    counted_e, group,
                )
        finally:
            thread.join()
            counted_g.close()
            counted_e.close()

        total = counted_g.sent_bytes + counted_e.sent_bytes
        rows[label] = {
            "garbler_to_evaluator_bytes": counted_g.sent_bytes,
            "evaluator_to_garbler_bytes": counted_e.sent_bytes,
            "bytes_total": total,
            "bytes_per_region": round(total / problem.num_regions),
            "messages": counted_g.messages + counted_e.messages,
        }
        print(f"  {label}: {total:,} bytes "
              f"({rows[label]['bytes_per_region']:,}/region)")

    return {"problem": problem_name, "regions": problem.num_regions,
            "bit_length": problem.bit_length, "rows": rows}


# --- experiment 5: implementation footprint ---------------------------------


def _loc(paths: list[Path]) -> dict:
    total = sloc = 0
    for p in paths:
        for line in p.read_text().splitlines():
            total += 1
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                sloc += 1
    return {"files": len(paths), "lines": total, "code_lines": sloc}


def exp_footprint() -> dict:
    src = ROOT / "src"
    out = {
        "yao_crypto_core": _loc(sorted((src / "smpc_gc" / "yao").glob("*.py"))),
        "threshold_driver": _loc([src / "smpc_gc" / "threshold.py"]),
        "shared_infrastructure": _loc([
            src / "smpc_gc" / p
            for p in ("channel.py", "types.py", "mock.py", "cli.py", "__init__.py")
        ]),
        "transport_and_summation": _loc(sorted(
            p for p in src.glob("*.py") if p.name not in ("main.py", "demo_setup.py")
        )),
        "runtime_dependencies": ["cryptography (standard primitives only)"],
    }
    print(f"  yao crypto core: {out['yao_crypto_core']['code_lines']} code lines; "
          f"whole system: "
          f"{sum(v['code_lines'] for k, v in out.items() if isinstance(v, dict))} "
          "code lines, zero SMPC dependencies")
    return out


# --- report rendering -------------------------------------------------------


def _table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(str(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def _fmt_s(v) -> str:
    return f"{v:.2f} s" if isinstance(v, (int, float)) else "—"


def render_report(res: dict) -> str:
    cfg_labels = list(res["problems"]["rows"][0]["runs"].keys())
    parts: list[str] = []

    def add(text: str = "") -> None:
        parts.append(text)

    add("# Measurements: from-scratch Yao's Garbled Circuits\n")
    add(f"Generated by `experiments/run_experiments.py` on {res['generated']} "
        f"({res['mode']} mode).\n")
    add("Every timed measurement below is a **genuine two-process 2PC run**: "
        "party 0 and party 1 are separate OS processes, each holding only its "
        "own share file, talking over real sockets. Wall time is what a user "
        "actually waits, including process spawn and rendezvous. `ot-2048` is "
        "the default configuration; `ot-1024` is the faster, weaker OT group "
        "(`--ot-group 1024`).\n")

    add("## 1. Environment\n")
    env = res["environment"]
    add(_table(["", ""], [
        ["Platform", env["platform"]],
        ["Python", env["python"]],
        ["CPU count", env["cpu_count"]],
    ]) + "\n")

    add("## 2. Correctness (from the distributed runs)\n")
    rows, all_ok = [], True
    for r in res["problems"]["rows"]:
        row = [f"problems/{r['problem']}", r["regions"], r["bit_length"]]
        for c in cfg_labels:
            ok = r["runs"][c]["matches_solution"]
            all_ok &= ok
            row.append("✓" if ok else "✗")
        rows.append(row)
    add(_table(["problem", "regions", "bits"]
               + [f"{c} = solution" for c in cfg_labels], rows) + "\n")
    add("**Every configuration reveals exactly the expected output on every "
        "problem.**\n" if all_ok else "**MISMATCH — see results.json.**\n")

    add("## 3. Speed (two-process wall time)\n")
    add("### 3.1 Per problem\n")
    rows = [[f"problems/{r['problem']}", r["regions"], r["bit_length"]]
            + [_fmt_s(r["runs"][c]["seconds_wall"]) for c in cfg_labels]
            for r in res["problems"]["rows"]]
    add(_table(["problem", "regions", "bits"] + cfg_labels, rows) + "\n")

    add("### 3.2 Scaling with number of regions (16-bit shares)\n")
    rows = [[e["regions"]] + [_fmt_s(e["seconds"].get(c)) for c in cfg_labels]
            for e in res["scaling"]["by_regions"]]
    add(_table(["regions"] + cfg_labels, rows) + "\n")

    add("### 3.3 Scaling with share bit-width (4 regions)\n")
    rows = [[e["bit_length"]] + [_fmt_s(e["seconds"].get(c)) for c in cfg_labels]
            for e in res["scaling"]["by_bit_length"]]
    add(_table(["bit_length"] + cfg_labels, rows) + "\n")
    add("Cost grows linearly in `regions × bit_length`: the engine runs textbook "
        "**base OT**, one modular exponentiation per evaluator input bit. This is "
        "the dominant cost and the reason the deployed system keeps shares as "
        "narrow as the field allows (20 bits for `p = 2^20 - 3`). OT extension "
        "would amortize the base OTs and is the standard next step.\n")

    add("### 3.4 Fixed protocol overhead\n")
    ovh = res["overhead"]
    add(_table(["configuration", "smallest possible run"],
               [[c, _fmt_s(ovh["seconds"].get(c))] for c in cfg_labels]) + "\n")
    add(f"_{ovh['note']}._ Subtracting this floor from the numbers above gives "
        "the marginal cost of the cryptography itself.\n")

    add("## 4. Communication cost\n")
    comm = res["communication"]
    rows = [[label,
             f"{v['garbler_to_evaluator_bytes']:,}",
             f"{v['evaluator_to_garbler_bytes']:,}",
             f"{v['bytes_total']:,}",
             f"{v['bytes_per_region']:,}",
             v["messages"]]
            for label, v in comm["rows"].items()]
    add(_table(["configuration", "garbler→evaluator B", "evaluator→garbler B",
                "total B", "B/region", "messages"], rows) + "\n")
    add(f"Measured exactly on the channel (problems/{comm['problem']}, "
        f"{comm['regions']} regions × {comm['bit_length']} bits). The garbled "
        "tables dominate: four 128-bit ciphertexts per AND gate. Traffic is a "
        "function of the public parameters only, so it leaks nothing about the "
        "inputs.\n")

    add("## 5. Implementation footprint\n")
    fp = res["footprint"]
    add(_table(["component", "files", "code lines"], [
        ["`smpc_gc/yao/` — circuit, garbling, OT, protocol",
         fp["yao_crypto_core"]["files"], fp["yao_crypto_core"]["code_lines"]],
        ["`smpc_gc/threshold.py` — per-region driver",
         fp["threshold_driver"]["files"], fp["threshold_driver"]["code_lines"]],
        ["shared infrastructure (channel, types, mock, CLI)",
         fp["shared_infrastructure"]["files"],
         fp["shared_infrastructure"]["code_lines"]],
        ["transport + secure summation",
         fp["transport_and_summation"]["files"],
         fp["transport_and_summation"]["code_lines"]],
    ]) + "\n")
    add("**Runtime dependencies:** `cryptography`, used only for the standard "
        "primitives around the protocol (Ed25519, X25519, HKDF, AES-GCM). The "
        "SMPC itself — garbled circuits and oblivious transfer — is implemented "
        "from scratch on `hashlib`, `secrets` and `socket`.\n")

    add("## 6. Why there is no second engine\n")
    add("An earlier iteration put the evaluation behind a pluggable backend "
        "interface and added [MPyC](https://github.com/lschoe/mpyc) as a second "
        "engine, to compare against an established framework. It was removed. "
        "Two reasons, in order of importance:\n")
    add("1. **MPyC does not implement Yao's Garbled Circuits.** It is *honest-"
        "majority Shamir secret sharing* over arithmetic circuits — a different "
        "primitive. Benchmarking it against this engine compares two unrelated "
        "techniques, which is not the comparison the project is about.\n")
    add("2. **In the two-party setting it provides no input privacy at all.** "
        "Honest-majority Shamir requires `t < m/2`. With `m = 2` parties MPyC "
        "runs at threshold `t = 0`, and a degree-0 sharing polynomial is the "
        "constant `f(X) = secret` — so the \"share\" *is* the secret. We "
        "confirmed this experimentally before dropping it: party 1 read party "
        "0's private input verbatim from its own share. Yao's protocol is what "
        "the proposal specifies precisely because it is secure for two "
        "parties.\n")
    add("MPyC would be a sound choice for a *different* architecture — one "
        "4-party session across all four hospitals, skipping the reduction to "
        "two parties entirely, where `t = 1` and no single hospital learns "
        "anything. That is a real alternative design, and it is noted as such; "
        "it is not a drop-in backend for the proposal's hybrid pipeline.\n")
    add("With one engine, the `ThresholdBackend` abstraction and its registry "
        "were pure indirection, so they were removed too. "
        "`smpc_gc.threshold.evaluate_threshold` is now called directly.\n")

    return "\n".join(parts) + "\n"


# --- driver -----------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true",
                        help="smaller sweep (~1 min instead of ~3)")
    parser.add_argument("--render-only", action="store_true",
                        help="re-render measurements.md from the existing results.json")
    args = parser.parse_args()

    results_path = OUT_DIR / "results.json"
    report_path = OUT_DIR / "measurements.md"

    if args.render_only:
        res = json.loads(results_path.read_text())
    else:
        t0 = time.perf_counter()
        print("[1/5] correctness + speed on problems/ (two processes per run) ...")
        problems = exp_problems(args.quick)
        print("[2/5] scaling (regions, bit length; two processes per run) ...")
        scaling = exp_scaling(args.quick)
        print("[3/5] protocol overhead floor ...")
        overhead = exp_overhead(args.quick)
        print("[4/5] communication cost ...")
        communication = exp_communication(args.quick)
        print("[5/5] implementation footprint ...")
        footprint = exp_footprint()

        res = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "quick" if args.quick else "full",
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "cpu_count": __import__("os").cpu_count(),
            },
            "problems": problems,
            "scaling": scaling,
            "overhead": overhead,
            "communication": communication,
            "footprint": footprint,
        }
        results_path.write_text(json.dumps(res, indent=2) + "\n")
        print(f"\nDone in {time.perf_counter() - t0:.1f}s.")

    report_path.write_text(render_report(res))
    print(f"  raw data : {results_path}")
    print(f"  tables   : {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

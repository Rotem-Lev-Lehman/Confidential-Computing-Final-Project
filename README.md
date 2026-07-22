# Confidential Computing Final Project — SMPC

Privacy-Preserving COVID-19 Regional Quarantine Alert System (see
[`proposal.md`](proposal.md)).

This subtree implements the **Garbled Circuit / Logic Evaluation Layer**: the
non-linear, 2-party threshold sub-protocol that decides, for every monitored
region, whether the combined case count crosses the quarantine threshold — and
reveals the region's identity **only** when it does.

For every region `j`, given two consolidated additive shares
`A_j` (Node 1 / Garbler / party 0) and `B_j` (Node 2 / Evaluator / party 1),
the parties securely compute:

```
output_j = (A_j + B_j) > threshold ? region_id_j : "Clear"
```

Nothing about a sub-threshold region (whether it has 0 or 49 cases) is revealed.

## Two interchangeable backends, one set of flags

The evaluation sits behind a `ThresholdBackend` interface, and **every CLI flag
means the same thing for every backend** — switching engines is *only*
`--backend`:

| `--backend` | Engine | Technique | Status |
|-------------|--------|-----------|--------|
| `yao` (default) | **this repo** | Yao's Garbled Circuits + OT (from scratch) | runs out of the box |
| `mpyc` | [MPyC](https://github.com/lschoe/mpyc) | honest-majority Shamir secret sharing | runs out of the box |

Each backend converts the shared flags to whatever its engine needs internally
(e.g. `--party/--host/--port` become MPyC's native `-M/-I/-P` flags). The MPyC
backend demonstrates the same computation on an established framework (the
"swappable library" requirement); the real cryptographic deliverable is `yao`.
Adding another engine is a new subclass of `ThresholdBackend` registered in
[`smpc_gc/interface.py`](smpc_gc/interface.py).

## From-scratch Yao's Garbled Circuits + Oblivious Transfer

The core deliverable is a **self-contained implementation of the 2PC protocol**
in [`smpc_gc/yao/`](smpc_gc/yao) — no SMPC library does the cryptography:

| File | What it implements |
|------|--------------------|
| [`circuit.py`](smpc_gc/yao/circuit.py) | The `A + B > threshold` boolean circuit (ripple-carry adder → comparator → multiplexer), reduced to `XOR`/`AND` gates |
| [`garbling.py`](smpc_gc/yao/garbling.py) | The garbling scheme: **free-XOR + point-and-permute**, garbled AND tables, output decoding |
| [`ot.py`](smpc_gc/yao/ot.py) | **1-out-of-2 Oblivious Transfer** (Chou–Orlandi) over a MODP Diffie–Hellman group |
| [`protocol.py`](smpc_gc/yao/protocol.py) | The split Garbler / Evaluator halves (`run_garbler` / `run_evaluator`) that exchange messages over a channel |

The garbler holds `A`, the evaluator holds `B` and fetches its input-wire labels
by OT (so its bits stay private), then evaluates the garbled circuit and decodes
the output. The two parties run in **separate processes** and only ever exchange
messages over a shared `Channel`; neither call ever holds both parties' secret
bits. Threat model: honest-but-curious, matching the proposal.

## Shared resources (the integration points)

Everything backend-agnostic lives at the top of the `smpc_gc` package and is
used by *all* backends — these are the seams where the other student's
networking / secure-summation layer plugs in:

| Module | Shared resource | Integration note |
|--------|-----------------|------------------|
| [`smpc_gc/channel.py`](smpc_gc/channel.py) | `Channel` protocol + socket transport + `open_channel()` factory | **The transport swap point.** Replace `open_channel` (or pass any `ChannelFactory` to a backend) with the real networking layer — anything with `send(obj)` / `recv()` / `close()`. Nothing else changes. |
| [`smpc_gc/types.py`](smpc_gc/types.py) | `ThresholdProblem` / `RegionResult` | The A/B share hand-off boundary from the secure-summation layer. |
| [`smpc_gc/interface.py`](smpc_gc/interface.py) | `ThresholdBackend` ABC + registry | How engines are discovered and swapped. |
| [`smpc_gc/mock.py`](smpc_gc/mock.py) | mock generation + JSON problem loading | Stands in for the summation layer until integration. |

## Quick start

```bash
uv sync --extra dev

# From-scratch Garbled Circuits + OT (default backend), mocked A/B
uv run smpc-gc
uv run smpc-gc --seed 3 --regions 12 --threshold 50

# The identical problem on MPyC — nothing changes but the backend flag
uv run smpc-gc --backend mpyc

# Faster (weaker) OT group — 1024-bit MODP instead of the default 2048-bit (yao only)
uv run smpc-gc --ot-group 1024

# Inspect backends and their availability
uv run smpc-gc --list-backends
```

Each local run ends with a plaintext cross-check confirming the secure result
equals the cleartext `A + B > threshold` outcome.

## Real two-party runs

By default (`--party` unset) a backend runs a **local simulation**: one process
holds both shares (the `yao` backend still drives garbler and evaluator against
each other over a real in-process socket pair).

For a genuine networked run, start the two parties as **separate processes**.
Each loads a JSON problem with **only its own** share vector, and the parties
rendezvous on `--host:--port`. The flags are identical for every backend —
below, swap `yao` for `mpyc` and nothing else changes:

```bash
uv run smpc-gc --backend yao --input problems/1/problem_A.json --party 0   # holds A
uv run smpc-gc --backend yao --input problems/1/problem_B.json --party 1   # holds B
```

(Start order doesn't matter — party 1 retries the connection for a few
seconds. MPyC internally uses `port` for party 0 and `port+1` for party 1.)

A problem file (party 0's omits `b_shares`, party 1's omits `a_shares`):

```json
{ "threshold": 50, "region_ids": [1001, 1002],
  "a_shares": [30, 10], "b_shares": null, "bit_length": 16 }
```

## Problems

[`problems/`](problems) holds ten ready-made scenarios, each a directory with
party 0's input (`problem_A.json`), party 1's input (`problem_B.json`) and the
expected public outcome (`solution.json`). Run one locally by merging the two
files (see `smpc_gc.mock.load_problem_dir`), or distribute them as above.

## Experiments

[`experiments/run_experiments.py`](experiments/run_experiments.py) benchmarks
the two backends against each other and generates the comparison report.
**Every timed run is a genuine two-process 2PC session** (party 0 and party 1
as separate OS processes over real sockets — no simulation mode): correctness
on every problem in `problems/`, end-to-end wall time, scaling with regions /
bit-width / OT group, the fixed per-session overhead, bytes on the wire, and
implementation footprint.

```bash
uv run python experiments/run_experiments.py                # full run (~4 min)
uv run python experiments/run_experiments.py --quick        # subset (~1 min)
uv run python experiments/run_experiments.py --render-only  # regenerate report.md only
```

Outputs: `experiments/results.json` (raw measurements) and
`experiments/report.md` (the generated report).

## Layout

```
smpc_gc/
  yao/                        # ★ from-scratch Yao's GC + OT (the core deliverable)
    circuit.py                #   A+B>threshold boolean circuit
    garbling.py               #   free-XOR + point-and-permute garbling
    ot.py                     #   Chou–Orlandi 1-out-of-2 Oblivious Transfer
    protocol.py               #   split Garbler / Evaluator halves (talk over a channel)
  channel.py                  # shared party-to-party transport (the swap point)
  types.py                    # ThresholdProblem / RegionResult (the A/B interface boundary)
  interface.py                # ThresholdBackend ABC + backend registry
  backends/yao_backend.py     # adapter for the from-scratch engine
  backends/mpyc_backend.py    # MPyC adapter (translates the unified flags to -M/-I/-P)
  mock.py                     # mock A/B generation + JSON problem loading
  cli.py                      # `smpc-gc` command (one flag set for all backends)
main.py                       # thin entry point -> smpc_gc.cli
problems/                     # ten problem instances + expected solutions
experiments/                  # backend-comparison harness -> report.md
tests/                        # test_yao.py, test_threshold.py, test_problems.py
```

## Tests

```bash
uv run pytest
```

* `test_yao.py` — the OT (both group sizes), the garbling scheme, the full
  protocol on boundary cases, and the two-process distributed run.
* `test_threshold.py` — problem/mock semantics and the MPyC backend end-to-end.
* `test_problems.py` — **every problem in `problems/` on every backend**,
  checked against `solution.json`, plus a genuine two-process CLI run per
  backend with identical flags (only `--backend` differs).

### A note on performance

The `yao` backend runs textbook **base OT** — one Diffie–Hellman exponentiation
per evaluator input bit — so cost scales with `--bit-length` × regions × group
size. The default is the recommended-strength 2048-bit group (~1.7 s per 16-bit
region in pure Python); `--ot-group 1024` is ~5× faster (~0.35 s per region)
when you just want a quick demo. OT extension (amortizing base OTs) is the
standard optimization and is left as future work.

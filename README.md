# Privacy-Preserving COVID-19 Regional Quarantine Alert System

Confidential Computing final project — an end-to-end **Secure Multi-Party
Computation** system implementing [`proposal.md`](proposal.md).

> **Reading this project?** Start with **[`report.md`](report.md)** — the
> complete project report: architecture, cryptographic construction, the full
> security analysis, and the experimental results. This README is the
> developer-facing overview.

Four independent hospital networks jointly compute which regions have **more
than 50 COVID-19 cases**, without pooling patient data and without revealing
anything about regions below the threshold. A region with 0 cases and a region
with 49 cases are indistinguishable in the output.

```
$ ./run_all.sh
...
==========================================================
  QUARANTINE ALERT  (threshold: more than 50 cases)
==========================================================
  region    72701 (id 1001)  ->  clear
  region    72703 (id 1002)  ->  QUARANTINE
  region    72704 (id 1003)  ->  clear
  ...
----------------------------------------------------------
  11 region(s) must be locked down: 72703, 72712, 72716, ...
==========================================================
```

The counts behind those verdicts are never assembled anywhere — not on a node,
not on disk, not in a log.

---

## Quick start

```bash
uv sync --extra dev          # install
./run_all.sh                 # generate a demo scenario and run all 4 nodes
uv run pytest                # 156 tests
```

`run_all.sh` calls `src/demo_setup.py` on first use to generate per-node identity
keys, write the matching public keys into `config.json`, and synthesize hospital
records. Re-run with `--seed N` for a different scenario, or delete `keys/` and
`data/` to regenerate.

Other ways in:

```bash
./run_all.sh --ot-group 1024                # ~5x faster, weaker group, quick demo
./run_all.sh --show-shares                  # also print each node's raw share
uv run python src/main.py --node-id 1 --records data/hospital1.txt   # one node
uv run smpc-gc                              # the 2PC threshold layer on its own
```

---

## How it works

The architecture is **hybrid SMPC**: linear work (summing counts) is done
efficiently across all four nodes with additive secret sharing; the non-linear
work (the threshold comparison and conditional disclosure) is done by a
two-party garbled circuit.

```
   ┌───────────────────────────────────────────────────────────┐
   │ Phase 1 — Secure Sum          (all 4 nodes, F_p)          │
   │   local records -> histogram vector V                     │
   │   V split into 4 additive shares, one per node            │
   │   each node sums the shares it holds  ->  G_i             │
   └───────────────────────────┬───────────────────────────────┘
                               │  no node holds the global vector
   ┌───────────────────────────▼───────────────────────────────┐
   │ Phase 2 — Share Migration     (4 nodes -> 2 parties)      │
   │   node 3 -> node 1,  node 4 -> node 2                     │
   │   A = G_1 + G_3 (mod p)      B = G_2 + G_4 (mod p)        │
   │   A + B = true count (mod p)                              │
   └───────────────────────────┬───────────────────────────────┘
                               │  A and B are each uniform over F_p
   ┌───────────────────────────▼───────────────────────────────┐
   │ Phase 3 — Yao's Garbled Circuit   (node 1 <-> node 2)     │
   │   Node 1 garbles;  Node 2 fetches its labels by OT        │
   │   (A + B mod p) > 50 ? region_id : "Clear"                │
   └───────────────────────────┬───────────────────────────────┘
                               ▼
                    Node 2 publishes the alert list
```

Everything crosses the **same authenticated, encrypted channel** — Phase 3's
garbled tables and OT values included. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

### Why the circuit does the modular reduction

Phase 1's shares live in 𝔽ₚ, so `A + B` over the integers is either the true
count `T` or `T + p`. Deciding which is itself a comparison on secret data, so
the circuit does it: one conditional subtraction (`S ≥ p ? S − p : S`) between
the adder and the comparator.

That keeps Phase 1's **information-theoretic** hiding all the way to Phase 3 —
no statistical masking anywhere — and it is *cheaper* than masking with integers
would be: 20-bit shares instead of 47, so 20 base OTs per region instead of 47
(the dominant cost), and 195 AND gates instead of 287.

---

## Layout

All Python lives under `src/`; everything beside it is data, docs or tooling.

```
src/
  main.py                     # per-node entry point; runs all three phases
  demo_setup.py, keygen.py    # identity keys + demo scenario
  config_loader.py            # public config + strict validation
  sigma_handshake.py          # SIGMA AKE, per-node Ed25519 identities   [transport]
  secure_channel.py           # AES-256-GCM, counter nonces, AAD         [transport]
  node.py                     # P2P mesh, framing, authenticated delivery[transport]
  vectorize.py                # records -> histogram vector              [phase 1]
  secret_sharing.py           # additive sharing over F_p                [phase 1]
  secure_sum.py               # the distributed secure sum               [phase 1]
  share_reduction.py          # 4 nodes -> 2 parties                     [phase 2]
  gc_handoff.py               # the Phase 2 -> Phase 3 boundary          [phase 2/3]
  gc_channel.py               # adapter: run the GC over our transport   [phase 3]
  smpc_gc/                    # the 2PC threshold engine                 [phase 3]
    yao/                      #   ★ from-scratch Yao's GC + OT
      circuit.py              #     A+B>threshold, with mod-p reduction
      garbling.py             #     free-XOR + point-and-permute garbling
      ot.py                   #     Chou-Orlandi 1-out-of-2 Oblivious Transfer
      protocol.py             #     split Garbler / Evaluator halves
    threshold.py              #   evaluate_threshold(): one circuit per region
    channel.py                #   transport contract + socket implementation
    types.py                  #   ThresholdProblem / RegionResult
    mock.py, cli.py           #   mock/JSON problems, the `smpc-gc` command

config.json                   # public config (regions, field, node addresses)
problems/                     # ten problem instances + expected solutions
experiments/                  # measurement harness -> measurements.md
tests/                        # 156 tests
run_all.sh                    # launch the whole demo
```

---

## The two halves

The project was split along the interface boundary described in
[`division.md`](division.md), so both halves could be built and tested
independently:

* **Networking & Secure Summation** (Phases 1–2, transport) — the mesh, the
  SIGMA handshake, additive sharing, the secure sum, share migration.
* **Garbled Circuits & Logic Evaluation** (Phase 3) — the boolean circuit,
  garbling, Oblivious Transfer, the two-party protocol.

They meet at exactly two seams, both of which are covered by tests:

* `smpc_gc.types.ThresholdProblem` — the `A`/`B` hand-off (`gc_handoff.py`,
  `tests/test_gc_handoff.py`).
* `smpc_gc.channel.Channel` — the transport contract. `gc_channel.NodeChannel`
  implements it over the SIGMA-encrypted mesh, so the crypto layer runs over
  real hospital links without changing a line (`tests/test_gc_channel.py`).

---

## From-scratch cryptography

No SMPC library is involved. The one runtime dependency, `cryptography`, supplies
only the standard primitives *around* the protocol (Ed25519, X25519, HKDF,
AES-GCM). The secure computation itself is built on `hashlib`, `secrets` and
`socket`:

| File | What it implements |
|---|---|
| `src/smpc_gc/yao/circuit.py` | ripple-carry adder → conditional mod-p subtraction → comparator → multiplexer, reduced to `XOR`/`AND` |
| `src/smpc_gc/yao/garbling.py` | free-XOR + point-and-permute, garbled AND tables, output decoding |
| `src/smpc_gc/yao/ot.py` | 1-out-of-2 Oblivious Transfer (Chou–Orlandi) over MODP |
| `src/smpc_gc/yao/protocol.py` | the Garbler / Evaluator halves |

The garbler holds `A`, the evaluator holds `B` and fetches its input-wire labels
by OT. The two halves never co-hold secret bits — even the local simulation
drives them against each other over a real socket pair.

### Why there is only one engine (and what happened to MPyC)

An earlier iteration put the evaluation behind a pluggable `ThresholdBackend`
interface and added [MPyC](https://github.com/lschoe/mpyc) as a second engine, to
compare our implementation against an established framework. **We evaluated it,
found it unsuitable, and removed it.** Two reasons, in order of importance:

1. **MPyC does not implement Yao's Garbled Circuits.** It is *honest-majority
   Shamir secret sharing* over arithmetic circuits — a different primitive
   entirely. Benchmarking it against this engine compares two unrelated
   techniques, which is not the comparison this project is about.

2. **In the two-party setting it provides no input privacy at all.**
   Honest-majority Shamir requires `t < m/2`. With `m = 2` parties MPyC runs at
   threshold `t = 0`, and a degree-0 sharing polynomial is the constant
   `f(X) = secret` — so the "share" *is* the secret. We confirmed this
   experimentally before dropping it: party 1 read party 0's private input
   verbatim from its own share. Yao's protocol is what `proposal.md` specifies
   precisely because it *is* secure for two parties.

MPyC would be sound for a *different* architecture: one 4-party session across
all four hospitals, skipping the reduction to two parties entirely, where
`t = 1` and no single hospital learns anything. That is a legitimate alternative
design — but it is not a drop-in engine for the proposal's hybrid pipeline.

With one engine left, the backend abstraction and its registry were pure
indirection, so they went too. `smpc_gc.threshold.evaluate_threshold` is called
directly. The `Channel` seam remains — that one earns its keep, since it is what
lets the 2PC run over the SIGMA-encrypted mesh instead of a bare socket.

---

## Tests

```bash
uv run pytest                 # everything (~1 min)
uv run pytest -m "not slow"   # skip the multi-process and 2048-bit runs
```

| File | Covers |
|---|---|
| `test_secure_sum.py` | vectorization, additive sharing, the secure sum |
| `test_share_reduction.py` | Phase 2 routing, reconstruction, share uniformity |
| `test_sigma_handshake.py` | authentication, impersonation, replay, MITM |
| `test_node_transport.py` | replay/reorder rejection, frame limits, duplicate contributions, timeouts |
| `test_config_loader.py` | every config invariant, including primality and field sizing |
| `test_yao.py` | OT (both groups + validation), garbling, the protocol |
| `test_modulus.py` | modular reconstruction, both wrap branches, end to end |
| `test_gc_handoff.py` | the Phase 2→3 schema round-trip on real parameters |
| `test_gc_channel.py` | the GC engine running over the encrypted mesh |
| `test_threshold.py` | problem semantics, validation, JSON round-trip |
| `test_problems.py` | every problem in `problems/`, plus a two-process CLI run |
| `test_end_to_end.py` | the whole system as 4 OS processes, alert list vs ground truth |

---

## Experiments

`experiments/run_experiments.py` measures the engine: correctness on every
problem, wall-clock scaling with regions / share width / OT group, the fixed
protocol overhead, bytes on the wire, and implementation footprint. Every timed
run is a genuine two-process 2PC session.

```bash
uv run python experiments/run_experiments.py            # full (~3 min)
uv run python experiments/run_experiments.py --quick    # subset (~1 min)
```

Outputs `experiments/results.json` and `experiments/measurements.md`; the
project report ([`report.md`](report.md)) cites these numbers.

---

## Assumptions and scope

Per `proposal.md` §3: honest-but-curious participants and a fixed, statically
configured topology with no node-failure handling. The network between nodes is
treated as untrusted. Full detail, including deliberate demo trade-offs and
residual risks, is in [`THREAT_MODEL.md`](THREAT_MODEL.md).

`proposal.md` §4 (multi-day trend detection for regions trending upward without
crossing the threshold on any single day) is **not implemented** — it remains
future work, alongside OT extension for performance.

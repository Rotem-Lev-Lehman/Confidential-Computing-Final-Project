# Threat model

What this system protects, against whom, and what it deliberately does not
protect. Read alongside [`proposal.md`](proposal.md) §3 (Project Assumptions).

This is the detailed reference. For the security analysis in the context of the
whole project — architecture, construction, and results — see
[`report.md`](report.md).

---

## 1. The setting

Four independent hospital networks hold patient records. Public health officials
need the list of regions with **more than 50 total cases**. The system computes
that list without any hospital learning another's data and without revealing
anything about regions below the threshold.

### Two deployments

The same code runs in two settings, and several security properties differ
between them because the *environment* differs, not because the protocol does.

| | **Demo** (what we show in class) | **Production** (what the proposal describes) |
|---|---|---|
| Deployment | 4 processes, one machine, one operator | 4 hospital networks, separate machines |
| Participants | honest-but-curious | honest-but-curious |
| Network | loopback, trusted | **untrusted** — this is why SIGMA + AES-GCM exist |
| Console | one shared terminal | four separate consoles, four organizations |
| Local disk | one shared filesystem | four separate filesystems |

Everything below states which setting it applies to.

---

## 2. Adversary model

**Honest-but-curious (semi-honest) participants**, per `proposal.md` §3: nodes
follow the protocol faithfully but try to learn whatever they can from what they
legitimately see — their own inputs, the messages they receive, and their logs.

**An active network adversary.** In production the links between hospitals cross
untrusted infrastructure. We assume an attacker who can observe, drop, reorder,
duplicate, and inject traffic, and who can connect to any node's port.

**Non-collusion between the two 2PC parties.** Node 1 (Garbler) and Node 2
(Evaluator) must not pool their consolidated vectors `A` and `B`; together those
reconstruct every regional count. This is the standard assumption for 2PC and
matches the proposal's "non-collusion among a majority of the computing nodes."

### Out of scope

* **Malicious participants.** A node that deviates from the protocol — garbling a
  different circuit, lying about the output, sending malformed shares — is
  outside the stated model. Several defences against this are implemented anyway
  (§5), but no completeness is claimed.
* **Compromised endpoints.** If a hospital's machine is owned, its own patient
  data is already lost.
* **Traffic analysis.** Message sizes and timings scale with the public
  parameters (region count, share width) and leak nothing beyond them.
* **Availability.** A node that refuses to participate stops the computation.
  There is no dropped-node handling; the proposal fixes the topology.

---

## 3. What each phase hides, and from whom

### Phase 1 — Secure Sum (all nodes)

Each node splits every regional count into `n` additive shares over 𝔽ₚ and keeps
one share of each peer's vector.

* **Guarantee:** information-theoretic. Any proper subset of the shares of a
  value is uniform over 𝔽ₚ and independent of that value — this holds against an
  adversary with unbounded computing power, not merely a bounded one.
* **What a node sees:** three uniformly random vectors, plus its own data.
* **What nobody sees:** the Global Region Vector. It exists only as four shares
  spread across four nodes.

### Phase 2 — Share Migration (all nodes)

Nodes 3 and 4 send their Phase 1 shares to Nodes 1 and 2, which consolidate them
into `A` and `B` with `A + B ≡ true count (mod p)`.

* **Guarantee:** still information-theoretic, and inherited unchanged — a Phase 1
  share is *already* a uniform mask, so nothing extra needs adding.
* **What Node 1 sees:** `A`, uniform over 𝔽ₚ, independent of the counts. Same for
  Node 2 and `B`.
* **Design note:** an earlier version re-shared the raw local vectors with a
  2⁴⁰-bit integer mask, which is only *statistically* hiding (leakage ≈
  count/2⁴⁰ per share) and made Phase 1 unused. Keeping the reduction inside the
  field is strictly stronger, and cheaper — see §6.

### Phase 3 — Garbled Circuit (Nodes 1 and 2)

The two parties evaluate, per region, `(A + B mod p) > 50 ? region_id : Clear`.

* **Guarantee:** computational, under standard assumptions — a circular
  correlation-robust hash (SHA-256, modelled as a random oracle) for garbling,
  and Computational Diffie–Hellman in a 2048-bit MODP group for the Oblivious
  Transfer.
* **What the Evaluator sees:** garbled tables, random-looking wire labels, and
  OT ciphertexts. It obtains exactly one label per wire and cannot form the
  other without solving CDH.
* **What the Garbler sees:** the evaluator's OT choice values `B`, which are
  uniform in the group regardless of the choice bits.
* **What both learn:** only the public output — `region_id` or `Clear` per
  region.

### The published result

`Clear` at a public region index. So the output *does* reveal which regions are
below the threshold — but never by how much. A region with 0 cases and one with
49 produce byte-identical transcripts, which is exactly what `proposal.md` §1
demands ("must not leak whether a safe region has 0 cases or 49 cases").

Revealing *that* a region is clear is inherent in the proposal's own output
formula (`Need Quarantine ? Region ID : "Clear"`), and is arguably required —
officials need to know which regions were assessed. A stricter variant would
shuffle the region order or pad the output set; that is left as future work.

---

## 4. Transport security

Every message between nodes, in every phase including the garbled circuit,
crosses the same protected channel.

| Property | Mechanism | Where |
|---|---|---|
| Peer authentication | SIGMA sign-and-MAC, per-node Ed25519 identity keys | `src/sigma_handshake.py` |
| Key agreement | Ephemeral X25519, HKDF-SHA256, transcript-bound | `src/sigma_handshake.py` |
| Forward secrecy | DH keys discarded after the handshake | `src/sigma_handshake.py` |
| Confidentiality + integrity | AES-256-GCM per directed link | `src/secure_channel.py` |
| Replay / reorder resistance | Counter nonces + `sender→receiver#seq` as AAD, never transmitted | `src/secure_channel.py` |
| Sender attribution | Messages carry the SIGMA-*authenticated* id, not a self-declared one | `src/node.py` |
| Memory-exhaustion resistance | Length-prefixed frames, 8 MiB cap checked before allocation | `src/node.py` |
| Liveness | Socket and collection timeouts; a dead peer raises, never hangs | `src/node.py` |
| Session hygiene | One inbound session per peer; self-connections refused; connection cap | `src/node.py` |

**There is no shared secret anywhere.** Each node holds its own private key; the
public keys are in `config.json`. A valid signature proves *which* node is on the
other end, not merely that it belongs to a group.

**This covers all three phases.** Phase 3's garbled tables and OT values travel
over the same protected links as Phase 1 and Phase 2 traffic, because the 2PC
engine takes its transport as a parameter (`src/gc_channel.py`). An earlier
iteration also offered an MPyC engine, which could *not* be covered — MPyC brings
its own networking with no hook to substitute ours, so it opened a second,
unprotected connection. That was one of several reasons it was dropped; see
`README.md`.

---

## 5. Hardening beyond the stated model

The proposal assumes semi-honest participants, so the following are not required
by the model. They are implemented anyway, because they are cheap and because a
security claim is worth more when it does not rest on a single assumption:

* **OT group-element validation** — both parties reject values outside the
  order-q subgroup, so a deviating garbler cannot use a small-order `A` to probe
  the evaluator's choice bits (`smpc_gc/yao/ot.py`).
* **Transcript-bound OT key derivation** — `A` and `B` are hashed into every OT
  key, as in Chou–Orlandi, rather than the shared element alone.
* **One contribution per authenticated peer** — `Node.collect` rejects a peer
  that sends twice, so a deviating node cannot displace another's data
  (`node.py`).
* **Strict message typing** — both 2PC halves verify the type of every message
  received rather than reading a missing key as `None`
  (`smpc_gc/yao/protocol.py`).
* **Strict lengths** — OT ciphertexts must be exactly one wire label wide, so a
  truncated ciphertext is an error rather than a short label.

### Known residual risks under a malicious party

* A malicious **garbler** could garble a circuit other than the agreed one; the
  evaluator has no way to check. Defending this needs cut-and-choose or
  authenticated garbling.
* A malicious **evaluator** could report a false output in message 5.
* Neither is defended, both are out of model, and both are stated here rather
  than left implicit.

---

## 6. Deliberate demo trade-offs

These are **accepted risks in the demo deployment**, listed so it is clear they
were identified and scoped rather than missed. Each is bounded by the demo
environment and does not exist in production.

### 6.1 All four nodes print to one console

`run_all.sh` runs the four node processes in one terminal. With `--show-shares`,
each node prints its Phase 1 share of the global vector, and the four shares
together reconstruct it.

* **Why it is acceptable:** in production the four consoles belong to four
  organizations on four machines; no combined transcript exists. Showing the
  shares is also the clearest way to demonstrate that a share is uniform noise.
* **Bounded by:** the flag is **off by default**. The default output is phase
  progress plus the public alert list.

### 6.2 `--gc-out` dumps a party's share vector

The two parties' dump files together reconstruct every regional count,
sub-threshold ones included.

* **Why it is acceptable:** in production the two files are written on two
  different machines by two different hospitals; neither can read the other's.
* **Bounded by:** the flag is **off by default** — the real pipeline hands the
  vectors to the 2PC engine in memory and never touches disk. When used, files
  are written mode `0600` into per-node subdirectories, and `gc_input/` is
  gitignored.

### 6.3 `demo_setup.py` rewrites `config.json`

It generates fresh identity keys and writes the public halves into the config.

* **Why it is acceptable:** the committed `config.json` ships placeholder public
  keys whose private halves nobody has — deliberately, so a checkout cannot
  authenticate as any node.
* **Bounded by:** private keys go to `keys/` mode `0600`, which is gitignored.

### 6.4 Synthetic patient data

`data/` holds generated records, not real ones. Gitignored regardless, and
written `0600`, so the demo habits match the production ones.

---

## 7. Cryptographic parameter choices

| Parameter | Value | Rationale |
|---|---|---|
| Field modulus `p` | 1048573 (2²⁰−3, prime) | Must exceed `num_nodes × max_local_count` so the global sum cannot wrap. Validated at startup, including primality. |
| Share width | 20 bits (`p.bit_length()`) | Base OT costs one modular exponentiation per evaluator input bit, so this is the dominant cost driver. |
| Wire labels | 128 bits | Standard for garbled circuits. |
| Gate hash | SHA-256, truncated to 128 bits | Modelled as a random oracle; free-XOR needs circular correlation robustness. |
| OT group | RFC 3526 MODP-2048 (default) | Current recommended strength. `--ot-group 1024` is ~5× faster for demos and explicitly weaker. |
| Identity keys | Ed25519 | Per-node; no shared secret. |
| AKE | X25519 + HKDF-SHA256 | Ephemeral, for forward secrecy. |
| Record encryption | AES-256-GCM | 32-byte session key from the handshake. |

**Known performance limitation.** The OT is textbook *base* OT — one public-key
operation per evaluator input bit, no OT extension. Cost is linear in
`regions × bit_length`. OT extension is the standard fix and is left as future
work; it changes performance, not the security argument.

---

## 8. Summary

| Claim | Strength | Rests on |
|---|---|---|
| No node learns another's local counts | Information-theoretic | Additive secret sharing over 𝔽ₚ |
| No node learns the global per-region totals | Information-theoretic | Shares never combined outside the circuit |
| Sub-threshold counts never revealed | Computational | Yao's GC + OT (RO model, CDH) |
| Only the two parties can run Phase 3 | Computational | SIGMA authentication, Ed25519 |
| Traffic cannot be read, forged, or replayed | Computational | AES-256-GCM, counter nonces, AAD |
| Correct results | Verified | 156 tests, including the full pipeline as 4 OS processes |

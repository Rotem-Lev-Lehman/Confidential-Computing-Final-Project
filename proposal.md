# Project Proposal: Privacy-Preserving COVID-19 Regional Quarantine Alert System Using SMPC

## Students

Rotem Lev Lehman, Eli Ben Shimol, Danel Boikis, Lidor Tubul.

---

## Outline

This document outlines our team's project proposal for the Confidential Computing course. It covers two foundational pillars of Secure Multi-Party Computation (SMPC)—the **Secure Sum Protocol** (via Additive Secret Sharing) and **Yao’s Garbled Circuits (GC)**—by implementing a hybrid, privacy-preserving distributed application to identify pandemic hot spots without compromising patient privacy.

---

## 1. Problem Statement & Scenario

During an active COVID-19 outbreak, **four independent hospital networks** maintain local databases containing patient diagnostic records, including the specific geographic region each patient resides in. To prevent community spread, public health officials need to know which regions have crossed a critical **quarantine threshold** (defined as **more than 50 total cases** in that region) so they can enforce localized lockdown measures.

### The Privacy Constraints

* **No centralized pooling:** Due to strict health data privacy laws (e.g., HIPAA or GDPR), hospitals cannot pool their raw patient data into a single database.
* **Zero leakage on sub-threshold regions:** If a region has 50 or fewer total cases across all hospitals combined, its case count and identity **must remain completely hidden**. A hospital must not leak whether a safe region has 0 cases or 49 cases, preventing unnecessary panic and protecting the privacy of sparsely populated areas.
* **Anonymized scaling:** Total patient volumes per hospital must not be revealed.

---

## Alternative Technical Approaches

Before settling on our proposed hybrid SMPC architecture, we evaluated several technical paradigms for solving this privacy-preserving threshold problem:

| Approach | Trust Assumption | Privacy Guarantees | Performance Overhead | Implementation Complexity |
| --- | --- | --- | --- | --- |
| **Centralized TEE** (e.g., Intel SGX) | Trust in hardware manufacturer (Intel/AMD) and CPU security. | High; data is encrypted in transit and processed in a secure enclave. | **Low;** processes at near-native CPU speeds. | Medium; requires specialized hardware and SDKs. |
| **Fully Homomorphic Encryption (FHE)** | Cryptographic hardness assumptions (Lattice-based). | High; data remains encrypted during summation and thresholding. | **Very High;** evaluation of non-linear threshold circuits is extremely slow. | High; requires complex math libraries. |
| **Differential Privacy (DP)** | Trust in the aggregating aggregator to add noise properly. | Statistical; guarantees data can't be pinned to an individual, but introduces accuracy errors. | **Very Low;** minimal mathematical noise injection overhead. | Low; simple noise-generation algorithms. |
| **Hybrid SMPC (Secure Sum + Yao's GC)** *(Chosen)* | Non-collusion among a majority of the computing nodes. | Cryptographic; mathematical certainty that no data is leaked unless a threshold is crossed. | **Medium;** fast linear addition, with minimal 2-party overhead for the threshold checks. | High; requires custom cryptographic protocol integration. |

---

## 2. System Architecture & Cryptographic Flow

The chosen system uses a **Hybrid SMPC Architecture** designed to optimize performance. Linear operations (summing case counts per region) are performed efficiently across all 4 nodes using a Secure Sum protocol, while non-linear operations (the greater-than-50 threshold logic and conditional region disclosure) are handled by a 2-Party Garbled Circuit sub-protocol.

```
[4-Node P2P Mesh] ──► Compute Shared Global Vector (via Secure Sum)
                            │
                            ▼ (Linear Share Reduction to 2 Parties)
                 ┌─────────────────────────────────────┐
                 │ 2-Party Garbled Circuit Engine      │
                 │                                     │
                 │  Node 1 (Garbler) ──► Garbles Circuit│
                 │                            │        │
                 │  Node 2 (Evaluator) ◄──────┘        │
                 └─────────────────────────────────────┘
                            │
                            ▼
               [Conditional Threshold Output]

```

### Phase 1: Local Vectorization & Distributed Aggregation (Secure Sum)

1. **Histogram Vectorization:** Every hospital maps its local database into a fixed-length vector $\vec{V}$ of size $M$ (where $M$ is the number of monitored geographic regions, e.g., 20 specific zip codes). The value at index $j$ is the local COVID-19 case count for that region.
2. **Additive Secret Sharing:** To initiate the Secure Sum, each hospital splits its local vector elements into random additive shares over a finite prime field $\mathbb{F}_p$ such that the sum of the shares equals the local value. These shares are distributed across the 4-node P2P mesh network.
3. **Homomorphic Summation:** Because additive secret sharing is inherently homomorphic, the nodes sum their received shares locally without any network communication:

$$\text{Global Share}_j = \text{Share}_{\text{Hosp1}}(j) + \text{Share}_{\text{Hosp2}}(j) + \text{Share}_{\text{Hosp3}}(j) + \text{Share}_{\text{Hosp4}}(j)$$

The nodes now collectively hold a secret-shared **Global Region Vector** $\vec{G}$, which represents the secure sum of the regional totals completely blindly.

### Phase 2: Protocol Switching & Share Migration

A 4-party circuit is computationally heavy. To process the threshold logic cleanly, the 4 nodes compress their shares down to 2 designated nodes: **Node 1 (Garbler)** and **Node 2 (Evaluator)**.

* Nodes 3 and 4 mathematically mask and send their algebraic shares to Nodes 1 and 2.
* This leaves Node 1 holding a single consolidated value ($A$) and Node 2 holding a single consolidated value ($B$), such that $A + B = \text{True Regional Case Count} \pmod p$.

### Phase 3: The Garbled Circuit & Threshold Check (Yao's 2PC)

Node 1 and Node 2 execute a two-party Yao's Garbled Circuit protocol for each regional element:

1. **Circuit Design:** The boolean circuit takes two private binary inputs ($A$ and $B$) and executes the following internal logic:

$$\text{Need Quarantine} = (A + B) > 50$$

$$\text{Output} = \text{Need Quarantine} \ ? \ \text{Region ID} \ : \ \text{"Clear"}$$

2. **Garbling & Evaluation:** Node 1 encrypts (garbles) the logic gates. Node 2 uses **Oblivious Transfer (OT)** to fetch its corresponding input wire labels from Node 1 without revealing its data. Node 2 then evaluates the circuit.
3. **Quarantine Notification Alert:** If the threshold is crossed, the circuit decrypts to reveal the actual `Region ID`. Node 2 collects these active hot spot IDs and broadcasts the final quarantine alert list to public health authorities. If a region has 50 or fewer cases, the circuit outputs `"Clear"`, revealing absolutely nothing about the actual count.

---

## 3. Project Assumptions

During the project, we assume the following:

* **Honest-but-Curious (Semi-Honest) Adversaries:** We assume nodes follow the protocols honestly but will try to learn info from logs.
* **Fixed Topology:** The network mesh is static and hardcoded via local config files. There is no dynamic node discovery or handling of dropped connections.

---

## 4. Future Work

This project can be extended in the future, if we see we have the time for it, to also identify trends of specific regions during several consecutive days. For example, if on the first day we have 40 COVID cases in region A, on day 2 - 42, and on day 3 - 45, we will set an alert about this region even though it has not passed the 50 patients threshold on any individual day.

# PSAS-MTS Protocol Implementation

An exact, zero-shortcut implementation of the **PSAS-MTS** (*Provable Secure ECC and HMAC-Based Robust and Efficient Authentication Scheme for Maritime Transportation System*) protocol, matching the specification published in *IEEE Transactions on Intelligent Transportation Systems* (Vol. 26, No. 12, Dec 2025).

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Git

### Running the Protocol & Verification Suite
```bash
python psas_mts.py
```

This single command executes:
1. **System Initialization & Registration** (Vessel, HAP, Control Station).
2. **Step-by-Step Authentication Flow** (Steps 1–7).
3. **Computation & Communication Cost Evaluation**.
4. **Informal Security Proposition Verification**.
5. **BAN Logic Proof Trace** (S1–S30).
6. **Random Oracle Model (ROR) Theorem Evaluator**.
7. **Functional Unit Tests & Active Attack Simulation Suite**.

---

## 📁 Repository Structure

- [psas_mts.py](file:///d:/Implementations/PSAS-MTS/psas_mts.py) — System execution runner & orchestrator.
- [entities.py](file:///d:/Implementations/PSAS-MTS/entities.py) — Memory & runtime models for Vessel, HAP, and Control Station.
- [initialization.py](file:///d:/Implementations/PSAS-MTS/initialization.py) — Setup of parameters & CS credentials.
- [registration_vessel.py](file:///d:/Implementations/PSAS-MTS/registration_vessel.py) / [registration_hap.py](file:///d:/Implementations/PSAS-MTS/registration_hap.py) — Identity and key enrollment phases.
- [authentication.py](file:///d:/Implementations/PSAS-MTS/authentication.py) — Core 7-step cryptographic handshake and key agreement.
- [crypto_primitives.py](file:///d:/Implementations/PSAS-MTS/crypto_primitives.py) — SECP160R1 ECC operations, fixed-width XORs, hashes, and concatenations.
- [performance.py](file:///d:/Implementations/PSAS-MTS/performance.py) — Verification of standard computation timings (36.654 ms total).
- [communication_cost.py](file:///d:/Implementations/PSAS-MTS/communication_cost.py) — Network bandwidth analysis (3712 bits total).
- [ban_logic.py](file:///d:/Implementations/PSAS-MTS/ban_logic.py) — Implementation of Burrows-Abadi-Needham logic derivation.
- [ror_model.py](file:///d:/Implementations/PSAS-MTS/ror_model.py) — Semantic security bounds and advantage evaluations under the Random Oracle Model.
- [informal_security.py](file:///d:/Implementations/PSAS-MTS/informal_security.py) — Rules verifying resistance to all 15 protocol attacks.
- [test_protocol.py](file:///d:/Implementations/PSAS-MTS/test_protocol.py) — Unit testing suite for individual components.
- [test_attacks.py](file:///d:/Implementations/PSAS-MTS/test_attacks.py) — Active adversary attack vectors (Replay, MITM, Impersonation).
- [psas_mts.spdl](file:///d:/Implementations/PSAS-MTS/psas_mts.spdl) — Scyther security verification script.
- [docs/](file:///d:/Implementations/PSAS-MTS/docs/) — Specification files, design parameters, and verification requirements.

---

## 📊 Verification Metrics

### 1. Performance Compliance
- **Computation Cost**: **36.654 ms** (Vessel: 20.563 ms, HAP: 12.351 ms, CS: 3.740 ms) mapped to Table VIII.
- **Communication Cost**: **3712 bits** (msg1: 672, msg2: 1184, msg3: 672, msg4: 1184) mapped to Table V.

### 2. Formal Security Properties
- **BAN Logic Goals (G1–G5)**: Successfully derived using 30 formal steps (S1–S30).
- **ROR Model (Theorems 1 & 2)**: Negligible impersonation advantages and proof of session key semantic security.
- **Scyther (Figure 6 Claims)**: Verified clean under active network adversary simulations.

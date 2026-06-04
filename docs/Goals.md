\# GOALS.md — Single Source of Truth for PSAS-MTS Implementation



\## Paper Reference

\- Title: Design of a Provable Secure ECC and HMAC-Based Robust and Efficient Authentication Scheme for Maritime Transportation System

\- Authors: Sanjeev Kumar Dwivedi, Mohammad Abdussami, Mohd Shariq, Ruhul Amin, Shehzad Ashraf Chaudhry, Ashok Kumar Das, Norziana Jamil

\- Published: IEEE Transactions on Intelligent Transportation Systems, Vol. 26, No. 12, December 2025

\- DOI: 10.1109/TITS.2025.3605529

\- Protocol Name: PSAS-MTS (Provable Secure Authentication Scheme for Maritime Transportation System)



\---



\## Primary Objective

Implement the PSAS-MTS protocol exactly as described in the paper. Every formula, every

variable, every verification step must match the paper precisely. No assumptions, no

shortcuts, no simplifications. The implementation must reproduce every result claimed

in the paper.



\---



\## Success Criteria Checklist



\### 1. Protocol Correctness

\- \[ ] System initialization produces valid CS key pair (PrCS, PUCS = PrCS · G)

\- \[ ] HAP registration produces valid HAP key pair (PrHAP, PUHAP = PrHAP · G)

\- \[ ] Vessel registration produces correct PIDV = h(IDV || PrCS)

\- \[ ] Vessel registration produces correct QV = h(IDV || PIN) XOR PrV

\- \[ ] Vessel registration produces correct RV = PIDV XOR h(PrV)

\- \[ ] Vessel registration produces correct SV = h(PIDV || PIN || PrV)

\- \[ ] Login verification: SV' = h(PIDV || PIN || PrV) matches stored SV

\- \[ ] PSAS-MTS 2: all of M1, M2, M3, M4, X, Y computed correctly

\- \[ ] PSAS-MTS 3: Z1, ssk, Tag1 computed correctly by HAP

\- \[ ] PSAS-MTS 4: CS verifies Tag1, recovers PIDV', IDHAP', verifies M4

\- \[ ] PSAS-MTS 5: CS computes W, M5, M6, SKV,CS, VerSK correctly

\- \[ ] PSAS-MTS 6: HAP verifies M6, computes ssk2, Tag2

\- \[ ] PSAS-MTS 7: Vessel verifies Tag2, recovers W', verifies M5, establishes SKV,CS

\- \[ ] Session key agreement: SKV,CS at vessel == SKV,CS at CS



\### 2. Performance Results (must match paper exactly)

\- \[ ] Total computation cost = 36.654 ms (Table VIII, Our scheme)

\- \[ ] Communication cost = 3712 bits (Table V, Our scheme)

\- \[ ] Per-operation timings match Table VII exactly:

&#x20; - Th (hash) on Device = 0.009 ms, Server = 0.004 ms, Drone/HAP = 0.006 ms

&#x20; - Ted (sym enc/dec) on Device = 0.018 ms, Server = 0.009 ms, Drone/HAP = 0.013 ms

&#x20; - Tb (bilinear pairing) on Device = 17.36 ms, Server = 4.038 ms, Drone/HAP = 12.52 ms

&#x20; - Tpa (point mul ECC) on Device = 5.116 ms, Server = 0.926 ms, Drone/HAP = 4.107 ms

&#x20; - Tpad (point add ECC) on Device = 0.013 ms, Server = 0.006 ms, Drone/HAP = 0.018 ms



\### 3. Communication Cost Breakdown (must match Table V and Table VI)

\- \[ ] ECC point = 160 bits

\- \[ ] Identity = 160 bits

\- \[ ] XOR result = 160 bits

\- \[ ] Hash output = 160 bits

\- \[ ] Timestamp = 32 bits

\- \[ ] Random number = 128 bits

\- \[ ] HMAC output = 160 bits

\- \[ ] msg1 = {Y, T1, M1, M3, M4} = 160+32+160+160+160 = 672 bits

\- \[ ] msg2 = {msg1, Tag1, IDHAP, Z1, T2} = 672+160+160+160+32 = 1184 bits

\- \[ ] msg3 = {Z, M5, M6, VerSK, T3} = 160+160+160+160+32 = 672 bits

\- \[ ] msg4 = {msg3, Tag2, IDHAP, Z1, T4} = 672+160+160+160+32 = 1184 bits

\- \[ ] Total = 672 + 1184 + 672 + 1184 = 3712 bits



\### 4. Computation Cost Breakdown (must match Table VIII, Our scheme row)

\- \[ ] Vessel operations: 11Th + 4Tpa = 11(0.009) + 4(5.116) = 0.099 + 20.464 = 20.563 ms

\- \[ ] HAP operations: 5Th + 3Tpa = 5(0.006) + 3(4.107) = 0.030 + 12.321 = 12.351 ms

\- \[ ] CS operations: 9Th + 4Tpa = 9(0.004) + 4(0.926) = 0.036 + 3.704 = 3.740 ms

\- \[ ] Wait — exact formula from Table VIII Our row: 11Th + 4Tpa (vessel) + (HAP) + (CS)

\- \[ ] Total latency = 36.654 ms



\### 5. Security Features (must match Table III, Our column — all checkmarks)

\- \[ ] SPF1: Achieves anonymity and untraceability

\- \[ ] SPF2: Achieves mutual authentication

\- \[ ] SPF3: Secure against offline-password guessing attacks

\- \[ ] SPF4: Secure against user/server impersonation attacks

\- \[ ] SPF5: Secure against replay attacks

\- \[ ] SPF6: Secure against MITM attacks

\- \[ ] SPF7: Secure against ephemeral information leakage attacks

\- \[ ] SPF8: Forward and backward secrecy

\- \[ ] SPF9: Secure against stolen verifiers attacks

\- \[ ] SPF10: Secure against device capture attacks

\- \[ ] SPF11: Secure against drone capture attacks

\- \[ ] SPF12: Secure against denial-of-service attacks

\- \[ ] SPF13: Secure against de-synchronization attacks

\- \[ ] SPF14: Achieves session-key security

\- \[ ] SPF15: Provides session-key verification



\### 6. Formal Security — ROR Model (must prove both theorems)

\- \[ ] Theorem 1: Pr\[EViCs] = 1/qhs (negligible)

\- \[ ] Theorem 1: Pr\[EHapCs] = 1/(qhm · p) (negligible)

\- \[ ] Theorem 1: Pr\[ECsHapV] = 1/qhs (negligible)

\- \[ ] Theorem 2: Pr\[SK(V,CS) = h(IDCS||PIDV||W||T3)] >= ε/8 − Pr\[EViCs]/2 (semantic security holds)

\- \[ ] ROR queries implemented: Setup, h(mk), HMAC(k, mK), Send(Eα, Mα), Execute(Vi, CSj), Reveal(Eα), Test(Eα)



\### 7. Formal Security — BAN Logic (must derive all 5 goals)

\- \[ ] G1: CS |≡ msg1

\- \[ ] G2: CS |≡ PIDV

\- \[ ] G3: V |≡ msg3

\- \[ ] G4: V |≡ W

\- \[ ] G5: V |≡ SK

\- \[ ] All 12 assumptions A1–A12 correctly modeled

\- \[ ] All derivation steps S1–S30 correctly traced



\### 8. Scyther Verification Claims (must match Figure 6)

\- \[ ] Proposed, Vessel1: Secret IDcs — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel2: Secret IDhap — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel3: SKR SKvcs — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel4: Secret PUcs — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel5: Secret Prv — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel6: Niagree — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel7: Nisynch — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel8: Alive — Ok, No attacks within bounds

\- \[ ] Proposed, Vessel9: Weakagree — Ok, No attacks within bounds

\- \[ ] Proposed, HAP1: Secret IDcs — Ok, No attacks within bounds

\- \[ ] Proposed, HAP2: Secret IDhap — Ok, No attacks within bounds

\- \[ ] Proposed, HAP3: SKR SKvcs — Ok, No attacks within bounds

\- \[ ] Proposed, HAP4: Secret PUcs — Ok, No attacks within bounds

\- \[ ] Proposed, HAP5: Secret Prv — Ok, No attacks within bounds

\- \[ ] Proposed, HAP6: Niagree — Ok, No attacks within bounds

\- \[ ] Proposed, HAP7: Nisynch — Ok, No attacks within bounds

\- \[ ] Proposed, HAP8: Alive — Ok, No attacks within bounds

\- \[ ] Proposed, HAP9: Weakagree — Ok, No attacks within bounds



\---



\## What We Are NOT Doing

\- We are NOT simplifying any formula

\- We are NOT skipping any verification step

\- We are NOT using placeholder values for timings — all timings come from Table VII exactly

\- We are NOT approximating communication costs — every bit must be accounted for per Table VI

\- We are NOT inventing security proofs — we are tracing the paper's exact proof steps

\- We are NOT using a different ECC curve than what the paper specifies (160-bit, matching SHA-1 output size)



\---



\## Definition of Done

The implementation is complete when:

1\. A single run of `psas\_mts.py` executes all 7 authentication steps with all verifications passing

2\. `performance.py` outputs exactly 36.654 ms total and 3712 bits

3\. `informal\_security.py` outputs PASS for all 10 propositions

4\. `ban\_logic.py` outputs DERIVED for all 5 goals (G1–G5)

5\. `ror\_model.py` outputs SECURE for both theorems

6\. `test\_attacks.py` outputs RESISTED for all attack scenarios

7\. The Scyther `.spdl` file, when run through the Scyther tool, produces all Ok results matching Figure 6


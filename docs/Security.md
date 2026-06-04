\# SECURITY.md — Complete Security Analysis Specification



\## Overview

The PSAS-MTS scheme is analyzed for security through three methods:

1\. Informal security analysis (10 propositions)

2\. Formal security using the Real-Or-Random (ROR) model (2 theorems)

3\. Formal proof of correctness using BAN logic (5 goals, 30 derivation steps)

4\. Scyther simulation tool verification (18 claims)



\---



\## Part 1: Informal Security Analysis



\### SPF Feature Definitions (from Table III acronym list)

\- SPF1: Achieves anonymity and untraceability

\- SPF2: Achieves mutual authentication

\- SPF3: Secure against offline-password guessing attacks

\- SPF4: Secure against user/server impersonation attacks

\- SPF5: Secure against replay attacks

\- SPF6: Secure against MITM attacks

\- SPF7: Secure against ephemeral information leakage attacks

\- SPF8: Forward and backward secrecy

\- SPF9: Secure against stolen verifiers attacks

\- SPF10: Secure against device capture attacks

\- SPF11: Secure against drone capture attacks

\- SPF12: Secure against denial-of-service attacks

\- SPF13: Secure against de-synchronization attacks

\- SPF14: Achieves session-key security

\- SPF15: Provides session-key verification



\### Proposition 1 — MITM Attack Resistance (SPF6)

Claim: PSAS-MTS is secure under MITM attacks.

Proof logic:

&#x20; - Adversary A can compute messages {msg1, msg2, msg3, msg4} over insecure channel

&#x20; - A attempts to alter these messages

&#x20; - A cannot generate legitimate messages because it lacks {PIDV, a1, b1, c1}

&#x20; - Hashes of messages are sent over open channels

&#x20; - Received messages are verified by intended recipients immediately

&#x20; - Therefore PSAS-MTS resists MITM attacks

Test: Modify any field of any message in transit → verification at receiver must FAIL



\### Proposition 2 — Impersonation Attack Resistance (SPF4)

Claim: PSAS-MTS is safe under impersonation attacks.

Proof logic:

&#x20; - A must produce valid {msg1, msg2, msg3, msg4} to impersonate a participant

&#x20; - Must produce valid parameters {Y, M1, M3, M4, Z, M5, VerSK}

&#x20; - To construct msg1 and msg3, A needs {PIDV, a1, M2, W, c1, SK}

&#x20; - A does not know secret and random values used

&#x20; - A cannot spoof legitimate participants in polynomial time

Test: Attempt to send fake msg1 without knowing PIDV and a1 → CS verification must FAIL



\### Proposition 3 — Vessel Capture Attack Resistance (SPF10)

Claim: PSAS-MTS resists vessel capture attacks.

Proof logic:

&#x20; - A captures vessel and obtains stored {PUV, QV, RV, SV}

&#x20; - Without knowing PIDV, A cannot construct {M1, M2, M4}

&#x20; - A cannot compute valid SKV,CS

&#x20; - Credentials from one vessel cannot be used for other vessels

&#x20; - PIDV is not stored directly; only recoverable at login with IDV and PIN

Test: Use captured {PUV, QV, RV, SV} without IDV and PIN → cannot construct valid msg1



\### Proposition 4 — Session Key Disclosure Resistance (SPF14)

Claim: PSAS-MTS overcomes session key disclosure attacks.

Proof logic:

&#x20; - SKV,CS = h(IDCS ∥ PIDV ∥ W ∥ T3) depends on {PIDV, c1}

&#x20; - These are not directly shared; obtained via public channel in masked form

&#x20; - Hash function properties prevent A from deriving actual values from masked values

&#x20; - A cannot compute valid SKV,CS

Test: Even knowing all public messages, cannot compute SKV,CS without c1 or PIDV



\### Proposition 5 — ESL (Ephemeral Secret Leakage) Resistance (SPF7, SPF8)

Claim: PSAS-MTS resists ESL attacks and provides perfect forward/backward secrecy.

Proof logic:

&#x20; - SKV,CS depends on ephemeral secrets {a1, b1, c1} plus long-term PIDV

&#x20; - Ephemeral secrets are modified in each session

&#x20; - Long-term secret PIDV is not stored in V

&#x20; - If A discovers current session key, cannot compute past or future session keys

&#x20; - c1 and T3 change every session, making W unique per session

Test: Reveal session ephemeral {a1, b1, c1} from session i → cannot compute SK for session j



\### Proposition 6 — Anonymity, Unlinkability, Untraceability (SPF1)

Claim: PSAS-MTS ensures user anonymity, unlinkability, and untraceability.

Proof logic:

&#x20; - Messages use PIDV (pseudo-identity) not IDV (real identity)

&#x20; - msg1 parameters {Y, T1, M1, M3, M4} change every session (a1 is fresh each time)

&#x20; - M3 = M2 ⊕ IDHAP hides HAP identity

&#x20; - msg3 parameters {Z, M5, M6, VerSK, T3} change every session (c1 is fresh each time)

&#x20; - A capturing two different session messages cannot determine the sender

Test: Two runs of protocol → msg1 from run 1 is computationally unlinkable to msg1 from run 2



\### Proposition 7 — Replay Attack Resistance (SPF5)

Claim: PSAS-MTS resists replay attacks.

Proof logic:

&#x20; - Timestamps {T1, T2, T3, T4} are included in all messages

&#x20; - Random numbers {a1, b1, c1} are used to compute messages and session keys

&#x20; - Each session has new timestamps AND new random numbers

&#x20; - Freshness check |T\*i - Ti| < ΔT at every receiver

&#x20; - Replayed messages have stale timestamps → rejected

Test: Replay msg1 from previous session → HAP freshness check must FAIL



\### Proposition 8 — Insider Attack Resistance (SPF9)

Claim: PSAS-MTS is safe from insider attacks.

Proof logic:

&#x20; - IDV and PUV are sent to CS during registration → both publicly known

&#x20; - PrV and PIN are NOT transmitted to CS during registration

&#x20; - A CS system administrator (malevolent insider) has no access to PrV or PIN

&#x20; - Cannot carry out insider attack

Test: CS administrator with full database access → cannot recover PrV or PIN



\### Proposition 9 — Perfect Forward and Backward Secrecy (SPF8)

Claim: PSAS-MTS provides perfect forward and backward secrecy.

Proof logic:

&#x20; - SKV,CS = h(IDCS ∥ PIDV ∥ W ∥ T3)

&#x20; - W = c1 · Y depends on session-specific c1 and timestamp T3

&#x20; - c1 and T3 change every session

&#x20; - Even if c1 and T3 from one session are disclosed:

&#x20;   - Cannot compute SKV,CS for previous sessions (different c1, T3)

&#x20;   - Cannot compute SKV,CS for future sessions (different c1, T3)

Test: Disclose c1 and T3 from session i → cannot compute SK for sessions i-1 or i+1



\### Proposition 10 — Session-Specific Temporary Information Resistance (SPF7)

Claim: PSAS-MTS is safe from session-specific temporary information attacks.

Proof logic:

&#x20; - V chooses a1, computes X = a1 · PUCS and Y = a1 · G

&#x20; - Y is sent in msg1 over public channel

&#x20; - Infeasible to obtain a1 from Y due to ECDLP

&#x20; - b1 is infeasible to obtain from Z1 (due to ECDLP)

&#x20; - c1 is infeasible to obtain from Z (due to ECDLP)

Test: Given Y in public channel → cannot recover a1



\---



\## Part 2: Formal Security — ROR Model



\### Security Model Setup

Two entities in the model:

&#x20; - A: Adversary

&#x20; - R: Responder (simulates the protocol)



Notation:

&#x20; - E^α: α-th instance of a participating entity (V, HAP, or CS)

&#x20; - EViCs: Event that A impersonates V to CS by faking msg1

&#x20; - EHapCs: Event that A impersonates HAP to CS by faking msg2

&#x20; - ECsHapV: Event that A forges msg3 to deceive both HAP and V

&#x20; - Esc: Event that A breaches semantic security of PSAS-MTS



\### Queries (from Table IV)



| Query | Description |

|---|---|

| Setup | R answers by returning system parameters to A |

| h(mk) | R stores list Lhs. On querying h(mk), generates random rk ∈ Z\*p and stores {mk, rk} in Lhs. If not found, C picks record {mk, rk} from Lhs and returns rk |

| HMAC(k, mK) | R stores list Lhm containing tuples of form HMAC(k, mK, M). On querying HMAC(k, mK), generates random M ∈ Z\*p and stores {k, mk, M} in Lhm. If not found, C picks {k, mK, M} from Lhm and returns M |

| Send(E^α, M\_α) | Send represents an active attack; R acts as per originally proposed protocol, on this query and sends corresponding message to A |

| Execute(V^x\_i, CS^y\_j) | This query represents the passive attack, and the proposed scheme works as per protocol specification and returns R1, R2, and R3 |

| Reveal(E^α) | R returns current session key SK shared among A and an entity E^α |

| Test(E^α) | A requests E^α for the key SK; E^α replies probabilistically as outcome of a flipped unbiased coin c |



\### Theorem 1: Mutual Authentication

Statement: PSAS-MTS furnishes mutual authentication, provided events

Pr\[EViCs], Pr\[EHapCs], and Pr\[ECsHapV] are negligible.



Proof steps:

1\. For V → HAP direction (Pr\[EViCs]):

&#x20;  - A performs Send(V, msg1) queries

&#x20;  - Forging succeeds only if R verifies M4 = h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1)

&#x20;  - R can extract record from list Lhs with probability 1/qhs

&#x20;  - Therefore: Pr\[EViCs] = 1/qhs



2\. For HAP → CS direction (Pr\[EHapCs]):

&#x20;  - A submits Send(HAP, msg2) query

&#x20;  - Forging succeeds only if R verifies:

&#x20;    - Tag1 = HMACssk(msg1 ∥ IDHAP ∥ T2)  AND

&#x20;    - IDHAP = M2 ⊕ M3 (correctly)

&#x20;  - R extracts record from Lhm with probability 1/qhm

&#x20;  - Probability of computing M2 = h(PIDv ∥ Xy ∥ T1) is 1/|p|

&#x20;  - Therefore: Pr\[EHapCs] = 1/(qhm · p)



3\. For CS → HAP → V direction (Pr\[ECsHapV]):

&#x20;  - A executes Send(CS, msg3)

&#x20;  - Forging succeeds only if R verifies M5 = h(PIDV ∥ W'x ∥ T3)

&#x20;  - A gets record from Lhs with probability 1/qhs

&#x20;  - Therefore: Pr\[ECsHapV] = 1/qhs



Conclusion: A cannot forge V→HAP, HAP→CS, and CS→V with non-negligible probability.



\### Theorem 2: Semantic Security

Statement: PSAS-MTS is semantically secure.



Proof:

Define Ekey: R guesses c correctly during Test session with non-negligible advantage.

Pr\[Ekey] ≥ ε/2



Let E^V\_Test, E^HAP\_Test, E^CS\_Test be events that V, HAP, CS are queried through Test:



&#x20; ε/2 ≤ Pr\[Ekey]

&#x20;    = Pr\[Ekey ∧ E^V\_Test]

&#x20;    + Pr\[Ekey ∧ E^HAP\_Test ∧ E^CS\_Test ∧ EViCs]

&#x20;    + Pr\[Ekey ∧ E^HAP\_Test ∧ ¬EHapCs]

&#x20;    + Pr\[Ekey ∧ E^CS\_Test ∧ ¬ECsHapVi]

&#x20;    ≤ Pr\[Ekey ∧ E^V\_Test]

&#x20;    + Pr\[Ekey ∧ E^HAP\_Test ∧ ¬EViCs]

&#x20;    + Pr\[Ekey ∧ E^CS\_Test ∧ ¬ECsHapVi]



Since Pr\[E^HAP\_Test ∧ ¬EViCs ∧ ¬ECsHapV] = E^V\_Test:



&#x20; Pr\[SK(V,CS) = h(IDCS ∥ PIDV ∥ W ∥ T3)] ≥ ε/8 − Pr\[EViCs]/2



Using Theorem 1, Pr\[EViCs] = 1/qhs (negligible).

Therefore PSAS-MTS is semantically secure.



\---



\## Part 3: Formal Security — BAN Logic



\### Protocol Idealization

The protocol is idealized in BAN logic notation as:



\- V → HAP: msg1 = {Y, T1, {PIDV}\_{h(X)}, {M2}\_{IDHAP}, {PIDV, IDHAP, IDCS, T1}\_X}

\- HAP → CS: msg2 = {msg1, {msg1, IDHAP, T2}\_{ssk}, IDHAP, Z1, T2}

\- CS → HAP: msg3 = {Z, {PIDV, T3}\_W, {IDHAP, IDCS, T3}\_{Z1}, {X}\_{SK}, T3}

\- HAP → V:  msg4 = {msg3, {msg3, IDHAP, T4}\_{ssk2}, IDHAP, Z1, T4}



\### Security Goals (must be derived)

\- G1: CS |≡ msg1         (CS believes msg1 is authentic)

\- G2: CS |≡ PIDV         (CS believes in vessel's pseudo-identity)

\- G3: V  |≡ msg3         (Vessel believes msg3 is authentic)

\- G4: V  |≡ W            (Vessel believes in the shared point W)

\- G5: V  |≡ SK           (Vessel believes in the session key)



\### Initial Assumptions

\- A1:  CS |≡ CS ↔^ssk HAP          (CS believes ssk is shared with HAP)

\- A2:  CS |≡ #(T2)                  (CS believes T2 is fresh)

\- A3:  CS |≡ HAP |⇒ msg1            (CS grants HAP jurisdiction over msg1)

\- A4:  CS |≡ CS ↔^X V               (CS believes X is shared key with V)

\- A5:  CS |≡ #(T1)                  (CS believes T1 is fresh)

\- A6:  CS |≡ V |⇒ PIDV              (CS grants V jurisdiction over PIDV)

\- A7:  V  |≡ HAP ↔^ssk2 V           (V believes ssk2 is shared with HAP)

\- A8:  V  |≡ #(T4)                  (V believes T4 is fresh)

\- A9:  V  |≡ HAP |⇒ msg3            (V grants HAP jurisdiction over msg3)

\- A10: V  |≡ #(T3)                  (V believes T3 is fresh)

\- A11: V  |≡ V ↔^PIDV CS            (V believes PIDV is shared with CS)

\- A12: V  |≡ CS |⇒ W                (V grants CS jurisdiction over W)



\### Goal Derivation Steps (all 30 steps)



S1:  CS ◁ msg2                               \[seeing rule]

S2:  CS ◁ Tag1 = {msg1, IDHAP, T2}\_{ssk}    \[sub-component of S1]

S3:  CS |≡ HAP |∼ (msg1, IDHAP, T2)          \[A1 + MMR on S2]

S4:  CS |≡ #(msg1, IDHAP, T2)               \[from A2]

S5:  CS |≡ HAP |≡ (msg1, IDHAP, T2)         \[S4 + S3 + NVR]

S6:  CS |≡ HAP |≡ msg1                       \[sub-component of S5]

S7:  CS |≡ msg1  ← GOAL G1                  \[S6 + A3 + JR]



S8:  CS ◁ msg1 = {Y, T1, M1, M3, M4}        \[sub-component of S1]

S9:  CS |≡ #msg1                             \[freshness rule on A5]

S10: CS ◁ M1 = {PIDV}_{X}                   \[sub-component of S8] (Note: The original paper contains a typo here, dropping the h(⋅) on X that was correctly defined in the idealization. We replicate it here to match the paper's exact proof steps).

S11: CS |≡ #M1                               \[sub-component of S9]

S12: CS |≡ #PIDV                             \[sub-component of S11]

S13: CS |≡ V |∼ PIDV                         \[S10 + A4 + MMR]

S14: CS |≡ V |≡ PIDV                         \[S13 + S12 + NVR]

S15: CS |≡ PIDV  ← GOAL G2                  \[S14 + A6 + JR]



S16: V ◁ msg4                                \[seeing rule]

S17: V ◁ Tag2 = {msg3, IDHAP, T4}\_{ssk2}    \[sub-component of S16]

S18: V |≡ HAP |∼ (msg3, IDHAP, T4)           \[A7 + MMR on S17]

S19: V |≡ #(msg3, IDHAP, T4)                \[from A8]

S20: V |≡ HAP |≡ (msg3, IDHAP, T4)          \[S19 + S18 + NVR]

S21: V |≡ HAP |≡ msg3                        \[sub-component of S20]

S22: V |≡ msg3  ← GOAL G3                   \[S21 + A9 + JR]



S23: V ◁ msg3 = {Z, M5, M6, VerSK, T3}      \[sub-component of S16]

S24: V |≡ #msg3                              \[freshness rule on A10]

S25: V |≡ #M5                               \[sub-component of S24]

S26: V ◁ M5 = {W}\_{PIDV}                    \[sub-component of S23]

S27: V |≡ CS |∼ W                            \[S26 + S23 + MMR]

S28: V |≡ CS |≡ W                            \[S25 + S27 + NVR]

S29: V |≡ W  ← GOAL G4                      \[S28 + A12 + JR]



S30: V |≡ SK  ← GOAL G5                     \[W is core component of SK + session key rule]



\### BAN Logic Rules Used

\- MMR (Message Meaning Rule): If P |≡ P↔^K Q and P ◁ {X}\_K, then P |≡ Q |∼ X

\- NVR (Nonce Verification Rule): If P |≡ #X and P |≡ Q |∼ X, then P |≡ Q |≡ X

\- JR (Jurisdiction Rule): If P |≡ Q |⇒ X and P |≡ Q |≡ X, then P |≡ X

\- Sub-component rule: If P ◁ (X, Y) then P ◁ X and P ◁ Y

\- Freshness rule: If P |≡ #X and X is a sub-component of Y, then P |≡ #Y



\---



\## Part 4: Scyther Simulation



\### Tool Setup

\- Tool: Scyther formal verification tool

\- Language: Security Protocol Description Language (SPDL)

\- Libraries required: GraphViz, Python 2.7, wxPython

\- Reference: Cremers, "The Scyther Tool", CAV 2008



\### Roles to Define in SPDL

1\. Role: Vessel (V)

2\. Role: HAP

3\. Role: CS (ControlStation)



\### Claims to Verify (from Figure 6)

For role Vessel:

&#x20; 1. Proposed, Vessel1: Secret IDcs       → expected: Ok

&#x20; 2. Proposed, Vessel2: Secret IDhap      → expected: Ok

&#x20; 3. Proposed, Vessel3: SKR SKvcs         → expected: Ok

&#x20; 4. Proposed, Vessel4: Secret PUcs       → expected: Ok

&#x20; 5. Proposed, Vessel5: Secret Prv        → expected: Ok

&#x20; 6. Proposed, Vessel6: Niagree           → expected: Ok

&#x20; 7. Proposed, Vessel7: Nisynch           → expected: Ok

&#x20; 8. Proposed, Vessel8: Alive             → expected: Ok

&#x20; 9. Proposed, Vessel9: Weakagree         → expected: Ok



For role HAP:

&#x20; 10. Proposed, HAP1: Secret IDcs         → expected: Ok

&#x20; 11. Proposed, HAP2: Secret IDhap        → expected: Ok

&#x20; 12. Proposed, HAP3: SKR SKvcs           → expected: Ok

&#x20; 13. Proposed, HAP4: Secret PUcs         → expected: Ok

&#x20; 14. Proposed, HAP5: Secret Prv          → expected: Ok

&#x20; 15. Proposed, HAP6: Niagree             → expected: Ok

&#x20; 16. Proposed, HAP7: Nisynch             → expected: Ok

&#x20; 17. Proposed, HAP8: Alive               → expected: Ok

&#x20; 18. Proposed, HAP9: Weakagree           → expected: Ok



All 18 claims must show status: Ok, Comments: "No attacks within bounds."


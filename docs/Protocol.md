\# PROTOCOL.md — Complete PSAS-MTS Protocol Specification



\## Overview

PSAS-MTS involves three entities:

\- Vessel (V): IoT-enabled ship, resource-constrained

\- High Altitude Platform System (HAP): Aerial relay, semi-trusted

\- Control Station (CS): Trusted authority, manages vessel registry



Communication between all entities occurs over an insecure public channel

EXCEPT during registration phases which use a secure private channel.



\---



\## Phase 1: System Initialization (CS only)



CS performs this once at setup time.



1\. CS selects an elliptic curve Eq(u, v) with generator point G

2\. CS chooses its unique identity IDCS

3\. CS chooses its private key PrCS (random integer in \[1, q-1])

4\. CS computes its public key: PUCS = PrCS · G

5\. CS selects a secure one-way hash function h(·)

6\. CS publishes: {Eq(u,v), G, PUCS, IDCS, h(·)}

7\. CS keeps PrCS secret



\---



\## Phase 2: HAP Registration (HAP → CS, secure channel)



1\. HAP selects its identity IDHAP

2\. HAP chooses its private key PrHAP (random integer in \[1, q-1])

3\. HAP computes its public key: PUHAP = PrHAP · G

4\. HAP sends ⟨IDHAP, PUHAP⟩ to CS via secure channel

5\. CS stores ⟨IDHAP, PUHAP⟩ in its database

6\. No response message from CS to HAP in this phase



\---



\## Phase 3: Vessel Registration (V ↔ CS, secure channel)



\### Step 3.1 — Vessel side:

1\. Vessel selects ⟨IDV, PrV, PIN⟩

2\. Vessel computes: PUV = PrV · G

3\. Vessel sends ⟨IDV, PUV⟩ to CS via secure channel



\### Step 3.2 — CS side (upon receiving ⟨IDV, PUV⟩):

1\. CS computes: PIDV = h(IDV ∥ PrCS)

2\. CS stores ⟨IDV, PIDV, PUV⟩ in its database

3\. CS sends ⟨IDV, PUV⟩ back to Vessel via secure channel



Note: CS does NOT send PIDV to Vessel. Vessel computes it indirectly via RV.



\### Step 3.3 — Vessel side (upon receiving ⟨IDV, PUV⟩ back from CS):

1\. Vessel computes: QV = h(IDV ∥ PIN) ⊕ PrV

2\. Vessel computes: RV = PIDV ⊕ h(PrV)



Wait — Vessel does NOT know PIDV directly at this step.

Registration response from CS to Vessel: ⟨IDV, PUV⟩ (Note: To implement the paper exactly without assumptions, do not include PIDV
​
  here. The paper explicitly states the CS securely sends ⟨IDV , PUV⟩ back to V, even though this creates a logical paradox for V's local storage computation)



3\. Vessel computes: SV = h(PIDV ∥ PIN ∥ PrV)

4\. Vessel stores in memory: ⟨PUV, QV, RV, SV⟩

5\. Vessel does NOT store IDV, PIN, PrV, PIDV directly in memory

&#x20;  (these are recoverable from stored values during login)



\---



\## Phase 4: Authentication — Login (Vessel local)



\### PSAS-MTS 1 — Local Login Verification at Vessel:

Input: ⟨IDV, PIN⟩ entered by user + stored ⟨PUV, QV, RV, SV⟩



1\. Recover private key:    PrV  = h(IDV ∥ PIN) ⊕ QV

2\. Recover pseudo-identity: PIDV = RV ⊕ h(PrV)

3\. Compute verification:    SV'  = h(PIDV ∥ PIN ∥ PrV)

4\. Check: SV' =?= SV

&#x20;  - If YES: proceed to authentication

&#x20;  - If NO: terminate connection



\---



\## Phase 4: Authentication — Message Exchange



\### PSAS-MTS 2 — Vessel → HAP (msg1):



1\. Vessel chooses random number a1 ∈ \[1, q-1]

2\. Compute: X = a1 · PUCS       → yields point (Xx, Xy)

3\. Compute: Y = a1 · G

4\. Generate current timestamp T1

5\. Compute: M1 = PIDV ⊕ h(Xx)

6\. Compute: M2 = h(PIDV ∥ Xy ∥ T1)

7\. Compute: M3 = M2 ⊕ IDHAP

8\. Compute: M4 = h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1)



&#x20;  Note: X in M4 is the full ECC point (both coordinates concatenated)



9\. Send msg1 = ⟨Y, T1, M1, M3, M4⟩ to HAP via public channel



\---



\### PSAS-MTS 3 — HAP → CS (msg2):



Upon receiving msg1 at time T\*1:



1\. Verify freshness: |T\*1 − T1| < ΔT

&#x20;  - If NO: discard msg1

2\. HAP chooses random number b1 ∈ \[1, q-1]

3\. Compute: Z1  = b1 · G

4\. Compute: ssk = h(b1 · PUCS)



&#x20;  Note: b1 · PUCS = b1 · (PrCS · G). This is the HAP-CS shared secret.

&#x20;  CS can compute the same as: PrCS · Z1 = PrCS · (b1 · G) = b1 · PrCS · G = b1 · PUCS



5\. Generate current timestamp T2

6\. Compute: Tag1 = HMACssk(msg1 ∥ IDHAP ∥ T2)



&#x20;  Note: msg1 here means the full serialized bytes of msg1.



7\. Send msg2 = ⟨msg1, Tag1, IDHAP, Z1, T2⟩ to CS via public channel



\---



\### PSAS-MTS 4 — Authentication at Control Station:



Upon receiving msg2 at time T\*2:



1\. Verify freshness: |T\*2 − T2| < ΔT

&#x20;  - If NO: discard msg2

2\. Recompute shared secret: ssk' = h(PrCS · Z1)

3\. Recompute HMAC tag:      Tag1' = HMACssk'(msg1 ∥ IDHAP ∥ T2)

4\. Verify: Tag1' =?= Tag1

&#x20;  - If NO: terminate



5\. Recover X:    X' = PrCS · Y         → yields point (X'x, X'y)

6\. Recover PIDV: PIDV' = M1 ⊕ h(X'x)

7\. Check PIDV' exists in CS database

&#x20;  - If NOT FOUND: terminate



8\. Recompute: M2'    = h(PIDV' ∥ X'y ∥ T1)

9\. Recover:   IDHAP' = M2' ⊕ M3

10\. Verify: IDHAP' =?= received IDHAP

&#x20;   - If NO: terminate



11\. Recompute: M4' = h(PIDV' ∥ IDHAP ∥ IDCS ∥ X' ∥ T1)

12\. Verify: M4' =?= M4

&#x20;   - If NO: terminate

&#x20;   - If YES: Vessel V is authenticated



\---



\### PSAS-MTS 5 — CS → HAP (msg3):



After successful authentication of V:



1\. CS chooses random number c1 ∈ \[1, q-1]

2\. Compute: Z = c1 · G

3\. Compute: W = c1 · Y              → yields point (Wx, Wy)



&#x20;  Note: c1 · Y = c1 · (a1 · G) = a1 · (c1 · G) = a1 · Z

&#x20;  This means Vessel can recover W as: W' = a1 · Z



4\. Compute: M5    = h(PIDV' ∥ Wx ∥ T3)

5\. Compute: M6    = h(IDHAP ∥ IDCS ∥ Z1 ∥ T3)



&#x20;  Note: M6 is a plain concatenation, NOT a hash



6\. Generate current timestamp T3

7\. Compute: SKV,CS = h(IDCS ∥ PIDV ∥ W ∥ T3)

8\. Compute: VerSK  = h(SKV,CS ∥ X')



&#x20;  Note: X' is the full point recovered by CS (both coordinates)



9\. Send msg3 = ⟨Z, M5, M6, VerSK, T3⟩ to HAP via public channel



\---



\### PSAS-MTS 6 — HAP → V (msg4):



Upon receiving msg3 at time T\*3:



1\. Verify freshness: |T\*3 − T3| < ΔT

&#x20;  - If NO: discard msg3

2\. Recompute: M6'  = h(IDHAP ∥ IDCS ∥ Z1 ∥ T3)

3\. Verify: M6' =?= M6

&#x20;  - If NO: terminate



4\. Compute: ssk2  = h(b1 · PUV)



&#x20;  Note: b1 · PUV = b1 · (PrV · G). Vessel recovers same as: PrV · Z1 = PrV · (b1 · G)



5\. Generate current timestamp T4

6\. Compute: Tag2  = HMACssk2(msg3 ∥ IDHAP ∥ T4)

7\. Send msg4 = ⟨msg3, Tag2, IDHAP, Z1, T4⟩ to Vessel via public channel



\---



\### PSAS-MTS 7 — Authentication at Vessel:



Upon receiving msg4 at time T\*4:



1\. Verify freshness: |T\*4 − T4| < ΔT

&#x20;  - If NO: discard msg4



2\. Recompute: ssk2'  = h(PrV · Z1)

3\. Recompute: Tag2'  = HMACssk2'(msg3 ∥ IDHAP ∥ T4)  
(Note: The paper text contains a typo stating mgs3 instead of msg3 here, but Table III confirms msg3 is the correct input).
4\. Verify: Tag2' =?= Tag2

&#x20;  - If NO: terminate



5\. Recover: W'  = a1 · Z

6\. Recompute: M5'  = h(PIDV ∥ W'x ∥ T3)

7\. Verify: M5' =?= M5

&#x20;  - If NO: terminate

&#x20;  - If YES: CS is authenticated



8\. Compute: SKV,CS'  = h(IDCS ∥ PIDV ∥ W' ∥ T3)

9\. Compute: VerSK'   = h(SKV,CS' ∥ X)



&#x20;  Note: X is the original point computed by Vessel in Step 2 (a1 · PUCS)



10\. Verify: VerSK' =?= VerSK

&#x20;   - If NO: terminate

&#x20;   - If YES: session key SKV,CS is established



\---



\## Session Key Agreement Result

\- Vessel holds: SKV,CS = h(IDCS ∥ PIDV ∥ W' ∥ T3) where W' = a1 · Z = a1 · c1 · G

\- CS holds:     SKV,CS = h(IDCS ∥ PIDV ∥ W  ∥ T3) where W  = c1 · Y = c1 · a1 · G

\- Since a1·c1·G = c1·a1·G, both parties hold the same session key. ✓



\---



\## Key Correctness Equalities



| CS computes | Vessel computes | Equal because |

|---|---|---|

| ssk' = h(PrCS · Z1) | — | PrCS·(b1·G) = b1·(PrCS·G) = b1·PUCS = ssk |

| X' = PrCS · Y | X = a1 · PUCS | PrCS·(a1·G) = a1·(PrCS·G) → X' = X |

| ssk2 = h(b1 · PUV) | ssk2' = h(PrV · Z1) | b1·(PrV·G) = PrV·(b1·G) |

| W = c1 · Y | W' = a1 · Z | c1·(a1·G) = a1·(c1·G) |

| SKV,CS = h(IDCS∥PIDV∥W∥T3) | SKV,CS' = h(IDCS∥PIDV∥W'∥T3) | W = W' |



\---



\## Message Summary Table



| Message | Direction | Contents | Channel |

|---|---|---|---|

| Registration | V → CS | ⟨IDV, PUV⟩ | Secure |

| Registration response | CS → V | ⟨IDV, PUV, PIDV⟩ | Secure |

| msg1 | V → HAP | ⟨Y, T1, M1, M3, M4⟩ | Public |

| msg2 | HAP → CS | ⟨msg1, Tag1, IDHAP, Z1, T2⟩ | Public |

| msg3 | CS → HAP | ⟨Z, M5, M6, VerSK, T3⟩ | Public |

| msg4 | HAP → V | ⟨msg3, Tag2, IDHAP, Z1, T4⟩ | Public |


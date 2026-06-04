\# TESTING.md — Test Plan and Expected Outcomes



\## Test Philosophy

Every test must have a clear expected outcome from the paper.

No test passes by coincidence — each pass must directly verify a

specific claim made in the paper.



\---



\## Test Category 1: Protocol Correctness (test\_protocol.py)



\### TC-01: Registration Correctness

Test: Run vessel registration and verify stored values.

Input: IDV, PrV, PIN, CS with PrCS

Expected:

&#x20; - PIDV = h(IDV ∥ PrCS) \[computed by CS]

&#x20; - QV   = h(IDV ∥ PIN) ⊕ PrV

&#x20; - RV   = PIDV ⊕ h(PrV)

&#x20; - SV   = h(PIDV ∥ PIN ∥ PrV)

&#x20; - All stored in VesselMemory

Pass condition: All 4 formulas produce correct bytes



\### TC-02: Login Success — Correct Credentials

Test: Login with correct IDV and PIN

Expected:

&#x20; - PrV  = h(IDV ∥ PIN) ⊕ QV  matches original PrV

&#x20; - PIDV = RV ⊕ h(PrV)        matches original PIDV

&#x20; - SV'  = h(PIDV ∥ PIN ∥ PrV) matches stored SV

&#x20; - Login returns True

Pass condition: All 3 equalities hold, login succeeds



\### TC-03: Login Failure — Wrong PIN

Test: Login with correct IDV but wrong PIN'

Expected:

&#x20; - PrV'  derived will be wrong

&#x20; - PIDV' derived will be wrong

&#x20; - SV''  = h(PIDV' ∥ PIN' ∥ PrV') ≠ SV

&#x20; - Login returns False

Pass condition: Login correctly rejected



\### TC-04: msg1 Construction

Test: Vessel creates msg1

Input: PIDV, a1, PUCS, IDHAP, IDCS

Expected fields in msg1:

&#x20; - Y  = a1 · G                         (ECC point)

&#x20; - T1 = current timestamp              (32-bit int)

&#x20; - M1 = PIDV ⊕ h(Xx) where X=(Xx,Xy) = a1·PUCS

&#x20; - M3 = M2 ⊕ IDHAP where M2 = h(PIDV∥Xy∥T1)

&#x20; - M4 = h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1)

Pass condition: All 5 fields match formula computation



\### TC-05: msg2 Construction and HAP Processing

Test: HAP receives msg1, creates msg2

Expected:

&#x20; - Freshness check |T\*1 - T1| < ΔT passes

&#x20; - Z1 = b1 · G

&#x20; - ssk = h(b1 · PUCS)

&#x20; - Tag1 = HMACssk(msg1 ∥ IDHAP ∥ T2)

&#x20; - msg2 contains {msg1, Tag1, IDHAP, Z1, T2}

Pass condition: All fields correctly computed



\### TC-06: CS Authentication of Vessel (PSAS-MTS 4)

Test: CS processes msg2

Expected: All verification steps pass:

&#x20; - Freshness check passes

&#x20; - ssk' = h(PrCS · Z1) == ssk (verified via Tag1' = Tag1)

&#x20; - Tag1' = Tag1 ✓

&#x20; - X'  = PrCS · Y == X (original vessel point)

&#x20; - PIDV' = M1 ⊕ h(X'x) == PIDV ✓

&#x20; - PIDV' found in CS database ✓

&#x20; - M2'  = h(PIDV' ∥ X'y ∥ T1) ✓

&#x20; - IDHAP' = M2' ⊕ M3 == IDHAP ✓

&#x20; - M4' = M4 ✓ → Vessel authenticated

Pass condition: All 6 verification checks pass



\### TC-07: msg3 Construction and CS Response

Test: CS creates msg3 after authenticating vessel

Expected:

&#x20; - Z  = c1 · G

&#x20; - W  = c1 · Y = (Wx, Wy)

&#x20; - M5 = h(PIDV' ∥ Wx ∥ T3)

&#x20; - M6 = concat(IDHAP, IDCS, Z1, T3)

&#x20; - SKV,CS = h(IDCS ∥ PIDV ∥ W ∥ T3)

&#x20; - VerSK  = h(SKV,CS ∥ X')

&#x20; - msg3 contains {Z, M5, M6, VerSK, T3}

Pass condition: All fields correctly computed



\### TC-08: HAP Processing of msg3 (PSAS-MTS 6)

Test: HAP receives msg3, creates msg4

Expected:

&#x20; - Freshness check passes

&#x20; - M6' = concat(IDHAP, IDCS, Z1, T3) == M6 ✓

&#x20; - ssk2 = h(b1 · PUV)

&#x20; - Tag2 = HMACssk2(msg3 ∥ IDHAP ∥ T4)

&#x20; - msg4 contains {msg3, Tag2, IDHAP, Z1, T4}

Pass condition: All fields correctly computed



\### TC-09: Vessel Authentication of CS (PSAS-MTS 7)

Test: Vessel processes msg4

Expected: All verification steps pass:

&#x20; - Freshness check passes

&#x20; - ssk2' = h(PrV · Z1) == ssk2 (via Tag2' = Tag2)

&#x20; - Tag2' = Tag2 ✓

&#x20; - W'   = a1 · Z == W ✓

&#x20; - M5'  = h(PIDV ∥ W'x ∥ T3) == M5 ✓ → CS authenticated

&#x20; - SKV,CS' = h(IDCS ∥ PIDV ∥ W' ∥ T3)

&#x20; - VerSK'  = h(SKV,CS' ∥ X) == VerSK ✓

Pass condition: All 5 verification checks pass



\### TC-10: Session Key Agreement

Test: Compare session keys at Vessel and CS

Expected: SKV,CS (at Vessel) == SKV,CS (at CS)

Proof: a1·c1·G = c1·a1·G → W' = W → same hash input

Pass condition: Byte-for-byte equality of session keys



\---



\## Test Category 2: Attack Resistance (test\_attacks.py)



\### TA-01: Replay Attack — msg1

Test: Record msg1 from session 1. Replay it in session 2.

Attack: Send old msg1 to HAP

Expected: HAP freshness check |T\*1 - T1| >= ΔT → REJECTED

Pass condition: Exception or rejection raised at HAP

Maps to: Proposition 7, SPF5



\### TA-02: Replay Attack — msg2

Test: Record msg2 from session 1. Replay it in session 2.

Expected: CS freshness check |T\*2 - T2| >= ΔT → REJECTED

Pass condition: Exception or rejection raised at CS



\### TA-03: MITM — Modify M1 in msg1

Test: Intercept msg1, flip bits in M1, forward to HAP

Expected: CS cannot recover correct PIDV' → database lookup fails → REJECTED

Pass condition: CS authentication step fails



\### TA-04: MITM — Modify M4 in msg1

Test: Intercept msg1, compute new M4 with different value

Expected: CS M4' ≠ modified M4 → REJECTED (since A doesn't know PIDV)

Pass condition: CS M4 verification fails



\### TA-05: MITM — Modify Tag1 in msg2

Test: Intercept msg2, change one byte of Tag1

Expected: CS Tag1' ≠ modified Tag1 → REJECTED

Pass condition: CS HMAC verification fails



\### TA-06: MITM — Modify M6 in msg3

Test: Intercept msg3, change M6

Expected: HAP M6' ≠ modified M6 → REJECTED

Pass condition: HAP M6 verification fails



\### TA-07: MITM — Modify Tag2 in msg4

Test: Intercept msg4, change one byte of Tag2

Expected: Vessel Tag2' ≠ modified Tag2 → REJECTED

Pass condition: Vessel HMAC verification fails



\### TA-08: Vessel Impersonation — Without PIDV

Test: Adversary tries to create valid msg1 without knowing PIDV

Expected: Cannot compute correct M1, M4 → CS PIDV lookup fails

Pass condition: CS authentication fails



\### TA-09: HAP Impersonation — Without ssk

Test: Adversary intercepts msg1, tries to create msg2 with fake Tag1

Expected: Tag1 cannot be forged without ssk = h(b1·PUCS) → CS Tag1 verify fails

Pass condition: CS HMAC verification fails



\### TA-10: CS Impersonation — Without c1 or W

Test: Adversary creates fake msg3 without knowing c1 or PIDV

Expected: Cannot compute valid M5, VerSK → Vessel M5 verify fails

Pass condition: Vessel M5 verification fails



\### TA-11: Vessel Capture — Stolen {QV, RV, SV} Without PIN

Test: Adversary has QV, RV, SV but not IDV or PIN

Expected:

&#x20; - Cannot compute PrV = h(IDV ∥ PIN) ⊕ QV (needs IDV and PIN)

&#x20; - Cannot compute PIDV = RV ⊕ h(PrV) (needs PrV)

&#x20; - Cannot create valid msg1

Pass condition: Cannot proceed past step 1 without PIN



\### TA-12: Drone/HAP Capture — Stolen PrHAP

Test: Adversary captures HAP, learns PrHAP

Expected impact is LIMITED:

&#x20; - Can compute PUHAP = PrHAP · G (already public)

&#x20; - Cannot recover PIDV (not stored in HAP)

&#x20; - Cannot forge ssk (needs b1 which is fresh per-session)

&#x20; - Cannot compute SKV,CS

Pass condition: Session key and PIDV remain secure



\### TA-13: Insider Attack — CS Admin

Test: CS administrator has full access to database {IDV, PIDV, PUV}

Expected:

&#x20; - Cannot find PrV (not stored)

&#x20; - Cannot find PIN (not stored)

&#x20; - Cannot forge a valid msg1 session without PrV and PIN

Pass condition: Cannot impersonate vessel



\### TA-14: ESL (Ephemeral Secret Leakage) — Forward Secrecy

Test: Disclose {a1, b1, c1, T1, T2, T3} from session i

Expected: Cannot compute SKV,CS for any session j ≠ i

&#x20; - SKV,CS for session j = h(IDCS ∥ PIDV ∥ Wj ∥ T3j)

&#x20; - Wj = c1j · Y\_j = different random c1j and Y\_j

Pass condition: Session j's key is computationally independent



\### TA-15: ESL — Backward Secrecy

Test: Disclose current session's {a1, c1} 

Expected: Previous session keys cannot be derived

Pass condition: Previous SKV,CS unchanged



\---



\## Test Category 3: Performance Verification (performance.py, communication\_cost.py)



\### TP-01: Communication Cost = 3712 bits

Test: Run communication\_cost.py

Expected output:

&#x20; msg1 = 672 bits

&#x20; msg2 = 1184 bits

&#x20; msg3 = 672 bits

&#x20; msg4 = 1184 bits

&#x20; Total = 3712 bits

Pass condition: Exact match



\### TP-02: Computation Cost = 36.654 ms

Test: Run performance.py

Expected output:

&#x20; Vessel: 11Th + 4Tpa = X ms

&#x20; HAP:    ...           = Y ms

&#x20; CS:     ...           = Z ms

&#x20; Total:  36.654 ms

Pass condition: Total within ±0.001 ms of 36.654



\---



\## Test Category 4: Formal Security (ror\_model.py, ban\_logic.py)



\### TF-01: BAN Logic Goals G1-G5

Test: Run ban\_logic.py

Expected:

&#x20; G1: CS |≡ msg1   → DERIVED ✓

&#x20; G2: CS |≡ PIDV   → DERIVED ✓

&#x20; G3: V  |≡ msg3   → DERIVED ✓

&#x20; G4: V  |≡ W      → DERIVED ✓

&#x20; G5: V  |≡ SK     → DERIVED ✓

Pass condition: All 5 goals derived



\### TF-02: ROR Model Theorem 1

Test: Run ror\_model.py theorem 1

Expected: Pr\[EViCs], Pr\[EHapCs], Pr\[ECsHapV] all computed and shown negligible

Pass condition: All three probabilities < 1/large\_number



\### TF-03: ROR Model Theorem 2

Test: Run ror\_model.py theorem 2

Expected: Semantic security bound ε/8 - Pr\[EViCs]/2 computed

Pass condition: Bound shown to imply security



\---



\## Expected Full Run Output of psas\_mts.py



```

=== PSAS-MTS Protocol Execution ===



\[INIT] CS initialized: IDCS=..., PUCS=(x=...,y=...)

\[REG]  HAP registered: IDHAP=...

\[REG]  Vessel registered: PIDV=..., QV=..., RV=..., SV=...



\[AUTH Step 1] Login: PASS (SV' == SV)

\[AUTH Step 2] Vessel → HAP: msg1 created

&#x20; Y  = (x=..., y=...)

&#x20; T1 = ...

&#x20; M1 = ...

&#x20; M3 = ...

&#x20; M4 = ...

\[AUTH Step 3] HAP → CS: msg2 created

&#x20; Z1  = (x=..., y=...)

&#x20; ssk = ...

&#x20; Tag1 = ...

\[AUTH Step 4] CS authenticates Vessel: PASS

&#x20; ssk' == ssk:    PASS

&#x20; Tag1' == Tag1:  PASS

&#x20; PIDV found:     PASS

&#x20; IDHAP' == IDHAP: PASS

&#x20; M4' == M4:      PASS

\[AUTH Step 5] CS → HAP: msg3 created

&#x20; W  = (x=..., y=...)

&#x20; M5 = ...

&#x20; SKV,CS = ...

\[AUTH Step 6] HAP → Vessel: msg4 created

&#x20; ssk2 = ...

&#x20; Tag2 = ...

\[AUTH Step 7] Vessel authenticates CS: PASS

&#x20; Tag2' == Tag2: PASS

&#x20; M5' == M5:     PASS

&#x20; VerSK' == VerSK: PASS



\[SESSION KEY] Vessel SKV,CS = ...

\[SESSION KEY] CS     SKV,CS = ...

\[SESSION KEY] Match: PASS ✓



=== Performance Analysis ===

Computation: 36.654 ms ✓

Communication: 3712 bits ✓



=== Security Features (Table III) ===

SPF1  Anonymity \& Untraceability:    PASS ✓

SPF2  Mutual Authentication:         PASS ✓

SPF3  Offline Password Guessing:     PASS ✓

SPF4  Impersonation Resistance:      PASS ✓

SPF5  Replay Resistance:             PASS ✓

SPF6  MITM Resistance:               PASS ✓

SPF7  ESL Resistance:                PASS ✓

SPF8  Forward/Backward Secrecy:      PASS ✓

SPF9  Stolen Verifier Resistance:    PASS ✓

SPF10 Device Capture Resistance:     PASS ✓

SPF11 Drone Capture Resistance:      PASS ✓

SPF12 DoS Resistance:                PASS ✓

SPF13 De-synchronization Resistance: PASS ✓

SPF14 Session Key Security:          PASS ✓

SPF15 Session Key Verification:      PASS ✓



=== BAN Logic Goals ===

G1: CS |≡ msg1  → DERIVED ✓

G2: CS |≡ PIDV  → DERIVED ✓

G3: V  |≡ msg3  → DERIVED ✓

G4: V  |≡ W     → DERIVED ✓

G5: V  |≡ SK    → DERIVED ✓



=== ROR Model ===

Theorem 1 (Mutual Authentication): SECURE ✓

Theorem 2 (Semantic Security):     SECURE ✓



=== FINAL RESULT: ALL GOALS MET ✓ ===

```


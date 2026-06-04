\# NOTATION.md — Symbols, Notation, and Python Variable Mapping



\## Source

All notation taken directly from Table II of the paper (page 23129).



\---



\## Symbol Table



| Paper Symbol | Description | Python Variable Name | Type |

|---|---|---|---|

| A | Adversary | adversary | class Adversary |

| V | Vessel | vessel | class Vessel |

| HAP | High Altitude Platform | hap | class HAP |

| CS | Control Station | cs | class ControlStation |

| IDV | Identity of Vessel | vessel.ID | bytes |

| IDHAP | Identity of HAP | hap.ID | bytes |

| IDCS | Identity of Control Station | cs.ID | bytes |

| ⟨PUV, PrV⟩ | Public and private key-pair of V | vessel.PU, vessel.Pr | ECPoint, int |

| ⟨PUHAP, PrHAP⟩ | Public and private key-pair of HAP | hap.PU, hap.Pr | ECPoint, int |

| ⟨PUCS, PrCS⟩ | Public and private key-pair of CS | cs.PU, cs.Pr | ECPoint, int |

| PIDV | Pseudo-identity of V | vessel.PID | bytes |

| PIN | Secret information of V, known by only V | vessel.PIN | bytes |

| ⟨a1, b1, c1⟩ | Random numbers | a1, b1, c1 | int |

| h(·) | Secure one-way hash | h() | function → bytes |

| HMAC(·) | Hash-based message authentication code | hmac\_op() | function → bytes |

| ssk | Short-term secret key used in HMAC | ssk | bytes |

| SKV,CS | Session key between V and CS | SK\_V\_CS | bytes |

| ⟨T1, T2, T3, T4⟩ | Time-stamps | T1, T2, T3, T4 | int (unix ms) |

| ⊕ | XOR operation | xor() | function → bytes |

| ∥ | Concatenation operator | concat() | function → bytes |



\---



\## Derived / Intermediate Variables



\### Vessel Registration Phase (computed by V)

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| PUV | PrV · G | vessel.PU | Vessel public key |

| PIDV | h(IDV ∥ PrCS) | vessel.PID | Pseudo-identity, computed by CS |

| QV | h(IDV ∥ PIN) ⊕ PrV | vessel.QV | Stored credential protecting PrV |

| RV | PIDV ⊕ h(PrV) | vessel.RV | Stored credential protecting PIDV |

| SV | h(PIDV ∥ PIN ∥ PrV) | vessel.SV | Verification token |



\### Login \& Authentication Step 1 — Vessel

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| PrV | h(IDV ∥ PIN) ⊕ QV | recovered\_PrV | Recovered private key |

| PIDV | RV ⊕ h(PrV) | recovered\_PIDV | Recovered pseudo-identity |

| SV' | h(PIDV ∥ PIN ∥ PrV) | SV\_prime | Login verification token |



\### Authentication Step 2 — Vessel → HAP (msg1)

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| X | a1 · PUCS = (Xx, Xy) | X | ECC point, both coordinates used |

| Xx | x-coordinate of X | X\_x | int |

| Xy | y-coordinate of X | X\_y | int |

| Y | a1 · G | Y | ECC point sent in msg1 |

| M1 | PIDV ⊕ h(Xx) | M1 | Masked pseudo-identity |

| M2 | h(PIDV ∥ Xy ∥ T1) | M2 | Hash binding PID, Y-coord, timestamp |

| M3 | M2 ⊕ IDHAP | M3 | Masked HAP identity |

| M4 | h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1) | M4 | Authentication token |

| msg1 | ⟨Y, T1, M1, M3, M4⟩ | msg1 | Sent from V to HAP |



\### Authentication Step 3 — HAP → CS (msg2)

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| Z1 | b1 · G | Z1 | HAP ephemeral public point |

| ssk | h(b1 · PUCS) | ssk | Short-term shared secret (HAP-CS) |

| Tag1 | HMACssk(msg1 ∥ IDHAP ∥ T2) | Tag1 | HMAC tag authenticating HAP to CS |

| msg2 | ⟨msg1, Tag1, IDHAP, Z1, T2⟩ | msg2 | Sent from HAP to CS |



\### Authentication Step 4 — CS Verification

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| ssk' | h(PrCS · Z1) | ssk\_prime | CS recomputes shared secret |

| Tag1' | HMACssk'(msg1 ∥ IDHAP ∥ T2) | Tag1\_prime | CS recomputes tag to verify |

| X' | PrCS · Y | X\_prime | CS recovers X using its private key |

| PIDV' | M1 ⊕ h(X'x) | PIDV\_prime | CS recovers pseudo-identity |

| M2' | h(PIDV' ∥ X'y ∥ T1) | M2\_prime | CS recomputes M2 |

| IDHAP' | M2' ⊕ M3 | IDHAP\_prime | CS recovers HAP identity |

| M4' | h(PIDV' ∥ IDHAP ∥ IDCS ∥ X' ∥ T1) | M4\_prime | CS recomputes M4 to verify vessel |



\### Authentication Step 5 — CS → HAP (msg3)

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| c1 | random number chosen by CS | c1 | int |

| Z | c1 · G | Z | CS ephemeral public point |

| W | c1 · Y = (Wx, Wy) | W | Shared point for session key |

| Wx | x-coordinate of W | W\_x | int |

| Wy | y-coordinate of W | W\_y | int |

| M5 | h(PIDV' ∥ Wx ∥ T3) | M5 | Token binding PID, W, timestamp |

| M6 | h(IDHAP ∥ IDCS ∥ Z1 ∥ T3) | M6 | Hash token for HAP verification |

| SKV,CS | h(IDCS ∥ PIDV ∥ W ∥ T3) | SK\_V\_CS | Session key computed by CS |

| VerSK | h(SKV,CS ∥ X') | VerSK | Session key verifier |

| msg3 | ⟨Z, M5, M6, VerSK, T3⟩ | msg3 | Sent from CS to HAP |



\### Authentication Step 6 — HAP → V (msg4)

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| M6' | h(IDHAP ∥ IDCS ∥ Z1 ∥ T3) | M6_prime | HAP recomputes M6 hash to verify |

| ssk2 | h(b1 · PUV) | ssk2 | Short-term shared secret (HAP-V) |

| Tag2 | HMACssk2(msg3 ∥ IDHAP ∥ T4) | Tag2 | HMAC tag authenticating HAP to V |

| msg4 | ⟨msg3, Tag2, IDHAP, Z1, T4⟩ | msg4 | Sent from HAP to Vessel |



\### Authentication Step 7 — Vessel Verification

| Paper Symbol | Formula | Python Variable | Description |

|---|---|---|---|

| ssk2' | h(PrV · Z1) | ssk2\_prime | Vessel recomputes HAP-V shared secret |

| Tag2' | HMACssk2'(msg3 ∥ IDHAP ∥ T4) | Tag2\_prime | Vessel recomputes tag to verify |

| W' | a1 · Z | W\_prime | Vessel recovers W using its random a1 |

| M5' | h(PIDV ∥ W'x ∥ T3) | M5\_prime | Vessel recomputes M5 to verify CS |

| SKV,CS' | h(IDCS ∥ PIDV ∥ W' ∥ T3) | SK\_V\_CS\_prime | Session key computed by Vessel |

| VerSK' | h(SKV,CS' ∥ X) | VerSK\_prime | Vessel recomputes verifier |



\---



\## ECC Notation



| Symbol | Meaning | Python |

|---|---|---|

| G | Generator point of elliptic curve | CURVE.G |

| Eq(a, b) | Elliptic curve: y² mod q = (x³ + ax + b) mod q | CURVE |

| k · P | Scalar multiplication: add P to itself k times | ec\_mul(k, P) |

| P + Q | Point addition on elliptic curve | ec\_add(P, Q) |

| ECDLP | Given k·P, infeasible to find k | (security assumption) |



\---



\## Hash and HMAC Notation



| Symbol | Meaning | Python | Output Size |

|---|---|---|---|

| h(·) | SHA-256 truncated to 160 bits OR full SHA-1 | h() | 160 bits = 20 bytes |

| HMAC(k, m) | HMAC-SHA256 with key k over message m | hmac\_op(k, m) | 160 bits = 20 bytes |



Note: The paper uses 160-bit outputs for all hash and identity values (matching Table VI).

We use SHA-256 and truncate to 160 bits (20 bytes) to maintain the 160-bit size assumption

while using a stronger hash function. Alternatively SHA-1 produces 160 bits natively.



\---



\## Timestamp Convention



| Symbol | Meaning | Python Type | Size (Table VI) |

|---|---|---|---|

| T1 | Timestamp at Vessel when msg1 is created | int (unix ms) | 32 bits |

| T2 | Timestamp at HAP when msg2 is created | int (unix ms) | 32 bits |

| T3 | Timestamp at CS when msg3 is created | int (unix ms) | 32 bits |

| T4 | Timestamp at HAP when msg4 is created | int (unix ms) | 32 bits |

| ΔT | Maximum transmission delay | float (ms) | config constant |

| T\*1 | Time msg1 is received at HAP | int (unix ms) | — |

| T\*2 | Time msg2 is received at CS | int (unix ms) | — |

| T\*3 | Time msg3 is received at HAP | int (unix ms) | — |

| T\*4 | Time msg4 is received at Vessel | int (unix ms) | — |



Freshness condition: |T\*i − Ti| < ΔT must hold for every message.



\---



\## Concatenation Rules



All concatenations use ∥ which in Python is implemented as byte concatenation.

The order of concatenation must exactly match the paper. For example:



\- h(IDV ∥ PrCS) means: hash(bytes(IDV) + bytes(PrCS))

\- h(PIDV ∥ PIN ∥ PrV) means: hash(bytes(PIDV) + bytes(PIN) + bytes(PrV))

\- All integers (private keys, scalars) are converted to fixed-width big-endian bytes

&#x20; before concatenation. Width = 20 bytes (160 bits) for all values.

\- ECC points are serialized as: x-coordinate (20 bytes) ∥ y-coordinate (20 bytes) = 40 bytes

&#x20; when the full point is concatenated (as in M4 where X is used)

\- When only Xx or Xy is used (as in M1, M2), only that 20-byte coordinate is used


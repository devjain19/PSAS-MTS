\# CRYPTO.md — Cryptographic Primitives Specification



\## 1. Elliptic Curve Cryptography (ECC)



\### Curve Definition

The elliptic curve is defined as:

&#x20; Eq(a, b) : y² mod q = (x³ + ax + b) mod q

&#x20; Condition: 4a³ + 27b² ≠ 0 (mod q)

&#x20; Where: x, y, a, b ∈ Fq (finite field of order q)



\### Curve Selection

The paper uses a 160-bit ECC curve. This matches the 160-bit size assumption in Table VI

for ECC points, identities, and hash outputs.



We use the NIST curve secp160r1 OR we simulate with a small test curve for unit tests.

For production-accurate timing benchmarks we use the 160-bit curve.



secp160r1 parameters:

&#x20; p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF

&#x20; a  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC

&#x20; b  = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45

&#x20; Gx = 0x4A96B5688EF573284664698968C38BB913CBFC82

&#x20; Gy = 0x23A628553168947D59DCC912042351377AC5FB32

&#x20; n  = 0x0100000000000000000001F4C8F927AED3CA752257

&#x20; h  = 1



\### Point Operations



\#### Point Addition: P + Q = R

Given P(x1, y1) and Q(x2, y2) on Eq:

&#x20; λ = (y2 - y1) / (x2 - x1) mod q    \[if P ≠ Q]

&#x20; λ = (3x1² + a) / (2y1) mod q        \[if P = Q, i.e. point doubling]

&#x20; x3 = λ² - x1 - x2 mod q

&#x20; y3 = λ(x1 - x3) - y1 mod q

&#x20; R = (x3, y3)

&#x20; 

Special cases:

&#x20; P + O = P  (O is point at infinity)

&#x20; P + (-P) = O  (where -P = (x, -y mod q))



\#### Scalar Multiplication: k · P

Computed via double-and-add algorithm:

&#x20; Result = O  (identity)

&#x20; For each bit of k from MSB to LSB:

&#x20;   Result = 2 · Result

&#x20;   If bit == 1: Result = Result + P

&#x20; Return Result



\#### ECDLP Security Assumption

Given Q = k · P, it is computationally infeasible to determine k.

This is the foundation of security for:

\- All ephemeral shared secrets (ssk, ssk2)

\- Session key agreement (W = c1 · Y = a1 · Z)

\- Protection of private keys from public keys



\### Serialization for Hashing/Concatenation

\- A scalar k is serialized as 20-byte big-endian integer

\- An ECC point P(x, y):

&#x20; - Full point: x as 20 bytes || y as 20 bytes = 40 bytes total

&#x20; - x-coordinate only: x as 20 bytes

&#x20; - y-coordinate only: y as 20 bytes



\---



\## 2. One-Way Cryptographic Hash h(·)



\### Definition (from paper, Section III.C)

h(·) : {0,1}\* → {0,1}^n

A function mapping variable-length input to fixed-length n-bit output.



\### Required Properties

1\. Pre-image resistance: Given q, infeasible to find p such that h(p) = q

2\. Second-preimage resistance: Given p1, infeasible to find p2 ≠ p1 such that h(p1) = h(p2)

3\. Strong collision resistance: Infeasible to find any (p1, p2) where p1 ≠ p2 and h(p1) = h(p2)



\### Implementation

\- Algorithm: SHA-256 truncated to 160 bits (first 20 bytes)

\- Output size: 160 bits = 20 bytes (matching Table VI)

\- Input: arbitrary bytes (concatenated values as specified per usage)



```python

import hashlib



def h(data: bytes) -> bytes:

&#x20;   return hashlib.sha256(data).digest()\[:20]  # 160 bits

```



\### Usage Instances in PSAS-MTS

| Usage | Input | Output |

|---|---|---|

| h(IDV ∥ PrCS) | identity bytes + private key bytes | PIDV (20 bytes) |

| h(IDV ∥ PIN) | identity bytes + PIN bytes | intermediate for QV |

| h(PrV) | private key bytes | intermediate for RV |

| h(PIDV ∥ PIN ∥ PrV) | three values concatenated | SV (20 bytes) |

| h(Xx) | x-coord of X (20 bytes) | mask for M1 |

| h(PIDV ∥ Xy ∥ T1) | PID + y-coord + timestamp | M2 (20 bytes) |

| h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1) | five values concat | M4 (20 bytes) |

| h(b1 · PUCS) | ECC point bytes | ssk (20 bytes) |

| h(PrCS · Z1) | ECC point bytes | ssk' (20 bytes) |

| h(PIDV' ∥ Wx ∥ T3) | PID + x-coord + timestamp | M5 (20 bytes) |

| h(IDCS ∥ PIDV ∥ W ∥ T3) | four values concat | SKV,CS (20 bytes) |

| h(SKV,CS ∥ X') | session key + full point | VerSK (20 bytes) |

| h(b1 · PUV) | ECC point bytes | ssk2 (20 bytes) |

| h(PrV · Z1) | ECC point bytes | ssk2' (20 bytes) |

| h(IDHAP ∥ IDCS ∥ Z1 ∥ T3) | four values concat | M6 (20 bytes) 



\---



\## 3. HMAC — Hash-based Message Authentication Code



\### Definition

HMAC(k, m) = h((k ⊕ opad) ∥ h((k ⊕ ipad) ∥ m))

Where:

&#x20; opad = 0x5c5c5c... (repeated, block-length)

&#x20; ipad = 0x3636363... (repeated, block-length)



\### Implementation

```python

import hmac as hmac\_lib

import hashlib



def HMAC(key: bytes, message: bytes) -> bytes:

&#x20;   return hmac\_lib.new(key, message, hashlib.sha256).digest()\[:20]  # 160 bits

```



\### Usage Instances in PSAS-MTS

| Step | Key | Message | Output |

|---|---|---|---|

| PSAS-MTS 3 (HAP) | ssk | msg1 ∥ IDHAP ∥ T2 | Tag1 |

| PSAS-MTS 4 (CS verify) | ssk' | msg1 ∥ IDHAP ∥ T2 | Tag1' |

| PSAS-MTS 6 (HAP) | ssk2 | msg3 ∥ IDHAP ∥ T4 | Tag2 |

| PSAS-MTS 7 (V verify) | ssk2' | msg3 ∥ IDHAP ∥ T4 | Tag2' |



\---



\## 4. XOR Operation ⊕



\### Definition

Bitwise exclusive-or of two equal-length byte strings.



```python

def xor(a: bytes, b: bytes) -> bytes:

&#x20;   assert len(a) == len(b), "XOR operands must be equal length"

&#x20;   return bytes(x ^ y for x, y in zip(a, b))

```



\### Usage Instances in PSAS-MTS

| Expression | Purpose |

|---|---|

| h(IDV ∥ PIN) ⊕ PrV | QV: hides PrV under PIN-derived mask |

| PIDV ⊕ h(PrV) | RV: hides PIDV under PrV-derived mask |

| PIDV ⊕ h(Xx) | M1: hides PIDV under X x-coord hash |

| M2 ⊕ IDHAP | M3: hides IDHAP under M2 |

| M2' ⊕ M3 | recovers IDHAP' at CS |



\### Fixed Width

All XOR operands must be exactly 20 bytes (160 bits). Pad or truncate

integers to this width before XOR.



\---



\## 5. Concatenation ∥



```python

def concat(\*args: bytes) -> bytes:

&#x20;   return b''.join(args)

```



Order must exactly match the paper formulas. No separators are inserted.

All values must be converted to fixed-width bytes before concatenation:

\- Identities: 20 bytes

\- Hash outputs: 20 bytes

\- ECC scalars (private keys, random numbers): 20 bytes

\- ECC x or y coordinates: 20 bytes

\- Full ECC points: 40 bytes (x ∥ y)

\- Timestamps: 4 bytes (32 bits, big-endian unsigned int)

\- Random numbers a1, b1, c1: 16 bytes (128 bits per Table VI)



\---



\## 6. Randomness



All random numbers (a1, b1, c1, PrV, PrHAP, PrCS) are chosen from \[1, q-1]

where q is the curve order. Use cryptographically secure random number generation:



```python

import secrets



def random\_scalar(curve\_order: int) -> int:

&#x20;   return secrets.randbelow(curve\_order - 1) + 1

```



\---



\## 7. Timing Model (from Table VII)



These are the reference execution times from the paper for performance comparison.

They are used in performance.py to compute total cost — NOT measured from actual

code execution (our code may run on different hardware).



| Primitive | Symbol | Device (ms) | Server (ms) | Drone/HAP (ms) |

|---|---|---|---|---|

| Hash function | Th | 0.009 | 0.004 | 0.006 |

| Symmetric enc/dec | Ted | 0.018 | 0.009 | 0.013 |

| Bilinear pairing | Tb | 17.36 | 4.038 | 12.52 |

| Point multiplication (ECC) | Tpa | 5.116 | 0.926 | 4.107 |

| Point addition (ECC) | Tpad | 0.013 | 0.006 | 0.018 |



Device = IoT device on Vessel

Server = Control Station server

Drone/HAP = HAP node


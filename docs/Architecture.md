# ARCHITECTURE.md — System Architecture and Entity Model

## System Overview
PSAS-MTS is a three-entity authentication protocol for IoT-enabled Maritime
Transportation Systems. The three entities are Vessel (V), High Altitude Platform
System (HAP), and Control Station (CS).

---

## Entities

### 1. Vessel (V)
Role: IoT-enabled ship seeking authenticated communication with Control Station.
Storage (after registration, stored in tamper-resistant memory):
  - PUV  : own public key (ECC point, 40 bytes)
  - QV   : h(IDV ∥ PIN) ⊕ PrV  (20 bytes)
  - RV   : PIDV ⊕ h(PrV)        (20 bytes)
  - SV   : h(PIDV ∥ PIN ∥ PrV)  (20 bytes)

Runtime knowledge (known only at login time, not stored):
  - IDV  : vessel identity
  - PIN  : secret PIN
  
Derived at runtime:
  - PrV  = h(IDV ∥ PIN) ⊕ QV
  - PIDV = RV ⊕ h(PrV)

Ephemeral (per-session):
  - a1   : random scalar chosen fresh each session
  - X    : a1 · PUCS
  - Y    : a1 · G
  - W'   : a1 · Z (recovered session point)
  - SKV,CS : session key

### 2. High Altitude Platform System (HAP)
Role: Aerial relay node. Forwards messages between Vessel and CS.
Performs HMAC verification to authenticate CS to Vessel.
Is NOT fully trusted — operates as a semi-trusted relay.

Storage (after registration):
  - IDHAP  : own identity
  - PrHAP  : own private key
  - PUHAP  : own public key = PrHAP · G

Runtime knowledge:
  - PUCS   : CS public key (publicly known)
  - PUV    : Vessel public key (from CS database or publicly known)

Ephemeral (per-session):
  - b1   : random scalar chosen fresh each session
  - Z1   : b1 · G
  - ssk  : h(b1 · PUCS) — shared secret with CS for this session
  - ssk2 : h(b1 · PUV)  — shared secret with Vessel for this session

### 3. Control Station (CS)
Role: Trusted authority. Manages vessel registry. Generates session key.
Always online. Highest computational resources.

Storage:
  - IDCS  : own identity
  - PrCS  : own private key (SECRET, never shared)
  - PUCS  : own public key = PrCS · G (public)
  - Database: {IDV, PIDV, PUV} for every registered vessel
  - Database: {IDHAP, PUHAP} for every registered HAP

Ephemeral (per-session):
  - c1    : random scalar chosen fresh each session
  - Z     : c1 · G
  - W     : c1 · Y (session point, equal to Vessel's W')
  - SKV,CS : session key (same as Vessel's)

---

## Network Model
[Vessel] ----(public channel)----> [HAP] ----(public channel)----> [CS]
<---(public channel)----       <---(public channel)-----
- All 4 authentication messages (msg1, msg2, msg3, msg4) travel over
  public insecure channels
- Registration messages travel over secure private channels
- HAP is a relay: it receives from one side and forwards (with additions) to the other
- CS is the endpoint that makes authentication decisions

---

## Adversary Model

### Dolev-Yao (DY) Adversary
- Can intercept, read, modify, delete, inject, replay any message on public channels
- Cannot break ECDLP, hash pre-image, or HMAC forgery
- Cannot access secure channel used during registration
- Cannot access values stored inside entity memories directly

### Canetti-Krawczyk (CK) Adversary (extension of DY)
- In addition to DY capabilities:
- Can compromise session states (learn ephemeral a1, b1, c1 from one session)
- Can learn long-term secrets from compromised entities
- PSAS-MTS is designed to resist even this stronger adversary

---

## Trust Hierarchy

| Entity | Trust Level | Has PrCS | Can forge messages |
|---|---|---|---|
| CS | Fully trusted | YES | N/A (initiates nothing malicious) |
| HAP | Semi-trusted relay | NO | Cannot forge without ssk or ssk2 |
| Vessel | Legitimate user | NO | Cannot impersonate CS or HAP |
| Adversary A | Untrusted | NO | Cannot forge without secrets |

---

## Data Flow per Phase

### Registration Flow
V ──[IDV, PUV]──────────────────────────────► CS
◄──[IDV, PUV, PIDV]──────────────────────── CS
(secure channel both ways)
HAP ──[IDHAP, PUHAP]────────────────────────► CS
(secure channel, no response needed)

### Authentication Flow
Step 2: V  ──[msg1: Y, T1, M1, M3, M4]──────────────► HAP
Step 3: HAP──[msg2: msg1, Tag1, IDHAP, Z1, T2]───────► CS
Step 5: CS ──[msg3: Z, M5, M6, VerSK, T3]────────────► HAP
Step 6: HAP──[msg4: msg3, Tag2, IDHAP, Z1, T4]──────► V
---

## Python Class Structure
ControlStation
├── ID: bytes
├── Pr: int
├── PU: ECPoint
├── curve: EllipticCurve
├── vessel_db: dict[bytes, VesselRecord]  # keyed by PIDV
├── hap_db: dict[bytes, HAPRecord]        # keyed by IDHAP
├── register_hap(IDHAP, PUHAP)
├── register_vessel(IDV, PUV) → (PIDV, PUV)
├── process_msg2(msg2) → msg3
└── get_session_key() → bytes
HAP
├── ID: bytes
├── Pr: int
├── PU: ECPoint
├── process_msg1(msg1) → msg2
└── process_msg3(msg3) → msg4
Vessel
├── ID: bytes
├── PIN: bytes
├── Pr: int  (runtime only)
├── PU: ECPoint
├── PID: bytes  (runtime only)
├── QV: bytes   (stored)
├── RV: bytes   (stored)
├── SV: bytes   (stored)
├── login(IDV, PIN) → bool
├── create_msg1(PUCS, IDHAP, IDCS) → (msg1, a1, X)
└── process_msg4(msg4, a1, X) → SKV_CS
---

## File-to-Entity Mapping

| File | Entities/Concepts Covered |
|---|---|
| config.py | Curve parameters, timing constants, bit-size constants |
| crypto_primitives.py | h(), HMAC(), xor(), concat(), ec_mul(), ec_add() |
| entities.py | Vessel, HAP, ControlStation classes |
| initialization.py | CS setup |
| registration_hap.py | HAP key generation and CS registration |
| registration_vessel.py | Vessel registration, QV/RV/SV computation |
| authentication.py | All 7 PSAS-MTS steps |
| performance.py | Computation cost from Table VII/VIII |
| communication_cost.py | Bit-size calculation from Table V/VI |
| ror_model.py | Formal security queries |
| informal_security.py | All 10 propositions |
| ban_logic.py | BAN logic goals G1–G5 |
| test_protocol.py | End-to-end correctness tests |
| test_attacks.py | Attack resistance tests |
| psas_mts.py | Main runner |

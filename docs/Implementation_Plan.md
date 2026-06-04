\# IMPLEMENTATION\_PLAN.md — File Structure and Build Order



\## Language and Environment

\- Language: Python 3.10+

\- Dependencies: only standard library + one ECC library

\- ECC library: tinyec (pure Python, supports secp160r1 or custom curves)

&#x20; OR use sympy for modular arithmetic and implement ECC manually for full control

\- No external cryptographic shortcuts that hide operations from our count



\## File Dependency Order (build in this sequence)
config.py              (no dependencies)

crypto\_primitives.py   (depends on config.py)

entities.py            (depends on crypto\_primitives.py, config.py)

initialization.py      (depends on entities.py)

registration\_hap.py    (depends on entities.py, initialization.py)

registration\_vessel.py (depends on entities.py, initialization.py)

authentication.py      (depends on all registration files)

performance.py         (depends on config.py)

communication\_cost.py  (depends on config.py)

informal\_security.py  (depends on authentication.py)

ror\_model.py          (depends on authentication.py)

ban\_logic.py          (depends on authentication.py)

test\_protocol.py      (depends on all above)

test\_attacks.py       (depends on all above)

psas\_mts.py           (depends on all above — main runner)
---



\## File Descriptions



\### config.py

Purpose: All constants, curve parameters, timing values.

Contents:

&#x20; - Elliptic curve secp160r1 parameters (p, a, b, Gx, Gy, n, h)

&#x20; - Table VI bit-size constants (IDENTITY\_BITS=160, TIMESTAMP\_BITS=32, etc.)

&#x20; - Table VII timing constants (Th\_device=0.009, Tpa\_device=5.116, etc.)

&#x20; - Delta\_T = maximum transmission delay in ms (suggest 100ms for simulation)

&#x20; - FIELD\_SIZE = 20 (bytes, = 160 bits)

Maps to: Table VI, Table VII



\### crypto\_primitives.py

Purpose: All low-level cryptographic operations.

Contents:

&#x20; - h(data: bytes) -> bytes: SHA-256 truncated to 160 bits

&#x20; - hmac\_op(key: bytes, msg: bytes) -> bytes: HMAC-SHA256 truncated to 160 bits

&#x20; - xor(a: bytes, b: bytes) -> bytes: XOR of equal-length byte strings

&#x20; - concat(\*args: bytes) -> bytes: byte concatenation

&#x20; - int\_to\_bytes(n: int, length: int) -> bytes: fixed-width big-endian integer

&#x20; - bytes\_to\_int(b: bytes) -> int: integer from bytes

&#x20; - ECPoint class: (x: int, y: int) or point at infinity

&#x20; - ec\_add(P: ECPoint, Q: ECPoint, curve) -> ECPoint

&#x20; - ec\_mul(k: int, P: ECPoint, curve) -> ECPoint

&#x20; - random\_scalar(order: int) -> int

Maps to: Section III.C, III.D, CRYPTO.md



\### entities.py

Purpose: Entity classes representing V, HAP, CS.

Contents:

&#x20; - class VesselMemory: stores PUV, QV, RV, SV (what is on device)

&#x20; - class VesselRuntime: holds IDV, PIN, PrV, PIDV during session

&#x20; - class HAP: stores IDHAP, PrHAP, PUHAP, PUCS, per-session b1, Z1, ssk, ssk2

&#x20; - class ControlStation: stores IDCS, PrCS, PUCS, vessel\_db, hap\_db

&#x20; - class VesselRecord: stores IDV, PIDV, PUV in CS database

&#x20; - class HAPRecord: stores IDHAP, PUHAP in CS database

Maps to: Section III.A, ARCHITECTURE.md



\### initialization.py

Purpose: CS system initialization.

Contents:

&#x20; - function initialize\_cs() -> ControlStation:

&#x20;   - Selects curve Eq(u,v) with generator G

&#x20;   - Generates IDCS

&#x20;   - Generates PrCS = random\_scalar(curve.order)

&#x20;   - Computes PUCS = ec\_mul(PrCS, G, curve)

&#x20;   - Returns initialized CS object

Maps to: Section IV.A



\### registration\_hap.py

Purpose: HAP key generation and registration with CS.

Contents:

&#x20; - function generate\_hap\_keys(IDHAP: bytes, curve) -> HAP:

&#x20;   - PrHAP = random\_scalar(curve.order)

&#x20;   - PUHAP = ec\_mul(PrHAP, G, curve)

&#x20;   - Returns HAP object

&#x20; - function register\_hap(hap: HAP, cs: ControlStation) -> None:

&#x20;   - Sends (IDHAP, PUHAP) to CS (simulate secure channel)

&#x20;   - CS stores in hap\_db

Maps to: Section IV.B



\### registration\_vessel.py

Purpose: Vessel key generation and registration with CS.

Contents:

&#x20; - function generate\_vessel\_keys(IDV: bytes, PrV: int, PIN: bytes, curve) -> tuple:

&#x20;   - PUV = ec\_mul(PrV, G, curve)

&#x20;   - Returns (PUV,)

&#x20; - function register\_vessel(IDV, PUV, PIN, PrV, cs) -> VesselMemory:

&#x20;   - V sends (IDV, PUV) to CS

&#x20;   - CS computes PIDV = h(IDV ∥ int\_to\_bytes(PrCS))

&#x20;   - CS stores (IDV, PIDV, PUV)

&#x20;   - CS sends (IDV, PUV, PIDV) back to V

&#x20;   - V computes QV = h(IDV ∥ PIN) XOR int\_to\_bytes(PrV)

&#x20;   - V computes RV = PIDV XOR h(int\_to\_bytes(PrV))

&#x20;   - V computes SV = h(PIDV ∥ PIN ∥ int\_to\_bytes(PrV))

&#x20;   - V stores (PUV, QV, RV, SV) in memory

&#x20;   - Returns VesselMemory

Maps to: Section IV.C



\### authentication.py

Purpose: All 7 PSAS-MTS authentication steps.

Contents:

&#x20; - function psas\_mts\_step1\_login(IDV, PIN, mem: VesselMemory) -> VesselRuntime:

&#x20;   - Recovers PrV, PIDV

&#x20;   - Verifies SV' = SV

&#x20;   - Returns VesselRuntime or raises AuthError

&#x20; - function psas\_mts\_step2\_vessel(runtime: VesselRuntime, IDHAP, PUCS, IDCS, curve) -> (msg1, a1, X):

&#x20;   - Computes a1, X, Y, M1, M2, M3, M4

&#x20;   - Returns msg1 dict and ephemeral state

&#x20; - function psas\_mts\_step3\_hap(msg1, hap: HAP, PUCS, curve) -> msg2:

&#x20;   - Verifies timestamp T1

&#x20;   - Computes b1, Z1, ssk, Tag1

&#x20;   - Returns msg2

&#x20; - function psas\_mts\_step4\_cs(msg2, cs: ControlStation, curve) -> msg3:

&#x20;   - Verifies timestamp T2

&#x20;   - Recomputes ssk', Tag1', X', PIDV', M2', IDHAP', M4'

&#x20;   - All verifications

&#x20;   - Computes c1, Z, W, M5, M6, SKV\_CS, VerSK

&#x20;   - Returns msg3

&#x20; - function psas\_mts\_step6\_hap(msg3, hap: HAP, PUV, curve) -> msg4:

&#x20;   - Verifies timestamp T3

&#x20;   - Verifies M6' = M6

&#x20;   - Computes ssk2, Tag2

&#x20;   - Returns msg4

&#x20; - function psas\_mts\_step7\_vessel(msg4, runtime: VesselRuntime, mem: VesselMemory, a1, X, IDCS, curve) -> bytes:

&#x20;   - Verifies timestamp T4

&#x20;   - Recomputes ssk2', Tag2', W', M5', SKV\_CS', VerSK'

&#x20;   - All verifications

&#x20;   - Returns session key SKV\_CS

Maps to: Section IV.D, PROTOCOL.md



\### performance.py

Purpose: Reproduce Table VII and Table VIII computation costs.

Contents:

&#x20; - class OperationCounter: counts Th, Tpa, Tpad, Ted, Tb per entity

&#x20; - function count\_vessel\_operations() -> OperationCounter

&#x20; - function count\_hap\_operations() -> OperationCounter

&#x20; - function count\_cs\_operations() -> OperationCounter

&#x20; - function compute\_total\_cost(vessel\_ops, hap\_ops, cs\_ops) -> float (ms)

&#x20; - function print\_cost\_table(): prints Table VIII row for our scheme

&#x20; Expected output: 36.654 ms

Maps to: Section VI.A, Table VII, Table VIII



\### communication\_cost.py

Purpose: Reproduce Table V communication cost of 3712 bits.

Contents:

&#x20; - Constants matching Table VI (bit sizes per primitive)

&#x20; - function compute\_msg1\_bits() -> int: should return 672

&#x20; - function compute\_msg2\_bits() -> int: should return 1184

&#x20; - function compute\_msg3\_bits() -> int: should return 672

&#x20; - function compute\_msg4\_bits() -> int: should return 1184

&#x20; - function compute\_total\_bits() -> int: should return 3712

&#x20; - function print\_cost\_table(): prints Table V row for our scheme

Maps to: Section VI.B, Table V, Table VI



\### informal\_security.py

Purpose: Test all 10 security propositions.

Contents:

&#x20; - function test\_mitm\_resistance(): modify message in transit → verify failure

&#x20; - function test\_impersonation\_resistance(): fake msg1 without PIDV → verify failure

&#x20; - function test\_vessel\_capture\_resistance(): use {QV,RV,SV} without PIN → verify failure

&#x20; - function test\_session\_key\_disclosure\_resistance(): derive SK from public msgs → verify infeasibility

&#x20; - function test\_esl\_resistance(): disclose {a1,b1,c1}, verify forward/backward secrecy

&#x20; - function test\_anonymity\_unlinkability(): two sessions, verify msg1s are unlinkable

&#x20; - function test\_replay\_resistance(): replay old msg1 → freshness check failure

&#x20; - function test\_insider\_resistance(): CS admin with DB → cannot get PrV or PIN

&#x20; - function test\_forward\_backward\_secrecy(): disclose session i's ephemerals → cannot compute j

&#x20; - function test\_session\_info\_resistance(): ECDLP test for a1, b1, c1

&#x20; - function run\_all\_propositions(): runs all 10, prints PASS/FAIL

Maps to: Section V.A, SECURITY.md Propositions 1-10



\### ror\_model.py

Purpose: Implement ROR model queries and prove Theorems 1 and 2.

Contents:

&#x20; - class Lhs: list for hash oracle queries

&#x20; - class Lhm: list for HMAC oracle queries

&#x20; - function query\_setup() -> system\_params

&#x20; - function query\_hash(mk) -> rk: stores in Lhs, returns random value

&#x20; - function query\_hmac(k, mK) -> M: stores in Lhm, returns random value

&#x20; - function query\_send(entity, message) -> response

&#x20; - function query\_execute(vessel\_instance, cs\_instance) -> (R1, R2, R3)

&#x20; - function query\_reveal(entity\_instance) -> SK

&#x20; - function query\_test(entity\_instance) -> bit

&#x20; - function prove\_theorem1() -> (Pr\_EViCs, Pr\_EHapCs, Pr\_ECsHapV)

&#x20; - function prove\_theorem2() -> semantic\_security\_bound

&#x20; - function run\_ror\_analysis(): prints SECURE/INSECURE for both theorems

Maps to: Section V.B, SECURITY.md Part 2



\### ban\_logic.py

Purpose: Trace all 30 BAN logic derivation steps and verify 5 goals.

Contents:

&#x20; - class BANStatement: represents a BAN logic statement

&#x20; - class BANProof: list of statements with justifications

&#x20; - function apply\_mmr(statement, assumption) -> BANStatement

&#x20; - function apply\_nvr(freshness\_stmt, meaning\_stmt) -> BANStatement

&#x20; - function apply\_jr(jurisdiction\_stmt, belief\_stmt) -> BANStatement

&#x20; - function apply\_sub\_component(statement, index) -> BANStatement

&#x20; - function apply\_freshness\_rule(assumption) -> BANStatement

&#x20; - function derive\_all\_goals() -> dict\[str, bool]: G1 through G5

&#x20; - function run\_ban\_proof(): prints DERIVED/NOT DERIVED for each goal

&#x20; - All 30 steps S1-S30 must be explicitly coded with justifications

Maps to: Section V.C, SECURITY.md Part 3



\### test\_protocol.py

Purpose: End-to-end correctness verification.

Contents:

&#x20; - function test\_registration(): verify all stored values are correct

&#x20; - function test\_login\_correct\_credentials(): SV' = SV → True

&#x20; - function test\_login\_wrong\_pin(): SV' ≠ SV → False

&#x20; - function test\_msg1\_creation(): verify all M1,M2,M3,M4 formulas

&#x20; - function test\_msg2\_creation(): verify ssk = h(b1·PUCS), Tag1

&#x20; - function test\_cs\_verification(): verify all 4 checks pass

&#x20; - function test\_msg3\_creation(): verify W, M5, M6, SKV\_CS, VerSK

&#x20; - function test\_msg4\_creation(): verify ssk2, Tag2

&#x20; - function test\_vessel\_verification(): verify all vessel-side checks pass

&#x20; - function test\_session\_key\_match(): SKV\_CS at vessel == SKV\_CS at CS

&#x20; - function run\_all\_tests(): prints PASS/FAIL for each

Maps to: GOALS.md Section 1



\### test\_attacks.py

Purpose: Attack simulation tests.

Contents:

&#x20; - function test\_replay\_attack(): capture msg1, replay → FAIL expected

&#x20; - function test\_mitm\_attack(): intercept and modify msg1 → FAIL expected

&#x20; - function test\_vessel\_impersonation(): forge msg1 → FAIL expected

&#x20; - function test\_hap\_impersonation(): forge msg2 → FAIL expected

&#x20; - function test\_cs\_impersonation(): forge msg3 → FAIL expected

&#x20; - function test\_vessel\_capture(): stolen {QV,RV,SV} without PIN → FAIL expected

&#x20; - function test\_drone\_capture(): stolen {PrHAP} → limited impact test

&#x20; - function test\_insider\_attack(): CS admin access → cannot forge vessel session

&#x20; - function run\_all\_attack\_tests(): prints RESISTED/VULNERABLE for each

Maps to: GOALS.md Section 6, SECURITY.md Propositions



\### psas\_mts.py

Purpose: Main runner that executes the complete protocol and reports all results.

Contents:

&#x20; - Calls all setup functions

&#x20; - Runs complete authentication flow

&#x20; - Prints step-by-step trace with all computed values

&#x20; - Reports session key agreement success/failure

&#x20; - Calls performance.py → prints 36.654 ms

&#x20; - Calls communication\_cost.py → prints 3712 bits

&#x20; - Calls informal\_security.py → prints all 10 propositions

&#x20; - Calls ban\_logic.py → prints G1-G5

&#x20; - Calls ror\_model.py → prints theorem results

&#x20; - Final summary: PASS/FAIL against GOALS.md checklist

Maps to: Everything


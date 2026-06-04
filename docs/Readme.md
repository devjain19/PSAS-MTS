---

## Common Mistakes to Avoid

### Mistake 1: Using the wrong coordinate in M1 vs M2
- M1 uses h(Xx) — the X-COORDINATE (not Y-coordinate, not full point)
- M2 uses Xy — the Y-COORDINATE directly (not hashed separately)
- M4 uses X — the FULL POINT (both coordinates concatenated)
This distinction is explicit in the paper and must be exact.

### Mistake 2: Wrong serialization of ECC points
- When a formula uses "X" as a whole (like in M4), serialize as Xx_bytes || Xy_bytes (40 bytes)
- When a formula uses "Xx" or "Xy" alone, serialize as just that coordinate (20 bytes)
- When a formula uses h(b1 · PUCS), serialize the point as full 40 bytes before hashing
This is critical — wrong serialization produces wrong hashes.

### Mistake 3: Confusing ssk and ssk2
- ssk  = h(b1 · PUCS) — HAP-CS shared secret (used in Tag1)
- ssk2 = h(b1 · PUV)  — HAP-Vessel shared secret (used in Tag2)
These are different keys derived from HAP's ephemeral scalar b1 with two different points.

### Mistake 4: Wrong session key formula
- SKV,CS = h(IDCS || PIDV || W || T3)
- NOT h(IDV || ...) — uses PIDV (pseudo-identity), not real identity IDV
- NOT h(... || W || ...) where W is just Wx — W is the full point (Wx || Wy)

### Mistake 5: Wrong VerSK computation
- VerSK  = h(SKV,CS || X')   — X' is CS's recovered point (PrCS · Y), full 40 bytes
- VerSK' = h(SKV,CS' || X)   — X is Vessel's original computed point (a1 · PUCS), full 40 bytes
- Since X' = X, these are equal. But using wrong point gives wrong VerSK.

###Mistake 6: Dropping the hash on M6
- M6 = h(IDHAP || IDCS || Z1 || T3)
- While the paper's paragraph text inadvertently drops the hash       symbol, Table III explicitly defines it as a hash function.
- You must hash M6 to correctly fulfill the 160-bit size requirement for communication costs


### Mistake 7: Hardcoding timing results
- The 36.654 ms must be computed as:
  sum(operation_count × timing_constant) for each entity
- Using Table VII constants + operation counts from Table VIII Our scheme row
- Do NOT hardcode 36.654 in performance.py

### Mistake 8: Confusing the two XOR operations in login
- h(IDV || PIN) ⊕ QV gives back PrV    [because QV = h(IDV||PIN) ⊕ PrV]
- RV ⊕ h(PrV)   gives back PIDV        [because RV = PIDV ⊕ h(PrV)]
The direction of recovery is: you XOR the stored value with a re-derived mask.

---

## Definition of Done

This project is complete when running `python psas_mts.py` produces output showing:

1. All 7 authentication steps complete with PASS on every verification
2. Session key at Vessel == Session key at CS (byte-for-byte match)
3. Computation cost = 36.654 ms (from Table VII/VIII reference values)
4. Communication cost = 3712 bits (from Table V/VI bit-size assumptions)
5. All 15 security features from Table III verified
6. All 5 BAN logic goals G1-G5 derived through steps S1-S30
7. Both ROR theorems showing SECURE
8. All 25 tests in test_protocol.py and test_attacks.py passing
9. Scyther .spdl file generated and verified to produce Figure 6 results

Any deviation from these exact results means the implementation is incomplete.
The paper is the specification. The specification is final.
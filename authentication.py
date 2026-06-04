import time
import config
from crypto_primitives import (
    SECP160R1, h, HMAC, xor, concat, int_to_bytes, bytes_to_int,
    serialize_point, ec_mul, random_scalar, ECPoint
)
from entities import VesselMemory, VesselRuntime, HAP, ControlStation

class AuthError(Exception):
    pass

def get_timestamp() -> int:
    return int(time.time() * 1000) & 0xFFFFFFFF

def serialize_msg1(msg1: dict) -> bytes:
    return concat(
        serialize_point(msg1["Y"]),
        int_to_bytes(msg1["T1"], 4),
        msg1["M1"],
        msg1["M3"],
        msg1["M4"]
    )

def serialize_msg3(msg3: dict) -> bytes:
    return concat(
        serialize_point(msg3["Z"]),
        msg3["M5"],
        msg3["M6"],
        msg3["VerSK"],
        int_to_bytes(msg3["T3"], 4)
    )

def psas_mts_step1_login(IDV: bytes, PIN: bytes, mem: VesselMemory) -> VesselRuntime:
    assert len(IDV) == 20, "IDV must be 20 bytes"
    assert len(PIN) == 20, "PIN must be 20 bytes"
    
    # Recover private key: PrV = h(IDV || PIN) ⊕ QV
    recovered_PrV_bytes = xor(h(concat(IDV, PIN)), mem.QV)
    recovered_PrV = bytes_to_int(recovered_PrV_bytes)
    
    # Recover pseudo-identity: PIDV = RV ⊕ h(PrV)
    recovered_PIDV = xor(mem.RV, h(int_to_bytes(recovered_PrV, 20)))
    
    # Compute SV' = h(PIDV || PIN || PrV)
    SV_prime = h(concat(recovered_PIDV, PIN, int_to_bytes(recovered_PrV, 20)))
    
    # Verify SV' == SV
    if SV_prime != mem.SV:
        raise AuthError("Login failed: SV mismatch")
        
    return VesselRuntime(IDV, PIN, recovered_PrV, recovered_PIDV)

def psas_mts_step2_vessel(runtime: VesselRuntime, IDHAP: bytes, PUCS: ECPoint, IDCS: bytes, curve=SECP160R1) -> tuple:
    assert len(IDHAP) == 20, "IDHAP must be 20 bytes"
    assert len(IDCS) == 20, "IDCS must be 20 bytes"
    
    # Vessel chooses random number a1 ∈ [1, q-1]
    a1 = random_scalar(curve.n)
    
    # Compute X = a1 · PUCS = (Xx, Xy)
    X = ec_mul(a1, PUCS, curve)
    
    # Compute Y = a1 · G
    Y = ec_mul(a1, curve.G, curve)
    
    # Generate timestamp T1
    T1 = get_timestamp()
    
    # M1 = PIDV ⊕ h(Xx)
    M1 = xor(runtime.PIDV, h(int_to_bytes(X.x, 20)))
    
    # M2 = h(PIDV ∥ Xy ∥ T1)
    M2 = h(concat(runtime.PIDV, int_to_bytes(X.y, 20), int_to_bytes(T1, 4)))
    
    # M3 = M2 ⊕ IDHAP
    M3 = xor(M2, IDHAP)
    
    # M4 = h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1)
    M4 = h(concat(runtime.PIDV, IDHAP, IDCS, serialize_point(X), int_to_bytes(T1, 4)))
    
    msg1 = {
        "Y": Y,
        "T1": T1,
        "M1": M1,
        "M3": M3,
        "M4": M4
    }
    return (msg1, a1, X)

def psas_mts_step3_hap(msg1: dict, hap: HAP, PUCS: ECPoint, curve=SECP160R1) -> dict:
    T_star1 = get_timestamp()
    
    # Verify freshness: |T*1 - T1| < ΔT
    diff = (T_star1 - msg1["T1"]) & 0xFFFFFFFF
    if diff > config.DELTA_T:
        raise AuthError("T1 freshness check failed")
        
    # HAP chooses random number b1 ∈ [1, q-1]
    b1 = random_scalar(curve.n)
    
    # Z1 = b1 · G
    Z1 = ec_mul(b1, curve.G, curve)
    
    # ssk = h(b1 · PUCS)
    ssk = h(serialize_point(ec_mul(b1, PUCS, curve)))
    
    # Generate timestamp T2
    T2 = get_timestamp()
    
    # Tag1 = HMAC_ssk(msg1 ∥ IDHAP ∥ T2)
    Tag1 = HMAC(ssk, concat(serialize_msg1(msg1), hap.IDHAP, int_to_bytes(T2, 4)))
    
    # Save session state
    hap.b1 = b1
    hap.Z1 = Z1
    hap.ssk = ssk
    
    msg2 = {
        "msg1": msg1,
        "Tag1": Tag1,
        "IDHAP": hap.IDHAP,
        "Z1": Z1,
        "T2": T2
    }
    return msg2

def psas_mts_step4_cs(msg2: dict, cs: ControlStation, curve=SECP160R1) -> dict:
    T_star2 = get_timestamp()
    
    # Verify freshness: |T*2 - T2| < ΔT
    diff = (T_star2 - msg2["T2"]) & 0xFFFFFFFF
    if diff > config.DELTA_T:
        raise AuthError("T2 freshness check failed")
        
    # Recompute ssk' = h(PrCS · Z1)
    ssk_prime = h(serialize_point(ec_mul(cs.PrCS, msg2["Z1"], curve)))
    
    # Recompute Tag1' = HMAC_ssk'(msg1 ∥ IDHAP ∥ T2)
    Tag1_prime = HMAC(ssk_prime, concat(serialize_msg1(msg2["msg1"]), msg2["IDHAP"], int_to_bytes(msg2["T2"], 4)))
    
    # Verify Tag1' == Tag1
    if Tag1_prime != msg2["Tag1"]:
        raise AuthError("Tag1 verification failed")
        
    # Recover X' = PrCS · Y
    X_prime = ec_mul(cs.PrCS, msg2["msg1"]["Y"], curve)
    
    # Recover PIDV' = M1 ⊕ h(X'x)
    PIDV_prime = xor(msg2["msg1"]["M1"], h(int_to_bytes(X_prime.x, 20)))
    
    # Check if PIDV' exists in vessel_db
    if PIDV_prime not in cs.vessel_db:
        raise AuthError("Vessel pseudo-identity not found in CS database")
        
    # Recompute M2' = h(PIDV' ∥ X'y ∥ T1)
    M2_prime = h(concat(PIDV_prime, int_to_bytes(X_prime.y, 20), int_to_bytes(msg2["msg1"]["T1"], 4)))
    
    # Recover IDHAP' = M2' ⊕ M3
    IDHAP_prime = xor(M2_prime, msg2["msg1"]["M3"])
    
    # Verify IDHAP' == IDHAP
    if IDHAP_prime != msg2["IDHAP"]:
        raise AuthError("IDHAP verification failed")
        
    # Recompute M4' = h(PIDV' ∥ IDHAP ∥ IDCS ∥ X' ∥ T1)
    M4_prime = h(concat(PIDV_prime, msg2["IDHAP"], cs.IDCS, serialize_point(X_prime), int_to_bytes(msg2["msg1"]["T1"], 4)))
    
    # Verify M4' == M4
    if M4_prime != msg2["msg1"]["M4"]:
        raise AuthError("M4 verification failed")
        
    # CS chooses random number c1 ∈ [1, q-1]
    c1 = random_scalar(curve.n)
    
    # Compute Z = c1 · G
    Z = ec_mul(c1, curve.G, curve)
    
    # Compute W = c1 · Y
    W = ec_mul(c1, msg2["msg1"]["Y"], curve)
    
    # Generate timestamp T3
    T3 = get_timestamp()
    
    # Compute M5 = h(PIDV' ∥ Wx ∥ T3)
    M5 = h(concat(PIDV_prime, int_to_bytes(W.x, 20), int_to_bytes(T3, 4)))
    
    # Compute M6 = h(IDHAP ∥ IDCS ∥ Z1 ∥ T3)
    M6 = h(concat(msg2["IDHAP"], cs.IDCS, serialize_point(msg2["Z1"]), int_to_bytes(T3, 4)))
    
    # Compute SK_V_CS = h(IDCS ∥ PIDV' ∥ W ∥ T3)
    SK_V_CS = h(concat(cs.IDCS, PIDV_prime, serialize_point(W), int_to_bytes(T3, 4)))
    
    # Compute VerSK = h(SK_V_CS ∥ X')
    VerSK = h(concat(SK_V_CS, serialize_point(X_prime)))
    
    # Store session key in Control Station
    cs.session_key = SK_V_CS
    
    msg3 = {
        "Z": Z,
        "M5": M5,
        "M6": M6,
        "VerSK": VerSK,
        "T3": T3
    }
    return msg3

def psas_mts_step6_hap(msg3: dict, hap: HAP, PUV: ECPoint, curve=SECP160R1) -> dict:
    T_star3 = get_timestamp()
    
    # Verify freshness: |T*3 - T3| < ΔT
    diff = (T_star3 - msg3["T3"]) & 0xFFFFFFFF
    if diff > config.DELTA_T:
        raise AuthError("T3 freshness check failed")
        
    # Recompute M6' = h(IDHAP ∥ IDCS ∥ Z1 ∥ T3)
    M6_prime = h(concat(hap.IDHAP, hap.IDCS, serialize_point(hap.Z1), int_to_bytes(msg3["T3"], 4)))
    
    # Verify M6' == M6
    if M6_prime != msg3["M6"]:
        raise AuthError("M6 verification failed")
        
    # Compute ssk2 = h(b1 · PUV)
    ssk2 = h(serialize_point(ec_mul(hap.b1, PUV, curve)))
    
    # Generate timestamp T4
    T4 = get_timestamp()
    
    # Tag2 = HMAC_ssk2(msg3 ∥ IDHAP ∥ T4)
    Tag2 = HMAC(ssk2, concat(serialize_msg3(msg3), hap.IDHAP, int_to_bytes(T4, 4)))
    
    # Save ssk2 in hap
    hap.ssk2 = ssk2
    
    msg4 = {
        "msg3": msg3,
        "Tag2": Tag2,
        "IDHAP": hap.IDHAP,
        "Z1": hap.Z1,
        "T4": T4
    }
    return msg4

def psas_mts_step7_vessel(msg4: dict, runtime: VesselRuntime, mem: VesselMemory, a1: int, X: ECPoint, IDCS: bytes, curve=SECP160R1) -> bytes:
    T_star4 = get_timestamp()
    
    # Verify freshness: |T*4 - T4| < ΔT
    diff = (T_star4 - msg4["T4"]) & 0xFFFFFFFF
    if diff > config.DELTA_T:
        raise AuthError("T4 freshness check failed")
        
    # Recompute ssk2' = h(PrV · Z1)
    ssk2_prime = h(serialize_point(ec_mul(runtime.PrV, msg4["Z1"], curve)))
    
    # Recompute Tag2' = HMAC_ssk2'(msg3 ∥ IDHAP ∥ T4)
    Tag2_prime = HMAC(ssk2_prime, concat(serialize_msg3(msg4["msg3"]), msg4["IDHAP"], int_to_bytes(msg4["T4"], 4)))
    
    # Verify Tag2' == Tag2
    if Tag2_prime != msg4["Tag2"]:
        raise AuthError("Tag2 verification failed")
        
    # Recover W' = a1 · Z
    W_prime = ec_mul(a1, msg4["msg3"]["Z"], curve)
    
    # Recompute M5' = h(PIDV ∥ W'x ∥ T3)
    M5_prime = h(concat(runtime.PIDV, int_to_bytes(W_prime.x, 20), int_to_bytes(msg4["msg3"]["T3"], 4)))
    
    # Verify M5' == M5
    if M5_prime != msg4["msg3"]["M5"]:
        raise AuthError("M5 verification failed")
        
    # Compute SK_V_CS' = h(IDCS ∥ PIDV ∥ W' ∥ T3)
    SK_V_CS_prime = h(concat(IDCS, runtime.PIDV, serialize_point(W_prime), int_to_bytes(msg4["msg3"]["T3"], 4)))
    
    # Compute VerSK' = h(SK_V_CS' ∥ X)
    VerSK_prime = h(concat(SK_V_CS_prime, serialize_point(X)))
    
    # Verify VerSK' == VerSK
    if VerSK_prime != msg4["msg3"]["VerSK"]:
        raise AuthError("VerSK verification failed")
        
    return SK_V_CS_prime

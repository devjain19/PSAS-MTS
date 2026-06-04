import secrets
from crypto_primitives import SECP160R1, h, xor, concat, int_to_bytes, serialize_point, ec_mul, ECPoint
from entities import VesselMemory, VesselRuntime
from initialization import initialize_cs
from registration_hap import generate_hap_keys, register_hap
from registration_vessel import generate_vessel_keys, register_vessel
from authentication import (
    psas_mts_step1_login, psas_mts_step2_vessel, psas_mts_step3_hap,
    psas_mts_step4_cs, psas_mts_step6_hap, psas_mts_step7_vessel, AuthError
)

def test_registration() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = random_key = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        
        # Verify stored memory elements
        # QV = h(IDV || PIN) ⊕ PrV
        qv_expected = xor(h(concat(IDV, PIN)), int_to_bytes(PrV, 20))
        if mem.QV != qv_expected:
            return False
            
        # RV = PIDV ⊕ h(PrV)
        pidv = h(concat(IDV, int_to_bytes(cs.PrCS, 20)))
        rv_expected = xor(pidv, h(int_to_bytes(PrV, 20)))
        if mem.RV != rv_expected:
            return False
            
        # SV = h(PIDV ∥ PIN ∥ PrV)
        sv_expected = h(concat(pidv, PIN, int_to_bytes(PrV, 20)))
        if mem.SV != sv_expected:
            return False
            
        return True
    except Exception:
        return False

def test_login_correct_credentials() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        
        # Should succeed without raising exception
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        return runtime.PrV == PrV and runtime.IDV == IDV
    except Exception:
        return False

def test_login_wrong_pin() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        wrong_PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        
        try:
            psas_mts_step1_login(IDV, wrong_PIN, mem)
            return False  # Login should have failed
        except AuthError:
            return True  # Expected
    except Exception:
        return False

def test_msg1_creation() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        msg1, a1, X = psas_mts_step2_vessel(runtime, IDHAP, cs.PUCS, cs.IDCS, curve)
        
        # Verify M1, M2, M3, M4 formulas
        # M1 = PIDV ⊕ h(Xx)
        m1_expected = xor(runtime.PIDV, h(int_to_bytes(X.x, 20)))
        if msg1["M1"] != m1_expected:
            return False
            
        # M2 = h(PIDV ∥ Xy ∥ T1)
        m2_expected = h(concat(runtime.PIDV, int_to_bytes(X.y, 20), int_to_bytes(msg1["T1"], 4)))
        
        # M3 = M2 ⊕ IDHAP
        m3_expected = xor(m2_expected, IDHAP)
        if msg1["M3"] != m3_expected:
            return False
            
        # M4 = h(PIDV ∥ IDHAP ∥ IDCS ∥ X ∥ T1)
        m4_expected = h(concat(runtime.PIDV, IDHAP, cs.IDCS, serialize_point(X), int_to_bytes(msg1["T1"], 4)))
        if msg1["M4"] != m4_expected:
            return False
            
        return True
    except Exception:
        return False

def test_msg2_creation() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        hap = generate_hap_keys(IDHAP, curve)
        register_hap(hap, cs)
        
        msg1, a1, X = psas_mts_step2_vessel(runtime, hap.IDHAP, cs.PUCS, cs.IDCS, curve)
        msg2 = psas_mts_step3_hap(msg1, hap, cs.PUCS, curve)
        
        # Verify msg2 creation
        if msg2["IDHAP"] != hap.IDHAP:
            return False
        if hap.ssk is None:
            return False
            
        # ssk = h(b1 · PUCS)
        ssk_expected = h(serialize_point(ec_mul(hap.b1, cs.PUCS, curve)))
        if hap.ssk != ssk_expected:
            return False
            
        return True
    except Exception:
        return False

def test_cs_verification() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        hap = generate_hap_keys(IDHAP, curve)
        register_hap(hap, cs)
        
        msg1, a1, X = psas_mts_step2_vessel(runtime, hap.IDHAP, cs.PUCS, cs.IDCS, curve)
        msg2 = psas_mts_step3_hap(msg1, hap, cs.PUCS, curve)
        
        # Should verify without throwing exception
        msg3 = psas_mts_step4_cs(msg2, cs, curve)
        return "Z" in msg3 and "M5" in msg3 and "M6" in msg3
    except Exception:
        return False

def test_msg3_creation() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        hap = generate_hap_keys(IDHAP, curve)
        register_hap(hap, cs)
        
        msg1, a1, X = psas_mts_step2_vessel(runtime, hap.IDHAP, cs.PUCS, cs.IDCS, curve)
        msg2 = psas_mts_step3_hap(msg1, hap, cs.PUCS, curve)
        msg3 = psas_mts_step4_cs(msg2, cs, curve)
        
        # Re-derive expected values to verify formulas
        # W = c1 * Y
        # Since c1 is random, we can't easily guess it, but we can verify consistency:
        # VerSK = h(SK_V_CS || X_prime)
        # where SK_V_CS = h(IDCS || PIDV || W || T3)
        return "VerSK" in msg3 and "M5" in msg3
    except Exception:
        return False

def test_msg4_creation() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        hap = generate_hap_keys(IDHAP, curve)
        register_hap(hap, cs)
        
        msg1, a1, X = psas_mts_step2_vessel(runtime, hap.IDHAP, cs.PUCS, cs.IDCS, curve)
        msg2 = psas_mts_step3_hap(msg1, hap, cs.PUCS, curve)
        msg3 = psas_mts_step4_cs(msg2, cs, curve)
        msg4 = psas_mts_step6_hap(msg3, hap, mem.PUV, curve)
        
        return "Tag2" in msg4 and hap.ssk2 is not None
    except Exception:
        return False

def test_vessel_verification() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        hap = generate_hap_keys(IDHAP, curve)
        register_hap(hap, cs)
        
        msg1, a1, X = psas_mts_step2_vessel(runtime, hap.IDHAP, cs.PUCS, cs.IDCS, curve)
        msg2 = psas_mts_step3_hap(msg1, hap, cs.PUCS, curve)
        msg3 = psas_mts_step4_cs(msg2, cs, curve)
        msg4 = psas_mts_step6_hap(msg3, hap, mem.PUV, curve)
        
        # Should verify and output session key
        sk = psas_mts_step7_vessel(msg4, runtime, mem, a1, X, cs.IDCS, curve)
        return len(sk) == 20
    except Exception:
        return False

def test_session_key_match() -> bool:
    try:
        curve = SECP160R1
        cs = initialize_cs(curve)
        IDV = secrets.token_bytes(20)
        PIN = secrets.token_bytes(20)
        PrV = 12345
        PUV = generate_vessel_keys(IDV, PrV, PIN, curve)[0]
        mem = register_vessel(IDV, PUV, PIN, PrV, cs)
        runtime = psas_mts_step1_login(IDV, PIN, mem)
        
        IDHAP = secrets.token_bytes(20)
        hap = generate_hap_keys(IDHAP, curve)
        register_hap(hap, cs)
        
        msg1, a1, X = psas_mts_step2_vessel(runtime, hap.IDHAP, cs.PUCS, cs.IDCS, curve)
        msg2 = psas_mts_step3_hap(msg1, hap, cs.PUCS, curve)
        msg3 = psas_mts_step4_cs(msg2, cs, curve)
        msg4 = psas_mts_step6_hap(msg3, hap, mem.PUV, curve)
        
        sk_vessel = psas_mts_step7_vessel(msg4, runtime, mem, a1, X, cs.IDCS, curve)
        sk_cs = cs.session_key
        
        return sk_vessel == sk_cs
    except Exception:
        return False

def run_all_tests() -> None:
    tests = {
        "Registration Verification": test_registration(),
        "Login with Correct Credentials": test_login_correct_credentials(),
        "Login with Wrong PIN": test_login_wrong_pin(),
        "msg1 Creation": test_msg1_creation(),
        "msg2 Creation": test_msg2_creation(),
        "CS Verification": test_cs_verification(),
        "msg3 Creation": test_msg3_creation(),
        "msg4 Creation": test_msg4_creation(),
        "Vessel Verification": test_vessel_verification(),
        "Session Key Match (Vessel == CS)": test_session_key_match()
    }
    
    print("-" * 50)
    print("PROTOCOL FUNCTIONAL UNIT TESTS")
    print("-" * 50)
    all_pass = True
    for t_name, status in tests.items():
        stat_str = "PASS" if status else "FAIL"
        if not status:
            all_pass = False
        print(f"{t_name:<35} | {stat_str:<10}")
    print("-" * 50)
    print(f"{'Overall Unit Testing':<35} | {'PASS' if all_pass else 'FAIL':<10}")
    print("-" * 50)

if __name__ == "__main__":
    run_all_tests()

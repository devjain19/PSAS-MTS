from crypto_primitives import SECP160R1, ec_mul, h, xor, concat, int_to_bytes
from entities import VesselMemory, VesselRecord, ControlStation

def generate_vessel_keys(IDV: bytes, PrV: int, PIN: bytes, curve=SECP160R1) -> tuple:
    assert len(IDV) == 20, "IDV must be 20 bytes"
    assert len(PIN) == 20, "PIN must be 20 bytes"
    PUV = ec_mul(PrV, curve.G, curve)
    return (PUV,)

def register_vessel(IDV: bytes, PUV, PIN: bytes, PrV: int, cs: ControlStation) -> VesselMemory:
    assert len(IDV) == 20, "IDV must be 20 bytes"
    assert len(PIN) == 20, "PIN must be 20 bytes"
    
    # CS side computation
    PIDV = h(concat(IDV, int_to_bytes(cs.PrCS, 20)))
    # Store in CS database
    cs.vessel_db[PIDV] = VesselRecord(IDV, PIDV, PUV)
    
    # Vessel side computation
    QV = xor(h(concat(IDV, PIN)), int_to_bytes(PrV, 20))
    RV = xor(PIDV, h(int_to_bytes(PrV, 20)))
    SV = h(concat(PIDV, PIN, int_to_bytes(PrV, 20)))
    
    return VesselMemory(PUV, QV, RV, SV)

import secrets
from crypto_primitives import SECP160R1, random_scalar, ec_mul
from entities import ControlStation

def initialize_cs(curve=SECP160R1, IDCS: bytes = None) -> ControlStation:
    if IDCS is None:
        IDCS = secrets.token_bytes(20)
    else:
        assert len(IDCS) == 20, "IDCS must be exactly 20 bytes"
    
    PrCS = random_scalar(curve.n)
    PUCS = ec_mul(PrCS, curve.G, curve)
    return ControlStation(IDCS, PrCS, PUCS)

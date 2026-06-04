from crypto_primitives import SECP160R1, random_scalar, ec_mul
from entities import HAP, HAPRecord, ControlStation

def generate_hap_keys(IDHAP: bytes, curve=SECP160R1) -> HAP:
    assert len(IDHAP) == 20, "IDHAP must be exactly 20 bytes"
    PrHAP = random_scalar(curve.n)
    PUHAP = ec_mul(PrHAP, curve.G, curve)
    return HAP(IDHAP, PrHAP, PUHAP)

def register_hap(hap: HAP, cs: ControlStation) -> None:
    # CS stores HAP record
    cs.hap_db[hap.IDHAP] = HAPRecord(hap.IDHAP, hap.PUHAP)
    # HAP stores PUCS and IDCS
    hap.PUCS = cs.PUCS
    hap.IDCS = cs.IDCS

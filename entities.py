from crypto_primitives import ECPoint

class VesselMemory:
    def __init__(self, PUV: ECPoint, QV: bytes, RV: bytes, SV: bytes):
        self.PUV = PUV
        self.QV = QV
        self.RV = RV
        self.SV = SV

class VesselRuntime:
    def __init__(self, IDV: bytes, PIN: bytes, PrV: int, PIDV: bytes):
        self.IDV = IDV
        self.PIN = PIN
        self.PrV = PrV
        self.PIDV = PIDV

class VesselRecord:
    def __init__(self, IDV: bytes, PIDV: bytes, PUV: ECPoint):
        self.IDV = IDV
        self.PIDV = PIDV
        self.PUV = PUV

class HAPRecord:
    def __init__(self, IDHAP: bytes, PUHAP: ECPoint):
        self.IDHAP = IDHAP
        self.PUHAP = PUHAP

class HAP:
    def __init__(self, IDHAP: bytes, PrHAP: int, PUHAP: ECPoint):
        self.IDHAP = IDHAP
        self.PrHAP = PrHAP
        self.PUHAP = PUHAP
        self.PUCS = None
        # Per-session variables
        self.b1 = None
        self.Z1 = None
        self.ssk = None
        self.ssk2 = None

class ControlStation:
    def __init__(self, IDCS: bytes, PrCS: int, PUCS: ECPoint):
        self.IDCS = IDCS
        self.PrCS = PrCS
        self.PUCS = PUCS
        self.vessel_db = {}  # key: PIDV (bytes) -> value: VesselRecord
        self.hap_db = {}     # key: IDHAP (bytes) -> value: HAPRecord

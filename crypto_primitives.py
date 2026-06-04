import hashlib
import hmac as hmac_lib
import secrets
import config

class ECPoint:
    def __init__(self, x: int | None, y: int | None):
        self.x = x
        self.y = y

    def is_infinity(self) -> bool:
        return self.x is None or self.y is None

    def __eq__(self, other):
        if not isinstance(other, ECPoint):
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "ECPoint(Infinity)"
        return f"ECPoint(x={hex(self.x)}, y={hex(self.y)})"

class Curve:
    def __init__(self, p: int, a: int, b: int, n: int, h: int, G: ECPoint):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.h = h
        self.G = G

SECP160R1_G = ECPoint(config.CURVE_GX, config.CURVE_GY)
SECP160R1 = Curve(
    p=config.CURVE_P,
    a=config.CURVE_A,
    b=config.CURVE_B,
    n=config.CURVE_N,
    h=config.CURVE_H,
    G=SECP160R1_G
)

def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:20]

def hmac_op(key: bytes, msg: bytes) -> bytes:
    return hmac_lib.new(key, msg, hashlib.sha256).digest()[:20]

HMAC = hmac_op

def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"XOR operands must be equal length: {len(a)} != {len(b)}"
    return bytes(x ^ y for x, y in zip(a, b))

def concat(*args: bytes) -> bytes:
    return b''.join(args)

def int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def serialize_point(P: ECPoint) -> bytes:
    if P.is_infinity():
        return b'\x00' * 40
    return int_to_bytes(P.x, 20) + int_to_bytes(P.y, 20)

def ec_add(P: ECPoint, Q: ECPoint, curve: Curve) -> ECPoint:
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P
    
    if P.x == Q.x:
        if (P.y + Q.y) % curve.p == 0:
            return ECPoint(None, None)
        # Point doubling
        num = (3 * P.x * P.x + curve.a) % curve.p
        den = (2 * P.y) % curve.p
    else:
        # Point addition
        num = (Q.y - P.y) % curve.p
        den = (Q.x - P.x) % curve.p
        
    inv = pow(den, curve.p - 2, curve.p)
    lam = (num * inv) % curve.p
    
    x3 = (lam * lam - P.x - Q.x) % curve.p
    y3 = (lam * (P.x - x3) - P.y) % curve.p
    return ECPoint(x3, y3)

def ec_mul(k: int, P: ECPoint, curve: Curve) -> ECPoint:
    result = ECPoint(None, None)
    temp = P
    curr_k = k
    while curr_k > 0:
        if curr_k & 1:
            result = ec_add(result, temp, curve)
        temp = ec_add(temp, temp, curve)
        curr_k >>= 1
    return result

def random_scalar(curve_order: int) -> int:
    return secrets.randbelow(curve_order - 1) + 1

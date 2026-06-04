import config

# Bit sizes per primitive from Table VI
IDENTITY_BITS = config.IDENTITY_BITS
TIMESTAMP_BITS = config.TIMESTAMP_BITS
XOR_BITS = config.XOR_BITS
HASH_BITS = config.HASH_BITS
ECC_POINT_BITS = config.ECC_POINT_BITS
RANDOM_NUMBER_BITS = config.RANDOM_NUMBER_BITS
HMAC_BITS = config.HMAC_BITS

def compute_msg1_bits() -> int:
    # msg1 = {Y, T1, M1, M3, M4}
    # Y (ECC point) = 160
    # T1 (timestamp) = 32
    # M1 (XOR) = 160
    # M3 (XOR) = 160
    # M4 (Hash) = 160
    return ECC_POINT_BITS + TIMESTAMP_BITS + XOR_BITS + XOR_BITS + HASH_BITS

def compute_msg2_bits() -> int:
    # msg2 = {msg1, Tag1, IDHAP, Z1, T2}
    # msg1 = 672
    # Tag1 (HMAC) = 160
    # IDHAP (Identity) = 160
    # Z1 (ECC point) = 160
    # T2 (timestamp) = 32
    return compute_msg1_bits() + HMAC_BITS + IDENTITY_BITS + ECC_POINT_BITS + TIMESTAMP_BITS

def compute_msg3_bits() -> int:
    # msg3 = {Z, M5, M6, VerSK, T3}
    # Z (ECC point) = 160
    # M5 (Hash) = 160
    # M6 (Hash) = 160
    # VerSK (Hash) = 160
    # T3 (timestamp) = 32
    return ECC_POINT_BITS + HASH_BITS + HASH_BITS + HASH_BITS + TIMESTAMP_BITS

def compute_msg4_bits() -> int:
    # msg4 = {msg3, Tag2, IDHAP, Z1, T4}
    # msg3 = 672
    # Tag2 (HMAC) = 160
    # IDHAP (Identity) = 160
    # Z1 (ECC point) = 160
    # T4 (timestamp) = 32
    return compute_msg3_bits() + HMAC_BITS + IDENTITY_BITS + ECC_POINT_BITS + TIMESTAMP_BITS

def compute_total_bits() -> int:
    return compute_msg1_bits() + compute_msg2_bits() + compute_msg3_bits() + compute_msg4_bits()

def print_cost_table() -> None:
    m1 = compute_msg1_bits()
    m2 = compute_msg2_bits()
    m3 = compute_msg3_bits()
    m4 = compute_msg4_bits()
    total = compute_total_bits()
    
    print("-" * 50)
    print(f"{'Message':<15} | {'Size (bits)':<15}")
    print("-" * 50)
    print(f"{'msg1 (V -> HAP)':<15} | {m1:<15}")
    print(f"{'msg2 (HAP -> CS)':<15} | {m2:<15}")
    print(f"{'msg3 (CS -> HAP)':<15} | {m3:<15}")
    print(f"{'msg4 (HAP -> V)':<15} | {m4:<15}")
    print("-" * 50)
    print(f"{'Total Comm. Cost':<15} | {total:<15} bits")
    print("-" * 50)

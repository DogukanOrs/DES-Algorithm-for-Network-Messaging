#!/usr/bin/env python3
"""
DES (Data Encryption Standard) - Complete Implementation
CMSE456/CMPE455 - Security of Computer Systems and Networks
Lab 2 - DES on Two Computers

This module implements the full DES algorithm.
Each transformation is exposed as a separate function for testing.
"""

# ============================================================
# Utility Functions
# ============================================================

def bytes_to_bits(data):
    """Convert bytes to a list of bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    """Convert a list of bits to bytes."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def bits_to_hex(bits):
    """Convert a list of bits to a hex string for display."""
    val = 0
    for b in bits:
        val = (val << 1) | b
    hex_len = (len(bits) + 3) // 4
    return format(val, f'0{hex_len}X')


def xor_bits(a, b):
    """XOR two equal-length bit lists."""
    return [x ^ y for x, y in zip(a, b)]


def permute(bits, table):
    """Apply a permutation table (1-indexed) to a bit list."""
    return [bits[t - 1] for t in table]


def left_circular_shift(bits, n):
    """Left circular shift a bit list by n positions."""
    return bits[n:] + bits[:n]


# ============================================================
# DES Standard Tables
# ============================================================

# Initial Permutation (IP)
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
]

# Inverse Initial Permutation (IP^-1)
IP_INV_TABLE = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
]

# Expansion Permutation (E) - 32 bits -> 48 bits
E_TABLE = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

# Permutation P - 32 bits -> 32 bits (after S-boxes)
P_TABLE = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
]

# Permuted Choice 1 (PC-1) - 64 bits -> 56 bits
PC1_TABLE = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]

# Permuted Choice 2 (PC-2) - 56 bits -> 48 bits
PC2_TABLE = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Left shift schedule for each of the 16 rounds
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-Boxes (S1 through S8)
S_BOXES = [
    # S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    # S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    # S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    # S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    # S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6,  2,  0, 14,  9, 11],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
]


# ============================================================
# DES Transformations
# ============================================================

def initial_permutation(bits):
    """Apply the Initial Permutation (IP) to a 64-bit block."""
    return permute(bits, IP_TABLE)


def inverse_initial_permutation(bits):
    """Apply the Inverse Initial Permutation (IP^-1) to a 64-bit block."""
    return permute(bits, IP_INV_TABLE)


def expansion_permutation(bits):
    """Expand 32-bit half-block to 48 bits using E table."""
    return permute(bits, E_TABLE)


def sbox_substitution(bits48):
    """Apply all 8 S-boxes to a 48-bit input, producing 32-bit output."""
    output = []
    for i in range(8):
        chunk = bits48[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = S_BOXES[i][row][col]
        output.extend([(val >> (3 - j)) & 1 for j in range(4)])
    return output


def permutation_p(bits):
    """Apply Permutation P to 32-bit S-box output."""
    return permute(bits, P_TABLE)


def generate_round_keys(key_bits):
    """
    Generate 16 round keys from a 64-bit key.
    Steps: PC-1 -> split C,D -> shift -> PC-2 for each round.
    """
    # Apply Permuted Choice 1 (64 -> 56 bits)
    key56 = permute(key_bits, PC1_TABLE)

    # Split into two 28-bit halves
    C = key56[:28]
    D = key56[28:]

    round_keys = []
    for i in range(16):
        # Left circular shift
        C = left_circular_shift(C, SHIFT_SCHEDULE[i])
        D = left_circular_shift(D, SHIFT_SCHEDULE[i])

        # Apply Permuted Choice 2 (56 -> 48 bits)
        cd = C + D
        round_key = permute(cd, PC2_TABLE)
        round_keys.append(round_key)

    return round_keys


def feistel_round(left, right, round_key):
    """
    One round of the DES Feistel function.
    new_left = right
    new_right = left XOR f(right, round_key)
    """
    # Step 1: Expansion/Permutation (32 -> 48 bits)
    expanded = expansion_permutation(right)

    # Step 2: XOR with round key
    xored = xor_bits(expanded, round_key)

    # Step 3: S-box substitution (48 -> 32 bits)
    sbox_out = sbox_substitution(xored)

    # Step 4: Permutation P
    p_out = permutation_p(sbox_out)

    # Step 5: XOR with left half
    new_right = xor_bits(left, p_out)

    # Step 6: Swap (left becomes old right)
    new_left = right

    return new_left, new_right


# ============================================================
# DES Block Encrypt / Decrypt
# ============================================================

def des_encrypt_block(block_bits, round_keys):
    """Encrypt a single 64-bit block using DES."""
    # Initial Permutation
    ip_out = initial_permutation(block_bits)

    # Split into left and right halves (32 bits each)
    left = ip_out[:32]
    right = ip_out[32:]

    # 16 Feistel rounds
    for i in range(16):
        left, right = feistel_round(left, right, round_keys[i])

    # Final swap (undo last swap) + combine
    combined = right + left  # Note: right + left (no swap after round 16)

    # Inverse Initial Permutation
    ciphertext = inverse_initial_permutation(combined)

    return ciphertext


def des_decrypt_block(block_bits, round_keys):
    """Decrypt a single 64-bit block using DES (keys in reverse order)."""
    # Initial Permutation
    ip_out = initial_permutation(block_bits)

    left = ip_out[:32]
    right = ip_out[32:]

    # 16 Feistel rounds with keys in REVERSE order
    for i in range(16):
        left, right = feistel_round(left, right, round_keys[15 - i])

    # Final swap + Inverse IP
    combined = right + left

    plaintext = inverse_initial_permutation(combined)

    return plaintext


# ============================================================
# Padding (PKCS5)
# ============================================================

def pkcs5_pad(data):
    """Pad data to a multiple of 8 bytes using PKCS5."""
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def pkcs5_unpad(data):
    """Remove PKCS5 padding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid PKCS5 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS5 padding")
    return data[:-pad_len]


# ============================================================
# Public API
# ============================================================

def des_encrypt(plaintext, key):
    """
    Encrypt arbitrary-length plaintext bytes with an 8-byte key.
    Returns ciphertext bytes.
    """
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes (64 bits)")

    # Generate round keys
    key_bits = bytes_to_bits(key)
    round_keys = generate_round_keys(key_bits)

    # Pad plaintext
    padded = pkcs5_pad(plaintext)

    # Encrypt each 8-byte block
    ciphertext = b''
    for block_idx in range(0, len(padded), 8):
        block = padded[block_idx:block_idx + 8]
        block_bits = bytes_to_bits(block)
        ct_bits = des_encrypt_block(block_bits, round_keys)
        ciphertext += bits_to_bytes(ct_bits)

    return ciphertext


def des_decrypt(ciphertext, key):
    """
    Decrypt ciphertext bytes with an 8-byte key.
    Returns plaintext bytes.
    """
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 bytes (64 bits)")
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be a multiple of 8 bytes")

    # Generate round keys
    key_bits = bytes_to_bits(key)
    round_keys = generate_round_keys(key_bits)

    # Decrypt each 8-byte block
    plaintext = b''
    for block_idx in range(0, len(ciphertext), 8):
        block = ciphertext[block_idx:block_idx + 8]
        block_bits = bytes_to_bits(block)
        pt_bits = des_decrypt_block(block_bits, round_keys)
        plaintext += bits_to_bytes(pt_bits)

    # Remove padding
    plaintext = pkcs5_unpad(plaintext)

    return plaintext

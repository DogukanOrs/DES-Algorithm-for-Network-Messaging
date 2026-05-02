#!/usr/bin/env python3
"""
DES Transformation Verification Tests
CMSE456/CMPE455 - Lab 2 - DES on Two Computers

Tests each DES transformation step-by-step using the NIST test vector:
  Key:        133457799BBCDFF1
  Plaintext:  0123456789ABCDEF
  Ciphertext: 85E813540F0AB405

Tests covered:
  2.1  Initial Permutation
  2.2  Inverse Initial Permutation
  2.3  Expansion/Permutation
  2.4  Round Key Generation (PC-1, shifts, PC-2)
  2.5  XOR with round key
  2.6  S-boxes
  2.7  Permutation P after S-boxes
  2.8  XOR with left half
  2.9  Swap of the halves
  2.10 Full encryption
  2.11 Full decryption
"""

import sys
from des import (
    bytes_to_bits, bits_to_bytes, bits_to_hex, permute, xor_bits,
    left_circular_shift,
    initial_permutation, inverse_initial_permutation,
    expansion_permutation, sbox_substitution, permutation_p,
    generate_round_keys, feistel_round,
    des_encrypt_block, des_decrypt_block,
    des_encrypt, des_decrypt,
    IP_TABLE, IP_INV_TABLE, E_TABLE, P_TABLE,
    PC1_TABLE, PC2_TABLE, SHIFT_SCHEDULE
)

PASS_COUNT = 0
FAIL_COUNT = 0


def check(name, got, expected):
    """Check a test result and print PASS/FAIL."""
    global PASS_COUNT, FAIL_COUNT
    status = "PASS" if got == expected else "FAIL"
    if status == "PASS":
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f"  [{status}] {name}")
    if got != expected:
        print(f"         Expected: {expected}")
        print(f"         Got:      {got}")
    return status == "PASS"


def main():
    # ==========================================
    # NIST Test Vector
    # ==========================================
    key_hex = "133457799BBCDFF1"
    pt_hex = "0123456789ABCDEF"
    ct_hex = "85E813540F0AB405"

    key_bytes = bytes.fromhex(key_hex)
    pt_bytes = bytes.fromhex(pt_hex)

    key_bits = bytes_to_bits(key_bytes)
    pt_bits = bytes_to_bits(pt_bytes)

    print("=" * 60)
    print("  DES TRANSFORMATION VERIFICATION TESTS")
    print("=" * 60)
    print(f"  Key:               {key_hex}")
    print(f"  Plaintext:         {pt_hex}")
    print(f"  Expected Cipher:   {ct_hex}")
    print("=" * 60)

    # ==========================================================
    # Test 2.1: Initial Permutation
    # ==========================================================
    print("\n  --- Test 2.1: Initial Permutation (IP) ---")
    ip_result = initial_permutation(pt_bits)
    ip_hex = bits_to_hex(ip_result)
    # Known: IP(0123456789ABCDEF) = CC00CCFFF0AAF0AA
    check("IP output", ip_hex, "CC00CCFFF0AAF0AA")
    print(f"  Input:  {pt_hex}")
    print(f"  Output: {ip_hex}")

    # ==========================================================
    # Test 2.2: Inverse Initial Permutation
    # ==========================================================
    print("\n  --- Test 2.2: Inverse Initial Permutation (IP^-1) ---")
    ip_inv_result = inverse_initial_permutation(ip_result)
    ip_inv_hex = bits_to_hex(ip_inv_result)
    check("IP then IP^-1 recovers original", ip_inv_hex, pt_hex)
    print(f"  IP^-1(IP(plaintext)) = {ip_inv_hex}")

    # ==========================================================
    # Test 2.3: Expansion/Permutation (E)
    # ==========================================================
    print("\n  --- Test 2.3: Expansion/Permutation (E) ---")
    R0 = ip_result[32:]
    R0_hex = bits_to_hex(R0)
    expanded = expansion_permutation(R0)
    expanded_hex = bits_to_hex(expanded)
    check("E output is 48 bits", len(expanded), 48)
    print(f"  R0 (32 bits): {R0_hex}")
    print(f"  E(R0) (48 bits): {expanded_hex}")

    # ==========================================================
    # Test 2.4: Round Key Generation
    # ==========================================================
    print("\n  --- Test 2.4: Round Key Generation ---")

    # 2.4.1: Permuted Choice 1
    print("\n  --- Test 2.4.1: Permuted Choice 1 (PC-1) ---")
    pc1_result = permute(key_bits, PC1_TABLE)
    pc1_hex = bits_to_hex(pc1_result)
    check("PC-1 produces 56 bits", len(pc1_result), 56)
    print(f"  Key (64 bits):     {key_hex}")
    print(f"  PC-1 (56 bits):    {pc1_hex}")
    C0 = pc1_result[:28]
    D0 = pc1_result[28:]
    print(f"  C0: {bits_to_hex(C0)}")
    print(f"  D0: {bits_to_hex(D0)}")

    # 2.4.2: Left Circular Shifts
    print("\n  --- Test 2.4.2: Left Circular Shift Schedule ---")
    expected_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    check("Shift schedule", SHIFT_SCHEDULE, expected_shifts)
    print(f"  Schedule: {SHIFT_SCHEDULE}")

    # Show shift example
    C0_shifted = left_circular_shift(C0, 1)
    print(f"  C0 before shift:  {bits_to_hex(C0)}")
    print(f"  C0 after shift 1: {bits_to_hex(C0_shifted)}")

    # 2.4.3: Permuted Choice 2 - verify all 16 round keys
    print("\n  --- Test 2.4.3: Permuted Choice 2 (PC-2) - Round Keys ---")
    round_keys = generate_round_keys(key_bits)
    check("16 round keys generated", len(round_keys), 16)

    # Known correct round keys for key 133457799BBCDFF1
    expected_keys = [
        "1B02EFFC7072",  # K1
        "79AED9DBC9E5",  # K2
        "55FC8A42CF99",  # K3
        "72ADD6DB351D",  # K4
        "7CEC07EB53A8",  # K5
        "63A53E507B2F",  # K6
        "EC84B7F618BC",  # K7
        "F78A3AC13BFB",  # K8
        "E0DBEBEDE781",  # K9
        "B1F347BA464F",  # K10
        "215FD3DED386",  # K11
        "7571F59467E9",  # K12
        "97C5D1FABA41",  # K13
        "5F43B7F2E73A",  # K14
        "BF918D3D3F0A",  # K15
        "CB3D8B0E17F5",  # K16
    ]

    for i, rk in enumerate(round_keys):
        rk_hex = bits_to_hex(rk)
        check(f"K{i+1:2d} = {rk_hex}", rk_hex, expected_keys[i])

    # ==========================================================
    # Test 2.5: XOR with Round Key
    # ==========================================================
    print("\n  --- Test 2.5: XOR with Round Key ---")
    xor_result = xor_bits(expanded, round_keys[0])
    xor_hex = bits_to_hex(xor_result)
    check("XOR result is 48 bits", len(xor_result), 48)
    print(f"  E(R0):         {expanded_hex}")
    print(f"  K1:            {bits_to_hex(round_keys[0])}")
    print(f"  E(R0) XOR K1:  {xor_hex}")

    # ==========================================================
    # Test 2.6: S-boxes
    # ==========================================================
    print("\n  --- Test 2.6: S-box Substitution ---")
    sbox_result = sbox_substitution(xor_result)
    sbox_hex = bits_to_hex(sbox_result)
    check("S-box output is 32 bits", len(sbox_result), 32)
    print(f"  Input (48 bits):  {xor_hex}")
    print(f"  Output (32 bits): {sbox_hex}")

    # Show individual S-box lookups for first input
    print("  Individual S-box results:")
    for i in range(8):
        chunk = xor_result[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        from des import S_BOXES
        val = S_BOXES[i][row][col]
        print(f"    S{i+1}: input={bits_to_hex(chunk)} row={row} col={col} -> {val} ({format(val, '04b')})")

    # ==========================================================
    # Test 2.7: Permutation P after S-boxes
    # ==========================================================
    print("\n  --- Test 2.7: Permutation P ---")
    p_result = permutation_p(sbox_result)
    p_hex = bits_to_hex(p_result)
    check("P output is 32 bits", len(p_result), 32)
    print(f"  S-box out:  {sbox_hex}")
    print(f"  P(S-box):   {p_hex}")

    # ==========================================================
    # Test 2.8: XOR with Left Half
    # ==========================================================
    print("\n  --- Test 2.8: XOR with Left Half ---")
    L0 = ip_result[:32]
    L0_hex = bits_to_hex(L0)
    new_R1 = xor_bits(L0, p_result)
    new_R1_hex = bits_to_hex(new_R1)
    check("R1 is 32 bits", len(new_R1), 32)
    print(f"  L0:              {L0_hex}")
    print(f"  f(R0, K1):       {p_hex}")
    print(f"  R1 = L0 XOR f:   {new_R1_hex}")

    # ==========================================================
    # Test 2.9: Swap of the Halves
    # ==========================================================
    print("\n  --- Test 2.9: Swap of the Halves ---")
    new_L1 = R0  # new left = old right
    check("After swap L1 = old R0", bits_to_hex(new_L1), R0_hex)
    print(f"  Before swap: L0={L0_hex}  R0={R0_hex}")
    print(f"  After swap:  L1={bits_to_hex(new_L1)}  R1={new_R1_hex}")

    # ==========================================================
    # Test 2.10: Full Encryption
    # ==========================================================
    print("\n  --- Test 2.10: Full DES Encryption ---")
    ct_bits = des_encrypt_block(pt_bits, round_keys)
    ct_result_hex = bits_to_hex(ct_bits)
    check("Encryption matches NIST vector", ct_result_hex, ct_hex)
    print(f"  Plaintext:   {pt_hex}")
    print(f"  Ciphertext:  {ct_result_hex}")

    # ==========================================================
    # Test 2.11: Full Decryption
    # ==========================================================
    print("\n  --- Test 2.11: Full DES Decryption ---")
    pt_dec_bits = des_decrypt_block(ct_bits, round_keys)
    pt_dec_hex = bits_to_hex(pt_dec_bits)
    check("Decryption recovers plaintext", pt_dec_hex, pt_hex)
    print(f"  Ciphertext:  {ct_result_hex}")
    print(f"  Decrypted:   {pt_dec_hex}")

    # ==========================================================
    # Bonus: Round-trip with padding (multi-byte message)
    # ==========================================================
    print("\n  --- Bonus: Multi-block Encrypt/Decrypt Round-trip ---")
    test_message = b"Hello, DES Lab 2!"
    ct = des_encrypt(test_message, key_bytes)
    pt_dec = des_decrypt(ct, key_bytes)
    check("Round-trip plaintext match", pt_dec, test_message)
    print(f"  Original:    {test_message}")
    print(f"  Encrypted:   {ct.hex().upper()}")
    print(f"  Decrypted:   {pt_dec}")

    # ==========================================================
    # Summary
    # ==========================================================
    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {PASS_COUNT} passed, {FAIL_COUNT} failed, "
          f"{PASS_COUNT + FAIL_COUNT} total")
    print(f"{'=' * 60}")

    if FAIL_COUNT == 0:
        print("  ALL TESTS PASSED!")
    else:
        print(f"  {FAIL_COUNT} TEST(S) FAILED!")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MeowHash256 — Test Suite (V1–V6, N1–N4)

Tests:
  1. Constants verification
  2. Determinism
  3. Output size
  4. Uniqueness
  5. Avalanche effect
  6. C/Python consistency
  7. Reference values (updated for N1–N4)
  8. V1 verification (SILVER_64 odd)
  9. Short input sensitivity
"""

import os
import sys
import ctypes
import subprocess
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from python.meowhash256 import meowhash256, meowhash256_hex, MAGIC_64, MAGIC_128, AES_SBOX, SILVER_64


def load_c_library():
    lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'build', 'libmeowhash256.so')
    if not os.path.exists(lib_path):
        lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                'build', 'libmeowhash_v6.so')
    if not os.path.exists(lib_path):
        print(f"[WARN] C library not found, building...")
        subprocess.run(['make', 'lib'], cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                'build', 'libmeowhash256.so')

    lib = ctypes.CDLL(lib_path)
    lib.meow_hash_v6.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.meow_hash_v6.restype = None
    lib.meow_hash_v6_hex.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.meow_hash_v6_hex.restype = None
    return lib


def c_meowhash256(lib, data):
    output = ctypes.create_string_buffer(32)
    if len(data) == 0:
        lib.meow_hash_v6(None, 0, output)
    else:
        lib.meow_hash_v6(data, len(data), output)
    return output.raw


def c_meowhash256_hex(lib, data):
    hex_buf = ctypes.create_string_buffer(65)
    if len(data) == 0:
        lib.meow_hash_v6_hex(None, 0, hex_buf)
    else:
        lib.meow_hash_v6_hex(data, len(data), hex_buf)
    return hex_buf.value.decode('ascii')


def bit_diff(a, b):
    diff = 0
    for x, y in zip(a, b):
        diff += bin(x ^ y).count('1')
    return diff


passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name} -- {detail}")
        failed += 1


def test_constants():
    print("\n=== Constant Verification ===")
    check("MAGIC_128 length", len(MAGIC_128) == 128)
    check("MAGIC_64 count", len(MAGIC_64) == 16)
    check("AES_SBOX length", len(AES_SBOX) == 256)
    check("AES_SBOX[0] == 0x63", AES_SBOX[0] == 0x63)
    check("AES_SBOX[0xFF] == 0x16", AES_SBOX[0xFF] == 0x16)

    # V1: SILVER_64 must be odd
    check("V1: SILVER_64 is odd", SILVER_64 & 1 == 1,
          f"SILVER_64 = 0x{SILVER_64:016X} has {bin(SILVER_64 & 0xFF).count('0')} trailing zeros")
    check("V1: SILVER_64 trailing zeros == 0",
          (SILVER_64 & 7) != 0,
          f"Last 3 bits: {SILVER_64 & 7}")

    for i in range(16):
        expected = struct.unpack_from('<Q', MAGIC_128, i * 8)[0]
        check(f"MAGIC_64[{i}] matches MAGIC_128", MAGIC_64[i] == expected)


def test_determinism():
    print("\n=== Determinism ===")
    inputs = [b"", b"a", b"MeowHash", b"Hello, World!", b"\x00" * 100, os.urandom(1024)]
    for data in inputs:
        h1 = meowhash256(data)
        h2 = meowhash256(data)
        label = repr(data[:20]) + ("..." if len(data) > 20 else "")
        check(f"Deterministic: {label}", h1 == h2)


def test_output_size():
    print("\n=== Output Size ===")
    for size in [0, 1, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 1000, 10000]:
        data = os.urandom(size) if size > 0 else b""
        h = meowhash256(data)
        check(f"Output 32 bytes for {size}-byte input", len(h) == 32)


def test_uniqueness():
    print("\n=== Uniqueness ===")
    hashes = set()
    inputs = [
        b"", b"a", b"b", b"ab", b"ba", b"abc", b"MeowHash",
        b"MeowHash\x00", b"\x00MeowHash", b"meowhash",
        b"A" * 100, b"A" * 101,
    ]
    for data in inputs:
        h = meowhash256(data)
        hashes.add(h)
    check(f"All {len(inputs)} different inputs produce unique hashes",
          len(hashes) == len(inputs))


def test_avalanche():
    print("\n=== Avalanche Effect ===")
    base = b"MeowHash256 avalanche test input"
    h_base = meowhash256(base)

    total_diff = 0
    num_flips = 0

    for byte_pos in range(len(base)):
        for bit_pos in range(8):
            modified = bytearray(base)
            modified[byte_pos] ^= (1 << bit_pos)
            h_mod = meowhash256(bytes(modified))
            diff = bit_diff(h_base, h_mod)
            total_diff += diff
            num_flips += 1

    avg_diff = total_diff / num_flips
    ratio = avg_diff / 256.0

    check(f"Average bit diff: {avg_diff:.1f}/256 ({ratio:.1%})",
          80 < avg_diff < 176,
          f"Expected ~128, got {avg_diff:.1f}")


def test_short_long_boundary():
    print("\n=== Short/Long Input Boundary ===")
    h63 = meowhash256(b"A" * 63)
    h64 = meowhash256(b"A" * 64)
    check("63 bytes (3 rounds) != 64 bytes (4 rounds)", h63 != h64)
    check("63-byte output size", len(h63) == 32)
    check("64-byte output size", len(h64) == 32)
    check("63-byte deterministic", meowhash256(b"A" * 63) == h63)
    check("64-byte deterministic", meowhash256(b"A" * 64) == h64)


def test_c_python_consistency(lib):
    print("\n=== C/Python Consistency ===")
    test_inputs = [
        b"",
        b"a",
        b"MeowHash",
        b"Hello, World!",
        b"\x00",
        b"\xff",
        b"A" * 7,
        b"A" * 8,
        b"A" * 9,
        b"A" * 15,
        b"A" * 16,
        b"A" * 31,
        b"A" * 32,
        b"A" * 63,
        b"A" * 64,
        b"A" * 100,
        b"A" * 1000,
        os.urandom(64),
        os.urandom(256),
        os.urandom(1024),
        os.urandom(4096),
    ]

    for data in test_inputs:
        py_hash = meowhash256(data)
        c_hash = c_meowhash256(lib, data)
        label = repr(data[:20]) + ("..." if len(data) > 20 else "")
        check(f"C == Python: {label} ({len(data)} bytes)",
              py_hash == c_hash,
              f"\n    Python: {py_hash.hex()}\n    C:      {c_hash.hex()}")


def test_c_python_hex_consistency(lib):
    print("\n=== Hex Output Consistency ===")
    for data in [b"", b"MeowHash", b"test123"]:
        py_hex = meowhash256_hex(data)
        c_hex = c_meowhash256_hex(lib, data)
        label = repr(data)
        check(f"Hex match: {label}", py_hex == c_hex,
              f"\n    Python: {py_hex}\n    C:      {c_hex}")


def test_reference_values():
    print("\n=== Reference Values (V1-V6, N1-N4) ===")
    refs = [
        (b"", 'empty string',
         '68054b0505fda46148b79f1b36a51c50e8049735e47d6cfdac8dcf5638a3144c'),
        (b"MeowHash", '"MeowHash"',
         '7c11887b28bc6ae6d272a16075646e2d7a809d2b0f5cbc8f2ec9f694ef4cdc53'),
    ]
    for data, desc, expected in refs:
        h = meowhash256_hex(data)
        print(f"  Input: {desc}")
        print(f"  Hash:  {h}")
        check(f"Reference: {desc}", h == expected,
              f"Expected {expected}, got {h}")

    print("\n  Computing 'a' x 1,000,000 ...")
    h = meowhash256_hex(b"a" * 1_000_000)
    print(f"  Hash:  {h}")
    check("1M 'a' reference",
          h == "8b8d2535e3e6475e73a51b410959d12dad621c34ce7b14285761451e0b68e633")


def test_v1_bijective():
    """V1: Verify SILVER_64 is odd and compute_node has no trivial collisions."""
    print("\n=== V1: compute_node Bijectivity ===")
    from python.meowhash256 import _compute_node

    # Check trailing zeros
    trailing = 0
    v = SILVER_64
    while v and (v & 1) == 0:
        trailing += 1
        v >>= 1
    check(f"SILVER_64 trailing zeros = {trailing}", trailing == 0)

    # Old weakness: a + 2^61 should NO LONGER collide
    a = 0x1234567890ABCDEF
    b = (a + (1 << 61)) & 0xFFFFFFFFFFFFFFFF
    na = _compute_node(a)
    nb = _compute_node(b)
    check("Old W1 weakness (a + 2^61) no longer collides", na != nb,
          f"node(a) = 0x{na:016X}, node(b) = 0x{nb:016X}")

    # Brute-force: check for collisions among many random inputs
    import random
    seen = {}
    collisions = 0
    n_trials = 500_000
    rng = random.Random(42)
    for _ in range(n_trials):
        x = rng.getrandbits(64)
        nx = _compute_node(x)
        if nx in seen and seen[nx] != x:
            collisions += 1
        seen[nx] = x
    check(f"No node collisions in {n_trials} trials", collisions == 0,
          f"Found {collisions} collisions")


def test_short_input_sensitivity():
    """Test that even 1-byte inputs produce well-distributed hashes."""
    print("\n=== Short Input Sensitivity ===")
    hashes = set()
    for b in range(256):
        h = meowhash256(bytes([b]))
        hashes.add(h)
    check("All 256 single-byte inputs produce unique hashes", len(hashes) == 256)

    # Check hamming distances between consecutive single-byte hashes
    h0 = meowhash256(b'\x00')
    h1 = meowhash256(b'\x01')
    hd = bit_diff(h0, h1)
    check(f"Hamming(H(0x00), H(0x01)) = {hd} (expect ~128)",
          80 < hd < 176, f"Got {hd}")


if __name__ == '__main__':
    print("=" * 60)
    print("MeowHash256 — Test Suite (V1-V6 + Butterfly-Fix)")
    print("=" * 60)

    test_constants()
    test_determinism()
    test_output_size()
    test_uniqueness()
    test_avalanche()
    test_short_long_boundary()
    test_v1_bijective()
    test_short_input_sensitivity()

    try:
        lib = load_c_library()
        test_c_python_consistency(lib)
        test_c_python_hex_consistency(lib)
    except (OSError, FileNotFoundError) as e:
        print(f"\n[SKIP] C/Python consistency tests: {e}")

    test_reference_values()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    sys.exit(1 if failed > 0 else 0)

#!/usr/bin/env python3
"""
MeowHash256 — Test Suite

Tests:
  1. Constants verification
  2. Determinism
  3. Output size
  4. Uniqueness
  5. Avalanche effect
  6. C/Python consistency
  7. Reference values
"""

import os
import sys
import ctypes
import subprocess
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from python.meowhash256 import meowhash256, meowhash256_hex, MAGIC_64, MAGIC_128, AES_SBOX


def load_c_library():
    lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'build', 'libmeowhash256.so')
    if not os.path.exists(lib_path):
        # Try old name
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
    print("\n=== Reference Values ===")
    refs = [
        (b"", 'empty string',
         '0327d2a5b61959ed3f80901e24a29a7da0a9c5b57a7c4fde8d0620f986923978'),
        (b"MeowHash", '"MeowHash"',
         '2c9e16c3e938585960244fcf139794668f1ca8f874c674d59ddc8a4b468d44e4'),
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
          h == "f499d98544d72c3a2580b60372200ec816d609b8c9fc23d9191df9af3b482994")


if __name__ == '__main__':
    print("=" * 60)
    print("MeowHash256 — Test Suite")
    print("=" * 60)

    test_constants()
    test_determinism()
    test_output_size()
    test_uniqueness()
    test_avalanche()
    test_short_long_boundary()

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

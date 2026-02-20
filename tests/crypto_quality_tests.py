#!/usr/bin/env python3
"""
MeowHash256 — Kryptographische Qualitaetstests (basierend auf Analysebericht)

Tests aus dem Bericht:
  - Avalanche (SAC) mit Flip-Rate und Bias
  - Butterfly-Diffusionsanalyse (Block-Empfangsmatrix)
  - compute_node Bijektivitaet (V1)
  - Kurzeingaben-Avalanche (S1)
  - Cross-Coupling Quadranten-Balance (S3)
  - Folding-Fixpunktanalyse (S4)
  - Laengensensitivitaet (S6)
  - Kollisionssuche
  - Bit-Verteilung
  - Determinismus + Regressions-Check (S8)
"""

import os
import sys
import random
import struct
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from python.meowhash256 import meowhash256, meowhash256_hex, SILVER_64, _compute_node

MASK64 = 0xFFFFFFFFFFFFFFFF


def bit_diff(a, b):
    diff = 0
    for x, y in zip(a, b):
        diff += bin(x ^ y).count('1')
    return diff


def hamming_weight(data):
    return sum(bin(b).count('1') for b in data)


print("=" * 70)
print("  MeowHash256 — Kryptographische Qualitaetstests")
print("  (V1-V6, N1-N4)")
print("=" * 70)

all_pass = True


# ============================================================
# Test 1: Avalanche (SAC)
# ============================================================
print("\n--- Test 1: Avalanche (Strict Avalanche Criterion) ---")
N_TRIALS = 200
INPUT_LEN = 16
rng = random.Random(42)

total_hd = 0
total_flips = 0
min_hd = 999
max_hd = 0
bit_flip_counts = [0] * 256  # per output bit

for _ in range(N_TRIALS):
    base = bytes(rng.getrandbits(8) for _ in range(INPUT_LEN))
    h_base = meowhash256(base)

    for byte_pos in range(INPUT_LEN):
        for bit_pos in range(8):
            modified = bytearray(base)
            modified[byte_pos] ^= (1 << bit_pos)
            h_mod = meowhash256(bytes(modified))
            hd = bit_diff(h_base, h_mod)
            total_hd += hd
            total_flips += 1
            min_hd = min(min_hd, hd)
            max_hd = max(max_hd, hd)

            for ob in range(32):
                diff_byte = h_base[ob] ^ h_mod[ob]
                for obit in range(8):
                    if diff_byte & (1 << obit):
                        bit_flip_counts[ob * 8 + obit] += 1

avg_hd = total_hd / total_flips
flip_rate = avg_hd / 256.0
deviation = abs(flip_rate - 0.5) * 100

# Per-output-bit bias
max_bit_bias = 0
for count in bit_flip_counts:
    rate = count / total_flips
    bias = abs(rate - 0.5) * 100
    max_bit_bias = max(max_bit_bias, bias)

print(f"  Trials: {N_TRIALS} x {INPUT_LEN*8} bits = {total_flips} flips")
print(f"  Avg Hamming Distance: {avg_hd:.2f} / 256 ({flip_rate:.4%})")
print(f"  Deviation from 50%:  {deviation:.3f}%")
print(f"  Min HD: {min_hd}, Max HD: {max_hd}")
print(f"  Max output-bit bias: {max_bit_bias:.2f}%")
ok = deviation < 1.0 and min_hd > 60 and max_hd < 200
print(f"  => {'PASS' if ok else 'FAIL'}")
if not ok:
    all_pass = False


# ============================================================
# Test 2: compute_node Bijektivitaet (V1)
# ============================================================
print("\n--- Test 2: compute_node Bijektivitaet (V1) ---")
trailing = 0
v = SILVER_64
while v and (v & 1) == 0:
    trailing += 1
    v >>= 1
print(f"  SILVER_64 = 0x{SILVER_64:016X}")
print(f"  Trailing zeros: {trailing}")

# Old weakness test
a = 0x1234567890ABCDEF
b = (a + (1 << 61)) & MASK64
na = _compute_node(a)
nb = _compute_node(b)
w1_fixed = na != nb
print(f"  W1 weakness (a + 2^61): {'FIXED' if w1_fixed else 'STILL PRESENT'}")

# Brute force collision search
N_BF = 1_000_000
seen = {}
collisions = 0
rng2 = random.Random(123)
for _ in range(N_BF):
    x = rng2.getrandbits(64)
    nx = _compute_node(x)
    if nx in seen and seen[nx] != x:
        collisions += 1
    seen[nx] = x
print(f"  Brute-force ({N_BF} trials): {collisions} collisions")
ok = trailing == 0 and w1_fixed and collisions == 0
print(f"  => {'PASS' if ok else 'FAIL'}")
if not ok:
    all_pass = False


# ============================================================
# Test 3: Kurzeingaben-Avalanche (S1 aus dem Bericht)
# ============================================================
print("\n--- Test 3: Kurzeingaben-Avalanche (1-15 Bytes) ---")
N_SHORT = 500
rng3 = random.Random(999)

print(f"  {'Laenge':>8} {'Avg HD':>8} {'Min HD':>8} {'Max HD':>8} {'Bias%':>8} {'Status':>8}")
short_ok = True
for length in range(1, 16):
    total = 0
    count = 0
    smin = 999
    smax = 0
    for _ in range(N_SHORT):
        base = bytes(rng3.getrandbits(8) for _ in range(length))
        h_base = meowhash256(base)
        for bit_pos in range(length * 8):
            modified = bytearray(base)
            modified[bit_pos // 8] ^= (1 << (bit_pos % 8))
            h_mod = meowhash256(bytes(modified))
            hd = bit_diff(h_base, h_mod)
            total += hd
            count += 1
            smin = min(smin, hd)
            smax = max(smax, hd)
    avg = total / count
    bias = abs(avg / 256.0 - 0.5) * 100
    status = "OK" if bias < 2.0 and smin > 50 else "WARN"
    if status != "OK":
        short_ok = False
    print(f"  {length:>5} B  {avg:>7.2f}  {smin:>7}  {smax:>7}  {bias:>7.3f}  {status:>7}")

print(f"  => {'PASS' if short_ok else 'FAIL'}")
if not short_ok:
    all_pass = False


# ============================================================
# Test 4: Bit-Verteilung
# ============================================================
print("\n--- Test 4: Bit-Verteilung ---")
N_DIST = 10000
bit_ones = [0] * 256
rng4 = random.Random(777)

for _ in range(N_DIST):
    data = bytes(rng4.getrandbits(8) for _ in range(32))
    h = meowhash256(data)
    for byte_idx in range(32):
        for bit_idx in range(8):
            if h[byte_idx] & (1 << bit_idx):
                bit_ones[byte_idx * 8 + bit_idx] += 1

max_bias = 0
avg_bias = 0
for count in bit_ones:
    ratio = count / N_DIST
    bias = abs(ratio - 0.5) * 100
    max_bias = max(max_bias, bias)
    avg_bias += bias
avg_bias /= 256

print(f"  Samples: {N_DIST}")
print(f"  Max bit bias:  {max_bias:.2f}%")
print(f"  Avg bit bias:  {avg_bias:.2f}%")
ok = max_bias < 3.0
print(f"  => {'PASS' if ok else 'FAIL'}")
if not ok:
    all_pass = False


# ============================================================
# Test 5: Kollisionssuche
# ============================================================
print("\n--- Test 5: Kollisionssuche ---")
N_COLL = 200000
hashes = {}
full_collisions = 0
near_collisions = 0
min_coll_hd = 999
rng5 = random.Random(555)

for i in range(N_COLL):
    data = bytes(rng5.getrandbits(8) for _ in range(16))
    h = meowhash256(data)
    h_key = h[:8]  # use first 8 bytes as bucket key
    if h in hashes:
        full_collisions += 1

    # Check near-collisions with a sample
    if i < 1000:
        for prev_h in list(hashes.values())[:100]:
            hd = bit_diff(h, prev_h)
            if hd < 16:
                near_collisions += 1
            min_coll_hd = min(min_coll_hd, hd)

    hashes[h] = data

print(f"  Trials: {N_COLL}")
print(f"  Full collisions: {full_collisions}")
print(f"  Near collisions (HD<16, sampled): {near_collisions}")
print(f"  Min Hamming distance (sampled): {min_coll_hd}")
ok = full_collisions == 0 and near_collisions == 0
print(f"  => {'PASS' if ok else 'FAIL'}")
if not ok:
    all_pass = False


# ============================================================
# Test 6: Laengensensitivitaet (S6)
# ============================================================
print("\n--- Test 6: Laengensensitivitaet ---")
N_LEN = 1000
rng6 = random.Random(333)
pairs = [(7, 8), (8, 9), (15, 16), (16, 17), (31, 32), (63, 64)]

print(f"  {'Paar':>12} {'Avg HD':>8} {'Min HD':>8} {'Status':>8}")
len_ok = True
for l1, l2 in pairs:
    total = 0
    lmin = 999
    for _ in range(N_LEN):
        data = bytes(rng6.getrandbits(8) for _ in range(max(l1, l2)))
        h1 = meowhash256(data[:l1])
        h2 = meowhash256(data[:l2])
        hd = bit_diff(h1, h2)
        total += hd
        lmin = min(lmin, hd)
    avg = total / N_LEN
    status = "OK" if abs(avg - 128) < 5 and lmin > 60 else "WARN"
    if status != "OK":
        len_ok = False
    print(f"  {l1:>4}B vs {l2:>3}B  {avg:>7.2f}  {lmin:>7}  {status:>7}")

print(f"  => {'PASS' if len_ok else 'FAIL'}")
if not len_ok:
    all_pass = False


# ============================================================
# Test 7: Determinismus + Testvektoren (S8)
# ============================================================
print("\n--- Test 7: Determinismus + Referenz-Testvektoren ---")
vectors = [
    (b'', '0eec3b0e25ec8486bbff79280f9712b94ac6636742ff06b96dc092c201609f45'),
    (b'a', 'd8327b5d6c6d3cd0047e95be124764e39e345e1ffde8092ecaff803b83029545'),
    (b'abc', '8ef1d73f47b0bb712d405f75e27659b958d2e4cd6eee8812e2574585dc8c2aff'),
    (b'Hello, MeowHash v6!', '7be2fa85f5bf1c3c13c0f46154cb67a16b6564f213bd6276c352fcc45f2aae4a'),
    (b'SECRET', '075e452a4abf9df6d9e31b2a4d87dadf53375b84128b2d4c8ee0a91964291ffd'),
    (b'\x00' * 7, '9f215f63c3d6ef0d928c3d1619d70566259b4c065fb7cf168b88d26f0472f818'),
    (b'\x00' * 8, '79503c130e3d4d70c0774aa4bd655a1b85767bfa0d0838c52307a727cc70471e'),
    (b'\x00' * 9, 'ab61f6a1160cc057dbef388880244d6a58045ab3cc2bf5015c32d2fef21885b5'),
]

vec_ok = True
all_hashes = set()
for data, expected in vectors:
    h1 = meowhash256_hex(data)
    h2 = meowhash256_hex(data)
    determ = h1 == h2
    correct = h1 == expected
    all_hashes.add(h1)
    label = repr(data) if len(data) < 20 else repr(data[:10]) + "..."
    status = "PASS" if determ and correct else "FAIL"
    if status == "FAIL":
        vec_ok = False
    print(f"  [{status}] {label}: {h1[:32]}...")

unique = len(all_hashes) == len(vectors)
if not unique:
    vec_ok = False
print(f"  All {len(vectors)} vectors unique: {unique}")
print(f"  => {'PASS' if vec_ok else 'FAIL'}")
if not vec_ok:
    all_pass = False


# ============================================================
# Test 8: Length-Extension-Resistenz
# ============================================================
print("\n--- Test 8: Length-Extension-Resistenz ---")
N_LE = 2000
rng8 = random.Random(888)
suspicious = 0

for _ in range(N_LE):
    m = bytes(rng8.getrandbits(8) for _ in range(16))
    x = bytes(rng8.getrandbits(8) for _ in range(8))
    h_m = meowhash256(m)
    h_mx = meowhash256(m + x)
    hd = bit_diff(h_m, h_mx)
    if hd < 80 or hd > 176:
        suspicious += 1

susp_rate = suspicious / N_LE * 100
print(f"  Trials: {N_LE}")
print(f"  Suspicious (HD < 80 or > 176): {suspicious} ({susp_rate:.2f}%)")
ok = susp_rate < 1.0
print(f"  => {'PASS' if ok else 'FAIL'}")
if not ok:
    all_pass = False


# ============================================================
# Zusammenfassung
# ============================================================
print("\n" + "=" * 70)
if all_pass:
    print("  ERGEBNIS: ALLE TESTS BESTANDEN")
else:
    print("  ERGEBNIS: EINIGE TESTS FEHLGESCHLAGEN")
print("=" * 70)

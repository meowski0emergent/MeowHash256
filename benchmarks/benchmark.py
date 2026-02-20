#!/usr/bin/env python3
"""
MeowHash256 — Benchmark Suite

Compares MeowHash256 against common hash algorithms:
  Cryptographic:     MD5, SHA-1, SHA-256, SHA-512, BLAKE2b
  Non-cryptographic: xxHash64, xxHash128, MurmurHash3, CRC32
"""

import os
import sys
import time
import hashlib
import ctypes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from python.meowhash256 import meowhash256


def load_c_library():
    lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'build', 'libmeowhash256.so')
    if not os.path.exists(lib_path):
        lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                'build', 'libmeowhash_v7.so')
    lib = ctypes.CDLL(lib_path)
    lib.meow_hash_v7.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.meow_hash_v7.restype = None
    return lib


def c_meowhash256(lib, data):
    output = ctypes.create_string_buffer(32)
    lib.meow_hash_v7(data, len(data), output)
    return output.raw


def bench(name, func, data, iterations):
    for _ in range(min(5, iterations)):
        func(data)

    start = time.perf_counter()
    for _ in range(iterations):
        func(data)
    elapsed = time.perf_counter() - start

    ms_per_iter = (elapsed / iterations) * 1000
    bytes_per_sec = len(data) / (elapsed / iterations) if elapsed > 0 else 0
    mb_per_sec = bytes_per_sec / (1024 * 1024)
    gb_per_sec = bytes_per_sec / (1024 * 1024 * 1024)

    return {
        'name': name,
        'ms_per_iter': ms_per_iter,
        'mb_per_sec': mb_per_sec,
        'gb_per_sec': gb_per_sec,
        'total_time': elapsed,
        'iterations': iterations,
    }


def hash_md5(data): return hashlib.md5(data).digest()
def hash_sha1(data): return hashlib.sha1(data).digest()
def hash_sha256(data): return hashlib.sha256(data).digest()
def hash_sha512(data): return hashlib.sha512(data).digest()
def hash_blake2b(data): return hashlib.blake2b(data, digest_size=32).digest()

def hash_xxh64(data):
    import xxhash
    return xxhash.xxh64(data).digest()

def hash_xxh128(data):
    import xxhash
    return xxhash.xxh128(data).digest()

def hash_mmh3_128(data):
    import mmh3
    return mmh3.hash128(data).to_bytes(16, 'little')

def hash_crc32(data):
    import zlib
    return zlib.crc32(data).to_bytes(4, 'little')


def run_benchmark(data_size_bytes, iterations, c_lib=None):
    data = os.urandom(data_size_bytes)
    size_label = format_size(data_size_bytes)

    print(f"\n{'='*94}")
    print(f"  Benchmark: {size_label} input | {iterations} iterations")
    print(f"{'='*94}")
    print(f"  {'Algorithm':<24} {'Output':>8} {'ms/iter':>10} {'MB/s':>12} {'GB/s':>10}")
    print(f"  {'-'*24} {'-'*8} {'-'*10} {'-'*12} {'-'*10}")

    algorithms = []

    if c_lib:
        algorithms.append(('MeowHash256 (C)', lambda d: c_meowhash256(c_lib, d), 256))

    algorithms.append(('MeowHash256 (Python)', meowhash256, 256))
    algorithms.append(('MD5', hash_md5, 128))
    algorithms.append(('SHA-1', hash_sha1, 160))
    algorithms.append(('SHA-256', hash_sha256, 256))
    algorithms.append(('SHA-512', hash_sha512, 512))
    algorithms.append(('BLAKE2b-256', hash_blake2b, 256))

    try:
        import xxhash
        algorithms.append(('xxHash64', hash_xxh64, 64))
        algorithms.append(('xxHash128', hash_xxh128, 128))
    except ImportError:
        pass

    try:
        import mmh3
        algorithms.append(('MurmurHash3-128', hash_mmh3_128, 128))
    except ImportError:
        pass

    algorithms.append(('CRC32', hash_crc32, 32))

    results = []
    for name, func, bits in algorithms:
        iters = max(1, iterations // 100) if 'Python' in name and data_size_bytes > 10000 else iterations
        r = bench(name, func, data, iters)
        r['bits'] = bits
        results.append(r)
        marker = '***' if 'Meow' in name else '   '
        print(f"  {marker} {name:<21} {bits:>5} bit {r['ms_per_iter']:>9.3f}ms {r['mb_per_sec']:>10.1f}  {r['gb_per_sec']:>8.3f}")

    return results


def format_size(n):
    if n >= 1024 * 1024:
        return f"{n / (1024*1024):.0f} MB"
    elif n >= 1024:
        return f"{n / 1024:.0f} KB"
    else:
        return f"{n} B"


def print_ranking(all_results):
    print(f"\n{'='*94}")
    print("  RANKING (by throughput)")
    print(f"{'='*94}")

    for size_label, results in all_results:
        print(f"\n  [{size_label}]")
        sha256_tp = next((r['mb_per_sec'] for r in results if r['name'] == 'SHA-256'), 1)
        if sha256_tp == 0:
            sha256_tp = 1

        for r in sorted(results, key=lambda x: x['mb_per_sec'], reverse=True):
            ratio = r['mb_per_sec'] / sha256_tp
            bar_len = int(min(ratio * 12, 40))
            bar = '#' * bar_len
            marker = ' **' if 'Meow' in r['name'] and 'C)' in r['name'] else '   '
            print(f"    {r['name']:<24} {r['mb_per_sec']:>8.1f} MB/s  {ratio:>5.2f}x  {bar}{marker}")


if __name__ == '__main__':
    print("=" * 94)
    print("  MeowHash256 — Performance Benchmark")
    print("=" * 94)

    c_lib = None
    try:
        c_lib = load_c_library()
        print("\n  [OK] C library loaded")
    except OSError as e:
        print(f"\n  [WARN] C library not available: {e}")

    all_results = []

    configs = [
        (64, 50000),
        (1024, 20000),
        (65536, 1000),
        (1048576, 100),
        (10485760, 20),
    ]

    for data_size, iters in configs:
        results = run_benchmark(data_size, iters, c_lib)
        all_results.append((format_size(data_size), results))

    print_ranking(all_results)

    print(f"\n{'='*94}")
    print("  Benchmark complete.")
    print(f"{'='*94}")

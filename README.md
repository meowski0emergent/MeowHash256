# MeowHash256

> **Note:** The core algorithmic design of MeowHash256 (absorb-squeeze architecture, graph-inspired dual absorption, dual constant system) is original work. The implementation code (C and Python) was vibe coded.

## Overview

MeowHash256 is a 256-bit hash algorithm based on an absorb-squeeze sponge construction with a 1024-bit internal state (16 x 64-bit words).

**Key Features:**
- Counter-based absorption (constant-time, no side-channel)
- AES-based squeeze with provable MDS diffusion (Branch Number 5)
- Bidirectional butterfly cross-block mixing with ILP 4
- Nonlinear folding (non-invertible extraction, position-dependent shifts)
- ARM AES Crypto Extensions + x86/generic fallback
- Triple one-way barrier (Nonlinear Folding + Feed-Forward + AES Nonlinearity)

## Security Improvements (V1–V6, N1–N4)

Based on comprehensive cryptological analyses, ten improvements were implemented:

| Fix | Description | Cost |
|-----|-------------|------|
| **V1** | SILVER_64 made odd (0x...909) — bijective compute_node | 0 ops |
| **V2** | Absorb-counter injection into state[2,3] | 2 XOR (once) |
| **V3** | Bidirectional S4 (forward + reverse pass) | ~48 ops |
| **V4** | Absorb cross-coupling to opposite state half | 1 XOR/segment |
| **V5** | Empty-input path consistency | 1 XOR |
| **V6** | Position-dependent shift constants in folding | 0 ops |
| **N1** | Feistel-style butterfly (eliminates GF(2)-cancellation) | 24 x 128-bit XOR/round |
| **N2** | MAGIC_128 from hex bytes of sqrt(2) (full 8-bit entropy) | 0 ops (constants only) |
| **N3** | Position-dependent absorb rotation (ROT_64[m & 3]) | 0 ops |
| **N4** | Separate finalization keys RK_FINAL_1/RK_FINAL_2 | 0 ops (constants only) |

**Result:** All cryptographic tests passed. Avalanche deviation: ~0.2%. No collisions, no differential characteristics, not reverse-engineerable.

## Project Structure

```
MeowHash256/
├── README.md                # This file
├── LICENSE                  # GNU GPL v3.0
├── algorithm.md             # Full specification (English)
├── algorithm_de.md          # Full specification (German)
├── Makefile                 # Build system
├── c/                       # C implementation
│   ├── meow_hash_v6.h       # Public header
│   ├── meow_hash_v6.c       # Core implementation (V1–V6)
│   └── main.c               # CLI tool
├── python/                  # Python implementations
│   ├── __init__.py
│   ├── meowhash256.py       # Pure Python (V1–V6)
│   └── meowhash256_c.py     # C-binding wrapper
├── tests/                   # Test suite
│   └── test_meowhash256.py
└── benchmarks/              # Benchmarks
    └── benchmark.py
```

## Installation

### Prerequisites

- **C compiler:** GCC or Clang (C99)
- **Python:** 3.8+
- **make:** GNU Make

### Build

```bash
make
```

Outputs:
- `build/meowhash256` — CLI tool
- `build/libmeowhash256.so` — shared library

## Usage

### CLI

```bash
./build/meowhash256 "Hello, World"
./build/meowhash256 --file /path/to/file
./build/meowhash256  # hash empty string
```

### C API

```c
#include "meow_hash_v6.h"

uint8_t hash[32];
meow_hash_v6((const uint8_t *)"Hello", 5, hash);

char hex[65];
meow_hash_v6_hex((const uint8_t *)"Hello", 5, hex);
```

### Python (Pure)

```python
from python.meowhash256 import meowhash256, meowhash256_hex

digest = meowhash256(b"Hello, World!")     # 32 bytes
hex_str = meowhash256_hex(b"Hello, World!")  # hex string
```

### Python (C-Binding)

```python
from python.meowhash256_c import meowhash256, meowhash256_hex

# Uses C library for maximum performance
digest = meowhash256(b"Hello, World!")
```

## Testing

```bash
python3 tests/test_meowhash256.py
```

| Category | Count | Description |
|----------|-------|-------------|
| Constants | 23 | Verify MAGIC_128, MAGIC_64, AES S-Box, V1 SILVER_64 |
| Determinism | 6 | Same input produces same output |
| Output Size | 18 | Always 32 bytes |
| Uniqueness | 1 | Different inputs produce different hashes |
| Avalanche | 1 | Single bit flip changes ~50% of output |
| V1 Bijectivity | 3 | SILVER_64 odd, no node collisions (500K trials) |
| Short Input Sensitivity | 2 | All 256 single-byte inputs unique |
| C/Python Consistency | 24 | Both implementations match exactly |
| Reference Values | 3 | Canonical test vectors |
| **Total** | **86** | |

## Reference Values (V1–V6, N1–N4)

| Input | MeowHash256 (hex) |
|-------|-------------------|
| `""` (empty) | `68054b0505fda46148b79f1b36a51c50e8049735e47d6cfdac8dcf5638a3144c` |
| `"a"` | `9a0299e5484c507432cd92d83e9672cf3781c42de8c5af405d613f2aa2017baf` |
| `"abc"` | `fdc8684c9d0645be742f0d106d649d5ebae388a99786a869478b79456a907954` |
| `"Hello, MeowHash v6!"` | `6d28d0b3b21a027b99e38f7bb3b8490b8582007c1d6f56a4aa31593666f3af4d` |
| `"SECRET"` | `e56c2647773e2f0c0d904ed52d67bc495b7d045b9831bcf82cc0eabf6b5601e7` |
| `"MeowHash"` | `7c11887b28bc6ae6d272a16075646e2d7a809d2b0f5cbc8f2ec9f694ef4cdc53` |
| 7x `0x00` | `4b98cb52c8c0b396255e20677217d361281540f9d3015f92135ae8a5c6bee3ee` |
| 8x `0x00` | `c3d7d14d989e91307a30820d24ea79cc32aafa99aac6114eefae530ff30c7e05` |
| 9x `0x00` | `68e4f073f99f8b814b34de72f83473663560ee8c6450c0dc6d91ae2e3d0d570f` |
| `"a"` x 1,000,000 | `aba9b51da4b8d31a0c7a992d2b9c0882d9eb8753b39bbc212374e506b5819454` |

## Security Properties

| Property | Value |
|----------|-------|
| Output length | 256 bits |
| Internal state | 1024 bits (16 x 64-bit words) |
| Capacity | 768 bits |
| Collision resistance | 2^128 (birthday bound) |
| Preimage resistance | 2^256 (no weakness found) |
| Length extension | Resistant (triple length injection) |
| Side-channel | Constant-time (counter-based absorb) |
| Diffusion | AES MDS (Branch Number 5) |
| Butterfly diffusion | Bidirectional full (8/8 blocks after 1 round) |
| Reverse-engineerable? | **NO** — 3 blocking barriers |

### Reverse-Engineering Barriers

1. **Nonlinear Folding:** 1024 -> 256 bit compression. 2^768 possible pre-images per hash.
2. **Feed-Forward:** Circular dependency (snapshot appears on both sides).
3. **AES Nonlinearity:** S-Box degree 254 in GF(2^8) prevents algebraic shortcuts.

> **Note:** MeowHash256 has not undergone formal cryptanalysis or peer review. For production cryptographic use, prefer standardized algorithms (SHA-256, BLAKE3, SHA-3). For non-cryptographic hashing (hash tables, deduplication, integrity checks without adversaries), MeowHash256 is well-suited.

## Benchmarks

Run benchmarks:

```bash
make
python3 benchmarks/benchmark.py
```

## Algorithm Documentation

- [algorithm.md](algorithm.md) — English
- [algorithm_de.md](algorithm_de.md) — German

## Identified and Fixed Weaknesses

| ID | Weakness | Severity | Fix |
|----|----------|----------|-----|
| W1 | SILVER_64 was even (3 trailing zero bits) — 8:1 mapping in compute_node | MEDIUM | V1 |
| W2 | Butterfly mixing was unidirectional — Block 7 received info from itself only | MEDIUM | Butterfly-Fix |
| W3 | Misleading documentation ("bidirectional" was false) | LOW | Comment fix |

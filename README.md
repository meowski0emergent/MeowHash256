# MeowHash256

> **Note:** The core algorithmic design of MeowHash256 (absorb-squeeze architecture, graph-inspired dual absorption, dual constant system) is original work. The implementation code (C and Python) was vibe coded.

## Overview

MeowHash256 is a 256-bit hash algorithm based on an absorb-squeeze sponge construction.

**Key Features:**
- Counter-based absorption (constant-time, no side-channel)
- AES-based squeeze with provable MDS diffusion (Branch Number 5)
- Butterfly cross-block mixing with ILP 4
- Nonlinear folding (non-invertible extraction)
- ARM AES Crypto Extensions + x86/generic fallback

## Project Structure

```
MeowHash256/
├── README.md                # This file
├── LICENSE.md               # GNU GPL v3.0
├── algorithm.md             # Full specification (English)
├── algorithm_de.md          # Full specification (German)
├── Makefile                 # Build system
├── c/                       # C implementation
│   ├── meow_hash_v6.h       # Public header
│   ├── meow_hash_v6.c       # Core implementation
│   └── main.c               # CLI tool
├── python/                  # Python implementations
│   ├── __init__.py
│   ├── meowhash256.py       # Pure Python
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
meowhash256((const uint8_t *)"Hello", 5, hash);

char hex[65];
meowhash256_hex((const uint8_t *)"Hello", 5, hex);
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
|---|---|---|
| Constants | 21 | Verify MAGIC_128, MAGIC_64, AES S-Box |
| Determinism | 6 | Same input → same output |
| Output Size | 18 | Always 32 bytes |
| Uniqueness | 1 | Different inputs → different hashes |
| Avalanche | 1 | Single bit flip → ~50% output change |
| C/Python Consistency | 21 | Both implementations match |
| Reference Values | 3 | Canonical test vectors |
| **Total** | **79** | |

## Reference Values

| Input | MeowHash256 (hex) |
|---|---|
| `""` (empty) | `0327d2a5b61959ed3f80901e24a29a7da0a9c5b57a7c4fde8d0620f986923978` |
| `"MeowHash"` | `2c9e16c3e938585960244fcf139794668f1ca8f874c674d59ddc8a4b468d44e4` |
| `"a" × 1,000,000` | `f499d98544d72c3a2580b60372200ec816d609b8c9fc23d9191df9af3b482994` |

## Benchmarks

ARM Graviton (aarch64), 1 MB input:

| Algorithm | Output | Throughput | vs SHA-256 |
|---|---|---|---|
| xxHash128 | 128 bit | 29,059 MB/s | 15.98× |
| **MeowHash256 (C)** | **256 bit** | **3,337 MB/s** | **1.83×** |
| SHA-256 | 256 bit | 1,819 MB/s | 1.00× |
| BLAKE2b-256 | 256 bit | 867 MB/s | 0.48× |

Run benchmarks:

```bash
make
python benchmarks/benchmark.py
```

## Security Properties

| Property | Value |
|---|---|
| Output length | 256 bits |
| Collision resistance | 2^128 (birthday bound) |
| Preimage resistance | 2^220 – 2^256 |
| Length extension | Resistant |
| Side-channel | Constant-time |
| Diffusion | AES MDS (Branch Number 5) |

> **Note:** MeowHash256 has not undergone formal cryptanalysis. For production cryptographic use, prefer standardized algorithms (SHA-256, BLAKE3, SHA-3).

## Algorithm Documentation

- [algorithm.md](algorithm.md) — English
- [algorithm_de.md](algorithm_de.md) — German


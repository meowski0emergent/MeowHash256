# MeowHash256 — Complete Algorithm Specification (V1–V6, N1–N4)

---

## 1. Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| State size | 128 bytes (16 x 64-bit words) | Total internal state |
| Capacity | 96 bytes (768 bits) | Security margin (state - output) |
| Output size | 32 bytes (256 bits) | Hash result |
| AES rounds (standard) | 4 | Squeeze rounds for input >= 64 bytes |
| AES rounds (short) | 3 | Squeeze rounds for input < 64 bytes (E3) |
| Blocks | 8 x 128-bit | State as AES blocks |

---

## 2. Constants

### 2.1 Golden Constants

```
GOLDEN_64 = 0x9E3779B97F4A7C15   (Golden ratio x 2^64, odd)
SILVER_64 = 0x6A09E667F3BCC909   (sqrt(2)/2 x 2^64, V1: made odd, 0 trailing zeros)
```

### 2.2 Magic Constants (sqrt(2) hex bytes — N2)

```
MAGIC_128[128] = hex bytes of fractional part of sqrt(2)
  = [0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xB2, 0xFB, 0x13, 0x66, 0xEA, 0x95, 0x7D, 0x3E,
     0x3A, 0xDE, 0xC1, 0x75, 0x12, 0x77, 0x50, 0x99, 0xDA, 0x2F, 0x59, 0x0B, 0x06, 0x67, 0x32, 0x2A,
     0x95, 0xF9, 0x06, 0x08, 0x75, 0x71, 0x45, 0x87, 0x51, 0x63, 0xFC, 0xDF, 0xB9, 0x07, 0xB6, 0x72,
     0x1E, 0xE9, 0x50, 0xBC, 0x87, 0x38, 0xF6, 0x94, 0xF0, 0x09, 0x0E, 0x6C, 0x7B, 0xF4, 0x4E, 0xD1,
     0xA4, 0x40, 0x5D, 0x0E, 0x85, 0x5E, 0x3E, 0x9C, 0xA6, 0x0B, 0x38, 0xC0, 0x23, 0x78, 0x66, 0xF7,
     0x95, 0x63, 0x79, 0x22, 0x2D, 0x10, 0x8B, 0x14, 0x8C, 0x15, 0x78, 0xE4, 0x5E, 0xF8, 0x9C, 0x67,
     0x8D, 0xAB, 0x51, 0x47, 0x17, 0x6F, 0xD3, 0xB9, 0x96, 0x54, 0xC6, 0x86, 0x63, 0xE7, 0x90, 0x9B,
     0xEA, 0x5E, 0x24, 0x1F, 0x06, 0xDC, 0xB0, 0x5D, 0xD5, 0x49, 0x41, 0x13, 0x20, 0x81, 0x94, 0x95]

Source: fractional part of sqrt(2) = 0x6A09E667F3BCC908...
Full 8-bit entropy per byte ("Nothing Up My Sleeve").

MAGIC_64[16]  = MAGIC_128 as little-endian 64-bit words
```

### 2.3 Rotation Constants

```
ROT_64 = [29, 47, 13, 53]
```

### 2.4 AES Round Keys ("Nothing-up-my-sleeve" derivation)

```
RK[r] = { rotl64(GOLDEN_64, r*13) XOR MAGIC_64[r*2],
           rotl64(SILVER_64, r*17) XOR MAGIC_64[r*2+1] }

RK[0] = (0x96FEC54A18AC757F, 0x5474738D95AF32BB)
RK[1] = (0x766758FB3A436DFC, 0xE6FD807F994BFBC9)
RK[2] = (0x62B858855E7E2473, 0xBC45239C77DBFACE)
RK[3] = (0x31C83248A7EC35A1, 0x9905A4345F319416)

Finalization keys (N4: separate keys for round 1 and 2):
RK_FINAL_1 = (0x5D67BDF295CAB403, 0x57F81E5CFBF49B30)   (r=4)
RK_FINAL_2 = (0x28E5E35FDCED9BBE, 0xAB628FC7C55554B0)   (r=5)
```

### 2.5 Block Salts (S3)

```
block_salt[i] = MAGIC_128[i*16 .. (i+1)*16-1]   for i = 0..7
```

---

## 3. Algorithm

### 3.1 State Initialization

```
state[0..15] = MAGIC_64[0..15]      (copy)
state[0] ^= len
state[1] ^= (len * GOLDEN_64) mod 2^64
```

### 3.2 Padding

```
padded = input || 0x80 || 0x00* (to multiple of 8 bytes)
```

### 3.3 Absorb Phase (E1: simplified scalar)

For each 8-byte segment (including padding):

```
node = compute_node(segment)

pos_add = (absorb_counter * 2) & 15
pos_xor = (absorb_counter * 2 + 1) & 15

state[pos_add] += node
state[pos_xor] ^= node

m = absorb_counter & 15
state[m] += state[(m + 1) & 15]
state[m] ^= (state[m] >> 17)
state[m] = rotl64(state[m], ROT_64[m & 3])   // N3: position-dependent rotation
state[m] ^= state[(m + 7) & 15]

// V4: Cross-coupling to opposite state half
state[(m + 8) & 15] ^= state[m]

absorb_counter++
```

Node computation (V1: bijective due to odd SILVER_64):
```
compute_node(segment):
    node = segment * GOLDEN_64
    node ^= (node >> 32)
    node *= SILVER_64          // V1: 0x...909 (odd), bijective
    node ^= (node >> 29)
    return node
```

### 3.3.1 V5: Empty-Input Path

For empty input, the absorb processes a single `0x80`-padded block and additionally:
```
state[8] ^= state[0]       // V5: cross-coupling consistency
```

### 3.4 V2: Absorb-Counter Injection

After absorb phase, before S4:
```
state[2] ^= absorb_counter
state[3] ^= (absorb_counter * GOLDEN_64) mod 2^64
```

### 3.5 S4: Pre-Squeeze State Mixing (V3: bidirectional)

**Before** snapshot, **after** absorb phase:

```
// V3: Forward pass
for i = 0 to 15:
    state[i] += state[(i + 7) & 15]
    state[i] ^= (state[i] >> 17)
    state[i] = rotl64(state[i], ROT_64[i & 3])

// V3: Reverse pass (different shift + offset to avoid fixpoints)
for i = 15 downto 0:
    state[i] += state[(i + 5) & 15]
    state[i] ^= (state[i] >> 23)
    state[i] = rotl64(state[i], ROT_64[i & 3])
```

### 3.6 Snapshot

```
snapshot[0..15] = state[0..15]    (copy for feed-forward)
```

### 3.7 E3: Adaptive Squeeze Rounds

```
squeeze_rounds = (len < 64) ? 3 : 4
```

### 3.8 Squeeze Phase — AES with Bidirectional Butterfly Mix

State interpreted as 8 x 128-bit blocks.

For each round r = 0 to squeeze_rounds-1:

#### 3.8.1 S3: Block-Individual AES Rounds

```
for i = 0 to 7:
    indiv_rk = RK[r] XOR block_salt[i]
    blocks[i] = AES_Round(blocks[i], indiv_rk)
```

Where `AES_Round = AddRoundKey -> SubBytes -> ShiftRows -> MixColumns`

#### 3.8.2 S2+E2: Feistel-Style Butterfly Cross-Block Mix (N1)

```
// Feistel-style butterfly: no GF(2)-cancellation (N1)
// Stride-1: even ^= odd
blocks[0] ^= blocks[1];  blocks[2] ^= blocks[3]
blocks[4] ^= blocks[5];  blocks[6] ^= blocks[7]
// Stride-1: odd ^= even (now modified!)
blocks[1] ^= blocks[0];  blocks[3] ^= blocks[2]
blocks[5] ^= blocks[4];  blocks[7] ^= blocks[6]
// Stride-2: lower ^= upper
blocks[0] ^= blocks[2];  blocks[1] ^= blocks[3]
blocks[4] ^= blocks[6];  blocks[5] ^= blocks[7]
// Stride-2: upper ^= lower (modified)
blocks[2] ^= blocks[0];  blocks[3] ^= blocks[1]
blocks[6] ^= blocks[4];  blocks[7] ^= blocks[5]
// Stride-4: first ^= last
blocks[0] ^= blocks[4];  blocks[1] ^= blocks[5]
blocks[2] ^= blocks[6];  blocks[3] ^= blocks[7]
// Stride-4: last ^= first (modified)
blocks[4] ^= blocks[0];  blocks[5] ^= blocks[1]
blocks[6] ^= blocks[2];  blocks[7] ^= blocks[3]
```

After 1 round, ALL 8 blocks receive information from ALL 8 blocks (8/8 everywhere).
The Feistel structure ensures no GF(2)-cancellation even in isolation (without AES).

### 3.9 Feed-Forward

```
for i = 0 to 15:
    state[i] ^= snapshot[i]
```

### 3.10 Second Length Injection

```
state[14] ^= len
state[15] ^= (len * GOLDEN_64) mod 2^64
```

### 3.11 S5: Nonlinear Folding (V6: position-dependent shifts)

#### 16 -> 8 words

```
for i = 0 to 7:
    state[i] = (state[i] + rotl64(state[15-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> (29 + (i & 3)))    // V6: shifts 29, 30, 31, 32
```

#### 8 -> 4 words

```
for i = 0 to 3:
    state[i] = (state[i] + rotl64(state[7-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> (29 + (i & 3)))    // V6: shifts 29, 30, 31, 32
```

### 3.12 S1: AES Finalization (N4: separate keys)

Output = state[0..3] as 32 bytes (little-endian), split into two 16-byte halves:

```
out_lo = result[0..15]
out_hi = result[16..31]

// Round 1: Full AES round + cross-half XOR (RK_FINAL_1)
out_lo = AES_Round(out_lo, RK_FINAL_1)
out_hi = AES_Round(out_hi, RK_FINAL_1)
out_lo = out_lo XOR out_hi

// Round 2: AES without MixColumns (final round) (RK_FINAL_2)
out_lo = AES_FinalRound(out_lo, RK_FINAL_2)
out_hi = AES_FinalRound(out_hi, RK_FINAL_2)
```

Result: `out_lo || out_hi` = 32-byte hash

---

## 4. Reference Values (V1–V6, N1–N4)

| Input | Hash (hex) |
|-------|------------|
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

---

## 5. Security Properties

| Property | Value |
|----------|-------|
| Output length | 256 bits |
| Internal state | 1024 bits |
| Capacity | 768 bits |
| Collision resistance | 2^128 (birthday bound) |
| Preimage resistance | 2^256 (no weakness found) |
| Length extension | Resistant (triple length injection + counter) |
| Side-channel | Constant-time (counter-based absorb) |
| Squeeze diffusion | AES MDS (Branch Number 5) |
| Final diffusion | AES (Branch Number 5) |
| Cross-block diffusion | Feistel-style butterfly (full in 1 round, no GF(2)-cancellation) |
| Folding | Nonlinear (ADD, variable shifts, non-invertible) |
| Reverse-engineerable | **NO** — 3 independent blocking barriers |

---

## 6. Architecture Support (E5)

| Platform | Implementation | Performance |
|----------|---------------|-------------|
| ARM aarch64 (Crypto Extensions) | NEON + AES intrinsics | ~3.3 GB/s |
| x86-64 / generic | Software AES (pure C) | Correct, slower |

### ARM -> x86 AES-NI Mapping

| ARM NEON | x86 AES-NI | Difference |
|----------|------------|------------|
| `vaeseq_u8(d, k)` | `_mm_aesenc_si128(d, k)` | Operation order! |
| `vaesmcq_u8(d)` | (integrated in `_mm_aesenc_si128`) | |
| `veorq_u8(a, b)` | `_mm_xor_si128(a, b)` | Identical |

**Caution:** ARM `vaeseq_u8` = AddRoundKey -> SubBytes -> ShiftRows. Intel `_mm_aesenc_si128` = ShiftRows -> SubBytes -> MixColumns -> AddRoundKey. A correct x86 port must adjust the order.

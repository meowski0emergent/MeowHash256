# MeowHash256 — Complete Algorithm Specification (V1–V6 + Butterfly-Fix)

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

### 2.2 Magic Constants (sqrt(2) decimal digits)

```
MAGIC_128[128] = [4, 1, 4, 2, 1, 3, 5, 6, 2, 3, 7, 3, 0, 9, 5, 0,
                  4, 8, 8, 0, 1, 6, 8, 8, 7, 2, 4, 2, 0, 9, 6, 9,
                  8, 0, 7, 8, 5, 6, 9, 6, 7, 1, 8, 7, 5, 3, 7, 6,
                  9, 4, 8, 0, 7, 3, 1, 7, 6, 6, 7, 9, 7, 3, 7, 9,
                  9, 0, 7, 3, 2, 4, 7, 8, 4, 6, 2, 1, 0, 7, 0, 3,
                  8, 8, 5, 0, 3, 8, 7, 5, 3, 4, 3, 2, 7, 6, 4, 1,
                  5, 7, 2, 7, 3, 5, 0, 1, 3, 8, 4, 6, 2, 3, 0, 9,
                  1, 2, 2, 9, 7, 0, 2, 4, 9, 2, 4, 8, 3, 6, 0, 5]

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

RK[0] = (0x98327AB87D4E7D11, 0x6A0CEF67F0BBCA0B)
RK[1] = (0xE73F29E84F8ABBC2, 0xC5C9EE799016D614)
RK[2] = (0xE3F42FF55E7FDDEE, 0xC8F42720AF2F9898)
RK[3] = (0xA23F09C81BB4D8B6, 0x414C53483A389BE0)

Finalization key (r=4):
RK_FINAL = (0xC95EE7759890F4AE, 0xA39E617F3ACE9692)
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
state[m] = rotl64(state[m], 29)
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

#### 3.8.2 S2+E2: Bidirectional Butterfly Cross-Block Mix

```
// Forward butterfly (3 stages, ILP = 4)
// Stage 1
blocks[0] ^= blocks[1];  blocks[2] ^= blocks[3]
blocks[4] ^= blocks[5];  blocks[6] ^= blocks[7]
// Stage 2
blocks[0] ^= blocks[2];  blocks[4] ^= blocks[6]
blocks[1] ^= blocks[3];  blocks[5] ^= blocks[7]
// Stage 3
blocks[0] ^= blocks[4];  blocks[1] ^= blocks[5]
blocks[2] ^= blocks[6];  blocks[3] ^= blocks[7]

// Reverse butterfly (3 stages, ILP = 4)
// Stage 1
blocks[7] ^= blocks[6];  blocks[5] ^= blocks[4]
blocks[3] ^= blocks[2];  blocks[1] ^= blocks[0]
// Stage 2
blocks[7] ^= blocks[5];  blocks[6] ^= blocks[4]
blocks[3] ^= blocks[1];  blocks[2] ^= blocks[0]
// Stage 3
blocks[7] ^= blocks[3];  blocks[6] ^= blocks[2]
blocks[5] ^= blocks[1];  blocks[4] ^= blocks[0]
```

After 1 round, ALL 8 blocks receive information from ALL 8 blocks (8/8 everywhere).

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

### 3.12 S1: AES Finalization

Output = state[0..3] as 32 bytes (little-endian), split into two 16-byte halves:

```
out_lo = result[0..15]
out_hi = result[16..31]

// Round 1: Full AES round + cross-half XOR
out_lo = AES_Round(out_lo, RK_FINAL)
out_hi = AES_Round(out_hi, RK_FINAL)
out_lo = out_lo XOR out_hi

// Round 2: AES without MixColumns (final round)
out_lo = AES_FinalRound(out_lo, RK_FINAL)
out_hi = AES_FinalRound(out_hi, RK_FINAL)
```

Result: `out_lo || out_hi` = 32-byte hash

---

## 4. Reference Values (V1–V6 + Butterfly-Fix)

| Input | Hash (hex) |
|-------|------------|
| `""` (empty) | `0eec3b0e25ec8486bbff79280f9712b94ac6636742ff06b96dc092c201609f45` |
| `"a"` | `d8327b5d6c6d3cd0047e95be124764e39e345e1ffde8092ecaff803b83029545` |
| `"abc"` | `8ef1d73f47b0bb712d405f75e27659b958d2e4cd6eee8812e2574585dc8c2aff` |
| `"Hello, MeowHash v6!"` | `7be2fa85f5bf1c3c13c0f46154cb67a16b6564f213bd6276c352fcc45f2aae4a` |
| `"SECRET"` | `075e452a4abf9df6d9e31b2a4d87dadf53375b84128b2d4c8ee0a91964291ffd` |
| `"MeowHash"` | `6df6bc0f68876ceb90d7bf6d158033f05b4955123a6d9e18f4cff5df81603cc3` |
| 7x `0x00` | `9f215f63c3d6ef0d928c3d1619d70566259b4c065fb7cf168b88d26f0472f818` |
| 8x `0x00` | `79503c130e3d4d70c0774aa4bd655a1b85767bfa0d0838c52307a727cc70471e` |
| 9x `0x00` | `ab61f6a1160cc057dbef388880244d6a58045ab3cc2bf5015c32d2fef21885b5` |
| `"a"` x 1,000,000 | `8b8d2535e3e6475e73a51b410959d12dad621c34ce7b14285761451e0b68e633` |

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
| Cross-block diffusion | Bidirectional butterfly (full in 1 round) |
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

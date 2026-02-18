# MeowHash256 — Complete Algorithm Specification

---

## 1. Parameters

| Parameter | Value | Description |
|---|---|---|
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
SILVER_64 = 0x6A09E667F3BCC908   (sqrt(2)/2 x 2^64)
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

RK[0] = (0x98327AB87D4E7D11, 0x6A0CEF67F0BBCA0A)
RK[1] = (0xE73F29E84F8ABBC2, 0xC5C9EE799014D614)
RK[2] = (0xE3F42FF55E7FDDEE, 0xC8F42724AF2F9898)
RK[3] = (0xA23F09C81BB4D8B6, 0x414453483A389BE0)

Finalization key (r=4):
RK_FINAL = (0xC95EE7759890F4AE, 0xA39E617F3ACE9682)
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

absorb_counter++
```

Node computation:
```
compute_node(segment):
    node = segment * GOLDEN_64
    node ^= (node >> 32)
    node *= SILVER_64
    node ^= (node >> 29)
    return node
```

### 3.4 S4: Pre-Squeeze State Mixing

**Before** snapshot, **after** absorb phase:

```
for i = 0 to 15:
    state[i] += state[(i + 7) & 15]
    state[i] ^= (state[i] >> 17)
    state[i] = rotl64(state[i], ROT_64[i & 3])
```

### 3.5 Snapshot

```
snapshot[0..15] = state[0..15]    (copy for feed-forward)
```

### 3.6 E3: Adaptive Squeeze Rounds

```
squeeze_rounds = (len < 64) ? 3 : 4
```

### 3.7 Squeeze Phase — AES with Butterfly Mix

State interpreted as 8 x 128-bit blocks.

For each round r = 0 to squeeze_rounds-1:

#### 3.7.1 S3: Block-Individual AES Rounds

```
for i = 0 to 7:
    indiv_rk = RK[r] XOR block_salt[i]
    blocks[i] = AES_Round(blocks[i], indiv_rk)
```

Where `AES_Round = AddRoundKey -> SubBytes -> ShiftRows -> MixColumns`

#### 3.7.2 S2+E2: Butterfly Cross-Block Mix

```
// Stage 1: 4 independent pairs (ILP = 4)
blocks[0] ^= blocks[1];  blocks[2] ^= blocks[3]
blocks[4] ^= blocks[5];  blocks[6] ^= blocks[7]

// Stage 2: 4 independent pairs (ILP = 4)
blocks[0] ^= blocks[2];  blocks[4] ^= blocks[6]
blocks[1] ^= blocks[3];  blocks[5] ^= blocks[7]

// Stage 3: 4 independent pairs (ILP = 4)
blocks[0] ^= blocks[4];  blocks[1] ^= blocks[5]
blocks[2] ^= blocks[6];  blocks[3] ^= blocks[7]
```

### 3.8 Feed-Forward

```
for i = 0 to 15:
    state[i] ^= snapshot[i]
```

### 3.9 Second Length Injection

```
state[14] ^= len
state[15] ^= (len * GOLDEN_64) mod 2^64
```

### 3.10 S5: Nonlinear Folding

#### 16 -> 8 words

```
for i = 0 to 7:
    state[i] = (state[i] + rotl64(state[15-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> 29)
```

#### 8 -> 4 words

```
for i = 0 to 3:
    state[i] = (state[i] + rotl64(state[7-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> 29)
```

### 3.11 S1: AES Finalization

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

## 4. Reference Values

| Input | Hash (hex) |
|---|---|
| `""` (empty) | `0327d2a5b61959ed3f80901e24a29a7da0a9c5b57a7c4fde8d0620f986923978` |
| `"MeowHash"` | `2c9e16c3e938585960244fcf139794668f1ca8f874c674d59ddc8a4b468d44e4` |
| `"a" x 1,000,000` | `f499d98544d72c3a2580b60372200ec816d609b8c9fc23d9191df9af3b482994` |

---

## 5. Architecture Support (E5)

| Platform | Implementation | Performance |
|---|---|---|
| ARM aarch64 (Crypto Extensions) | NEON + AES intrinsics | ~3.3 GB/s |
| x86-64 / generic | Software AES (pure C) | Correct, slower |

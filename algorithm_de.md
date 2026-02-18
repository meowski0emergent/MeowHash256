# MeowHash256 — Vollständige Algorithmusspezifikation

---

## 1. Parameter

| Parameter | Wert | Beschreibung |
|---|---|---|
| State-Größe | 128 Bytes (16 x 64-Bit-Wörter) | Gesamter interner Zustand |
| Kapazität | 96 Bytes (768 Bits) | Sicherheitsmarge (State - Output) |
| Output-Größe | 32 Bytes (256 Bits) | Hash-Ergebnis |
| AES-Runden (Standard) | 4 | Squeeze-Runden für Eingabe >= 64 Bytes |
| AES-Runden (kurz) | 3 | Squeeze-Runden für Eingabe < 64 Bytes (E3) |
| Blöcke | 8 x 128-Bit | State als AES-Blöcke |

---

## 2. Konstanten

### 2.1 Goldene Konstanten

```
GOLDEN_64 = 0x9E3779B97F4A7C15   (Goldener Schnitt x 2^64, ungerade)
SILVER_64 = 0x6A09E667F3BCC908   (sqrt(2)/2 x 2^64)
```

### 2.2 Magische Konstanten (sqrt(2) Dezimalstellen)

```
MAGIC_128[128] = [4, 1, 4, 2, 1, 3, 5, 6, 2, 3, 7, 3, 0, 9, 5, 0,
                  4, 8, 8, 0, 1, 6, 8, 8, 7, 2, 4, 2, 0, 9, 6, 9,
                  8, 0, 7, 8, 5, 6, 9, 6, 7, 1, 8, 7, 5, 3, 7, 6,
                  9, 4, 8, 0, 7, 3, 1, 7, 6, 6, 7, 9, 7, 3, 7, 9,
                  9, 0, 7, 3, 2, 4, 7, 8, 4, 6, 2, 1, 0, 7, 0, 3,
                  8, 8, 5, 0, 3, 8, 7, 5, 3, 4, 3, 2, 7, 6, 4, 1,
                  5, 7, 2, 7, 3, 5, 0, 1, 3, 8, 4, 6, 2, 3, 0, 9,
                  1, 2, 2, 9, 7, 0, 2, 4, 9, 2, 4, 8, 3, 6, 0, 5]

MAGIC_64[16]  = MAGIC_128 als Little-Endian 64-Bit-Wörter
```

### 2.3 Rotationskonstanten

```
ROT_64 = [29, 47, 13, 53]
```

### 2.4 AES-Rundenschlüssel ("Nothing-up-my-sleeve")

```
Ableitung:
  RK[r] = { rotl64(GOLDEN_64, r*13) XOR MAGIC_64[r*2],
             rotl64(SILVER_64, r*17) XOR MAGIC_64[r*2+1] }

RK[0] = (0x98327AB87D4E7D11, 0x6A0CEF67F0BBCA0A)
RK[1] = (0xE73F29E84F8ABBC2, 0xC5C9EE799014D614)
RK[2] = (0xE3F42FF55E7FDDEE, 0xC8F42724AF2F9898)
RK[3] = (0xA23F09C81BB4D8B6, 0x414453483A389BE0)

Finalisierungsschlüssel (r=4):
RK_FINAL = (0xC95EE7759890F4AE, 0xA39E617F3ACE9682)
```

### 2.5 Block-Salts (S3)

```
block_salt[i] = MAGIC_128[i*16 .. (i+1)*16-1]   für i = 0..7
```

---

## 3. Algorithmus

### 3.1 State-Initialisierung

```
state[0..15] = MAGIC_64[0..15]      (Kopie)
state[0] ^= len
state[1] ^= (len * GOLDEN_64) mod 2^64
```

### 3.2 Padding

```
padding = input || 0x80 || 0x00* (bis Vielfaches von 8 Bytes)
```

### 3.3 Absorb-Phase (E1: vereinfacht, skalar)

Für jedes 8-Byte-Segment `segment` (inkl. Padding):

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

Knotenberechnung:
```
compute_node(segment):
    node = segment * GOLDEN_64
    node ^= (node >> 32)
    node *= SILVER_64
    node ^= (node >> 29)
    return node
```

### 3.4 S4: Pre-Squeeze State Mixing

**Vor** dem Snapshot, **nach** der Absorb-Phase:

```
for i = 0 to 15:
    state[i] += state[(i + 7) & 15]
    state[i] ^= (state[i] >> 17)
    state[i] = rotl64(state[i], ROT_64[i & 3])
```

Zweck: Vollständige State-Durchmischung unabhängig von der Eingabelänge. Bei kurzen Eingaben (1-7 Bytes) werden sonst nur 12.5% des State direkt berührt.

### 3.5 Snapshot

```
snapshot[0..15] = state[0..15]    (Kopie für Feed-Forward)
```

### 3.6 E3: Adaptive Squeeze-Runden

```
squeeze_rounds = (len < 64) ? 3 : 4
```

### 3.7 Squeeze-Phase — AES mit Butterfly-Mix

State wird als 8 x 128-Bit-Blöcke interpretiert.

Für jede Runde r = 0 bis squeeze_rounds-1:

#### 3.7.1 S3: Block-individuelle AES-Runden

```
for i = 0 to 7:
    indiv_rk = RK[r] XOR block_salt[i]
    blocks[i] = AES_Round(blocks[i], indiv_rk)
```

Wobei `AES_Round = AddRoundKey -> SubBytes -> ShiftRows -> MixColumns`

#### 3.7.2 S2+E2: Butterfly Cross-Block Mix

```
// Stufe 1: 4 unabhängige Paare (ILP = 4)
blocks[0] ^= blocks[1]
blocks[2] ^= blocks[3]
blocks[4] ^= blocks[5]
blocks[6] ^= blocks[7]

// Stufe 2: 4 unabhängige Paare (ILP = 4)
blocks[0] ^= blocks[2]
blocks[4] ^= blocks[6]
blocks[1] ^= blocks[3]
blocks[5] ^= blocks[7]

// Stufe 3: 4 unabhängige Paare (ILP = 4)
blocks[0] ^= blocks[4]
blocks[1] ^= blocks[5]
blocks[2] ^= blocks[6]
blocks[3] ^= blocks[7]
```

Eigenschaften:
- 12 XOR-Operationen pro Runde (statt 8 sequenzielle)
- ILP = 4 (statt 0 bei sequenzieller Kette)
- Latenz: 3 Zyklen statt 8 (auf 4-wide NEON-Pipeline)
- Bidirektionale Diffusion: Block 0 enthält nach 1 Runde Info von allen 8 Blöcken

### 3.8 Feed-Forward

```
for i = 0 to 15:
    state[i] ^= snapshot[i]
```

### 3.9 Zweite Längeninjektion

```
state[14] ^= len
state[15] ^= (len * GOLDEN_64) mod 2^64
```

### 3.10 S5: Nichtlineare Faltung

#### 16 -> 8 Wörter

```
for i = 0 to 7:
    state[i] = (state[i] + rotl64(state[15-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> 29)
```

#### 8 -> 4 Wörter

```
for i = 0 to 3:
    state[i] = (state[i] + rotl64(state[7-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> 29)
```

Die Addition (statt nur XOR) macht die Faltung nichtlinear und nicht trivial invertierbar.

### 3.11 S1: AES-Finalisierung

Output = state[0..3] als 32 Bytes (Little-Endian). Aufgeteilt in zwei 16-Byte-Hälften:

```
out_lo = result[0..15]
out_hi = result[16..31]

// Runde 1: Volle AES-Runde + Cross-Half-XOR
out_lo = AES_Round(out_lo, RK_FINAL)     // AddRoundKey+SubBytes+ShiftRows+MixColumns
out_hi = AES_Round(out_hi, RK_FINAL)
out_lo = out_lo XOR out_hi               // Inter-Half-Diffusion

// Runde 2: AES ohne MixColumns (Finalrunde)
out_lo = AES_FinalRound(out_lo, RK_FINAL)  // AddRoundKey+SubBytes+ShiftRows
out_hi = AES_FinalRound(out_hi, RK_FINAL)
```

Ergebnis: `out_lo || out_hi` = 32-Byte-Hash

Branch Number steigt von 1 (einzelne S-Box) auf 5 (volle AES-Runde mit MDS-MixColumns).

---

## 4. Sicherheitseigenschaften

| Eigenschaft | Wert |
|---|---|
| Ausgabelänge | 256 Bit |
| Kollisionsresistenz | 2^128 (Birthday-Bound) |
| Preimage-Resistenz (geschätzt) | 2^220 - 2^256 |
| Längen-Erweiterungsresistenz | Ja |
| Seitenkanal-Resistenz | Konstante Zeit (zählerbasiert) |
| Squeeze-Diffusion | AES MDS (Branch Number 5) |
| Finale Diffusion | AES (Branch Number 5) |
| Cross-Block-Diffusion | Butterfly (voll in O(log n)) |
| Faltung | Nichtlinear (ADD, nicht invertierbar) |

---

## 5. Testvektoren

| Eingabe | Hash (hex) |
|---|---|
| `""` (leer) | `0327d2a5b61959ed3f80901e24a29a7da0a9c5b57a7c4fde8d0620f986923978` |
| `"MeowHash"` | `2c9e16c3e938585960244fcf139794668f1ca8f874c674d59ddc8a4b468d44e4` |
| `"a" x 1.000.000` | `f499d98544d72c3a2580b60372200ec816d609b8c9fc23d9191df9af3b482994` |

---

## 6. Architektur-Unterstützung (E5)

| Plattform | Implementierung | Performance |
|---|---|---|
| ARM aarch64 (mit Crypto Extensions) | NEON + AES intrinsics | ~3.3 GB/s |
| x86-64 / generic | Software AES (pure C) | Korrekt, langsamer |

### ARM -> x86 AES-NI Mapping

| ARM NEON | x86 AES-NI | Unterschied |
|---|---|---|
| `vaeseq_u8(d, k)` | `_mm_aesenc_si128(d, k)` | Operationsreihenfolge! |
| `vaesmcq_u8(d)` | (in `_mm_aesenc_si128` integriert) | |
| `veorq_u8(a, b)` | `_mm_xor_si128(a, b)` | Identisch |

**Achtung:** ARM `vaeseq_u8` = AddRoundKey -> SubBytes -> ShiftRows. Intel `_mm_aesenc_si128` = ShiftRows -> SubBytes -> MixColumns -> AddRoundKey. Eine korrekte x86-Portierung muss die Reihenfolge anpassen.

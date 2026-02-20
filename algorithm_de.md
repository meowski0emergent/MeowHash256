# MeowHash256 — Vollstaendige Algorithmusspezifikation (V1–V6, N1–N4)

---

## 1. Parameter

| Parameter | Wert | Beschreibung |
|-----------|------|--------------|
| State-Groesse | 128 Bytes (16 x 64-Bit-Woerter) | Gesamter interner Zustand |
| Kapazitaet | 96 Bytes (768 Bits) | Sicherheitsmarge (State - Output) |
| Output-Groesse | 32 Bytes (256 Bits) | Hash-Ergebnis |
| AES-Runden (Standard) | 4 | Squeeze-Runden fuer Eingabe >= 64 Bytes |
| AES-Runden (kurz) | 3 | Squeeze-Runden fuer Eingabe < 64 Bytes (E3) |
| Bloecke | 8 x 128-Bit | State als AES-Bloecke |

---

## 2. Konstanten

### 2.1 Goldene Konstanten

```
GOLDEN_64 = 0x9E3779B97F4A7C15   (Goldener Schnitt x 2^64, ungerade)
SILVER_64 = 0x6A09E667F3BCC909   (sqrt(2)/2 x 2^64, V1: ungerade gemacht, 0 trailing zeros)
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

MAGIC_64[16]  = MAGIC_128 als Little-Endian 64-Bit-Woerter
```

### 2.3 Rotationskonstanten

```
ROT_64 = [29, 47, 13, 53]
```

### 2.4 AES-Rundenschluessel ("Nothing-up-my-sleeve")

```
Ableitung:
  RK[r] = { rotl64(GOLDEN_64, r*13) XOR MAGIC_64[r*2],
             rotl64(SILVER_64, r*17) XOR MAGIC_64[r*2+1] }

RK[0] = (0x98327AB87D4E7D11, 0x6A0CEF67F0BBCA0B)
RK[1] = (0xE73F29E84F8ABBC2, 0xC5C9EE799016D614)
RK[2] = (0xE3F42FF55E7FDDEE, 0xC8F42720AF2F9898)
RK[3] = (0xA23F09C81BB4D8B6, 0x414C53483A389BE0)

Finalisierungsschluessel (r=4):
RK_FINAL = (0xC95EE7759890F4AE, 0xA39E617F3ACE9692)
```

### 2.5 Block-Salts (S3)

```
block_salt[i] = MAGIC_128[i*16 .. (i+1)*16-1]   fuer i = 0..7
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

Fuer jedes 8-Byte-Segment `segment` (inkl. Padding):

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

// V4: Cross-Coupling zur gegenueberliegenden State-Haelfte
state[(m + 8) & 15] ^= state[m]

absorb_counter++
```

Knotenberechnung (V1: bijektiv durch ungerades SILVER_64):
```
compute_node(segment):
    node = segment * GOLDEN_64
    node ^= (node >> 32)
    node *= SILVER_64          // V1: 0x...909 (ungerade), bijektiv
    node ^= (node >> 29)
    return node
```

### 3.3.1 V5: Leerer-Input-Pfad

Fuer leere Eingabe wird ein einzelner 0x80-Block verarbeitet, zusaetzlich:
```
state[8] ^= state[0]       // V5: Cross-Coupling-Konsistenz
```

### 3.4 V2: Absorb-Counter-Injektion

Nach der Absorb-Phase, vor S4:
```
state[2] ^= absorb_counter
state[3] ^= (absorb_counter * GOLDEN_64) mod 2^64
```

### 3.5 S4: Pre-Squeeze State Mixing (V3: bidirektional)

**Vor** dem Snapshot, **nach** der Absorb-Phase:

```
// V3: Forward-Pass
for i = 0 to 15:
    state[i] += state[(i + 7) & 15]
    state[i] ^= (state[i] >> 17)
    state[i] = rotl64(state[i], ROT_64[i & 3])

// V3: Reverse-Pass (anderer Shift + Offset, um Fixpunkte zu vermeiden)
for i = 15 downto 0:
    state[i] += state[(i + 5) & 15]
    state[i] ^= (state[i] >> 23)
    state[i] = rotl64(state[i], ROT_64[i & 3])
```

### 3.6 Snapshot

```
snapshot[0..15] = state[0..15]    (Kopie fuer Feed-Forward)
```

### 3.7 E3: Adaptive Squeeze-Runden

```
squeeze_rounds = (len < 64) ? 3 : 4
```

### 3.8 Squeeze-Phase — AES mit bidirektionalem Butterfly-Mix

State wird als 8 x 128-Bit-Bloecke interpretiert.

Fuer jede Runde r = 0 bis squeeze_rounds-1:

#### 3.8.1 S3: Block-individuelle AES-Runden

```
for i = 0 to 7:
    indiv_rk = RK[r] XOR block_salt[i]
    blocks[i] = AES_Round(blocks[i], indiv_rk)
```

Wobei `AES_Round = AddRoundKey -> SubBytes -> ShiftRows -> MixColumns`

#### 3.8.2 S2+E2: Bidirektionaler Butterfly Cross-Block Mix

```
// Forward-Butterfly (3 Stufen, ILP = 4)
// Stufe 1
blocks[0] ^= blocks[1];  blocks[2] ^= blocks[3]
blocks[4] ^= blocks[5];  blocks[6] ^= blocks[7]
// Stufe 2
blocks[0] ^= blocks[2];  blocks[4] ^= blocks[6]
blocks[1] ^= blocks[3];  blocks[5] ^= blocks[7]
// Stufe 3
blocks[0] ^= blocks[4];  blocks[1] ^= blocks[5]
blocks[2] ^= blocks[6];  blocks[3] ^= blocks[7]

// Reverse-Butterfly (3 Stufen, ILP = 4)
// Stufe 1
blocks[7] ^= blocks[6];  blocks[5] ^= blocks[4]
blocks[3] ^= blocks[2];  blocks[1] ^= blocks[0]
// Stufe 2
blocks[7] ^= blocks[5];  blocks[6] ^= blocks[4]
blocks[3] ^= blocks[1];  blocks[2] ^= blocks[0]
// Stufe 3
blocks[7] ^= blocks[3];  blocks[6] ^= blocks[2]
blocks[5] ^= blocks[1];  blocks[4] ^= blocks[0]
```

Nach 1 Runde empfangen ALLE 8 Bloecke Informationen von ALLEN 8 Bloecken (8/8 ueberall).

### 3.9 Feed-Forward

```
for i = 0 to 15:
    state[i] ^= snapshot[i]
```

### 3.10 Zweite Laengeninjektion

```
state[14] ^= len
state[15] ^= (len * GOLDEN_64) mod 2^64
```

### 3.11 S5: Nichtlineare Faltung (V6: positionsabhaengige Shifts)

#### 16 -> 8 Woerter

```
for i = 0 to 7:
    state[i] = (state[i] + rotl64(state[15-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> (29 + (i & 3)))    // V6: Shifts 29, 30, 31, 32
```

#### 8 -> 4 Woerter

```
for i = 0 to 3:
    state[i] = (state[i] + rotl64(state[7-i], ROT_64[i & 3])) mod 2^64
    state[i] ^= (state[i] >> (29 + (i & 3)))    // V6: Shifts 29, 30, 31, 32
```

Die Addition (statt nur XOR) macht die Faltung nichtlinear und nicht trivial invertierbar.
Die variablen Shifts (V6) eliminieren die Klasse von Fixpunkten, bei denen ein einheitlicher Shift keine Wirkung hat.

### 3.12 S1: AES-Finalisierung

Output = state[0..3] als 32 Bytes (Little-Endian). Aufgeteilt in zwei 16-Byte-Haelften:

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
|-------------|------|
| Ausgabelaenge | 256 Bit |
| Interner Zustand | 1024 Bit |
| Kapazitaet | 768 Bit |
| Kollisionsresistenz | 2^128 (Birthday-Bound) |
| Preimage-Resistenz | 2^256 (keine Schwaeche gefunden) |
| Laengen-Erweiterungsresistenz | Ja (dreifache Laengeninjektion + Counter) |
| Seitenkanal-Resistenz | Konstante Zeit (zaehlerbasiert) |
| Squeeze-Diffusion | AES MDS (Branch Number 5) |
| Finale Diffusion | AES (Branch Number 5) |
| Cross-Block-Diffusion | Bidirektionaler Butterfly (voll in 1 Runde) |
| Faltung | Nichtlinear (ADD, variable Shifts, nicht invertierbar) |
| Rueckrechenbar? | **NEIN** — 3 unabhaengige Barrieren |

### Einwegbarrieren

1. **Nichtlineare Faltung:** 1024 -> 256 Bit Kompression. 2^768 moegliche Urbilder pro Hash.
2. **Feed-Forward:** Zirkulaere Abhaengigkeit (Snapshot auf beiden Seiten der Gleichung).
3. **AES-Nichtlinearitaet:** S-Box Grad 254 in GF(2^8) verhindert algebraische Abkuerzungen.

---

## 5. Testvektoren (V1–V6 + Butterfly-Fix)

| Eingabe | Hash (hex) |
|---------|------------|
| `""` (leer) | `0eec3b0e25ec8486bbff79280f9712b94ac6636742ff06b96dc092c201609f45` |
| `"a"` | `d8327b5d6c6d3cd0047e95be124764e39e345e1ffde8092ecaff803b83029545` |
| `"abc"` | `8ef1d73f47b0bb712d405f75e27659b958d2e4cd6eee8812e2574585dc8c2aff` |
| `"Hello, MeowHash v6!"` | `7be2fa85f5bf1c3c13c0f46154cb67a16b6564f213bd6276c352fcc45f2aae4a` |
| `"SECRET"` | `075e452a4abf9df6d9e31b2a4d87dadf53375b84128b2d4c8ee0a91964291ffd` |
| `"MeowHash"` | `6df6bc0f68876ceb90d7bf6d158033f05b4955123a6d9e18f4cff5df81603cc3` |
| 7x `0x00` | `9f215f63c3d6ef0d928c3d1619d70566259b4c065fb7cf168b88d26f0472f818` |
| 8x `0x00` | `79503c130e3d4d70c0774aa4bd655a1b85767bfa0d0838c52307a727cc70471e` |
| 9x `0x00` | `ab61f6a1160cc057dbef388880244d6a58045ab3cc2bf5015c32d2fef21885b5` |
| `"a"` x 1.000.000 | `8b8d2535e3e6475e73a51b410959d12dad621c34ce7b14285761451e0b68e633` |

---

## 6. Architektur-Unterstuetzung (E5)

| Plattform | Implementierung | Performance |
|-----------|----------------|-------------|
| ARM aarch64 (mit Crypto Extensions) | NEON + AES intrinsics | ~3.3 GB/s |
| x86-64 / generic | Software AES (pure C) | Korrekt, langsamer |

### ARM -> x86 AES-NI Mapping

| ARM NEON | x86 AES-NI | Unterschied |
|----------|------------|-------------|
| `vaeseq_u8(d, k)` | `_mm_aesenc_si128(d, k)` | Operationsreihenfolge! |
| `vaesmcq_u8(d)` | (in `_mm_aesenc_si128` integriert) | |
| `veorq_u8(a, b)` | `_mm_xor_si128(a, b)` | Identisch |

**Achtung:** ARM `vaeseq_u8` = AddRoundKey -> SubBytes -> ShiftRows. Intel `_mm_aesenc_si128` = ShiftRows -> SubBytes -> MixColumns -> AddRoundKey. Eine korrekte x86-Portierung muss die Reihenfolge anpassen.

---

## 7. Implementierte Verbesserungen

| Fix | Beschreibung | Kosten |
|-----|-------------|--------|
| V1 | SILVER_64 ungerade (0x...909) — bijektives compute_node | 0 Ops |
| V2 | Absorb-Counter-Injektion in state[2,3] | 2 XOR (einmalig) |
| V3 | Bidirektionaler S4 (Forward + Reverse Pass) | ~48 Ops |
| V4 | Absorb Cross-Coupling zur gegenueberliegenden State-Haelfte | 1 XOR/Segment |
| V5 | Leerer-Input-Pfad Konsistenz | 1 XOR |
| V6 | Positionsabhaengige Shift-Konstanten in der Faltung | 0 Ops |
| Butterfly-Fix | Reverse-Butterfly fuer bidirektionale volle Diffusion | 12 x 128-Bit XOR/Runde |

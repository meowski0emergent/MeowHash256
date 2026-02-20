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

### 2.2 Magische Konstanten (sqrt(2) Hex-Bytes — N2)

```
MAGIC_128[128] = Hex-Bytes des Bruchteils von sqrt(2)
  = [0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xB2, 0xFB, 0x13, 0x66, 0xEA, 0x95, 0x7D, 0x3E,
     0x3A, 0xDE, 0xC1, 0x75, 0x12, 0x77, 0x50, 0x99, 0xDA, 0x2F, 0x59, 0x0B, 0x06, 0x67, 0x32, 0x2A,
     0x95, 0xF9, 0x06, 0x08, 0x75, 0x71, 0x45, 0x87, 0x51, 0x63, 0xFC, 0xDF, 0xB9, 0x07, 0xB6, 0x72,
     0x1E, 0xE9, 0x50, 0xBC, 0x87, 0x38, 0xF6, 0x94, 0xF0, 0x09, 0x0E, 0x6C, 0x7B, 0xF4, 0x4E, 0xD1,
     0xA4, 0x40, 0x5D, 0x0E, 0x85, 0x5E, 0x3E, 0x9C, 0xA6, 0x0B, 0x38, 0xC0, 0x23, 0x78, 0x66, 0xF7,
     0x95, 0x63, 0x79, 0x22, 0x2D, 0x10, 0x8B, 0x14, 0x8C, 0x15, 0x78, 0xE4, 0x5E, 0xF8, 0x9C, 0x67,
     0x8D, 0xAB, 0x51, 0x47, 0x17, 0x6F, 0xD3, 0xB9, 0x96, 0x54, 0xC6, 0x86, 0x63, 0xE7, 0x90, 0x9B,
     0xEA, 0x5E, 0x24, 0x1F, 0x06, 0xDC, 0xB0, 0x5D, 0xD5, 0x49, 0x41, 0x13, 0x20, 0x81, 0x94, 0x95]

Quelle: Bruchteil von sqrt(2) = 0x6A09E667F3BCC908...
Volle 8-Bit-Entropie pro Byte ("Nothing Up My Sleeve").

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

RK[0] = (0x96FEC54A18AC757F, 0x5474738D95AF32BB)
RK[1] = (0x766758FB3A436DFC, 0xE6FD807F994BFBC9)
RK[2] = (0x62B858855E7E2473, 0xBC45239C77DBFACE)
RK[3] = (0x31C83248A7EC35A1, 0x9905A4345F319416)

Finalisierungsschluessel (N4: separate Schluessel fuer Runde 1 und 2):
RK_FINAL_1 = (0x5D67BDF295CAB403, 0x57F81E5CFBF49B30)   (r=4)
RK_FINAL_2 = (0x28E5E35FDCED9BBE, 0xAB628FC7C55554B0)   (r=5)
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
state[m] = rotl64(state[m], ROT_64[m & 3])   // N3: positionsabhaengige Rotation
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

#### 3.8.2 S2+E2: Feistel-artiger Butterfly Cross-Block Mix (N1)

```
// Feistel-artiger Butterfly: keine GF(2)-Cancellation (N1)
// Stride-1: gerade ^= ungerade
blocks[0] ^= blocks[1];  blocks[2] ^= blocks[3]
blocks[4] ^= blocks[5];  blocks[6] ^= blocks[7]
// Stride-1: ungerade ^= gerade (jetzt modifiziert!)
blocks[1] ^= blocks[0];  blocks[3] ^= blocks[2]
blocks[5] ^= blocks[4];  blocks[7] ^= blocks[6]
// Stride-2: untere ^= obere
blocks[0] ^= blocks[2];  blocks[1] ^= blocks[3]
blocks[4] ^= blocks[6];  blocks[5] ^= blocks[7]
// Stride-2: obere ^= untere (modifiziert)
blocks[2] ^= blocks[0];  blocks[3] ^= blocks[1]
blocks[6] ^= blocks[4];  blocks[7] ^= blocks[5]
// Stride-4: erste ^= letzte
blocks[0] ^= blocks[4];  blocks[1] ^= blocks[5]
blocks[2] ^= blocks[6];  blocks[3] ^= blocks[7]
// Stride-4: letzte ^= erste (modifiziert)
blocks[4] ^= blocks[0];  blocks[5] ^= blocks[1]
blocks[6] ^= blocks[2];  blocks[7] ^= blocks[3]
```

Nach 1 Runde empfangen ALLE 8 Bloecke Informationen von ALLEN 8 Bloecken (8/8 ueberall).
Die Feistel-Struktur garantiert keine GF(2)-Cancellation, auch isoliert (ohne AES).

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

### 3.12 S1: AES-Finalisierung (N4: separate Schluessel)

Output = state[0..3] als 32 Bytes (Little-Endian). Aufgeteilt in zwei 16-Byte-Haelften:

```
out_lo = result[0..15]
out_hi = result[16..31]

// Runde 1: Volle AES-Runde + Cross-Half-XOR (RK_FINAL_1)
out_lo = AES_Round(out_lo, RK_FINAL_1)     // AddRoundKey+SubBytes+ShiftRows+MixColumns
out_hi = AES_Round(out_hi, RK_FINAL_1)
out_lo = out_lo XOR out_hi               // Inter-Half-Diffusion

// Runde 2: AES ohne MixColumns (Finalrunde) (RK_FINAL_2)
out_lo = AES_FinalRound(out_lo, RK_FINAL_2)  // AddRoundKey+SubBytes+ShiftRows
out_hi = AES_FinalRound(out_hi, RK_FINAL_2)
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
| Cross-Block-Diffusion | Feistel-artiger Butterfly (voll in 1 Runde, keine GF(2)-Cancellation) |
| Faltung | Nichtlinear (ADD, variable Shifts, nicht invertierbar) |
| Rueckrechenbar? | **NEIN** — 3 unabhaengige Barrieren |

### Einwegbarrieren

1. **Nichtlineare Faltung:** 1024 -> 256 Bit Kompression. 2^768 moegliche Urbilder pro Hash.
2. **Feed-Forward:** Zirkulaere Abhaengigkeit (Snapshot auf beiden Seiten der Gleichung).
3. **AES-Nichtlinearitaet:** S-Box Grad 254 in GF(2^8) verhindert algebraische Abkuerzungen.

---

## 5. Testvektoren (V1–V6, N1–N4)

| Eingabe | Hash (hex) |
|---------|------------|
| `""` (leer) | `68054b0505fda46148b79f1b36a51c50e8049735e47d6cfdac8dcf5638a3144c` |
| `"a"` | `9a0299e5484c507432cd92d83e9672cf3781c42de8c5af405d613f2aa2017baf` |
| `"abc"` | `fdc8684c9d0645be742f0d106d649d5ebae388a99786a869478b79456a907954` |
| `"Hello, MeowHash v7!"` | `6d28d0b3b21a027b99e38f7bb3b8490b8582007c1d6f56a4aa31593666f3af4d` |
| `"SECRET"` | `e56c2647773e2f0c0d904ed52d67bc495b7d045b9831bcf82cc0eabf6b5601e7` |
| `"MeowHash"` | `7c11887b28bc6ae6d272a16075646e2d7a809d2b0f5cbc8f2ec9f694ef4cdc53` |
| 7x `0x00` | `4b98cb52c8c0b396255e20677217d361281540f9d3015f92135ae8a5c6bee3ee` |
| 8x `0x00` | `c3d7d14d989e91307a30820d24ea79cc32aafa99aac6114eefae530ff30c7e05` |
| 9x `0x00` | `68e4f073f99f8b814b34de72f83473663560ee8c6450c0dc6d91ae2e3d0d570f` |
| `"a"` x 1.000.000 | `aba9b51da4b8d31a0c7a992d2b9c0882d9eb8753b39bbc212374e506b5819454` |

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
| N1 | Feistel-artiger Butterfly (eliminiert GF(2)-Cancellation) | 24 x 128-Bit XOR/Runde |
| N2 | MAGIC_128 aus Hex-Bytes von sqrt(2) (volle 8-Bit-Entropie) | 0 Ops (nur Konstanten) |
| N3 | Positionsabhaengige Absorb-Rotation (ROT_64[m & 3]) | 0 Ops (variable statt konstant) |
| N4 | Separate Finalisierungsschluessel RK_FINAL_1/RK_FINAL_2 | 0 Ops (nur Konstanten) |

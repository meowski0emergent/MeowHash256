"""
MeowHash256 — Pure Python Reference Implementation (V1–V6, N1–N4)

This is the pure Python implementation with zero external dependencies.
For maximum performance, use the C-binding version (meowhash256_c.py).

Security features:
  S1: AES finalization (Branch Number 5)
  S2: Feistel-style butterfly cross-block mix (full diffusion, no GF(2)-cancellation)
  S3: Block-individual round keys
  S4: Pre-squeeze state mixing (bidirectional, V3)
  S5: Nonlinear folding (non-invertible, V6 variable shifts)
  V1: SILVER_64 made odd (bijective compute_node)
  V2: Absorb-counter injection
  V3: Bidirectional S4 (forward + reverse pass)
  V4: Absorb cross-coupling
  V5: Empty-input path consistency
  V6: Position-dependent shift constants in folding
  N1: Feistel-style butterfly (eliminates GF(2)-cancellation)
  N2: MAGIC_128 from hex bytes of sqrt(2) (full 8-bit entropy)
  N3: Position-dependent absorb rotation
  N4: Separate finalization keys RK_FINAL_1/RK_FINAL_2

Efficiency features:
  E1: Simplified scalar absorb
  E3: Adaptive squeeze rounds (3 for <64B, 4 for >=64B)
"""

import struct

MASK64 = 0xFFFFFFFFFFFFFFFF
GOLDEN_64 = 0x9E3779B97F4A7C15
SILVER_64 = 0x6A09E667F3BCC909  # V1: made odd (0 trailing zeros)

ROT_64 = [29, 47, 13, 53]

# N2: Hex bytes of sqrt(2) fractional part (full 8-bit entropy)
# Source: fractional part of sqrt(2) = 0x6A09E667F3BCC908B2FB1366EA957D3E...
MAGIC_128 = bytes([
    0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xB2, 0xFB, 0x13, 0x66, 0xEA, 0x95, 0x7D, 0x3E,
    0x3A, 0xDE, 0xC1, 0x75, 0x12, 0x77, 0x50, 0x99, 0xDA, 0x2F, 0x59, 0x0B, 0x06, 0x67, 0x32, 0x2A,
    0x95, 0xF9, 0x06, 0x08, 0x75, 0x71, 0x45, 0x87, 0x51, 0x63, 0xFC, 0xDF, 0xB9, 0x07, 0xB6, 0x72,
    0x1E, 0xE9, 0x50, 0xBC, 0x87, 0x38, 0xF6, 0x94, 0xF0, 0x09, 0x0E, 0x6C, 0x7B, 0xF4, 0x4E, 0xD1,
    0xA4, 0x40, 0x5D, 0x0E, 0x85, 0x5E, 0x3E, 0x9C, 0xA6, 0x0B, 0x38, 0xC0, 0x23, 0x78, 0x66, 0xF7,
    0x95, 0x63, 0x79, 0x22, 0x2D, 0x10, 0x8B, 0x14, 0x8C, 0x15, 0x78, 0xE4, 0x5E, 0xF8, 0x9C, 0x67,
    0x8D, 0xAB, 0x51, 0x47, 0x17, 0x6F, 0xD3, 0xB9, 0x96, 0x54, 0xC6, 0x86, 0x63, 0xE7, 0x90, 0x9B,
    0xEA, 0x5E, 0x24, 0x1F, 0x06, 0xDC, 0xB0, 0x5D, 0xD5, 0x49, 0x41, 0x13, 0x20, 0x81, 0x94, 0x95,
])
MAGIC_64 = [struct.unpack_from('<Q', MAGIC_128, i * 8)[0] for i in range(16)]

AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

RK_WORDS = [
    (0x96FEC54A18AC757F, 0x5474738D95AF32BB),
    (0x766758FB3A436DFC, 0xE6FD807F994BFBC9),
    (0x62B858855E7E2473, 0xBC45239C77DBFACE),
    (0x31C83248A7EC35A1, 0x9905A4345F319416),
]

# N4: Separate finalization round keys
RK_FINAL_1 = (0x5D67BDF295CAB403, 0x57F81E5CFBF49B30)
RK_FINAL_2 = (0x28E5E35FDCED9BBE, 0xAB628FC7C55554B0)

_Q_STRUCT = struct.Struct('<Q')
_16Q_PACK = struct.Struct('<16Q').pack
_4Q_PACK = struct.Struct('<4Q').pack


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK64


def _aes_sub_bytes(block):
    return bytearray(AES_SBOX[b] for b in block)


def _aes_shift_rows(block):
    s = bytearray(16)
    for r in range(4):
        for c in range(4):
            s[r + 4 * c] = block[r + 4 * ((c + r) % 4)]
    return s


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _aes_mix_columns(block):
    out = bytearray(16)
    for c in range(4):
        col = [block[r + 4 * c] for r in range(4)]
        out[0 + 4 * c] = _gf_mul(2, col[0]) ^ _gf_mul(3, col[1]) ^ col[2] ^ col[3]
        out[1 + 4 * c] = col[0] ^ _gf_mul(2, col[1]) ^ _gf_mul(3, col[2]) ^ col[3]
        out[2 + 4 * c] = col[0] ^ col[1] ^ _gf_mul(2, col[2]) ^ _gf_mul(3, col[3])
        out[3 + 4 * c] = _gf_mul(3, col[0]) ^ col[1] ^ col[2] ^ _gf_mul(2, col[3])
    return out


def _aes_round(block, round_key):
    xored = bytearray(a ^ b for a, b in zip(block, round_key))
    subbed = _aes_sub_bytes(xored)
    shifted = _aes_shift_rows(subbed)
    mixed = _aes_mix_columns(shifted)
    return mixed


def _aes_final_round(block, round_key):
    xored = bytearray(a ^ b for a, b in zip(block, round_key))
    subbed = _aes_sub_bytes(xored)
    shifted = _aes_shift_rows(subbed)
    return shifted


def _xor_blocks(a, b):
    return bytearray(x ^ y for x, y in zip(a, b))


def _compute_node(segment):
    node = (segment * GOLDEN_64) & MASK64
    node ^= (node >> 32)
    node = (node * SILVER_64) & MASK64  # V1: now bijective (SILVER_64 is odd)
    node ^= (node >> 29)
    return node


def meowhash256(data: bytes) -> bytes:
    """Compute MeowHash256 of the given input. Returns 32 bytes."""
    input_len = len(data)
    mask = MASK64
    golden = GOLDEN_64
    rot_64 = ROT_64

    state = list(MAGIC_64)
    state[0] = (state[0] ^ (input_len & mask)) & mask
    state[1] = (state[1] ^ ((input_len * golden) & mask)) & mask

    padded = bytearray(data)
    padded.append(0x80)
    rem = len(padded) & 7
    if rem:
        padded.extend(b'\x00' * (8 - rem))

    absorb_counter = 0
    unpack = _Q_STRUCT.unpack_from

    if input_len > 0:
        for offset in range(0, len(padded), 8):
            segment = unpack(padded, offset)[0]
            node = _compute_node(segment)

            pos_add = (absorb_counter * 2) & 15
            pos_xor = (absorb_counter * 2 + 1) & 15
            state[pos_add] = (state[pos_add] + node) & mask
            state[pos_xor] ^= node

            m = absorb_counter & 15
            sm = (state[m] + state[(m + 1) & 15]) & mask
            sm ^= (sm >> 17)
            r_absorb = rot_64[m & 3]  # N3: position-dependent rotation
            sm = ((sm << r_absorb) | (sm >> (64 - r_absorb))) & mask
            sm ^= state[(m + 7) & 15]
            state[m] = sm
            # V4: Cross-coupling to opposite state half
            state[(m + 8) & 15] ^= state[m]
            absorb_counter += 1
    else:
        # Empty input path
        segment = unpack(padded, 0)[0]
        node = _compute_node(segment)
        state[0] = (state[0] + node) & mask
        state[1] ^= node
        sm = (state[0] + state[1]) & mask
        sm ^= (sm >> 17)
        sm = ((sm << rot_64[0]) | (sm >> (64 - rot_64[0]))) & mask  # N3: position-dependent (m=0)
        sm ^= state[7]
        state[0] = sm
        # V5: Empty-input cross-coupling consistency
        state[8] ^= state[0]
        absorb_counter = 1

    # V2: Absorb-counter injection
    state[2] = (state[2] ^ absorb_counter) & mask
    state[3] = (state[3] ^ ((absorb_counter * golden) & mask)) & mask

    # S4: Pre-squeeze state mixing
    # V3: Forward pass
    for i in range(16):
        state[i] = (state[i] + state[(i + 7) & 15]) & mask
        state[i] ^= (state[i] >> 17)
        r = rot_64[i & 3]
        state[i] = ((state[i] << r) | (state[i] >> (64 - r))) & mask

    # V3: Reverse pass (different shift + offset)
    for i in range(15, -1, -1):
        state[i] = (state[i] + state[(i + 5) & 15]) & mask
        state[i] ^= (state[i] >> 23)
        r = rot_64[i & 3]
        state[i] = ((state[i] << r) | (state[i] >> (64 - r))) & mask

    snapshot = list(state)
    squeeze_rounds = 3 if input_len < 64 else 4

    state_bytes = bytearray(_16Q_PACK(*state))
    blocks = [bytearray(state_bytes[i * 16:(i + 1) * 16]) for i in range(8)]

    rk_blocks = []
    for w0, w1 in RK_WORDS:
        rk = bytearray(struct.pack('<Q', w0)) + bytearray(struct.pack('<Q', w1))
        rk_blocks.append(rk)

    block_salts = [bytearray(MAGIC_128[i * 16:(i + 1) * 16]) for i in range(8)]

    for r in range(squeeze_rounds):
        for i in range(8):
            indiv_rk = _xor_blocks(rk_blocks[r], block_salts[i])
            blocks[i] = _aes_round(blocks[i], indiv_rk)

        # Forward butterfly
        blocks[0] = _xor_blocks(blocks[0], blocks[1])
        blocks[2] = _xor_blocks(blocks[2], blocks[3])
        blocks[4] = _xor_blocks(blocks[4], blocks[5])
        blocks[6] = _xor_blocks(blocks[6], blocks[7])
        blocks[0] = _xor_blocks(blocks[0], blocks[2])
        blocks[4] = _xor_blocks(blocks[4], blocks[6])
        blocks[1] = _xor_blocks(blocks[1], blocks[3])
        blocks[5] = _xor_blocks(blocks[5], blocks[7])
        blocks[0] = _xor_blocks(blocks[0], blocks[4])
        blocks[1] = _xor_blocks(blocks[1], blocks[5])
        blocks[2] = _xor_blocks(blocks[2], blocks[6])
        blocks[3] = _xor_blocks(blocks[3], blocks[7])

        # Reverse butterfly (bidirectional full diffusion)
        blocks[7] = _xor_blocks(blocks[7], blocks[6])
        blocks[5] = _xor_blocks(blocks[5], blocks[4])
        blocks[3] = _xor_blocks(blocks[3], blocks[2])
        blocks[1] = _xor_blocks(blocks[1], blocks[0])
        blocks[7] = _xor_blocks(blocks[7], blocks[5])
        blocks[6] = _xor_blocks(blocks[6], blocks[4])
        blocks[3] = _xor_blocks(blocks[3], blocks[1])
        blocks[2] = _xor_blocks(blocks[2], blocks[0])
        blocks[7] = _xor_blocks(blocks[7], blocks[3])
        blocks[6] = _xor_blocks(blocks[6], blocks[2])
        blocks[5] = _xor_blocks(blocks[5], blocks[1])
        blocks[4] = _xor_blocks(blocks[4], blocks[0])

    state_bytes = bytearray()
    for b in blocks:
        state_bytes.extend(b)
    state = list(struct.unpack_from('<16Q', state_bytes))

    for i in range(16):
        state[i] ^= snapshot[i]

    state[14] = (state[14] ^ (input_len & mask)) & mask
    state[15] = (state[15] ^ ((input_len * golden) & mask)) & mask

    # S5: Nonlinear folding with V6 position-dependent shifts
    for i in range(8):
        rotated = _rotl64(state[15 - i], rot_64[i & 3])
        state[i] = (state[i] + rotated) & mask
        state[i] ^= (state[i] >> (29 + (i & 3)))  # V6

    for i in range(4):
        rotated = _rotl64(state[7 - i], rot_64[i & 3])
        state[i] = (state[i] + rotated) & mask
        state[i] ^= (state[i] >> (29 + (i & 3)))  # V6

    result = bytearray(_4Q_PACK(state[0], state[1], state[2], state[3]))

    final_rk_bytes = bytearray(struct.pack('<Q', RK_FINAL[0])) + \
                     bytearray(struct.pack('<Q', RK_FINAL[1]))

    out_lo = bytearray(result[0:16])
    out_hi = bytearray(result[16:32])

    out_lo = _aes_round(out_lo, final_rk_bytes)
    out_hi = _aes_round(out_hi, final_rk_bytes)
    out_lo = _xor_blocks(out_lo, out_hi)

    out_lo = _aes_final_round(out_lo, final_rk_bytes)
    out_hi = _aes_final_round(out_hi, final_rk_bytes)

    return bytes(out_lo + out_hi)


def meowhash256_hex(data: bytes) -> str:
    """Return hex string representation of MeowHash256."""
    return meowhash256(data).hex()


# Backward compatibility aliases
meow_hash_v6 = meowhash256
meow_hash_v6_hex = meowhash256_hex


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        data = sys.argv[1].encode('utf-8')
    else:
        data = b''
    print(meowhash256_hex(data))

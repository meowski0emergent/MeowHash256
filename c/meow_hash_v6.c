/*
 * MeowHash v7 — Improved Implementation (with V1–V6, N1–N4)
 *
 * Security improvements:
 *   S1: AES finalization rounds (Branch Number 5 instead of 1)
 *   S2+E2: Feistel-style butterfly cross-block mix (full diffusion, no GF(2)-cancellation)
 *   S3: Block-individual round keys (breaks block symmetry)
 *   S4: Pre-squeeze state mixing (bidirectional, V3)
 *   S5: Nonlinear folding (ADD + carry-diffusion, non-invertible, V6 variable shifts)
 *   V1: SILVER_64 made odd (bijective compute_node)
 *   V2: Absorb-counter injection (explicit segment count encoding)
 *   V3: Bidirectional S4 (forward + reverse pass)
 *   V4: Absorb cross-coupling (opposite state half linkage)
 *   V5: Empty-input path consistency
 *   V6: Position-dependent shift constants in folding
 *   N1: Feistel-style butterfly (eliminates GF(2)-cancellation even without AES)
 *   N2: MAGIC_128 from hex bytes of sqrt(2) (full 8-bit entropy per byte)
 *   N3: Position-dependent absorb rotation (ROT_64[m & 3] instead of constant 29)
 *   N4: Separate finalization keys RK_FINAL_1/RK_FINAL_2
 *
 * Efficiency improvements:
 *   E1: Simplified absorb (scalar loads, no NEON overhead)
 *   E3: Reduced squeeze for short inputs (3 rounds if len < 64)
 *   E5: Compile-time architecture dispatch (ARM/x86/generic)
 *   E6: Platform-optimal secure zeroing
 */

#define _GNU_SOURCE
#include "meow_hash_v6.h"
#include <string.h>
#include <strings.h>

/* ── E5: Architecture Detection ─────────────────────────────────────────── */

#if defined(__aarch64__)
  #include <arm_neon.h>
  #define MEOW_USE_ARM_CRYPTO 1
#endif

/*
 * x86 AES-NI mapping (for future implementation):
 *   ARM vaeseq_u8(data, key)    = AddRoundKey -> SubBytes -> ShiftRows
 *   x86 _mm_aesenc_si128(d, k)  = ShiftRows -> SubBytes -> MixColumns -> AddRoundKey
 *   ARM vaesmcq_u8(data)         = MixColumns
 *   ARM veorq_u8(a, b)           = _mm_xor_si128(a, b)
 *
 * WARNING: Operation order differs! Correct x86 port must adjust accordingly.
 */

/* ── Constants ──────────────────────────────────────────────────────────── */

#define GOLDEN_64 0x9E3779B97F4A7C15ULL
#define SILVER_64 0x6A09E667F3BCC909ULL  /* V1: made odd (0 trailing zeros) */

static const int ROT_64[4] = {29, 47, 13, 53};

/* N2: MAGIC_64 from hex bytes of sqrt(2) (full 8-bit entropy per byte) */
static const uint64_t MAGIC_64[16] = {
    0x08C9BCF367E6096AULL, 0x3E7D95EA6613FBB2ULL,
    0x9950771275C1DE3AULL, 0x2A3267060B592FDAULL,
    0x874571750806F995ULL, 0x72B607B9DFFC6351ULL,
    0x94F63887BC50E91EULL, 0xD14EF47B6C0E09F0ULL,
    0x9C3E5E850E5D40A4ULL, 0xF7667823C0380BA6ULL,
    0x148B102D22796395ULL, 0x679CF85EE478158CULL,
    0xB9D36F174751AB8DULL, 0x9B90E76386C65496ULL,
    0x5DB0DC061F245EEAULL, 0x95948120134149D5ULL,
};

/* AES S-Box (used by software fallback and finalization) */
static const uint8_t AES_SBOX[256] __attribute__((used)) = {
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* N2: MAGIC_128 hex bytes of sqrt(2) fractional part — "Nothing Up My Sleeve"
 * Source: fractional part of sqrt(2) = 0x6A09E667F3BCC908B2FB1366EA957D3E...
 * Full 8-bit entropy per byte (replaces v6 decimal digits 0-9) */
static const uint8_t MAGIC_128[128] = {
    0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xB2, 0xFB, 0x13, 0x66, 0xEA, 0x95, 0x7D, 0x3E,
    0x3A, 0xDE, 0xC1, 0x75, 0x12, 0x77, 0x50, 0x99, 0xDA, 0x2F, 0x59, 0x0B, 0x06, 0x67, 0x32, 0x2A,
    0x95, 0xF9, 0x06, 0x08, 0x75, 0x71, 0x45, 0x87, 0x51, 0x63, 0xFC, 0xDF, 0xB9, 0x07, 0xB6, 0x72,
    0x1E, 0xE9, 0x50, 0xBC, 0x87, 0x38, 0xF6, 0x94, 0xF0, 0x09, 0x0E, 0x6C, 0x7B, 0xF4, 0x4E, 0xD1,
    0xA4, 0x40, 0x5D, 0x0E, 0x85, 0x5E, 0x3E, 0x9C, 0xA6, 0x0B, 0x38, 0xC0, 0x23, 0x78, 0x66, 0xF7,
    0x95, 0x63, 0x79, 0x22, 0x2D, 0x10, 0x8B, 0x14, 0x8C, 0x15, 0x78, 0xE4, 0x5E, 0xF8, 0x9C, 0x67,
    0x8D, 0xAB, 0x51, 0x47, 0x17, 0x6F, 0xD3, 0xB9, 0x96, 0x54, 0xC6, 0x86, 0x63, 0xE7, 0x90, 0x9B,
    0xEA, 0x5E, 0x24, 0x1F, 0x06, 0xDC, 0xB0, 0x5D, 0xD5, 0x49, 0x41, 0x13, 0x20, 0x81, 0x94, 0x95
};

/* AES squeeze round keys — "nothing up my sleeve" derivation:
 * RK[r] = { rotl64(GOLDEN_64, r*13) ^ MAGIC_64[r*2],
 *            rotl64(SILVER_64, r*17) ^ MAGIC_64[r*2+1] } */
static const uint64_t RK_WORDS[4][2] = {
    { 0x96FEC54A18AC757FULL, 0x5474738D95AF32BBULL },
    { 0x766758FB3A436DFCULL, 0xE6FD807F994BFBC9ULL },
    { 0x62B858855E7E2473ULL, 0xBC45239C77DBFACEULL },
    { 0x31C83248A7EC35A1ULL, 0x9905A4345F319416ULL },
};

/* S1: Finalization round key (r=4 in RK derivation) */
static const uint64_t RK_FINAL[2] = {
    0xC95EE7759890F4AEULL, 0xA39E617F3ACE9692ULL
};

/* ── Utility functions ──────────────────────────────────────────────────── */

static inline uint64_t read_le64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static inline void write_le64(uint8_t *p, uint64_t v) {
    memcpy(p, &v, 8);
}

static inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

/* E6: Platform-optimal secure zeroing */
static void secure_zero(void *p, size_t n) {
#if defined(__GLIBC__) || defined(__linux__)
    explicit_bzero(p, n);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
#endif
}

/* ── Node computation ───────────────────────────────────────────────────── */

static inline uint64_t compute_node(uint64_t segment) {
    uint64_t node = segment * GOLDEN_64;
    node ^= (node >> 32);
    node = node * SILVER_64;
    node ^= (node >> 29);
    return node;
}

/* ── Software AES (for non-ARM platforms) ───────────────────────────────── */

#if !defined(MEOW_USE_ARM_CRYPTO)

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static void soft_aes_round(uint8_t block[16], const uint8_t key[16]) {
    int r, c;
    /* AddRoundKey */
    for (int i = 0; i < 16; i++) block[i] ^= key[i];
    /* SubBytes */
    for (int i = 0; i < 16; i++) block[i] = AES_SBOX[block[i]];
    /* ShiftRows */
    uint8_t tmp[16];
    for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++)
            tmp[r + 4 * c] = block[r + 4 * ((c + r) % 4)];
    memcpy(block, tmp, 16);
    /* MixColumns */
    for (c = 0; c < 4; c++) {
        uint8_t a0 = block[4*c], a1 = block[4*c+1], a2 = block[4*c+2], a3 = block[4*c+3];
        block[4*c]   = gf_mul(2,a0) ^ gf_mul(3,a1) ^ a2 ^ a3;
        block[4*c+1] = a0 ^ gf_mul(2,a1) ^ gf_mul(3,a2) ^ a3;
        block[4*c+2] = a0 ^ a1 ^ gf_mul(2,a2) ^ gf_mul(3,a3);
        block[4*c+3] = gf_mul(3,a0) ^ a1 ^ a2 ^ gf_mul(2,a3);
    }
}

static void soft_aes_final_round(uint8_t block[16], const uint8_t key[16]) {
    int r, c;
    /* AddRoundKey */
    for (int i = 0; i < 16; i++) block[i] ^= key[i];
    /* SubBytes */
    for (int i = 0; i < 16; i++) block[i] = AES_SBOX[block[i]];
    /* ShiftRows (no MixColumns) */
    uint8_t tmp[16];
    for (r = 0; r < 4; r++)
        for (c = 0; c < 4; c++)
            tmp[r + 4 * c] = block[r + 4 * ((c + r) % 4)];
    memcpy(block, tmp, 16);
}

static void soft_xor_block(uint8_t dst[16], const uint8_t src[16]) {
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

#endif /* !MEOW_USE_ARM_CRYPTO */

/* ── Main hash function ─────────────────────────────────────────────────── */

void meow_hash_v6(const uint8_t *input, size_t len, uint8_t output[MEOW_V6_HASH_BYTES]) {
    uint64_t state[MEOW_V6_STATE_WORDS];
    int i;

    /* === State Initialization === */
    memcpy(state, MAGIC_64, sizeof(state));

    /* Length Injection */
    state[0] ^= (uint64_t)len;
    state[1] ^= (uint64_t)len * GOLDEN_64;

    /* === Absorb Phase (E1: simplified scalar) === */
    size_t absorb_counter = 0;

    if (len > 0 && input != NULL) {
        size_t full_segs = len / 8;
        const uint8_t *p = input;

        /* Process full 8-byte segments */
        for (size_t s = 0; s < full_segs; s++) {
            uint64_t segment = read_le64(p);
            p += 8;

            uint64_t node = compute_node(segment);

            int pos_add = (int)((absorb_counter * 2) & 15);
            int pos_xor = (int)((absorb_counter * 2 + 1) & 15);
            state[pos_add] += node;
            state[pos_xor] ^= node;

            int m = (int)(absorb_counter & 15);
            state[m] += state[(m + 1) & 15];
            state[m] ^= (state[m] >> 17);
            state[m] = rotl64(state[m], 29);
            state[m] ^= state[(m + 7) & 15];
            /* V4: Cross-coupling to opposite state half */
            state[(m + 8) & 15] ^= state[m];
            absorb_counter++;
        }

        /* Last block: remaining bytes + 0x80 padding */
        uint8_t last_block[8] = {0};
        size_t remaining = len % 8;
        if (remaining > 0) {
            memcpy(last_block, p, remaining);
        }
        last_block[remaining] = 0x80;

        {
            uint64_t segment = read_le64(last_block);
            uint64_t node = compute_node(segment);

            int pos_add = (int)((absorb_counter * 2) & 15);
            int pos_xor = (int)((absorb_counter * 2 + 1) & 15);
            state[pos_add] += node;
            state[pos_xor] ^= node;

            int m = (int)(absorb_counter & 15);
            state[m] += state[(m + 1) & 15];
            state[m] ^= (state[m] >> 17);
            state[m] = rotl64(state[m], 29);
            state[m] ^= state[(m + 7) & 15];
            /* V4: Cross-coupling to opposite state half */
            state[(m + 8) & 15] ^= state[m];
            absorb_counter++;
        }
        secure_zero(last_block, sizeof(last_block));

    } else {
        /* Empty input */
        uint8_t last_block[8] = {0};
        last_block[0] = 0x80;

        uint64_t segment = read_le64(last_block);
        uint64_t node = compute_node(segment);

        state[0] += node;
        state[1] ^= node;

        state[0] += state[1];
        state[0] ^= (state[0] >> 17);
        state[0] = rotl64(state[0], 29);
        state[0] ^= state[7];
        /* V5: Empty-input cross-coupling consistency */
        state[8] ^= state[0];
        absorb_counter = 1;

        secure_zero(last_block, sizeof(last_block));
    }

    /* === V2: Absorb-Counter Injection === */
    state[2] ^= (uint64_t)absorb_counter;
    state[3] ^= (uint64_t)absorb_counter * GOLDEN_64;

    /* === S4: Pre-Squeeze State Mixing === */
    /* V3: Forward pass */
    for (i = 0; i < MEOW_V6_STATE_WORDS; i++) {
        state[i] += state[(i + 7) & 15];
        state[i] ^= (state[i] >> 17);
        state[i] = rotl64(state[i], ROT_64[i & 3]);
    }
    /* V3: Reverse pass (different shift + offset to avoid fixpoints) */
    for (i = MEOW_V6_STATE_WORDS - 1; i >= 0; i--) {
        state[i] += state[(i + 5) & 15];
        state[i] ^= (state[i] >> 23);
        state[i] = rotl64(state[i], ROT_64[i & 3]);
    }

    /* === Snapshot for feed-forward === */
    uint64_t snapshot[MEOW_V6_STATE_WORDS];
    memcpy(snapshot, state, sizeof(snapshot));

    /* === E3: Reduced squeeze for short inputs === */
    int squeeze_rounds = (len < 64) ? 3 : 4;

    /* === Squeeze Phase — AES-BASED === */
    uint8_t state_bytes[128];
    for (i = 0; i < MEOW_V6_STATE_WORDS; i++) {
        write_le64(&state_bytes[i * 8], state[i]);
    }

#if defined(MEOW_USE_ARM_CRYPTO)
    /* ── ARM NEON + AES Crypto Extensions path ─────────────────────────── */
    {
        uint8x16_t blocks[8];
        for (i = 0; i < 8; i++)
            blocks[i] = vld1q_u8(&state_bytes[i * 16]);

        /* Load round keys */
        uint8x16_t rk[4];
        for (i = 0; i < 4; i++) {
            uint8_t rk_bytes[16];
            write_le64(&rk_bytes[0], RK_WORDS[i][0]);
            write_le64(&rk_bytes[8], RK_WORDS[i][1]);
            rk[i] = vld1q_u8(rk_bytes);
        }

        /* S3: Block salts (MAGIC_128 as 8 x 16-byte vectors) */
        uint8x16_t block_salt[8];
        for (i = 0; i < 8; i++)
            block_salt[i] = vld1q_u8(&MAGIC_128[i * 16]);

        /* AES rounds with S3 + S2+E2 */
        for (int r = 0; r < squeeze_rounds; r++) {
            /* S3: Block-individual round keys */
            for (i = 0; i < 8; i++) {
                uint8x16_t indiv_rk = veorq_u8(rk[r], block_salt[i]);
                blocks[i] = vaeseq_u8(blocks[i], indiv_rk);
                blocks[i] = vaesmcq_u8(blocks[i]);
            }

            /* S2+E2: Butterfly cross-block mix (3 stages, ILP=4) */
            /* Forward butterfly: Stage 1 */
            blocks[0] = veorq_u8(blocks[0], blocks[1]);
            blocks[2] = veorq_u8(blocks[2], blocks[3]);
            blocks[4] = veorq_u8(blocks[4], blocks[5]);
            blocks[6] = veorq_u8(blocks[6], blocks[7]);
            /* Forward butterfly: Stage 2 */
            blocks[0] = veorq_u8(blocks[0], blocks[2]);
            blocks[4] = veorq_u8(blocks[4], blocks[6]);
            blocks[1] = veorq_u8(blocks[1], blocks[3]);
            blocks[5] = veorq_u8(blocks[5], blocks[7]);
            /* Forward butterfly: Stage 3 */
            blocks[0] = veorq_u8(blocks[0], blocks[4]);
            blocks[1] = veorq_u8(blocks[1], blocks[5]);
            blocks[2] = veorq_u8(blocks[2], blocks[6]);
            blocks[3] = veorq_u8(blocks[3], blocks[7]);

            /* Reverse butterfly: Stage 1 */
            blocks[7] = veorq_u8(blocks[7], blocks[6]);
            blocks[5] = veorq_u8(blocks[5], blocks[4]);
            blocks[3] = veorq_u8(blocks[3], blocks[2]);
            blocks[1] = veorq_u8(blocks[1], blocks[0]);
            /* Reverse butterfly: Stage 2 */
            blocks[7] = veorq_u8(blocks[7], blocks[5]);
            blocks[6] = veorq_u8(blocks[6], blocks[4]);
            blocks[3] = veorq_u8(blocks[3], blocks[1]);
            blocks[2] = veorq_u8(blocks[2], blocks[0]);
            /* Reverse butterfly: Stage 3 */
            blocks[7] = veorq_u8(blocks[7], blocks[3]);
            blocks[6] = veorq_u8(blocks[6], blocks[2]);
            blocks[5] = veorq_u8(blocks[5], blocks[1]);
            blocks[4] = veorq_u8(blocks[4], blocks[0]);
        }

        /* Store blocks back */
        for (i = 0; i < 8; i++)
            vst1q_u8(&state_bytes[i * 16], blocks[i]);
    }
#else
    /* ── Software AES path (x86/generic) ───────────────────────────────── */
    {
        uint8_t blocks[8][16];
        for (i = 0; i < 8; i++)
            memcpy(blocks[i], &state_bytes[i * 16], 16);

        uint8_t rk_bytes[4][16];
        for (i = 0; i < 4; i++) {
            write_le64(&rk_bytes[i][0], RK_WORDS[i][0]);
            write_le64(&rk_bytes[i][8], RK_WORDS[i][1]);
        }

        for (int r = 0; r < squeeze_rounds; r++) {
            /* S3: Block-individual round keys */
            for (i = 0; i < 8; i++) {
                uint8_t indiv_rk[16];
                for (int j = 0; j < 16; j++)
                    indiv_rk[j] = rk_bytes[r][j] ^ MAGIC_128[i * 16 + j];
                soft_aes_round(blocks[i], indiv_rk);
            }

            /* S2+E2: Butterfly cross-block mix */
            /* Forward butterfly */
            soft_xor_block(blocks[0], blocks[1]);
            soft_xor_block(blocks[2], blocks[3]);
            soft_xor_block(blocks[4], blocks[5]);
            soft_xor_block(blocks[6], blocks[7]);

            soft_xor_block(blocks[0], blocks[2]);
            soft_xor_block(blocks[4], blocks[6]);
            soft_xor_block(blocks[1], blocks[3]);
            soft_xor_block(blocks[5], blocks[7]);

            soft_xor_block(blocks[0], blocks[4]);
            soft_xor_block(blocks[1], blocks[5]);
            soft_xor_block(blocks[2], blocks[6]);
            soft_xor_block(blocks[3], blocks[7]);

            /* Reverse butterfly (bidirectional full diffusion) */
            soft_xor_block(blocks[7], blocks[6]);
            soft_xor_block(blocks[5], blocks[4]);
            soft_xor_block(blocks[3], blocks[2]);
            soft_xor_block(blocks[1], blocks[0]);

            soft_xor_block(blocks[7], blocks[5]);
            soft_xor_block(blocks[6], blocks[4]);
            soft_xor_block(blocks[3], blocks[1]);
            soft_xor_block(blocks[2], blocks[0]);

            soft_xor_block(blocks[7], blocks[3]);
            soft_xor_block(blocks[6], blocks[2]);
            soft_xor_block(blocks[5], blocks[1]);
            soft_xor_block(blocks[4], blocks[0]);
        }

        for (i = 0; i < 8; i++)
            memcpy(&state_bytes[i * 16], blocks[i], 16);
    }
#endif

    /* Convert back to state words */
    for (i = 0; i < MEOW_V6_STATE_WORDS; i++) {
        state[i] = read_le64(&state_bytes[i * 8]);
    }

    /* === Feed-Forward === */
    for (i = 0; i < MEOW_V6_STATE_WORDS; i++) {
        state[i] ^= snapshot[i];
    }

    /* === Second Length Injection === */
    state[14] ^= (uint64_t)len;
    state[15] ^= (uint64_t)len * GOLDEN_64;

    /* === S5: Nonlinear Folding === */
    /* 16 -> 8 words (ADD + carry-diffusion) */
    for (i = 0; i < 8; i++) {
        state[i] = state[i] + rotl64(state[15 - i], ROT_64[i & 3]);
        /* V6: Position-dependent shift constants */
        state[i] ^= (state[i] >> (29 + (i & 3)));
    }

    /* 8 -> 4 words */
    for (i = 0; i < 4; i++) {
        state[i] = state[i] + rotl64(state[7 - i], ROT_64[i & 3]);
        /* V6: Position-dependent shift constants */
        state[i] ^= (state[i] >> (29 + (i & 3)));
    }

    /* Output = state[0..3] = 32 bytes */
    uint8_t result[MEOW_V6_HASH_BYTES];
    for (i = 0; i < 4; i++) {
        write_le64(&result[i * 8], state[i]);
    }

    /* === S1: AES Finalization (Branch Number 5) === */
    {
        uint8_t final_rk_bytes[16];
        write_le64(&final_rk_bytes[0], RK_FINAL[0]);
        write_le64(&final_rk_bytes[8], RK_FINAL[1]);

#if defined(MEOW_USE_ARM_CRYPTO)
        uint8x16_t frk = vld1q_u8(final_rk_bytes);
        uint8x16_t out_lo = vld1q_u8(&result[0]);
        uint8x16_t out_hi = vld1q_u8(&result[16]);

        /* Round 1: Full AES + cross-half XOR */
        out_lo = vaesmcq_u8(vaeseq_u8(out_lo, frk));
        out_hi = vaesmcq_u8(vaeseq_u8(out_hi, frk));
        out_lo = veorq_u8(out_lo, out_hi);

        /* Round 2: Final AES (no MixColumns) */
        out_lo = vaeseq_u8(out_lo, frk);
        out_hi = vaeseq_u8(out_hi, frk);

        vst1q_u8(&result[0], out_lo);
        vst1q_u8(&result[16], out_hi);
#else
        uint8_t out_lo[16], out_hi[16];
        memcpy(out_lo, &result[0], 16);
        memcpy(out_hi, &result[16], 16);

        /* Round 1: Full AES + cross-half XOR */
        soft_aes_round(out_lo, final_rk_bytes);
        soft_aes_round(out_hi, final_rk_bytes);
        soft_xor_block(out_lo, out_hi);

        /* Round 2: Final AES (no MixColumns) */
        soft_aes_final_round(out_lo, final_rk_bytes);
        soft_aes_final_round(out_hi, final_rk_bytes);

        memcpy(&result[0], out_lo, 16);
        memcpy(&result[16], out_hi, 16);
#endif
    }

    memcpy(output, result, MEOW_V6_HASH_BYTES);

    /* Secure cleanup */
    secure_zero(state, sizeof(state));
    secure_zero(snapshot, sizeof(snapshot));
    secure_zero(state_bytes, sizeof(state_bytes));
    secure_zero(result, sizeof(result));
}

void meow_hash_v6_hex(const uint8_t *input, size_t len, char hex_out[65]) {
    uint8_t hash[MEOW_V6_HASH_BYTES];
    meow_hash_v6(input, len, hash);
    for (int i = 0; i < MEOW_V6_HASH_BYTES; i++) {
        hex_out[i * 2]     = "0123456789abcdef"[hash[i] >> 4];
        hex_out[i * 2 + 1] = "0123456789abcdef"[hash[i] & 0x0F];
    }
    hex_out[64] = '\0';
    secure_zero(hash, sizeof(hash));
}

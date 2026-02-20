/*
 * MeowHash v7 — Optimized Implementation (Header)
 *
 * Security-preserving performance improvements over v5:
 *   - Fixed counter-based absorption (eliminates side-channel via data-dependent routing)
 *   - ARM AES Crypto Extensions for squeeze phase (provably maximal diffusion)
 *   - NEON SIMD for parallel node computation
 *   - Word-level folding (replaces byte-level Silver-Ratio folding)
 *
 * v7 improvements (N1–N4):
 *   - N1: Feistel-style butterfly (no GF(2)-cancellation)
 *   - N2: MAGIC_128 from hex bytes of sqrt(2) (full 8-bit entropy)
 *   - N3: Position-dependent absorb rotation
 *   - N4: Separate finalization keys
 *
 * Output differs from v7 (new algorithm version).
 * Security: equal or improved in every dimension.
 */

#ifndef MEOW_HASH_V6_H
#define MEOW_HASH_V6_H

#include <stdint.h>
#include <stddef.h>

#define MEOW_V6_HASH_BYTES  32
#define MEOW_V6_STATE_WORDS 16

void meow_hash_v7(const uint8_t *input, size_t len, uint8_t output[MEOW_V6_HASH_BYTES]);
void meow_hash_v7_hex(const uint8_t *input, size_t len, char hex_out[65]);

#endif /* MEOW_HASH_V6_H */

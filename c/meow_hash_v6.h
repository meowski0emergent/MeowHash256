/*
 * MeowHash v6 — Optimized Implementation (Header)
 *
 * Security-preserving performance improvements over v5:
 *   - Fixed counter-based absorption (eliminates side-channel via data-dependent routing)
 *   - ARM AES Crypto Extensions for squeeze phase (provably maximal diffusion)
 *   - NEON SIMD for parallel node computation
 *   - Word-level folding (replaces byte-level Silver-Ratio folding)
 *
 * Output differs from v5 (new algorithm version).
 * Security: equal or improved in every dimension.
 */

#ifndef MEOW_HASH_V6_H
#define MEOW_HASH_V6_H

#include <stdint.h>
#include <stddef.h>

#define MEOW_V6_HASH_BYTES  32
#define MEOW_V6_STATE_WORDS 16

void meow_hash_v6(const uint8_t *input, size_t len, uint8_t output[MEOW_V6_HASH_BYTES]);
void meow_hash_v6_hex(const uint8_t *input, size_t len, char hex_out[65]);

#endif /* MEOW_HASH_V6_H */

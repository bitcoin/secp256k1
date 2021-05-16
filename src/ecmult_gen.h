/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_H
#define SECP256K1_ECMULT_GEN_H

#include "scalar.h"
#include "group.h"

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)

  /* We need to control these values for exhaustive tests because
   * the tables cannot have infinities in them (secp256k1_ge_storage
   * doesn't support infinities) */
#undef COMB_BLOCKS
#undef COMB_TEETH
#undef COMB_SPACING

#  if EXHAUSTIVE_TEST_ORDER > 32
#    define COMB_BLOCKS 52
#    define COMB_TEETH 5
#  elif EXHAUSTIVE_TEST_ORDER > 16
#    define COMB_BLOCKS 64
#    define COMB_TEETH 4
#  elif EXHAUSTIVE_TEST_ORDER > 8
#    define COMB_BLOCKS 86
#    define COMB_TEETH 3
#  elif EXHAUSTIVE_TEST_ORDER > 4
#    define COMB_BLOCKS 128
#    define COMB_TEETH 2
#  else
#    define COMB_BLOCKS 256
#    define COMB_TEETH 1
#  endif

#  define COMB_SPACING 1

#else

  /* COMB_BLOCKS, COMB_TEETH, COMB_SPACING must all be positive and the product of the three (COMB_BITS)
   * must evaluate to a value in the range [256, 288]. The resulting memory usage for precomputation
   * will be COMB_POINTS_TOTAL * sizeof(secp256k1_ge_storage). */
#  ifndef COMB_BLOCKS
#    define COMB_BLOCKS 4
#  endif
#  ifndef COMB_TEETH
#    define COMB_TEETH 5
#  endif
#  ifndef COMB_SPACING
#    define COMB_SPACING ((COMB_BLOCKS * COMB_TEETH + 255) / (COMB_BLOCKS * COMB_TEETH))
#  endif

#endif

#if !(1 <= COMB_BLOCKS && COMB_BLOCKS <= 256)
#  error "COMB_BLOCKS must be in the range [1, 256]"
#endif
#if !(1 <= COMB_TEETH && COMB_TEETH <= 8)
#  error "COMB_TEETH must be in the range [1, 8]"
#endif
#if !(1 <= COMB_SPACING && COMB_SPACING <= 256)
#  error "COMB_SPACING must be in the range [1, 256]"
#endif

/* The remaining COMB_* parameters are derived values, don't modify these. */
#define COMB_BITS (COMB_BLOCKS * COMB_TEETH * COMB_SPACING)
#define COMB_GROUPED ((COMB_SPACING == 1) && ((32 % COMB_TEETH) == 0))
#define COMB_OFFSET (COMB_BITS == 256)
#define COMB_POINTS (1 << (COMB_TEETH - 1))
#define COMB_POINTS_TOTAL (COMB_BLOCKS * COMB_POINTS)
#define COMB_MASK (COMB_POINTS - 1)

#if !(256 <= COMB_BITS && COMB_BITS <= 288)
#  error "COMB_BITS must be in the range [256, 288]"
#endif

typedef struct {
    /* Precomputation data for the signed-digit multi-comb algorithm as described in section 3.3 of:
     *     "Fast and compact elliptic-curve cryptography", Mike Hamburg
     *         (https://eprint.iacr.org/2012/309)
     */
    secp256k1_ge_storage (*prec)[COMB_BLOCKS][COMB_POINTS];
#if COMB_OFFSET
    /* Signed recoding of a 256-bit scalar must be at least 257 bits, with the top bit always 1. We
     * support a 256-bit comb over a 257-bit recoding by pre-adding an 'offset' value to the context's
     * 'initial' value, to account for the high 1 bit. Note that the 'offset' is calculated to allow
     * for the (COMB_SPACING - 1) doublings in the _ecmult_gen ladder.
     */
    secp256k1_ge offset;
#endif
    secp256k1_scalar blind;
    secp256k1_gej initial;
} secp256k1_ecmult_gen_context;

static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
static void secp256k1_ecmult_gen_context_init(secp256k1_ecmult_gen_context* ctx);
static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context* ctx, void **prealloc);
static void secp256k1_ecmult_gen_context_finalize_memcpy(secp256k1_ecmult_gen_context *dst, const secp256k1_ecmult_gen_context* src);
static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context* ctx);
static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx);

/** Multiply with the generator: R = a*G */
static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context* ctx, secp256k1_gej *r, const secp256k1_scalar *a);

static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32);

#endif /* SECP256K1_ECMULT_GEN_H */

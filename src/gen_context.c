/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Thomas Daede, Cory Fields            *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/* Autotools creates libsecp256k1-config.h, of which ECMULT_GEN_PREC_BITS is needed.
   ifndef guard so downstream users can define their own if they do not use autotools. */
#if !defined(ECMULT_GEN_PREC_BITS)
#include "libsecp256k1-config.h"
#endif

/* We can't require the precomputed tables when creating them. */
#undef USE_ECMULT_STATIC_PRECOMPUTATION

/* In principle we could use external ASM, but this yields only a minor speedup in
   build time and it's very complicated. In particular when cross-compiling, we'd
   need to build the external ASM for the build and the host machine. */
#undef USE_EXTERNAL_ASM

#include "../include/secp256k1.h"
#include "assumptions.h"
#include "util.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_gen_impl.h"

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}

static const secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};

int main(int argc, char **argv) {
    secp256k1_ecmult_gen_context ctx;
    void *prealloc, *base;
    int inner;
    int outer;
    FILE* fp;
    const char *SC_FORMAT = "    SC(%uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu)";

    const int blocks = COMB_BLOCKS;
    const int points = COMB_POINTS;
#if COMB_OFFSET
    secp256k1_ge_storage offset;
#endif

    (void)argc;
    (void)argv;

    fp = fopen("src/ecmult_static_context.h","w");
    if (fp == NULL) {
        fprintf(stderr, "Could not open src/ecmult_static_context.h for writing!\n");
        return -1;
    }

    fprintf(fp, "#ifndef SECP256K1_ECMULT_STATIC_CONTEXT_H\n");
    fprintf(fp, "#define SECP256K1_ECMULT_STATIC_CONTEXT_H\n");
    fprintf(fp, "#include \"src/group.h\"\n");
    fprintf(fp, "#define SC SECP256K1_GE_STORAGE_CONST\n");
    fprintf(fp, "#if COMB_BLOCKS != %i || COMB_TEETH != %i || COMB_SPACING != %i\n", COMB_BLOCKS, COMB_TEETH, COMB_SPACING);
    fprintf(fp, "   #error configuration mismatch, invalid COMB_BLOCKS, COMB_TEETH, or COMB_SPACING. Try deleting ecmult_static_context.h before the build.\n");
    fprintf(fp, "#endif\n");

    base = checked_malloc(&default_error_callback, SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE);
    prealloc = base;
    secp256k1_ecmult_gen_context_init(&ctx);
    secp256k1_ecmult_gen_context_build(&ctx, &prealloc);

#if COMB_OFFSET
    secp256k1_ge_to_storage(&offset, &ctx.offset);
    fprintf(fp, "static const secp256k1_ge_storage secp256k1_ecmult_gen_ctx_offset =\n");
    fprintf(fp, SC_FORMAT, SECP256K1_GE_STORAGE_CONST_GET(offset));
    fprintf(fp, ";\n");
#endif

    fprintf(fp, "static const secp256k1_ge_storage secp256k1_ecmult_gen_ctx_prec[%i][%i] = {\n", blocks, points);
    for(outer = 0; outer != blocks; outer++) {
        fprintf(fp,"{\n");
        for(inner = 0; inner != points; inner++) {
            fprintf(fp, SC_FORMAT, SECP256K1_GE_STORAGE_CONST_GET((*ctx.prec)[outer][inner]));
            if (inner != (points - 1)) {
                fprintf(fp,",\n");
            } else {
                fprintf(fp,"\n");
            }
        }
        if (outer != (blocks - 1)) {
            fprintf(fp,"},\n");
        } else {
            fprintf(fp,"}\n");
        }
    }
    fprintf(fp,"};\n");
    secp256k1_ecmult_gen_context_clear(&ctx);
    free(base);

    fprintf(fp, "#undef SC\n");
    fprintf(fp, "#endif\n");
    fclose(fp);

    return 0;
}

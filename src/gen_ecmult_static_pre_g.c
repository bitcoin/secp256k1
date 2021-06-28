/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

#include <inttypes.h>
#include <stdio.h>

/* Autotools creates libsecp256k1-config.h, of which ECMULT_WINDOW_SIZE is needed.
   ifndef guard so downstream users can define their own if they do not use autotools. */
#if !defined(ECMULT_WINDOW_SIZE)
#include "libsecp256k1-config.h"
#endif

/* In principle we could use external ASM, but this yields only a minor speedup in
   build time and it's very complicated. In particular when cross-compiling, we'd
   need to build the external ASM for the build and the host machine. */
#undef USE_EXTERNAL_ASM

#include "../include/secp256k1.h"
#include "assumptions.h"
#include "util.h"
#include "field_impl.h"
#include "group_impl.h"
#include "ecmult.h"

static void secp256k1_ecmult_odd_multiples_table_storage(const int n, secp256k1_ge_storage *pre, const secp256k1_gej *a) {
    secp256k1_gej d;
    secp256k1_ge d_ge, p_ge;
    secp256k1_gej pj;
    secp256k1_fe zi;
    secp256k1_fe zr;
    secp256k1_fe dx_over_dz_squared;
    int i;

    secp256k1_gej_double_var(&d, a, NULL);

    /* First, we perform all the additions in an isomorphic curve obtained by multiplying
     * all `z` coordinates by 1/`d.z`. In these coordinates `d` is affine so we can use
     * `secp256k1_gej_add_ge_var` to perform the additions. For each addition, we store
     * the resulting y-coordinate and the z-ratio, since we only have enough memory to
     * store two field elements. These are sufficient to efficiently undo the isomorphism
     * and recompute all the `x`s.
     */
    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    secp256k1_ge_set_gej_zinv(&p_ge, a, &d.z);
    pj.x = p_ge.x;
    pj.y = p_ge.y;
    pj.z = a->z;
    pj.infinity = 0;

    for (i = 0; i < (n - 1); i++) {
        secp256k1_fe_normalize_var(&pj.y);
        secp256k1_fe_to_storage(&pre[i].y, &pj.y);
        secp256k1_gej_add_ge_var(&pj, &pj, &d_ge, &zr);
        secp256k1_fe_normalize_var(&zr);
        secp256k1_fe_to_storage(&pre[i].x, &zr);
    }

    /* Invert d.z in the same batch, preserving pj.z so we can extract 1/d.z */
    secp256k1_fe_mul(&zi, &pj.z, &d.z);
    secp256k1_fe_inv_var(&zi, &zi);

    /* Directly set `pre[n - 1]` to `pj`, saving the inverted z-coordinate so
     * that we can combine it with the saved z-ratios to compute the other zs
     * without any more inversions. */
    secp256k1_ge_set_gej_zinv(&p_ge, &pj, &zi);
    secp256k1_ge_to_storage(&pre[n - 1], &p_ge);

    /* Compute the actual x-coordinate of D, which will be needed below. */
    secp256k1_fe_mul(&d.z, &zi, &pj.z);  /* d.z = 1/d.z */
    secp256k1_fe_sqr(&dx_over_dz_squared, &d.z);
    secp256k1_fe_mul(&dx_over_dz_squared, &dx_over_dz_squared, &d.x);

    /* Going into the second loop, we have set `pre[n-1]` to its final affine
     * form, but still need to set `pre[i]` for `i` in 0 through `n-2`. We
     * have `zi = (p.z * d.z)^-1`, where
     *
     *     `p.z` is the z-coordinate of the point on the isomorphic curve
     *           which was ultimately assigned to `pre[n-1]`.
     *     `d.z` is the multiplier that must be applied to all z-coordinates
     *           to move from our isomorphic curve back to secp256k1; so the
     *           product `p.z * d.z` is the z-coordinate of the secp256k1
     *           point assigned to `pre[n-1]`.
     *
     * All subsequent inverse-z-coordinates can be obtained by multiplying this
     * factor by successive z-ratios, which is much more efficient than directly
     * computing each one.
     *
     * Importantly, these inverse-zs will be coordinates of points on secp256k1,
     * while our other stored values come from computations on the isomorphic
     * curve. So in the below loop, we will take care not to actually use `zi`
     * or any derived values until we're back on secp256k1.
     */
    i = n - 1;
    while (i > 0) {
        secp256k1_fe zi2, zi3;
        const secp256k1_fe *rzr;
        i--;

        secp256k1_ge_from_storage(&p_ge, &pre[i]);

        /* For each remaining point, we extract the z-ratio from the stored
         * x-coordinate, compute its z^-1 from that, and compute the full
         * point from that. */
        rzr = &p_ge.x;
        secp256k1_fe_mul(&zi, &zi, rzr);
        secp256k1_fe_sqr(&zi2, &zi);
        secp256k1_fe_mul(&zi3, &zi2, &zi);
        /* To compute the actual x-coordinate, we use the stored z ratio and
         * y-coordinate, which we obtained from `secp256k1_gej_add_ge_var`
         * in the loop above, as well as the inverse of the square of its
         * z-coordinate. We store the latter in the `zi2` variable, which is
         * computed iteratively starting from the overall Z inverse then
         * multiplying by each z-ratio in turn.
         *
         * Denoting the z-ratio as `rzr`, we observe that it is equal to `h`
         * from the inside of the above `gej_add_ge_var` call. This satisfies
         *
         *    rzr = d_x * z^2 - x * d_z^2
         *
         * where (`d_x`, `d_z`) are Jacobian coordinates of `D` and `(x, z)`
         * are Jacobian coordinates of our desired point -- except both are on
         * the isomorphic curve that we were using when we called `gej_add_ge_var`.
         * To get back to secp256k1, we must multiply both `z`s by `d_z`, or
         * equivalently divide both `x`s by `d_z^2`. Our equation then becomes
         *
         *    rzr = d_x * z^2 / d_z^2 - x
         *
         * (The left-hand-side, being a ratio of z-coordinates, is unaffected
         * by the isomorphism.)
         *
         * Rearranging to solve for `x`, we have
         *
         *     x = d_x * z^2 / d_z^2 - rzr
         *
         * But what we actually want is the affine coordinate `X = x/z^2`,
         * which will satisfy
         *
         *     X = d_x / d_z^2 - rzr / z^2
         *       = dx_over_dz_squared - rzr * zi2
         */
        secp256k1_fe_mul(&p_ge.x, rzr, &zi2);
        secp256k1_fe_negate(&p_ge.x, &p_ge.x, 1);
        secp256k1_fe_add(&p_ge.x, &dx_over_dz_squared);
        /* y is stored_y/z^3, as we expect */
        secp256k1_fe_mul(&p_ge.y, &p_ge.y, &zi3);
        /* Store */
        secp256k1_ge_to_storage(&pre[i], &p_ge);
    }
}

void print_table(FILE *fp, const char *name, int window_g, const secp256k1_gej *gj, int with_conditionals) {
    /* This array is only static because it may be unreasonably large to place on the stack. */
    static secp256k1_ge_storage pre[ECMULT_TABLE_SIZE(ECMULT_WINDOW_SIZE) < ECMULT_TABLE_SIZE(8)
                                  ? ECMULT_TABLE_SIZE(8)
                                  : ECMULT_TABLE_SIZE(ECMULT_WINDOW_SIZE)];
    int j;
    int i;

    secp256k1_ecmult_odd_multiples_table_storage(ECMULT_TABLE_SIZE(window_g), pre, gj);
    fprintf(fp, "static const secp256k1_ge_storage %s[ECMULT_TABLE_SIZE(WINDOW_G)] = {\n", name);
    fprintf(fp, " S(%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32
                  ",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32")\n",
                SECP256K1_GE_STORAGE_CONST_GET(pre[0]));
    j = 1;
    for(i = 3; i <= window_g; ++i) {
        if (with_conditionals) {
            fprintf(fp, "#if ECMULT_TABLE_SIZE(WINDOW_G) > %ld\n", ECMULT_TABLE_SIZE(i-1));
        }
        for(;j < ECMULT_TABLE_SIZE(i); ++j) {
            fprintf(fp, ",S(%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32
                          ",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32",%"PRIx32")\n",
                        SECP256K1_GE_STORAGE_CONST_GET(pre[j]));
        }
        if (with_conditionals) {
            fprintf(fp, "#endif\n");
        }
    }
    fprintf(fp, "};\n");

}

void print_two_tables(FILE *fp, int window_g, const secp256k1_ge *g, int with_conditionals) {
    secp256k1_gej gj;
    int i;

    secp256k1_gej_set_ge(&gj, g);
    print_table(fp, "secp256k1_pre_g", window_g, &gj, with_conditionals);
    for (i = 0; i < 128; ++i) {
        secp256k1_gej_double_var(&gj, &gj, NULL);
    }
    print_table(fp, "secp256k1_pre_g_128", window_g, &gj, with_conditionals);
}

int main(void) {
    const secp256k1_ge g = SECP256K1_G;
    const secp256k1_ge g_13 = SECP256K1_G_ORDER_13;
    const secp256k1_ge g_199 = SECP256K1_G_ORDER_199;
    const int window_g_13 = 4;
    const int window_g_199 = 8;
    FILE* fp;

    fp = fopen("src/ecmult_static_pre_g.h","w");
    if (fp == NULL) {
        fprintf(stderr, "Could not open src/ecmult_static_pre_g.h for writing!\n");
        return -1;
    }

    fprintf(fp, "/* This file was automatically generated by gen_ecmult_static_pre_g. */\n");
    fprintf(fp, "#ifndef SECP256K1_ECMULT_STATIC_PRE_G_H\n");
    fprintf(fp, "#define SECP256K1_ECMULT_STATIC_PRE_G_H\n");
    fprintf(fp, "#include \"group.h\"\n");
    fprintf(fp, "#ifdef S\n");
    fprintf(fp, "   #error macro identifier S already in use.\n");
    fprintf(fp, "#endif\n");
    fprintf(fp, "#define S(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) "
                "SECP256K1_GE_STORAGE_CONST(0x##a##u,0x##b##u,0x##c##u,0x##d##u,0x##e##u,0x##f##u,0x##g##u,"
                "0x##h##u,0x##i##u,0x##j##u,0x##k##u,0x##l##u,0x##m##u,0x##n##u,0x##o##u,0x##p##u)\n");
    fprintf(fp, "#if ECMULT_TABLE_SIZE(ECMULT_WINDOW_SIZE) > %ld\n", ECMULT_TABLE_SIZE(ECMULT_WINDOW_SIZE));
    fprintf(fp, "   #error configuration mismatch, invalid ECMULT_WINDOW_SIZE. Try deleting ecmult_static_pre_g.h before the build.\n");
    fprintf(fp, "#endif\n");
    fprintf(fp, "#if defined(EXHAUSTIVE_TEST_ORDER)\n");
    fprintf(fp, "#if EXHAUSTIVE_TEST_ORDER == 13\n");
    fprintf(fp, "#define WINDOW_G %d\n", window_g_13);

    print_two_tables(fp, window_g_13, &g_13, 0);

    fprintf(fp, "#elif EXHAUSTIVE_TEST_ORDER == 199\n");
    fprintf(fp, "#define WINDOW_G %d\n", window_g_199);

    print_two_tables(fp, window_g_199, &g_199, 0);

    fprintf(fp, "#else\n");
    fprintf(fp, "   #error No known generator for the specified exhaustive test group order.\n");
    fprintf(fp, "#endif\n");
    fprintf(fp, "#else /* !defined(EXHAUSTIVE_TEST_ORDER) */\n");
    fprintf(fp, "#define WINDOW_G ECMULT_WINDOW_SIZE\n");

    print_two_tables(fp, ECMULT_WINDOW_SIZE, &g, 1);

    fprintf(fp, "#endif\n");
    fprintf(fp, "#undef S\n");
    fprintf(fp, "#endif\n");
    fclose(fp);

    return 0;
}

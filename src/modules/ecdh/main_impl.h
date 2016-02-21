/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECDH_MAIN_
#define _SECP256K1_MODULE_ECDH_MAIN_

#include "include/secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

static void secp256k1_ecdh_hash(unsigned char *result, secp256k1_ge *pt) {
    unsigned char x[32];
    unsigned char y[1];
    secp256k1_sha256_t sha;

    /* Compute a hash of the point in compressed form
     * Note we cannot use secp256k1_eckey_pubkey_serialize here since it does not
     * expect its output to be secret and has a timing sidechannel. */
    secp256k1_fe_normalize(&pt->x);
    secp256k1_fe_normalize(&pt->y);
    secp256k1_fe_get_b32(x, &pt->x);
    y[0] = 0x02 | secp256k1_fe_is_odd(&pt->y);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, y, sizeof(y));
    secp256k1_sha256_write(&sha, x, sizeof(x));
    secp256k1_sha256_finalize(&sha, result);
}

int secp256k1_ecdh(const secp256k1_context *ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    secp256k1_gej res;
    secp256k1_ge pt;
    secp256k1_scalar s;
    ARG_CHECK(result != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);
    (void)ctx;

    secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        secp256k1_pubkey_load(ctx, &pt, point);
        secp256k1_ecmult_const(&res, &pt, &s);
        secp256k1_ge_set_gej(&pt, &res);
        secp256k1_ecdh_hash(result, &pt);
        ret = 1;
    }

    secp256k1_scalar_clear(&s);
    return ret;
}

int secp256k1_ecdh_opt(const secp256k1_context *ctx, unsigned char *result, const unsigned char *pub, size_t publen, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    secp256k1_fe k, t, zi;
    secp256k1_gej res;
    secp256k1_ge pt;
    secp256k1_scalar s;
    ARG_CHECK(result != NULL);
    ARG_CHECK(pub != NULL);
    ARG_CHECK(scalar != NULL);
    (void)ctx;

    if (!(publen == 33 && (pub[0] == 0x02 || pub[0] == 0x03))) {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pub, publen)) {
            return 0;
        }
        return secp256k1_ecdh(ctx, result, &pubkey, scalar);
    }

    if (!secp256k1_fe_set_b32(&t, &pub[1])) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        /*
         * Construct a point on an isomorphism described by u^2 == k (possibly on the twist)
         */
        secp256k1_ge_set_xo_iso(&pt, &k, &t);
        secp256k1_ecmult_const(&res, &pt, &s);

        /*
         * Set 't' to the reciprocal sqrt of 'k' and 'zi' to the inverse of 'res.z'.
         *
         * TODO Infinity is a possibility because the twist has smaller order - the sqrt
         *      would not be found in that case anyway, but need to handle possible 0 in res.z?
         *      (Probably need cmovs based on res.infinity into 'ret' and 'res.z', to replace
         *      the simple test here.)
         * TODO Need secp256k1_fe_par_rsqrt_inv_var to be constant-time (and maybe handle 0?)
         */
        if (res.infinity || !secp256k1_fe_par_rsqrt_inv_var(&t, &zi, &k, &res.z)) {
            ret = 0;
        }
        else {
            secp256k1_fe_mul(&zi, &zi, &t);

            /* Set (+/-)t = "pub.y" (from compressed input); adjust the sign of 'zi' accordingly */
            secp256k1_fe_mul(&t, &t, &k);
            secp256k1_fe_normalize(&t);
            if (secp256k1_fe_is_odd(&t) != (pub[0] == 0x03)) {
                secp256k1_fe_negate(&zi, &zi, 1);
            }

            secp256k1_ge_set_gej_zinv(&pt, &res, &zi);
            secp256k1_ecdh_hash(result, &pt);
            ret = 1;
        }
    }

    secp256k1_scalar_clear(&s);
    return ret;
}

#endif

/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MULTISET_MAIN_
#define _SECP256K1_MODULE_MULTISET_MAIN_


#include "include/secp256k1_multiset.h"

#include "hash.h"
#include "field.h"
#include "group.h"

/* Converts a group element (Jacobian) to a multiset.
 * Requires the field elements to be normalized
 * Infinite uses special value, z = 0 */
static void multiset_from_gej_var(secp256k1_multiset *target, const secp256k1_gej *input) {

    if (input->infinity) {
        memset(&target->d, 0, sizeof(target->d));
    }
    else {
        secp256k1_fe_get_b32(target->d, &input->x);
        secp256k1_fe_get_b32(target->d+32, &input->y);
        secp256k1_fe_get_b32(target->d+64, &input->z);
    }
}

/* Converts a multiset to group element (Jacobian)
 * Infinite uses special value, z = 0 */
static void gej_from_multiset_var(secp256k1_gej *target,  const secp256k1_multiset *input) {

    secp256k1_fe_set_b32(&target->x, input->d);
    secp256k1_fe_set_b32(&target->y, input->d+32);
    secp256k1_fe_set_b32(&target->z, input->d+64);

    target->infinity = secp256k1_fe_is_zero(&target->z) ? 1 : 0;
}

/* Converts a data element to a group element (affine)
 *
 * We use trial-and-rehash which is fast but non-constant time.
 * Though constant time algo's exist we are not concerned with timing attacks
 * as we make no attempt to hide the underlying data */
static void ge_from_data_var(secp256k1_ge *target, const unsigned char *input, size_t inputLen) {

    secp256k1_sha256_t hasher;
    unsigned char hash[32];

    /* hash to a first trial */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, input, inputLen);
    secp256k1_sha256_finalize(&hasher, hash);

    /* loop through trials, with 50% success per loop */
    for(;;)
    {
        secp256k1_fe x;

        if (secp256k1_fe_set_b32(&x, hash)) {

            if (secp256k1_ge_set_xquad(target, &x)) {

                VERIFY_CHECK(secp256k1_ge_is_valid_var(target));
                VERIFY_CHECK(!secp256k1_ge_is_infinity(target));
                break;
            }
        }

        /* hash to a new trial */
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, hash, sizeof(hash));
        secp256k1_sha256_finalize(&hasher, hash);
    }

}


/* Adds a data element to the multiset */
int secp256k1_multiset_add(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    secp256k1_ge newelm;
    secp256k1_gej source, target;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&source, multiset);
    ge_from_data_var(&newelm, input, inputLen);

    secp256k1_gej_add_ge_var(&target, &source, &newelm, NULL);

    secp256k1_fe_normalize(&target.x);
    secp256k1_fe_normalize(&target.y);
    secp256k1_fe_normalize(&target.z);
    multiset_from_gej_var(multiset, &target);

    return 1;
}

/* Removes a data element from the multiset */
int secp256k1_multiset_remove(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    secp256k1_ge newelm, neg_newelm;
    secp256k1_gej source, target;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&source, multiset);
    ge_from_data_var(&newelm, input, inputLen);

    /* find inverse and add */
    secp256k1_ge_neg(&neg_newelm, &newelm);
    secp256k1_gej_add_ge_var(&target, &source, &neg_newelm, NULL);

    secp256k1_fe_normalize(&target.x);
    secp256k1_fe_normalize(&target.y);
    secp256k1_fe_normalize(&target.z);
    multiset_from_gej_var(multiset, &target);

    return 1;
}

/* Adds input multiset to multiset */
int secp256k1_multiset_combine(const secp256k1_context* ctx, secp256k1_multiset *multiset, const secp256k1_multiset *input)
{
    secp256k1_gej gej_multiset, gej_input, gej_result;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    gej_from_multiset_var(&gej_multiset, multiset);
    gej_from_multiset_var(&gej_input, input);

    secp256k1_gej_add_var(&gej_result, &gej_multiset, &gej_input, NULL);

    secp256k1_fe_normalize(&gej_result.x);
    secp256k1_fe_normalize(&gej_result.y);
    secp256k1_fe_normalize(&gej_result.z);
    multiset_from_gej_var(multiset, &gej_result);

    return 1;
}


/* Hash the multiset into resultHash */
int secp256k1_multiset_finalize(const secp256k1_context* ctx, unsigned char *resultHash, const secp256k1_multiset *multiset)
{
    secp256k1_sha256_t hasher;
    unsigned char buffer[64];
    secp256k1_gej gej;
    secp256k1_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(resultHash != NULL);
    ARG_CHECK(multiset != NULL);

    gej_from_multiset_var(&gej, multiset);
    if (gej.infinity) {

        memset(buffer, 0xff, sizeof(buffer));
    } else {

        /* we must normalize to affine first */
        secp256k1_ge_set_gej(&ge, &gej);
        secp256k1_fe_normalize(&ge.x);
        secp256k1_fe_normalize(&ge.y);
        secp256k1_fe_get_b32(buffer, &ge.x);
        secp256k1_fe_get_b32(buffer+32, &ge.y);
    }

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, buffer, sizeof(buffer));
    secp256k1_sha256_finalize(&hasher, resultHash);

    return 1;
}

/* Inits the multiset with the constant for empty data,
   represented by the Jacobian GE infinite */
int secp256k1_multiset_init(const secp256k1_context* ctx, secp256k1_multiset *multiset) {


    const secp256k1_gej inf = SECP256K1_GEJ_CONST_INFINITY;

    VERIFY_CHECK(ctx != NULL);

    multiset_from_gej_var(multiset, &inf);

    return 1;
}

#endif

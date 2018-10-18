/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_AGGSIG_TESTS_
#define _SECP256K1_MODULE_AGGSIG_TESTS_

#include "secp256k1_aggsig.h"

void test_aggsig_api(void) {
    /* Setup contexts that just count errors */
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(none, 1024, 32768);
    unsigned char seckeys[5][32];
    secp256k1_pubkey pubkeys[5];
    secp256k1_aggsig_partial_signature partials[5];
    secp256k1_aggsig_context *aggctx;
    unsigned char seed[32] = { 1, 2, 3, 4, 0 };
    unsigned char sig[64];
    unsigned char *msg = seed;  /* shh ;) */
    int32_t ecount = 0;
    size_t i;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    for (i = 0; i < 5; i++) {
        secp256k1_scalar tmp_s;
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(seckeys[i], &tmp_s);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkeys[i], seckeys[i]) == 1);
    }

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 5, seed);
    CHECK(ecount == 0);
    CHECK(aggctx != NULL);
    secp256k1_aggsig_context_destroy(NULL);  /* harmless */
    secp256k1_aggsig_context_destroy(aggctx);

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 0, seed);
    CHECK(ecount == 0);
    CHECK(aggctx != NULL);
    secp256k1_aggsig_context_destroy(aggctx);

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 0, NULL);
    CHECK(ecount == 1);
    CHECK(aggctx == NULL);
    aggctx = secp256k1_aggsig_context_create(none, NULL, 0, seed);
    CHECK(ecount == 2);
    CHECK(aggctx == NULL);

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 5, seed);

    CHECK(!secp256k1_aggsig_generate_nonce(none, aggctx, 0));
    CHECK(ecount == 3);
    CHECK(secp256k1_aggsig_generate_nonce(sign, aggctx, 0));
    CHECK(ecount == 3);
    CHECK(!secp256k1_aggsig_generate_nonce(vrfy, aggctx, 0));
    CHECK(ecount == 4);
    CHECK(!secp256k1_aggsig_generate_nonce(both, aggctx, 0));  /* double-generate, not API error */
    CHECK(ecount == 4);
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 1));
    CHECK(ecount == 4);
    CHECK(!secp256k1_aggsig_generate_nonce(both, NULL, 2));
    CHECK(ecount == 5);
    CHECK(!secp256k1_aggsig_generate_nonce(both, aggctx, 5));   /* out of range, API error */
    CHECK(ecount == 6);

    CHECK(!secp256k1_aggsig_partial_sign(both, aggctx, &partials[0], msg, seckeys[0], 0));  /* not all nonces generated, not API error */
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 2));
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 3));
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 4));
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[0], msg, seckeys[0], 0));
    CHECK(!secp256k1_aggsig_partial_sign(both, aggctx, &partials[0], msg, seckeys[0], 0));  /* double sign, not API error */
    CHECK(ecount == 6);

    CHECK(!secp256k1_aggsig_partial_sign(none, aggctx, &partials[1], msg, seckeys[1], 1));
    CHECK(ecount == 7);
    CHECK(!secp256k1_aggsig_partial_sign(vrfy, aggctx, &partials[1], msg, seckeys[1], 1));
    CHECK(ecount == 8);
    CHECK(secp256k1_aggsig_partial_sign(sign, aggctx, &partials[1], msg, seckeys[1], 1));
    CHECK(ecount == 8);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, NULL, msg, seckeys[2], 2));
    CHECK(ecount == 9);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, &partials[2], NULL, seckeys[2], 2));
    CHECK(ecount == 10);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, &partials[2], msg, NULL, 2));
    CHECK(ecount == 11);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, &partials[2], msg, seckeys[2], 5));  /* out of range, API error */
    CHECK(ecount == 12);
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[2], msg, seckeys[2], 2));
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[3], msg, seckeys[3], 3));
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[4], msg, seckeys[4], 4));
    CHECK(ecount == 12);

    CHECK(secp256k1_aggsig_combine_signatures(none, aggctx, sig, partials, 5));
    CHECK(!secp256k1_aggsig_combine_signatures(none, aggctx, sig, partials, 4)); /* wrong sig count, not API error (should it be?)  */
    CHECK(!secp256k1_aggsig_combine_signatures(none, aggctx, sig, partials, 0));
    CHECK(ecount == 12);
    CHECK(!secp256k1_aggsig_combine_signatures(none, NULL, sig, partials, 5));
    CHECK(ecount == 13);
    CHECK(!secp256k1_aggsig_combine_signatures(none, aggctx, NULL, partials, 5));
    CHECK(ecount == 14);
    CHECK(!secp256k1_aggsig_combine_signatures(none, aggctx, sig, NULL, 5));
    CHECK(ecount == 15);

    memset(sig, 0, sizeof(sig));
    CHECK(!secp256k1_aggsig_verify(none, scratch, sig, msg, pubkeys, 5));
    CHECK(ecount == 16);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 5));
    CHECK(secp256k1_aggsig_combine_signatures(none, aggctx, sig, partials, 5));
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 4));
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 0));
    CHECK(secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 5));
    CHECK(ecount == 16);

    CHECK(!secp256k1_aggsig_verify(vrfy, NULL, sig, msg, pubkeys, 5));
    CHECK(ecount == 17);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, NULL, msg, pubkeys, 5));
    CHECK(ecount == 18);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, NULL, pubkeys, 5));
    CHECK(ecount == 19);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, NULL, 5));
    CHECK(ecount == 20);

    /* cleanup */
    secp256k1_aggsig_context_destroy(aggctx);
    secp256k1_scratch_space_destroy(scratch);
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

#define N_KEYS 200
void test_aggsig_onesigner(void) {
    secp256k1_pubkey pubkeys[N_KEYS];
    unsigned char seckeys[N_KEYS][32];
    secp256k1_aggsig_partial_signature partials[N_KEYS];
    const size_t n_pubkeys = sizeof(pubkeys) / sizeof(pubkeys[0]);
    secp256k1_scalar tmp_s;
    size_t i;
    size_t n_signers[] = { 1, 2, N_KEYS / 5, N_KEYS - 1, N_KEYS };
    const size_t n_n_signers = sizeof(n_signers) / sizeof(n_signers[0]);
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024, 32768);

    unsigned char msg[32];

    random_scalar_order_test(&tmp_s);
    secp256k1_scalar_get_b32(msg, &tmp_s);

    for (i = 0; i < n_pubkeys; i++) {
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(seckeys[i], &tmp_s);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkeys[i], seckeys[i]) == 1);
    }

    for (i = 0; i < n_n_signers; i++) {
        size_t j;
        unsigned char seed[32];
        unsigned char sig[64];
        secp256k1_aggsig_context *aggctx;

        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(seed, &tmp_s);
        aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, n_signers[i], seed);

        /* all nonces must be generated before signing */
        for (j = 0; j < n_signers[i]; j++) {
            CHECK(secp256k1_aggsig_generate_nonce(ctx, aggctx, j));
        }
        for (j = 0; j < n_signers[i]; j++) {
            CHECK(secp256k1_aggsig_partial_sign(ctx, aggctx, &partials[j], msg, seckeys[j], j));
        }
        CHECK(secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, partials, n_signers[i]));
        CHECK(secp256k1_aggsig_verify(ctx, scratch, sig, msg, pubkeys, n_signers[i]));
        /* Make sure verification with 0 pubkeys fails without Bad Things happenings */
        CHECK(!secp256k1_aggsig_verify(ctx, scratch, sig, msg, pubkeys, 0));

        secp256k1_aggsig_context_destroy(aggctx);
    }

    secp256k1_scratch_space_destroy(scratch);
}
#undef N_KEYS

void run_aggsig_tests(void) {
    test_aggsig_api();
    test_aggsig_onesigner();
}

#endif
